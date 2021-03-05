"""DNS Authenticator for StackPath."""
import logging

import pystackpath
import zope.interface
from acme.magic_typing import Any, Dict
from certbot.plugins import dns_common

from certbot import errors, interfaces

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://control.stackpath.com/api-management'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for StackPath

    This Authenticator uses the StackPath API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using StackPath for '
                   'DNS).')
    ttl = 120

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='StackPath credentials INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' \
               'the StackPath API.'

    def _validate_credentials(self, credentials):
        client_id = credentials.conf('client-id')
        client_secret = credentials.conf('client-secret')
        stack_id = credentials.conf('stack-id')
        if client_id:
            if not client_secret:
                raise errors.PluginError(
                    f'{credentials.confobj.filename}: '
                    f'dns_stackpath_client_secret_api_key is required when using a '
                    f'Client Secret API Key. (see {ACCOUNT_URL})'
                )
            if not stack_id:
                raise errors.PluginError(
                    f'{credentials.confobj.filename}: dns_stackpath_stack_id is required')
        else:
            raise errors.PluginError(
                f'{credentials.confobj.filename}: dns_stackpath_client_id, '
                f'dns_stackpath_client_secret and dns_stackpath_stack_id are required. '
                f'(see {ACCOUNT_URL})'
            )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'StackPath credentials INI file',
            None,
            self._validate_credentials
        )

    def _perform(self, domain, validation_name, validation):
        self._get_stackpath_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, unused):
        self._get_stackpath_client().del_txt_record(domain, validation_name, unused)

    def _get_stackpath_client(self):
        if self.credentials.conf('client-id') \
            and self.credentials.conf('client-secret') \
            and self.credentials.conf('stack-id'):
            return _StackPathClient(
                self.credentials.conf('client-id'),
                self.credentials.conf('client-secret'),
                self.credentials.conf('stack-id')
            )
        return _StackPathClient(None, None, None)


class _StackPathClient:
    """
    Encapsulates all communication with the StackPath API.
    """

    def __init__(self, client_id, client_secret, stack_id):
        self.stackpath = pystackpath.Stackpath(
            client_id,
            client_secret
        )
        self.stack_id = stack_id

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the StackPath zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the StackPath API
        """

        zone_id = self._find_zone_id(domain)
        zone = self._get_zone_info(zone_id)
        record_name = record_name.replace(f'.{zone.domain}', '')

        payload = {
            'name': record_name,  # we don't need full record name
            'type': 'TXT',
            'ttl': record_ttl,
            'data': record_content,
            'weight': 0
        }

        try:
            logger.debug('Attempting to add record to zone %s: %s', zone_id, payload)
            self.stackpath.stacks().get(self.stack_id).zones().get(zone_id).records().add(
                **payload)  # zones | pylint: disable=no-member
        except pystackpath.HTTPError as e:
            code = int(e)
            hint = None
        record_id = self._find_txt_record_id(zone_id, record_name)
        logger.debug('Successfully added TXT record with record_id: %s', record_id)

    def del_txt_record(self, domain, record_name, unused):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the StackPath zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            zone_id = self._find_zone_id(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding zone_id during deletion: %s', e)
            return

        if zone_id:
            zone = self._get_zone_info(zone_id)
            record_name = record_name.replace(f'.{zone.domain}', '')
            record_id = self._find_txt_record_id(zone_id, record_name)
            if record_id:
                try:
                    # zones | pylint: disable=no-member
                    self.stackpath.stacks().get(self.stack_id) \
                        .zones().get(zone_id) \
                        .records().get(record_id).delete()
                    logger.debug('Successfully deleted TXT record.')
                except pystackpath.HTTPError as e:
                    logger.warning('Encountered pystackpath.HTTPError deleting TXT record: %s', e)
            else:
                logger.debug('TXT record not found; no cleanup needed.')
        else:
            logger.debug(f'Zone not found; no cleanup needed. {domain}')

    def _get_zone_info(self, zone_id):
        try:
            zone = self.stackpath.stacks().get(self.stack_id).zones().get(zone_id)
            return zone
        except pystackpath.HTTPError as e:
            logger.debug(f'Zone not found; {zone_id}')

    def _find_zone_id(self, domain):
        """
        Find the zone_id for a given domain.

        :param str domain: The domain for which to find the zone_id.
        :returns: The zone_id, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if no zone_id is found.
        """

        zone_name_guesses = dns_common.base_domain_name_guesses(domain)
        zones = {}  # type: Dict[str, Any]
        code = msg = None
        for zone_name in zone_name_guesses:
            try:
                logger.debug(f'Looking for {zone_name}')
                zones = self.stackpath.stacks().get(self.stack_id) \
                    .zones().index(
                    filter=f"domain='{zone_name}'")  # zones | pylint: disable=no-member
            except pystackpath.HTTPError as e:
                code = int(e)
                msg = str(e)
                hint = None
            if zones['zones']:
                zone_id = zones['zones'][0].id
                logger.debug('Found zone_id of %s for %s using name %s', zone_id, domain, zone_name)
                return zone_id
        raise errors.PluginError(f'Zone ID for domain {domain} not found')

    def _find_txt_record_id(self, zone_id, record_name):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str zone_id: The zone_id which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :returns: The record_id, if found.
        :rtype: str
        """
        try:
            zone = self._get_zone_info(zone_id)
            record_name = record_name.replace(f'.{zone.domain}', '')
            # zones | pylint: disable=no-member
            resp = self.stackpath.stacks().get(self.stack_id) \
                .zones().get(zone_id) \
                .records().index(filter=f'name="{record_name}" and type="TXT"')
            records = resp.get('records', [])
        except pystackpath.HTTPError as e:
            logger.debug('Encountered pystackpath.HTTPError getting TXT record_id: %s', e)
            records = []

        if records:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.
            return records[0].id
        logger.debug('Unable to find TXT record.')
        return None
