"""
The `~certbot_dns_stackpath.dns_stackpath` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using the StackPath API.

Named Arguments
---------------

========================================  =====================================
``--dns-stackpath-credentials``          StackPath credentials_ INI file.
                                          (Required)
``--dns-stackpath-propagation-seconds``  The number of seconds to wait for DNS
                                          to propagate before asking the ACME
                                          server to verify the DNS record.
                                          (Default: 10)
========================================  =====================================


Credentials
-----------

Use of this plugin requires a configuration file containing StackPath API
credentials, obtained from your
`StackPath dashboard <https://control.stackpath.com/api-management>`_.

Using StackPath Client ID and Client Secret also requires at least version 0.5.0 of the ``pystackpath``
python module.
.

.. code-block:: ini
   :name: certbot_stackpath.ini
   :caption: Example credentials file using Client ID and Client Secret:

   # StackPath API credentials used by Certbot
   dns_stackpath_client_id = 0123456789abcdef0123456789abcdef01234
   dns_stackpath_client_secret = 0123456789abcdef0123456789abcdef012340123456789abcdef0123456789abcdef01234
   dns_stackpath_stack_id = f92247a9-a539-4711-b86e-5ad6f03e32c4

The path to this file can be provided interactively or using the
``--dns-stackpath-credentials`` command-line argument. Certbot records the path
to this file for use during renewal, but does not store the file's contents.

.. caution::
   You should protect these API credentials as you would the password to your
   StackPath account. Users who can read this file can use these credentials
   to issue arbitrary API calls on your behalf. Users who can cause Certbot to
   run using these credentials can complete a ``dns-01`` challenge to acquire
   new certificates or revoke existing certificates for associated domains,
   even if those domains aren't being managed by this server.

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).


Examples
--------

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``

   certbot certonly \\
     --dns-stackpath \\
     --dns-stackpath-credentials ~/.secrets/certbot/stackpath.ini \\
     -d example.com

.. code-block:: bash
   :caption: To acquire a single certificate for both ``example.com`` and
             ``www.example.com``

   certbot certonly \\
     --dns-stackpath \\
     --dns-stackpath-credentials ~/.secrets/certbot/stackpath.ini \\
     -d example.com \\
     -d www.example.com

.. code-block:: bash
   :caption: To acquire a certificate for ``example.com``, waiting 60 seconds
             for DNS propagation

   certbot certonly \\
     --dns-stackpath \\
     --dns-stackpath-credentials ~/.secrets/certbot/stackpath.ini \\
     --dns-stackpath-propagation-seconds 60 \\
     -d example.com

"""
