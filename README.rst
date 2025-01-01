StackPath DNS Authenticator plugin for Certbot
==============================================

⚠️ **This repository is archived and no longer maintained. The StackPath was shutdown on June 14, 2024.**

This plugin automates the process of completing a dns-01 challenge by creating, and subsequently removing, TXT records using the StackPath API.


Installation
------------

::

  pip install certbot-dns-stackpath


Setting credentials.ini
------------
**Generate client secret/id and stack id .**

After you set up API credentials in your StackPath account - you'll need the client id and secret.
You'll also need a 3rd item the "stack id", which isn't really well identified in the StackPath account page.
You'll find it labeled as the "SLUG" on your "My Stacks" account page. The one for my account looks like "my-default-stack-abc123"


**Create your credentials.ini file, with 3 items:**

.. code-block:: ini

  dns_stackpath_client_secret = xyz
  dns_stackpath_client_id = xyz
  dns_stackpath_stack_id = my-default-stack-abc123


Thanks to `@stutteringp0et <https://github.com/stutteringp0et>`_

Usage
------------

To acquire a single certificate for ``example.com``, waiting 60 seconds for DNS propagation:

.. code-block:: bash

    sudo certbot certonly \
    --authenticator dns-stackpath \
    --dns-stackpath-propagation-seconds 60 \
    --dns-stackpath-credentials credentials.ini 
    -d example.com
