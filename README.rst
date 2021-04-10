StackPath DNS Authenticator plugin for Certbot
==============================================

This plugin automates the process of completing a dns-01 challenge by creating, and subsequently removing, TXT records using the StackPath API.


Installation
------------

::

  pip install certbot-dns-stackpath


Examples
------------

To acquire a single certificate for ``example.com``, waiting 60 seconds for DNS propagation:

.. code-block:: bash

    sudo certbot certonly \
    --authenticator dns-stackpath \
    --dns-stackpath-propagation-seconds 60 \
    --dns-stackpath-credentials stackpath.ini 
    -d example.com
