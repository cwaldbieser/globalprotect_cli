
GlobalProtext SAML CLI interface
================================

Installation
------------

Uses `pipenv` to create Python virtual environment and track dependencies.

.. code:: shell

    $ pipenv install



Example Usage
-------------

.. code:: shell

    $ eval $(pipenv run ./login.py https://globalprotect.lafayette.edu/ssl-vpn/prelogin.esp waldbiec -l ERROR)
    $ echo "$COOKIE" | openconnect --protocol=gp -u "$VPN_USER" --passwd-on-stdin "https://$VPN_HOST/gateway:prelogin-cookie"

