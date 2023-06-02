##################################
 GlobalProtext SAML CLI interface
##################################

**************
 Installation
**************

Uses `pipenv` to create Python virtual environment and track
dependencies.

.. code:: shell

   $ pipenv install

Installing `pipenv`
===================

If you are unfamiliar with `pipenv`, the docs are at
https://pipenv.pypa.io/en/latest/ . In brief, if you run:

..
   code::bash

   $ pip install --user pipenv

This will install `pipenv` at ~/.local/bin/pipenv for the current user
on most Linux systems.

*********
 Duo MFA
*********

This script supports using the following Duo MFA authentication methods.
All methods assume you are using the Duo Universal Prompt.

-  WebAuthn
-  Duo Push

***************
 Example Usage
***************

.. code:: shell

   $ eval $(pipenv run ./login.py https://globalprotect.lafayette.edu/ssl-vpn/prelogin.esp waldbiec -l ERROR)
   $ echo "$COOKIE" | openconnect --protocol=gp -u "$VPN_USER" --passwd-on-stdin "https://$VPN_HOST/gateway:prelogin-cookie"

***************
 Sample Script
***************

Below is a sample script that takes 2 arguments-- your GlobalProtect
base URL and your username. It must have permission to run the
openconnect software (i.e. you might need to run as root). Your
OpenConnect client must be modern enough to support the "gp" protocol.

.. code:: shell

   #! /bin/bash

   # Requires Python 3.x
   # Set this to the full path of your pipenv executable.
   PIPENV=/root/.local/bin/pipenv
   # Set this to the folder where this project is located.
   GP_CLI_SOFTWARE_DIR=/opt/globalprotect_cli

   function usage
   {
       echo "Usage: $0 GP_ENDPOINT SSO_USER" >&2
   }

   GP_ENDPOINT="$1"
   SSO_USER="$2"
   if [ -z $GP_ENDPOINT ]; then
       usage
       exit 1
   fi
   if [ -z $SSO_USER ]; then
       usage
       exit 1
   fi

   PRELOGIN="$GP_ENDPOINT/ssl-vpn/prelogin.esp"
   cd "$GP_CLI_SOFTWARE_DIR"
   eval $($PIPENV run ./login.py "$PRELOGIN" "$SSO_USER" --duo-mfa -l ERROR)
   echo "VPN_HOST: $VPN_HOST"
   echo "VPN_USER: $VPN_USER"
   echo "COOKIE:   $COOKIE"
   # You can comment out these last 2 lines if you just want to test that
   # authentication works.  Once you get a cookie back in your output,
   # uncomment these lines to actually log into the VPN.
   PREAUTH_ENDPOINT="https://$VPN_HOST/gateway:prelogin-cookie"
   echo "$COOKIE" | openconnect --protocol=gp -u "$VPN_USER" --passwd-on-stdin "$PREAUTH_ENDPOINT"
