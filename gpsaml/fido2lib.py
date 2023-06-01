from __future__ import absolute_import, print_function, unicode_literals

import base64
import io
import os
import sys
# from getpass import getpass

from fido2 import webauthn
from fido2.client import Fido2Client, WindowsClient
from fido2.hid import CtapHidDevice
from logzero import logger


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


def present_challenge_to_authenticator(
    webauthn_cred_req_opts, origin='"https://api-6bfb7da1.duosecurity.com'
):
    """
    Present webauthn challenge and credential options to authenticator.
    Return assertion.
    """
    logger.info(
        "FIDO2 presenting WebAuthn challenge to an authenticator (e.g. Yubikey)"
    )
    use_prompt = False
    # pin = None
    uv = "discouraged"

    logger.debug("FIDO2 webauthn_cred_req_opts: {}".format(webauthn_cred_req_opts))
    rp_id = webauthn_cred_req_opts["rpId"]

    if WindowsClient.is_available():
        # Use the Windows WebAuthn API if available
        client = WindowsClient(origin)
    else:
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            logger.debug("Use USB HID channel.")
            use_prompt = True
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                logger.debug("Use NFC channel.")
            except Exception as e:
                logger.debug("NFC channel search error:", e)

        if not dev:
            logger.error("No FIDO device found")
            sys.exit(1)

        # Set up a FIDO 2 client using the origin https://example.com
        # client = Fido2Client(dev, "https://example.com")
        client = Fido2Client(dev, origin)

        # Prefer UV if supported
        if client.info.options.get("uv"):
            uv = "preferred"
            logger.debug("Authenticator supports User Verification")
        # elif client.info.options.get("clientPin"):
        #     # Prompt for PIN if needed
        #     pin = getpass("Please enter PIN: ")
        else:
            logger.debug("PIN not set, won't use")

    # Authenticate the credential
    if use_prompt:
        logger.debug("Touch your authenticator device now...")
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            tty = io.FileIO(fd, "w+")
            stream = io.TextIOWrapper(tty)
            stream.write("\nTouch your authenticator device now...\n")
            stream.flush()
        except Exception as ex:
            logger.warn("FIDO2 Could not write to current TTY. {}".format(ex))

    allowed_creds = []
    allow_creds_reps = []
    for entry in webauthn_cred_req_opts["allowCredentials"]:
        cred_type = entry["type"]
        cred_id = entry["id"]
        transports = list(entry.get("transports", []))
        pubkey_cred_descriptor = webauthn.PublicKeyCredentialDescriptor(
            type=cred_type,
            id=decode_base64(cred_id),
            transports=transports,
        )
        rep = dict(
            type=cred_type,
            id=cred_id,
            transports=transports,
        )
        allowed_creds.append(pubkey_cred_descriptor)
        allow_creds_reps.append(rep)

    challenge = webauthn_cred_req_opts["challenge"]
    timeout = webauthn_cred_req_opts["timeout"]
    pubkey_req_opts = webauthn.PublicKeyCredentialRequestOptions(
        decode_base64(challenge),
        timeout=timeout,
        rp_id=rp_id,
        allow_credentials=allowed_creds,
        user_verification=uv,
    )
    request_options = dict(publicKey=pubkey_req_opts)
    logger.debug(
        "[DEBUG] my request_options",
        dict(
            challenge=challenge,
            timeout=timeout,
            rp_id=rp_id,
            allow_credentials=allow_creds_reps,
            user_verification=uv,
        ),
    )
    # assertions, client_data = client.get_assertion(request_options["publicKey"], pin=pin)
    selection = client.get_assertion(request_options["publicKey"])
    assertions = selection.get_assertions()
    assertion = assertions[0]  # Only one cred in allowCredentials, only one response.
    authenticator_assertion_response = selection.get_response(0)
    logger.debug("ASSERTION DATA:", assertion)
    logger.info("FIDO2 Authenticator successfully validated challenge.")
    return assertion, authenticator_assertion_response.client_data
