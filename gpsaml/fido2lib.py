from __future__ import absolute_import, print_function, unicode_literals

import base64
import io
import os
import sys
import time
from contextlib import contextmanager

from fido2 import webauthn
from fido2.client import DefaultClientDataCollector, Fido2Client
from fido2.hid import CtapHidDevice
from fido2.pcsc import CtapPcscDevice
from logzero import logger
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import FuzzyWordCompleter
from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from smartcard.util import toHexString


def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)


@contextmanager
def get_fido2_client(origin):
    """
    Get a FIDO2 client.
    """
    devices = []
    device_map = {}
    hid_devices = [device for device in CtapHidDevice.list_devices()]
    logger.debug(f"CTAP HID devices: {hid_devices}")
    devices.extend(hid_devices)
    for device in hid_devices:
        device_map[device.product_name] = device
    r = readers()
    if len(r) > 0:
        device_map["Smart card reader"] = "Smart card reader"
    logger.debug(f"device map: {device_map}")
    ctap_device_name = os.environ.get("CTAP_DEVICE")
    dev = device_map.get(ctap_device_name)
    if dev is None:
        dev = interactive_select_device(device_map)
    if dev == "Smart card reader":
        dev = select_card_reader()
        connection = dev.createConnection()
        client = get_pcsc_fido2_client(connection, str(dev), origin)
        yield client
        connection.disconnect()
        connection.release()
    else:
        client = Fido2Client(dev, DefaultClientDataCollector(origin=origin))
        yield client


def get_pcsc_fido2_client(connection, reader_name, origin):
    """
    Get a Smart Card FIDO2 client.
    """
    while True:
        try:
            connection.connect()
            break
        except NoCardException:
            write_to_tty("Please insert card.")
            time.sleep(5)
    logger.debug(f"Card ATR: {toHexString(connection.getATR())}")
    ctap_device = CtapPcscDevice(connection, reader_name)
    client_data_collector = DefaultClientDataCollector(origin=origin)
    client = Fido2Client(ctap_device, client_data_collector)
    return client


def create_ctap_device_from_card_reader(card_reader):
    """
    Create a CTAP device from a card reader.
    """
    connection = card_reader.createConnection()
    while True:
        try:
            connection.connect()
            break
        except NoCardException:
            write_to_tty("Please insert card.")
            time.sleep(5)
    logger.debug(f"Card ATR: {toHexString(connection.getATR())}")
    ctap_device = CtapPcscDevice(connection, str(card_reader))
    return ctap_device


def select_card_reader():
    """
    Select a card reader.
    """
    card_reader = os.environ.get("CTAP_CARD_READER")
    if card_reader is None:
        return interactively_select_card_reader()
    r = readers()
    reader_map = dict((str(reader), reader) for reader in r)
    reader = reader_map.get(card_reader)
    if reader is None:
        logger.error(f"Card reader '{card_reader}' is not available.")
        sys.exit(1)
    return reader


def interactively_select_card_reader():
    """
    Interactively select a card reader.
    """
    r = readers()
    reader_map = dict((str(reader), reader) for reader in r)
    session = PromptSession()
    completer = FuzzyWordCompleter(reader_map.keys())
    invalid = True
    while invalid:
        selection = session.prompt("Choose a card reader > ", completer=completer)
        if selection in reader_map:
            invalid = False
    return reader_map[selection]


def interactive_select_device(device_map):
    """
    Interactively select a device.
    """
    session = PromptSession()
    device_names = device_map.keys()
    completer = FuzzyWordCompleter(device_names)
    invalid = True
    while invalid:
        selection = session.prompt("Choose an authenticator > ", completer=completer)
        if selection in device_map:
            invalid = False
    return device_map[selection]


def write_to_tty(message):
    """
    Write a message to the TTY.
    """
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        tty = io.FileIO(fd, "w+")
        stream = io.TextIOWrapper(tty)
        stream.write(f"\n{message}\n")
        stream.flush()
    except Exception as ex:
        logger.warn("Could not write to current TTY.")
        logger.exception(ex)


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
    uv = webauthn.UserVerificationRequirement.DISCOURAGED

    logger.debug(f"FIDO2 webauthn_cred_req_opts: {webauthn_cred_req_opts}")
    rp_id = webauthn_cred_req_opts["rpId"]

    # Locate a device
    with get_fido2_client(origin) as client:
        logger.debug(f"FIDO2 client options: {client.info.options}")

        # Authenticate the credential
        logger.debug("You may need to touch your authenticator device now...")
        write_to_tty("You may need to touch your authenticator device now...")
        allowed_creds = []
        allow_creds_reps = []
        for entry in webauthn_cred_req_opts["allowCredentials"]:
            cred_type = entry["type"]
            cred_id = entry["id"]
            transports = list(entry.get("transports", []))
            pubkey_cred_descriptor = webauthn.PublicKeyCredentialDescriptor(
                type=cred_type,
                id=decode_base64(cred_id),
                # transports=transports,
            )
            rep = {
                "type": cred_type,
                "id": cred_id,
                "transports": transports,
            }
            allowed_creds.append(pubkey_cred_descriptor)
            allow_creds_reps.append(rep)

        challenge = webauthn_cred_req_opts["challenge"]
        timeout = webauthn_cred_req_opts["timeout"]
        pubkey_req_opts = webauthn.PublicKeyCredentialRequestOptions(
            challenge=decode_base64(challenge),
            timeout=timeout,
            rp_id=rp_id,
            allow_credentials=allowed_creds,
            user_verification=uv,
        )
        logger.debug(f"request_options: {pubkey_req_opts}")
        # assertions, client_data = client.get_assertion(request_options["publicKey"], pin=pin)
        selection = client.get_assertion(pubkey_req_opts)
        result = selection.get_response(0)  # Returns an AuthenticationResponse
        logger.debug(f"Authentication response: {result}")
        response = result.response  # Extract the AuthenticatorAssertionResponse
        logger.debug(f"Authenticator assertion response: {response}")
        assertions = selection.get_assertions()
        assertion = assertions[
            0
        ]  # Only one cred in allowCredentials, only one response.
        # authenticator_assertion_response = selection.get_response(0)
    logger.info("FIDO2 Authenticator successfully validated challenge.")
    return assertion, response.client_data
