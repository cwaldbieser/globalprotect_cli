
import base64
import getpass
import json
import struct
import time
from urllib.parse import (
    quote_plus,
    urlencode,
    urljoin,
)
import xml.etree.cElementTree as ET
from logzero import logger
from .html_parsers import (
    FrameParser,
    get_form_from_response,
    form_to_dict,
)
from .fido2lib import present_challenge_to_authenticator


DUO_POLL_SECONDS = 10
DUO_AUTH_VERSION = '2.6'


def authn_duo_mfa(session, response, duo_device, duo_factor):
    """
    Process Duo MFA flow.
    """
    logger.info("Starting DUO MFA flow ...")
    login_url = response.url
    logger.debug("DUO login_url: {}".format(login_url))
    form_node = get_form_from_response(response, form_id='duo_form')
    signed_duo_response, app = _perform_duo_mfa_flow(session, login_url, response, duo_device, duo_factor)
    payload = form_to_dict(form_node)
    logger.debug("Form fields: {}".format(payload))
    payload['signedDuoResponse'] = ':'.join([signed_duo_response, app])
    keys = list(payload.keys())
    valid_keys = set(['signedDuoResponse', 'execution', '_eventId', 'geolocation'])
    for key in keys:
        if key not in valid_keys:
            del payload[key]
    response = session.post(login_url, data=payload)
    logger.info("DUO MFA flow complete.")
    return response


def _perform_duo_mfa_flow(session, login_url, response, duo_device, duo_factor):
    """
    Perform Duo MFA web flow.
    """
    parser = FrameParser()
    parser.process_frames(response.text)
    frame = parser.get_frame_by_id('duo_iframe')
    del parser
    host = frame['data-host']
    logger.debug("DUO host: {}".format(host))
    duo_poll_seconds = DUO_POLL_SECONDS
    status_endpoint = urljoin("https://{}".format(host), "/frame/status")
    logger.debug("DUO status endpoint: {}".format(status_endpoint))
    duo_auth_version = DUO_AUTH_VERSION
    duo_sig, app = tuple(frame['data-sig-request'].split(':'))
    auth_endpoint = "https://{}/frame/web/v1/auth?tx={}&parent={}&v={}".format(host, duo_sig, quote_plus(login_url), duo_auth_version)
    logger.debug("DUO auth_endpoint: {}".format(auth_endpoint))
    logger.debug("DUO HTTP GET auth_endpoint ...")
    raw_response = session.get(auth_endpoint, verify=True)
    logger.debug("DUO parsing auth_endpoint response ...")
    duo_form_html_node = get_form_from_response(raw_response, form_index=0)
    payload = form_to_dict(duo_form_html_node)
    logger.debug("DUO HTTP POST to auth_endpoint.  payload: {}".format(payload))
    raw_response = session.post(auth_endpoint, data=payload)
    logger.debug("DUO Got response from auth_endpoint.")
    duo_form_html_node = get_form_from_response(raw_response, form_index=0)
    payload = form_to_dict(duo_form_html_node)
    sid = payload['sid']
    logger.debug("DUO sid: {}".format(sid))
    # Get prompt endpoint; get txid
    payload['device'] = duo_device
    if duo_factor == "webauthn":
        payload['factor'] = "WebAuthn Credential"
    else:
        payload['factor'] = duo_factor
    if duo_factor == 'Passcode':
        payload['passcode'] = getpass.getpass("Passcode: ")
    action = duo_form_html_node.attrib.get('action', '')
    prompt_endpoint = urljoin("https://{}".format(host), action)
    logger.debug("DUO prompt endpoint: {}".format(prompt_endpoint))
    logger.debug("DUO prompt endpoint payload: {}".format(payload))
    response = session.post(prompt_endpoint, data=payload)
    logger.debug("Duo prompt endpoint response: {}".format(response.text))
    response = json.loads(response.text)
    if response.get('stat') != 'OK':
        raise Exception("DUO POST to prompt endpoint resulted in error: {}".format(response))
    txid = response.get("response", {}).get("txid")
    logger.debug("DUO txid: {}".format(txid))
    # Process 2nd factor.
    if duo_factor == 'webauthn':
        logger.debug("DUO Getting challenge from status endpoint ...")
        logger.debug("DUO device: {}".format(duo_device))
        payload['device'] = duo_device
        payload['factor'] = "WebAuthn Credential"
        payload['txid'] = txid
        logger.debug("DUO status endpoint: {}".format(status_endpoint))
        logger.debug("DUO payload: {}".format(payload))
        raw_response = session.post(status_endpoint, data=payload)
        logger.debug("DUO got response from status endpoint.")
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Error decoding JSON response from prompt endpoint: {}".format(ex))
            raise
        if response.get('stat') != 'OK':
            logger.error("DUO POST for credential challenge resulted in error: {}".format(response))
            raise Exception("DUO POST for credential challenge resulted in error: {}".format(response))
        webauthn_opts = response.get('response', {}).get('webauthn_credential_request_options') 
        origin = 'https://api-6bfb7da1.duosecurity.com'
        logger.info("Getting assertion from authenticator ...")
        assertion, client_data = present_challenge_to_authenticator(webauthn_opts, origin)
        logger.debug("DUO authenticator assertion: {}".format(assertion))
        payload['device'] = "webauthn_credential"
        payload['factor'] = "webauthn_finish"
        auth_data = assertion.auth_data
        b64_cred_id = base64.urlsafe_b64encode(assertion.credential['id']).decode('utf-8').rstrip('=')
        response_data = json.dumps(dict(
            sessionId=webauthn_opts['sessionId'],
            id=b64_cred_id,
            rawId=b64_cred_id,
            type=assertion.credential['type'],
            authenticatorData=base64.urlsafe_b64encode(auth_data.rp_id_hash + struct.pack(">BI", auth_data.flags, auth_data.counter)).decode('utf-8'),
            clientDataJSON=client_data.b64,
            signature=assertion.signature.hex(),
        ))
        logger.debug("DUO webauthn response_data: {}".format(response_data))
        payload['response_data'] = response_data
        valid_keys = set(['sid', 'device', 'factor', 'response_data', 'out_of_date', 'days_out_of_date', 'days_to_block'])
        keys = list(payload.keys())
        for k in keys:
            if not k in valid_keys:
                del payload[k]    
        logger.debug("DUO prompt URL: {}".format(prompt_endpoint))
        logger.debug("DUO payload : {}".format(payload))
        raw_response = session.post(prompt_endpoint, data=payload)
        logger.debug("DUO response received from webauthn_finish endpoint: {}".format(raw_response.text))
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Could not decode webauthn response.")
            raise ex
        stat = response.get('stat', '')
        if stat!= 'OK':
            logger.error("DUO webauthn stat: {}".format(stat))
            raise Exception("DUO webauthn stat: {}".format(stat))
        txid = response.get('response', {}).get('txid')

    payload = dict(sid=sid, txid=txid)
    logger.debug("DUO poll yield time: {}".format(duo_poll_seconds))
    while True:
        logger.debug("DUO polling for status ...")
        logger.debug("DUO status_endpoint: {}".format(status_endpoint))
        logger.debug("DUO status payload: {}".format(payload))
        raw_response = session.post(status_endpoint, data=payload)
        logger.debug("DUO Got response from status endpoint.")
        response = json.loads(raw_response.text)
        if response.get('stat') != 'OK':
            logger.error("DUO stat code: {}".format(response.get('stat')))
            raise Exception("POST to Duo status endpoint resulted in error: {}".format(raw_response.text))
        status_code = response.get('response', {}).get('status_code') 
        if status_code == 'pushed':
            logger.debug("DUO status code == 'pushed'")
            time.sleep(duo_poll_seconds)
            continue
        elif status_code == 'allow':
            logger.debug("DUO status code == 'allow'")
            result_url = response.get('response', {}).get('result_url')
            break
        else:
            logger.error("DUO status code: {}".format(response.get('stat')))
            logger.error("DUO raw response: {}".format(raw_response.text))
            raise Exception("Duo returned status code: `{}`".format(status_code))
    payload = dict(sid=sid)
    status_result_endpoint = urljoin("https://{}".format(host), result_url)
    logger.debug("DUO status result endpoint: {}".format(status_result_endpoint))
    raw_response = session.post(status_result_endpoint, data=payload)
    logger.debug("DUO status result endpoint response: {}".format(raw_response.text))
    response = json.loads(raw_response.text)
    cookie = response['response']['cookie']
    logger.debug("DUO cookie: {}".format(cookie))
    logger.debug("DUO app: {}".format(app))
    return cookie, app


