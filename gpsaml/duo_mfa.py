import base64
import getpass
import json
import struct
import sys
import time
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse, urlunparse

from logzero import logger
from rich import inspect

from .fido2lib import present_challenge_to_authenticator
from .html_parsers import FrameParser, form_to_dict, get_form_from_response

DUO_POLL_SECONDS = 10
DUO_AUTH_VERSION = "2.6"


def authn_duo_mfa(session, response, duo_device, duo_factor):
    """
    Process Duo MFA flow.
    """
    # TODO - params need modification for universal prompt
    logger.info("Starting DUO MFA flow ...")
    login_url = response.url
    logger.debug("DUO login_url: {}".format(login_url))
    p = urlparse(login_url)
    # params include `sid` and `tx` (a JWT).
    params = parse_qs(p.query)
    inspect(params)
    # Form includes `_xsrf` token.
    form_node = get_form_from_response(response, form_id="plugin_form")
    form_data = form_to_dict(form_node)
    inspect(form_data)
    # At this point, have the sid, tx, _xsrf
    _perform_duo_universal_prompt_flow(session, p, params, form_data)
    sys.exit(1)
    signed_duo_response, app = _perform_duo_mfa_flow(
        session, login_url, response, duo_device, duo_factor
    )
    payload = form_to_dict(form_node)
    logger.debug("Form fields: {}".format(payload))
    payload["signedDuoResponse"] = ":".join([signed_duo_response, app])
    keys = list(payload.keys())
    valid_keys = set(["signedDuoResponse", "execution", "_eventId", "geolocation"])
    for key in keys:
        if key not in valid_keys:
            del payload[key]
    response = session.post(login_url, data=payload)
    logger.info("DUO MFA flow complete.")
    return response


def _perform_duo_universal_prompt_flow(session, parsed_url, url_params, form_data):
    """
    Perform the Duo Universal Prompt flow.
    """
    sid = url_params["sid"]
    xsrf_token = form_data["_xsrf"]
    _start_duo_oidc_flow(session, parsed_url, form_data, url_params)
    _configure_duo_universal_prompt_flow(session, parsed_url, sid)
    # TODO: hard-coding webauthn factor
    factor = "WebAuthn Security Key"
    device = "null"
    device_key = ""
    txid = _submit_duo_universal_prompt_factor(session, parsed_url, sid, factor, device)
    wcro = _get_webauth_credential_request_options(session, parsed_url, sid, txid)
    inspect(wcro)
    session_id = wcro["sessionId"]
    origin = _create_webauthn_origin(parsed_url)
    assertion, client_data = present_challenge_to_authenticator(wcro, origin)
    inspect(assertion)
    inspect(client_data)
    txid = _submit_duo_webauthn_response_data(
        session, parsed_url, sid, session_id, assertion, client_data
    )
    _complete_webauthn(session, parsed_url, sid, txid)
    _complete_duo_oidc(session, parsed_url, xsrf_token, sid, txid, factor, device_key)


def _start_duo_oidc_flow(session, parsed_url, form_data, url_params):
    """
    Start the Duo OIDC flow.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt start OIDC url: {url}")
    resp = session.post(url, params=url_params, data=form_data)
    inspect(resp)


def _configure_duo_universal_prompt_flow(session, parsed_url, sid):
    """
    API call for getting information used to configure the universal prompt?
    May not strictly be necessary if you already know what options you are going to use.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/auth/prompt/data",
            "",
            "",
            "",
        )
    )
    params = {
        "post_auth_action": "OIDC_EXIT",
        "sid": sid,
    }
    logger.debug(f"Duo universal prompt request #2 url: {url}")
    resp = session.get(url, params=params)
    logger.debug(f"Duo universal prompt response #2 url: {resp.url}")
    inspect(resp)


def _complete_duo_oidc(session, parsed_url, xsrf_token, sid, txid, factor, device_key):
    """
    Complete Duo OIDC and redirect back to web SSO with the tokens we were
    looking for as query parameters.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/oidc/exit",
            "",
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt OIDC completion url: {url}")
    form_data = {
        "sid": sid,
        "txid": txid,
        "factor": factor,
        "device_key": device_key,
        "_xsrf": xsrf_token,
        "dampen_choice": "false",
    }
    inspect(form_data)
    resp = session.post(url, data=form_data)
    logger.debug(f"Duo OIDC completion response URL: {resp.url}")


def _complete_webauthn(session, parsed_url, sid, txid):
    """
    Complete the WebAuthN flow.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/status",
            "",
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt webauthn completion url: {url}")
    form_data = {
        "sid": sid,
        "txid": txid,
    }
    inspect(form_data)
    resp = session.post(url, data=form_data)
    inspect(resp)
    api_resp = resp.json()
    inspect(api_resp)


def _submit_duo_webauthn_response_data(
    session, parsed_url, sid, session_id, assertion, client_data
):
    """
    Submit the webauthn response data from security key or other webauthn device.
    Returns a transaction ID on success.
    """
    response_data = _create_webauthn_response_from_assertion(
        session_id, assertion, client_data
    )
    form_data = {
        "response_data": response_data,
        "device": "webauthn_credential",
        "factor": "webauthn_finish",
        "postAuthDestination": "OIDC_EXIT",
        "sid": sid,
    }
    inspect(form_data)
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/prompt",
            "",
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt webauthn response submission url: {url}")
    resp = session.post(url, data=form_data)
    inspect(resp)
    api_resp = resp.json()
    inspect(api_resp)
    return api_resp["response"]["txid"]


def _create_webauthn_response_from_assertion(session_id, assertion, client_data):
    """
    Create WebAuthN response data from an assertion.
    """
    auth_data = assertion.auth_data
    b64_cred_id = (
        base64.urlsafe_b64encode(assertion.credential["id"]).decode("utf-8").rstrip("=")
    )
    response_data = json.dumps(
        dict(
            sessionId=session_id,
            id=b64_cred_id,
            rawId=b64_cred_id,
            type=assertion.credential["type"],
            authenticatorData=base64.urlsafe_b64encode(
                auth_data.rp_id_hash
                + struct.pack(">BI", auth_data.flags, auth_data.counter)
            ).decode("utf-8"),
            clientDataJSON=client_data.b64,
            signature=assertion.signature.hex(),
        )
    )
    return response_data


def _create_webauthn_origin(parsed_url):
    """
    Create a WebAuthN origin from the API URL.
    """
    origin = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "",
            "",
            "",
            "",
        )
    )
    return origin


def _get_webauth_credential_request_options(session, parsed_url, sid, txid):
    """
    Get the webauth credential request options.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/status",
            "",
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt webauthn credential request options url: {url}")
    form_data = {
        "txid": txid,
        "sid": sid,
    }
    inspect(form_data)
    resp = session.post(url, data=form_data)
    inspect(resp)
    api_resp = resp.json()
    inspect(api_resp)
    return api_resp["response"]["webauthn_credential_request_options"]


def _submit_duo_universal_prompt_factor(session, parsed_url, sid, factor, device):
    """
    Submit the choice of 2nd factor to the Duo service.
    Returns a transaction ID used in a subsequent flow.
    """
    url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            "/frame/v4/prompt",
            "",
            "",
            "",
        )
    )
    logger.debug(f"Duo universal prompt 2nd factor submission url: {url}")
    form_data = {
        "device": device,
        "factor": factor,
        "sid": sid,
    }
    inspect(form_data)
    resp = session.post(url, data=form_data)
    inspect(resp)
    api_resp = resp.json()
    inspect(api_resp)
    return api_resp["response"]["txid"]


def _perform_duo_mfa_flow(session, login_url, response, duo_device, duo_factor):
    """
    Perform Duo MFA web flow.
    """
    parser = FrameParser()
    parser.process_frames(response.text)
    frame = parser.get_frame_by_id("duo_iframe")
    del parser
    host = frame["data-host"]
    logger.debug("DUO host: {}".format(host))
    duo_poll_seconds = DUO_POLL_SECONDS
    status_endpoint = urljoin("https://{}".format(host), "/frame/status")
    logger.debug("DUO status endpoint: {}".format(status_endpoint))
    duo_auth_version = DUO_AUTH_VERSION
    duo_sig, app = tuple(frame["data-sig-request"].split(":"))
    auth_endpoint = "https://{}/frame/web/v1/auth?tx={}&parent={}&v={}".format(
        host, duo_sig, quote_plus(login_url), duo_auth_version
    )
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
    sid = payload["sid"]
    logger.debug("DUO sid: {}".format(sid))
    # Get prompt endpoint; get txid
    payload["device"] = duo_device
    if duo_factor == "webauthn":
        payload["factor"] = "WebAuthn Credential"
    else:
        payload["factor"] = duo_factor
    if duo_factor == "Passcode":
        payload["passcode"] = getpass.getpass("Passcode: ")
    action = duo_form_html_node.attrib.get("action", "")
    prompt_endpoint = urljoin("https://{}".format(host), action)
    logger.debug("DUO prompt endpoint: {}".format(prompt_endpoint))
    logger.debug("DUO prompt endpoint payload: {}".format(payload))
    response = session.post(prompt_endpoint, data=payload)
    logger.debug("Duo prompt endpoint response: {}".format(response.text))
    response = json.loads(response.text)
    if response.get("stat") != "OK":
        raise Exception(
            "DUO POST to prompt endpoint resulted in error: {}".format(response)
        )
    txid = response.get("response", {}).get("txid")
    logger.debug("DUO txid: {}".format(txid))
    # Process 2nd factor.
    if duo_factor == "webauthn":
        logger.debug("DUO Getting challenge from status endpoint ...")
        logger.debug("DUO device: {}".format(duo_device))
        payload["device"] = duo_device
        payload["factor"] = "WebAuthn Credential"
        payload["txid"] = txid
        logger.debug("DUO status endpoint: {}".format(status_endpoint))
        logger.debug("DUO payload: {}".format(payload))
        raw_response = session.post(status_endpoint, data=payload)
        logger.debug("DUO got response from status endpoint.")
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error(
                "DUO Error decoding JSON response from prompt endpoint: {}".format(ex)
            )
            raise
        if response.get("stat") != "OK":
            logger.error(
                "DUO POST for credential challenge resulted in error: {}".format(
                    response
                )
            )
            raise Exception(
                "DUO POST for credential challenge resulted in error: {}".format(
                    response
                )
            )
        webauthn_opts = response.get("response", {}).get(
            "webauthn_credential_request_options"
        )
        origin = "https://api-6bfb7da1.duosecurity.com"
        logger.info("Getting assertion from authenticator ...")
        assertion, client_data = present_challenge_to_authenticator(
            webauthn_opts, origin
        )
        logger.debug("DUO authenticator assertion: {}".format(assertion))
        payload["device"] = "webauthn_credential"
        payload["factor"] = "webauthn_finish"
        auth_data = assertion.auth_data
        b64_cred_id = (
            base64.urlsafe_b64encode(assertion.credential["id"])
            .decode("utf-8")
            .rstrip("=")
        )
        response_data = json.dumps(
            dict(
                sessionId=webauthn_opts["sessionId"],
                id=b64_cred_id,
                rawId=b64_cred_id,
                type=assertion.credential["type"],
                authenticatorData=base64.urlsafe_b64encode(
                    auth_data.rp_id_hash
                    + struct.pack(">BI", auth_data.flags, auth_data.counter)
                ).decode("utf-8"),
                clientDataJSON=client_data.b64,
                signature=assertion.signature.hex(),
            )
        )
        logger.debug("DUO webauthn response_data: {}".format(response_data))
        payload["response_data"] = response_data
        valid_keys = set(
            [
                "sid",
                "device",
                "factor",
                "response_data",
                "out_of_date",
                "days_out_of_date",
                "days_to_block",
            ]
        )
        keys = list(payload.keys())
        for k in keys:
            if k not in valid_keys:
                del payload[k]
        logger.debug("DUO prompt URL: {}".format(prompt_endpoint))
        logger.debug("DUO payload : {}".format(payload))
        raw_response = session.post(prompt_endpoint, data=payload)
        logger.debug(
            "DUO response received from webauthn_finish endpoint: {}".format(
                raw_response.text
            )
        )
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Could not decode webauthn response.")
            raise ex
        stat = response.get("stat", "")
        if stat != "OK":
            logger.error("DUO webauthn stat: {}".format(stat))
            raise Exception("DUO webauthn stat: {}".format(stat))
        txid = response.get("response", {}).get("txid")

    payload = dict(sid=sid, txid=txid)
    logger.debug("DUO poll yield time: {}".format(duo_poll_seconds))
    while True:
        logger.debug("DUO polling for status ...")
        logger.debug("DUO status_endpoint: {}".format(status_endpoint))
        logger.debug("DUO status payload: {}".format(payload))
        raw_response = session.post(status_endpoint, data=payload)
        logger.debug("DUO Got response from status endpoint.")
        response = json.loads(raw_response.text)
        if response.get("stat") != "OK":
            logger.error("DUO stat code: {}".format(response.get("stat")))
            raise Exception(
                "POST to Duo status endpoint resulted in error: {}".format(
                    raw_response.text
                )
            )
        status_code = response.get("response", {}).get("status_code")
        if status_code == "pushed":
            logger.debug("DUO status code == 'pushed'")
            time.sleep(duo_poll_seconds)
            continue
        elif status_code in ("calling", "answered"):
            logger.debug("DUO status code == 'calling'")
            time.sleep(duo_poll_seconds)
            continue
        elif status_code == "allow":
            logger.debug("DUO status code == 'allow'")
            result_url = response.get("response", {}).get("result_url")
            break
        else:
            logger.error("DUO status code: {}".format(response.get("stat")))
            logger.error("DUO raw response: {}".format(raw_response.text))
            raise Exception("Duo returned status code: `{}`".format(status_code))
    payload = dict(sid=sid)
    status_result_endpoint = urljoin("https://{}".format(host), result_url)
    logger.debug("DUO status result endpoint: {}".format(status_result_endpoint))
    raw_response = session.post(status_result_endpoint, data=payload)
    logger.debug("DUO status result endpoint response: {}".format(raw_response.text))
    response = json.loads(raw_response.text)
    cookie = response["response"]["cookie"]
    logger.debug("DUO cookie: {}".format(cookie))
    logger.debug("DUO app: {}".format(app))
    return cookie, app
