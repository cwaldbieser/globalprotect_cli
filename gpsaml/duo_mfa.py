import base64
import getpass
import json
import struct
import time
from enum import Enum
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse, urlunparse

from logzero import logger
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import FuzzyWordCompleter
from rich import inspect

from .fido2lib import present_challenge_to_authenticator
from .html_parsers import FrameParser, form_to_dict, get_form_from_response

DUO_POLL_SECONDS = 10
DUO_AUTH_VERSION = "2.6"


class DuoAuthnFactor(Enum):
    WEBAUTHN = "WebAuthn Security Key"
    DUO_PUSH = "Duo Push"


def authn_duo_mfa(session, response):
    """
    Process Duo MFA flow.
    Returns the final response of the flow.
    """
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
    return _perform_duo_universal_prompt_flow(session, p, params, form_data)


def _perform_duo_universal_prompt_flow(session, parsed_url, url_params, form_data):
    """
    Perform the Duo Universal Prompt flow.
    Returns the final response.
    """
    sid = url_params["sid"]
    xsrf_token = form_data["_xsrf"]
    _start_duo_oidc_flow(session, parsed_url, form_data, url_params)
    duo_prompt_config = _configure_duo_universal_prompt_flow(session, parsed_url, sid)
    device, device_key, factor = select_factor(duo_prompt_config)
    inspect((device, device_key, factor))
    if factor == DuoAuthnFactor.WEBAUTHN.value:
        return _perform_duo_webauthn(session, parsed_url, sid, xsrf_token)
    elif factor == DuoAuthnFactor.DUO_PUSH.value:
        return _perform_duo_push(
            session, device, device_key, parsed_url, sid, xsrf_token
        )
    else:
        raise NotImplementedError(f"Factor '{factor}' not implemented.")


def select_factor(duo_prompt_config):
    """
    Allow the user to interactively select the Duo 2nd factor.
    """
    supported_methods = [item.value for item in DuoAuthnFactor]
    auth_methods = duo_prompt_config["response"]["auth_method_order"]
    factors = [
        entry["factor"]
        for entry in auth_methods
        if entry["factor"] in supported_methods
    ]
    session = PromptSession()
    factor_completer = FuzzyWordCompleter(factors)
    invalid = True
    while invalid:
        selected_factor = session.prompt(
            "Choose a 2nd factor > ", completer=factor_completer
        )
        if selected_factor in factors:
            invalid = False
    factor_map = {}
    for entry in auth_methods:
        factor = entry["factor"]
        device_key = entry.get("deviceKey")
        if device_key:
            factor_map.setdefault(factor, []).append(device_key)
        else:
            factor_map[factor] = []
    inspect(factor_map)
    devices = factor_map[selected_factor]
    logger.debug(f"Devices matching factor {selected_factor}: {devices}")
    if len(devices) == 0:
        device = "null"
        device_key = ""
    else:
        phones = duo_prompt_config["response"]["phones"]
        phones = [phone for phone in phones if phone["key"] in devices]
        phone_choices = [f"phone-{phone['end_of_number']}" for phone in phones]
        if len(phone_choices) > 1:
            session = PromptSession()
            device_completer = FuzzyWordCompleter(phone_choices)
            invalid = True
            while invalid:
                phone = session.prompt("Select a device > ", completer=device_completer)
                if phone in phone_choices:
                    invalid = False
            eon = phone[6:]
            device = None
            device_key = None
            for phone in phones:
                if phone["end_of_number"] == eon:
                    device = phone["index"]
                    device_key = phone["key"]
                    break
        else:
            device = phones[0]["index"]
            device_key = phones[0]["key"]
    return device, device_key, selected_factor


def _perform_duo_push(session, device, device_key, parsed_url, sid, xsrf_token):
    """
    Perform Duo Push.
    """
    factor = DuoAuthnFactor.DUO_PUSH
    extra_form_data = {
        "postAuthDestination": "OIDC_EXIT",
    }
    txid = _submit_duo_universal_prompt_factor(
        session, parsed_url, sid, factor.value, device, extra_form_data=extra_form_data
    )
    _complete_duo_push(session, parsed_url, sid, txid)
    return _complete_duo_oidc(
        session, parsed_url, xsrf_token, sid, txid, factor.value, device_key, "true"
    )


def _perform_duo_webauthn(session, parsed_url, sid, xsrf_token):
    """
    Perform Duo WebAuthN.
    """
    factor = DuoAuthnFactor.WEBAUTHN
    device = "null"
    device_key = ""
    txid = _submit_duo_universal_prompt_factor(
        session, parsed_url, sid, factor.value, device
    )
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
    return _complete_duo_oidc(
        session, parsed_url, xsrf_token, sid, txid, factor.value, device_key, "false"
    )


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
    logger.debug(f"Duo universal prompt configuration url: {url}")
    resp = session.get(url, params=params)
    logger.debug(f"Duo universal prompt configuration url: {resp.url}")
    api_resp = resp.json()
    inspect(api_resp)
    return api_resp


def _complete_duo_oidc(
    session, parsed_url, xsrf_token, sid, txid, factor, device_key, dampen_choice
):
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
        "dampen_choice": dampen_choice,
    }
    inspect(form_data)
    resp = session.post(url, data=form_data)
    logger.debug(f"Duo OIDC completion response URL: {resp.url}")
    return resp


def _complete_duo_push(session, parsed_url, sid, txid):
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
    logger.debug(f"Duo universal prompt Duo Push completion url: {url}")
    form_data = {
        "sid": sid,
        "txid": txid,
    }
    inspect(form_data)
    while True:
        logger.info("Polling for Duo Push ...")
        resp = session.post(url, data=form_data)
        inspect(resp)
        api_resp = resp.json()
        inspect(api_resp)
        status_code = api_resp["response"]["status_code"]
        logger.info(f"Duo status code: {status_code}")
        if status_code == "allow":
            return resp
        time.sleep(DUO_POLL_SECONDS)


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


def _submit_duo_universal_prompt_factor(
    session, parsed_url, sid, factor, device, extra_form_data=None
):
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
    if extra_form_data:
        form_data.update(extra_form_data)
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
