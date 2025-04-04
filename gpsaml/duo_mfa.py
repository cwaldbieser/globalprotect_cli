import base64
import json
import os
import struct
import time
from enum import Enum
from urllib.parse import parse_qs, urlparse, urlunparse

from logzero import logger
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import FuzzyWordCompleter

from .fido2lib import present_challenge_to_authenticator
from .html_parsers import form_to_dict, get_form_from_response

DUO_POLL_SECONDS = 10


class DuoAuthnFactor(Enum):
    WEBAUTHN = "WebAuthn Security Key"
    DUO_PUSH = "Duo Push"


def authn_duo_mfa(session, duo_login_url):
    """
    Process Duo MFA flow.
    Returns the final response of the flow.
    """
    p = urlparse(duo_login_url)
    duo_login_url = urlunparse((p.scheme, p.netloc, p.path, p.params, "", ""))
    qs = parse_qs(p.query)
    params = dict((k, v[0]) for k, v in qs.items())
    logger.debug(f"Requesting from Duo auth url: {duo_login_url}")
    logger.debug(f"Request params: {params}")
    response = session.get(duo_login_url, params=params)
    logger.info("Starting DUO MFA flow ...")
    login_url = response.url
    logger.debug(f"DUO login_url: {login_url}")
    p = urlparse(login_url)
    # params include `sid` and `tx` (a JWT).
    params = parse_qs(p.query)
    # Form includes `_xsrf` token.
    form_node = get_form_from_response(response, form_id="plugin_form")
    form_data = form_to_dict(form_node)
    # At this point, have the sid, tx, _xsrf
    logger.debug(f"params: {params}")
    logger.debug(f"form_data: {form_data}")
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
    selected_factor = os.environ.get("DUO_FACTOR")
    if selected_factor not in factors:
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
            phone = os.environ.get("DUO_DEVICE")
            if phone not in phone_choices:
                session = PromptSession()
                device_completer = FuzzyWordCompleter(phone_choices)
                invalid = True
                while invalid:
                    phone = session.prompt(
                        "Select a device > ", completer=device_completer
                    )
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
    session_id = wcro["sessionId"]
    origin = _create_webauthn_origin(parsed_url)
    assertion, client_data = present_challenge_to_authenticator(wcro, origin)
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
    # resp = session.post(url, params=url_params, data=form_data)
    # inspect(resp)
    session.post(url, params=url_params, data=form_data)


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
    while True:
        logger.info("Polling for Duo Push ...")
        resp = session.post(url, data=form_data)
        api_resp = resp.json()
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
    session.post(url, data=form_data)


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
    api_resp = resp.json()
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
    resp = session.post(url, data=form_data)
    api_resp = resp.json()
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
    resp = session.post(url, data=form_data)
    api_resp = resp.json()
    return api_resp["response"]["txid"]
