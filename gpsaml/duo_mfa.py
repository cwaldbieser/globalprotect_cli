import base64
import json
import os
import struct
import time
from enum import Enum
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from logzero import logger
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import FuzzyWordCompleter

from .fido2lib import present_challenge_to_authenticator

DUO_POLL_SECONDS = 10


class DuoAuthnFactor(Enum):
    """
    Duo multi-factor methods enumerations.
    """

    WEBAUTHN = "WebAuthn Security Key"
    DUO_PUSH = "Duo Push"


class DuoAuthNResponseError(Exception):
    """
    Duo authentication failure.
    """


def encode_base64(b):
    """
    Encode bytes as base64.
    """
    encoded = base64.urlsafe_b64encode(b).decode().rstrip("=")
    return encoded


def authn_duo_mfa(session, duo_login_url=None, response=None):
    """
    Process Duo MFA flow.
    Returns the final response of the flow.
    """
    if duo_login_url is not None:
        p = urlparse(duo_login_url)
        duo_login_url = urlunparse((p.scheme, p.netloc, p.path, p.params, "", ""))
        qs = parse_qs(p.query)
        params = dict((k, v[0]) for k, v in qs.items())
        logger.debug(f"Requesting from Duo auth url: {duo_login_url}")
        logger.debug(f"Request params: {params}")
        response = session.get(duo_login_url, params=params)
    if response is None:
        raise DuoAuthNResponseError("Duo authN response is None.")
    logger.info("Starting DUO MFA flow ...")
    login_url = response.url
    logger.debug(f"DUO login_url: {login_url}")
    # Login URL looks like:
    # /prompt/DAC8TIBYEC3Q22PRKFW2?authkey=AXOB3PN4G2XJ2FJDILYF&req_trace_group=80ca7f6e96796886f7f7bf2c
    # p.path.split("/")[-1] is some important identifier that is used in the conversation.
    # param `authkey` is also important.
    p = urlparse(login_url)
    duo_akey = p.path.split("/")[-1]
    params = parse_qs(p.query)
    duo_authkey = params["authkey"][0]
    duo_req_trace_group = params["req_trace_group"][0]
    # duo_req_trace_group = params["req_trace_group"]
    # logger.debug(f"HTML response: {response.text}")
    # form_node = get_form_from_response(response, form_id="plugin_form")
    # form_data = form_to_dict(form_node)
    # # At this point, have the sid, tx, _xsrf
    # logger.debug(f"params: {params}")
    # logger.debug(f"form_data: {form_data}")
    # return _perform_duo_universal_prompt_flow(session, p, params, form_data)
    return _perform_duo_universal_prompt_flow(
        session, p, duo_akey, duo_authkey, duo_req_trace_group
    )


def _perform_duo_universal_prompt_flow(
    session, parsed_url, duo_akey, duo_authkey, duo_req_trace_group
):
    """
    Perform the Duo Universal Prompt flow.
    Returns the final response.
    """
    headers = {"X-Duo-Req-Trace-Group": duo_req_trace_group}
    # (1)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_1_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "current_view": "index",
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "req-trace-group": duo_req_trace_group,
            "view_history": "",
        },
        "level": "info",
        "name": "platform info",
    }
    logger.debug(f"Duo flow URL 1: {duo_step_1_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_1_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (2) - feature flags
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/payload?authkey=AXV6JB3E1O1PJ77IMFEO&browser_features=%7B%22touch_supported%22%3Afalse%2C%22platform_authenticator_status%22%3A%22unavailable%22%2C%22webauthn_supported%22%3Atrue%2C%22screen_resolution_height%22%3A1080%2C%22screen_resolution_width%22%3A1920%2C%22screen_color_depth%22%3A24%2C%22is_uvpa_available%22%3Afalse%2C%22client_capabilities_uvpa%22%3Afalse%7D
    qs = {
        "authkey": duo_authkey,
        "browser_features": (
            '{"touch_supported":false,'
            '"platform_authenticator_status":"unavailable",'
            '"webauthn_supported":true,'
            '"screen_resolution_height":1080,'
            '"screen_resolution_width":1920,'
            '"screen_color_depth":24,'
            '"is_uvpa_available":false,'
            '"client_capabilities_uvpa":false}'
        ),
    }
    query = urlencode(qs)
    duo_step_2_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/payload",
            "",
            query,
            "",
        )
    )
    logger.debug(f"Duo flow URL 2: {duo_step_2_url}")
    response = session.get(duo_step_2_url, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")
    json_response = response.json()
    duo_ikey = json_response["response"]["ikey"]
    logger.debug(f"Duo ikey: {duo_ikey}")
    duo_ukey = json_response["response"]["ukey"]
    logger.debug(f"Duo ukey: {duo_ukey}")

    # (3)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_3_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {"status": "unperformed"},
            "card_name": "PreAuthnInitializationCard",
            "current_view": "pre_authn_init",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": "pre_authn_init",
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 3: {duo_step_3_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_3_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (4)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/pre_authn/initialization?authkey=AXV6JB3E1O1PJ77IMFEO&is_ipad=false&client_hints=eyJicmFuZHMiOlt7ImJyYW5kIjoiR29vZ2xlIENocm9tZSIsInZlcnNpb24iOiIxNDcifSx7ImJyYW5kIjoiTm90LkEvQnJhbmQiLCJ2ZXJzaW9uIjoiOCJ9LHsiYnJhbmQiOiJDaHJvbWl1bSIsInZlcnNpb24iOiIxNDcifV0sImZ1bGxWZXJzaW9uTGlzdCI6W3siYnJhbmQiOiJHb29nbGUgQ2hyb21lIiwidmVyc2lvbiI6IjE0Ny4wLjc3MjcuMTM3In0seyJicmFuZCI6Ik5vdC5BL0JyYW5kIiwidmVyc2lvbiI6IjguMC4wLjAifSx7ImJyYW5kIjoiQ2hyb21pdW0iLCJ2ZXJzaW9uIjoiMTQ3LjAuNzcyNy4xMzcifV0sIm1vYmlsZSI6ZmFsc2UsInBsYXRmb3JtIjoiTGludXgiLCJwbGF0Zm9ybVZlcnNpb24iOiIiLCJ1YUZ1bGxWZXJzaW9uIjoiMTQ3LjAuNzcyNy4xMzcifQ==
    payload = {
        "brands": [
            {"brand": "Google Chrome", "version": "147"},
            {"brand": "Not.A/Brand", "version": "8"},
            {"brand": "Chromium", "version": "147"},
        ],
        "fullVersionList": [
            {"brand": "Google Chrome", "version": "147.0.7727.137"},
            {"brand": "Not.A/Brand", "version": "8.0.0.0"},
            {"brand": "Chromium", "version": "147.0.7727.137"},
        ],
        "mobile": False,
        "platform": "Linux",
        "platformVersion": "",
        "uaFullVersion": "147.0.7727.137",
    }
    json_payload = json.dumps(payload)
    b64_payload = encode_base64(json_payload.encode("utf-8"))
    qs = {
        "authkey": duo_authkey,
        "is_ipad": False,
        "client_hints": b64_payload,
    }
    query = urlencode(qs)
    duo_step_4_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/pre_authn/initialization",
            "",
            query,
            "",
        )
    )
    logger.debug(f"Duo flow URL 4: {duo_step_4_url}")
    response = session.get(duo_step_4_url, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (5)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_5_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {"status": "unperformed"},
            "card_name": "DeviceHealthCard",
            "current_view": "device_health",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": "pre_authn_init,device_health",
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 5: {duo_step_5_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_5_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (6)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_6_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {"status": "unperformed"},
            "card_name": "PreAuthnEvaluationCard",
            "current_view": "pre_authn_eval",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": "pre_authn_init,device_health,pre_authn_eval",
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 6: {duo_step_6_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_6_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (7) - non-passkey factors
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/pre_authn/evaluation?authkey=AXV6JB3E1O1PJ77IMFEO&browser_features=%7B%22touch_supported%22%3Afalse%2C%22platform_authenticator_status%22%3A%22unavailable%22%2C%22webauthn_supported%22%3Atrue%2C%22screen_resolution_height%22%3A1080%2C%22screen_resolution_width%22%3A1920%2C%22screen_color_depth%22%3A24%2C%22is_uvpa_available%22%3Afalse%2C%22client_capabilities_uvpa%22%3Afalse%7D&local_trust_choice=undecided
    browser_features = json.dumps(
        {
            "touch_supported": False,
            "platform_authenticator_status": "unavailable",
            "webauthn_supported": True,
            "screen_resolution_height": 1080,
            "screen_resolution_width": 1920,
            "screen_color_depth": 24,
            "is_uvpa_available": False,
            "client_capabilities_uvpa": False,
        }
    )
    qs = {
        "authkey": duo_authkey,
        "browser_features": browser_features,
        "local_trust_choice": "undecided",
    }
    query = urlencode(qs)
    duo_step_7_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/pre_authn/evaluation",
            "",
            query,
            "",
        )
    )
    logger.debug(f"Duo flow URL 7: {duo_step_7_url}")
    response = session.get(duo_step_7_url, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (8)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_8_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "active_auth_method": {"id": "SECURITY_KEY"},
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {"status": "unperformed"},
            "available_auth_method_types": (
                "cross_platform,push,mobile_otp,sms_otp,phone_call,bypass_code"
            ),
            "can_opt_out_of_push": False,
            "card_name": "PasskeyAuthenticationCard",
            "current_view": "passkey",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": "pre_authn_init,device_health,pre_authn_eval,passkey",
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 8: {duo_step_8_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_8_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (9) - response contains available passkeys
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/factors/passkey/initialization?authkey=AXV6JB3E1O1PJ77IMFEO&browser_features=%7B%22touch_supported%22%3Afalse%2C%22platform_authenticator_status%22%3A%22unavailable%22%2C%22webauthn_supported%22%3Atrue%2C%22screen_resolution_height%22%3A1080%2C%22screen_resolution_width%22%3A1920%2C%22screen_color_depth%22%3A24%2C%22is_uvpa_available%22%3Afalse%2C%22client_capabilities_uvpa%22%3Afalse%7D&auth_method_type=cross_platform
    browser_features = json.dumps(
        {
            "touch_supported": False,
            "platform_authenticator_status": "unavailable",
            "webauthn_supported": True,
            "screen_resolution_height": 1080,
            "screen_resolution_width": 1920,
            "screen_color_depth": 24,
            "is_uvpa_available": False,
            "client_capabilities_uvpa": False,
        },
        indent=0,
    )
    qs = {
        "authkey": duo_authkey,
        "browser_features": browser_features,
        "auth_method_type": "cross_platform",
    }
    query = urlencode(qs)
    duo_step_9_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/factors/passkey/initialization",
            "",
            query,
            "",
        )
    )
    logger.debug(f"Duo flow URL 9: {duo_step_9_url}")
    response = session.get(duo_step_9_url, headers=headers)
    json_response = response.json()
    logger.debug(f"HTTP Response:\n{json.dumps(json_response, indent=4)}")
    credential_request_options = json_response["response"]["credential_request_options"]
    logger.debug(
        f"Credential request options:\n{json.dumps(credential_request_options, indent=4)}"
    )
    session_id = json_response["response"]["session_id"]
    logger.debug(f"Session ID: {session_id}")

    # Present challenge to the authenticator.
    origin = _create_webauthn_origin(parsed_url)
    logger.debug(f"Origin: {origin}")
    logger.debug("Sending credential request options to the authenticator ...")
    assertion, client_data = present_challenge_to_authenticator(
        credential_request_options, origin
    )
    logger.debug(f"Assertion: {assertion}")
    logger.debug(f"Client data: {client_data}")
    logger.debug(f"credential: {assertion.credential}")
    logger.debug(f"credential['id']: {assertion.credential['id']}")
    credential_id = assertion.credential["id"]
    encoded_credential_id = encode_base64(credential_id)
    logger.debug(f"Encoded credential ID: {encoded_credential_id}")
    auth_data = assertion.auth_data
    logger.debug(f"auth_data: {auth_data}")
    repackaged_client_data = {
        "type": client_data.type,
        "challenge": encode_base64(client_data.challenge),
        "origin": client_data.origin,
        "crossOrigin": client_data.cross_origin,
    }
    logger.debug(f"repackaged client data: {repackaged_client_data}")
    client_data_json = json.dumps(repackaged_client_data).replace(" ", "")
    logger.debug(f"client_data_json: {client_data_json}")
    encoded_client_data_json = encode_base64(client_data_json.encode("utf-8"))
    logger.debug(f"Encoded client data JSON: {encoded_client_data_json}")
    encoded_auth_data = encode_base64(auth_data)
    signature = assertion.signature
    logger.debug(f"Assertion signature: {signature}")
    encoded_signature = encode_base64(signature)
    logger.debug(f"Encoded signature: {encoded_signature}")
    jar = session.cookies
    for cname, cvalue in jar.items():
        logger.debug(f"COOKIE: {cname}: {cvalue}")

    # (10)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/factors/passkey
    passkey_headers = {
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-GPC": "1",
        "User-Agent": (
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0"
        ),
        "X-Duo-Req-Trace-Group": duo_req_trace_group,
    }
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_10_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/factors/passkey",
            "",
            query,
            "",
        )
    )
    data = {
        "authkey": duo_authkey,
        "auth_method_type": "cross_platform",
        "session_id": session_id,
        "result": {
            "public_key_credential": {
                "id": encoded_credential_id,
                "response": {
                    "authenticatorData": encoded_auth_data,
                    "clientDataJSON": encoded_client_data_json,
                    "signature": encoded_signature,
                },
                "type": "public-key",
                "authenticatorAttachment": None,
                "extensionResults": {"appid": False},
            }
        },
        "saw_good_news": False,
    }
    logger.debug(f"Duo flow URL 10: {duo_step_10_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    logger.debug(f"Request Headers:\n{passkey_headers}")
    response = session.post(duo_step_10_url, json=data, headers=passkey_headers)
    logger.debug(f"HTTP Response:\n {json.dumps(response.json(), indent=4)}")
    json_response = response.json()
    authenticator_key = json_response["response"]["authn_evaluation"][
        "authenticator_key"
    ]

    # (11)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_11_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "active_auth_method": {"id": "SECURITY_KEY"},
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {
                "evaluation": {
                    "auth_method_type": "cross_platform",
                    "authenticator_key": authenticator_key,
                    "is_allowed": True,
                    "request_browser_trust": True,
                    "status_enum": 5,
                },
                "status": "success",
            },
            "available_auth_method_types": (
                "cross_platform,push,mobile_otp,sms_otp,phone_call,bypass_code"
            ),
            "can_opt_out_of_push": False,
            "card_name": "TrustBrowserCard",
            "current_view": "browser_trust",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": (
                "pre_authn_init,device_health,pre_authn_eval,passkey,browser_trust"
            ),
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 11: {duo_step_11_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_11_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (12)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_events?authkey=AXV6JB3E1O1PJ77IMFEO
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_12_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_events",
            "",
            query,
            "",
        )
    )
    data = {
        "context": {
            "active_auth_method": {"id": "SECURITY_KEY"},
            "akey": duo_akey,
            "auth_flow": "mfa",
            "authn_result": {
                "evaluation": {
                    "auth_method_type": "cross_platform",
                    "authenticator_key": authenticator_key,
                    "is_allowed": True,
                    "request_browser_trust": True,
                    "status_enum": 5,
                },
                "status": "success",
            },
            "available_auth_method_types": (
                "cross_platform,push,mobile_otp,sms_otp,phone_call,bypass_code"
            ),
            "can_opt_out_of_push": False,
            "card_name": "SuccessCard",
            "current_view": "auth_success",
            "ikey": duo_ikey,
            "message": "Browser event",
            "platform_authenticator_status": "unavailable",
            "platform_id": "unknown",
            "ukey": duo_ukey,
            "view_history": (
                "pre_authn_init,device_health,"
                "pre_authn_eval,passkey,browser_trust,auth_success"
            ),
        },
        "level": "info",
        "name": "card_visit",
    }
    logger.debug(f"Duo flow URL 12: {duo_step_12_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_12_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (13)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/browser_trust
    duo_step_13_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/browser_trust",
            "",
            "",
            "",
        )
    )
    data = {"is_trusted": True, "authkey": duo_authkey}
    logger.debug(f"Duo flow URL 13: {duo_step_13_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_13_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")

    # (14) - Remember me
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/remember_me
    duo_step_14_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/remember_me",
            "",
            "",
            "",
        )
    )
    data = {"authkey": duo_authkey}
    logger.debug(f"Duo flow URL 14: {duo_step_14_url}")
    logger.debug(f"JSON payload:\n{json.dumps(data, indent=4)}")
    response = session.post(duo_step_14_url, json=data, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")
    jar = session.cookies
    for cname, cvalue in jar.items():
        logger.debug(f"COOKIE: {cname}: {cvalue}")

    # (15)
    # https://api-6bfb7da1.duosecurity.com/prompt/DAC8TIBYEC3Q22PRKFW2/auth/finalize_auth?authkey=AXQMXEBIVKN6EMPSSGVS
    qs = {
        "authkey": duo_authkey,
    }
    query = urlencode(qs)
    duo_step_15_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            f"/prompt/{duo_akey}/auth/finalize_auth",
            "",
            query,
            "",
        )
    )
    logger.debug(f"Duo flow URL 15: {duo_step_14_url}")
    response = session.get(duo_step_15_url, headers=headers)
    logger.debug(f"HTTP Response: {response.text}")
    json_response = response.json()
    exit_url = json_response["response"]["url"]
    logger.debug(f"DUO Exit URL: {exit_url}")
    response = session.get(exit_url)
    # device, device_key, factor = select_factor(duo_prompt_config)
    # if factor == DuoAuthnFactor.WEBAUTHN.value:
    #     return _perform_duo_webauthn(session, parsed_url, sid, xsrf_token)
    # if factor == DuoAuthnFactor.DUO_PUSH.value:
    #     return _perform_duo_push(
    #         session, device, device_key, parsed_url, sid, xsrf_token
    #     )
    # raise NotImplementedError(f"Factor '{factor}' not implemented.")
    return response


def select_factor(duo_prompt_config):
    """
    Allow the user to interactively select the Duo 2nd factor.
    """
    supported_methods = [item.value for item in DuoAuthnFactor]
    auth_methods = duo_prompt_config["response"]["auth_method_order"]
    logger.debug(f"Duo auth methods: {auth_methods}")
    factors = [
        entry["factor"]
        for entry in auth_methods
        if entry["factor"] in supported_methods
    ]
    logger.debug(f"Duo factors: {factors}")
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
    logger.debug(f"WebAuthN credential request options: {wcro}")
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
    b64_cred_id = encode_base64(assertion.credential["id"])
    response_data = json.dumps(
        {
            "sessionId": session_id,
            "id": b64_cred_id,
            "rawId": b64_cred_id,
            "type": assertion.credential["type"],
            "authenticatorData": base64.urlsafe_b64encode(
                auth_data.rp_id_hash
                + struct.pack(">BI", auth_data.flags, auth_data.counter)
            ).decode("utf-8"),
            "clientDataJSON": client_data.b64,
            "signature": assertion.signature.hex(),
        }
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
