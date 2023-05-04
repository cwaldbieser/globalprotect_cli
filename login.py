#! /usr/bin/env python

import argparse
import getpass
import logging
from urllib.parse import urljoin, urlparse

import logzero
import requests
from logzero import logger

from gpsaml.duo_mfa import authn_duo_mfa
from gpsaml.html_parsers import (form_to_dict, get_form_from_html,
                                 get_form_from_response)
from gpsaml.xml_parser import parse_prelogin


def main(args):
    """
    The main entrypoint.
    """
    logzero.loglevel(getattr(logging, args.log_level))
    s = requests.Session()
    prelogin_endpoint = args.prelogin
    resp = make_saml_request(s, prelogin_endpoint)
    resp = authn_user_passwd(s, resp, args.username)
    duo_factor, duo_device = parse_duo_opts(args.duo_mfa)
    if duo_factor is not None:
        resp = authn_duo_mfa(s, resp, duo_device=duo_device, duo_factor=duo_factor)
    resp = send_saml_response_to_globalprotect(s, resp)
    logger.debug("Response:\n{}".format(resp.text))
    logger.debug("Headers: {}".format(resp.headers))
    p = urlparse(prelogin_endpoint)
    host = p.netloc.split(":")[0]
    user = resp.headers["saml-username"]
    cookie = resp.headers["prelogin-cookie"]
    exports = dict(VPN_HOST=host, VPN_USER=user, COOKIE=cookie)
    for key, value in exports.items():
        print("export {}={}".format(key, value))


def parse_duo_opts(duo_mfa):
    """
    Parse Duo MFA options and return duo_factor, duo_device.
    """
    if duo_mfa is None:
        return None, None
    parts = tuple(duo_mfa.split(":", 1))
    return parts


def make_saml_request(s, prelogin_endpoint):
    """
    Make the SAML request on behalf of the GlobalProtect service provider.
    """
    resp = s.get(prelogin_endpoint)
    html_str = parse_prelogin(resp.text)
    form = get_form_from_html(html_str, form_id="myform")
    payload = form_to_dict(form)
    form_action = form.attrib["action"]
    resp = s.post(form_action, data=payload)
    return resp


def send_saml_response_to_globalprotect(s, resp):
    """
    POST the SAML response to the GlobalProtect ACS.
    """
    form = get_form_from_response(resp, form_index=0)
    form_url = resp.url
    logger.debug("Form URL: {}".format(form_url))
    form_action = urljoin(
        form_url,
        form.attrib.get("action", ""),
    )
    payload = form_to_dict(form)
    logger.debug("POSTing SAMLResponse to `{}` ...".format(form_action))
    resp = s.post(form_action, data=payload)
    return resp


def authn_user_passwd(s, resp, username):
    """
    Authenticate to the SAML2 form.
    Additionally perform any other authentication required (e.g. MFA).
    Return the SAML response.
    """
    form = get_form_from_response(resp, form_index=1)
    form_url = resp.url
    logger.debug("Form URL: {}".format(form_url))
    form_action = urljoin(
        form_url,
        form.attrib.get("action", ""),
    )
    payload = {}
    for tag in form.findall(".//input"):
        key = tag.attrib["name"]
        value = tag.attrib.get("value", "")
        payload[key] = value
    logger.debug("Unfilled form fields: {}".format(payload))
    payload["username"] = username
    passwd = getpass.getpass()
    payload["password"] = passwd
    resp = s.post(form_action, data=payload)
    return resp


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SAML Login via CLI.")
    parser.add_argument(
        "prelogin", action="store", help="The GlobalProtect prelogin.esp endpoint."
    )
    parser.add_argument("username", action="store", help="The username used to log in.")
    parser.add_argument(
        "-l",
        "--log-level",
        action="store",
        default="INFO",
        choices=["ERROR", "WARN", "INFO", "DEBUG"],
        help="The log level to use.",
    )
    parser.add_argument(
        "--duo-mfa",
        action="store",
        help="Duo MFA options.  E.g. `webauthn:DEVICE-ID` or `Duo Push:phone1`.",
    )
    args = parser.parse_args()
    main(args)
