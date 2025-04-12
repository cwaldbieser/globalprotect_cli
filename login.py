#! /usr/bin/env python

import argparse
import getpass
import json
import logging
from urllib.parse import urljoin, urlparse

import logzero
import requests
from logzero import logger

from gpsaml.duo_mfa import authn_duo_mfa
from gpsaml.html_parsers import form_to_dict, get_form_from_html, get_form_from_response
from gpsaml.xml_parser import parse_prelogin


def main(args):
    """
    The main entrypoint.
    """
    logzero.loglevel(getattr(logging, args.log_level))
    if args.log_file is not None:
        logzero.logfile(args.log_file)
    s = requests.Session()
    s.headers["User-Agent"] = "PAN GlobalProtect"

    if not args.test_auth_endpoint:
        prelogin_endpoint = args.prelogin
        saml_resp = make_saml_request(s, prelogin_endpoint)
    else:
        saml_resp = make_authn_request(s, args.test_auth_endpoint)
    authn_resp = authn_user_passwd(s, saml_resp, args.username)
    msg = f"authn_resp.status_code: {authn_resp.status_code}"
    logger.debug(msg)
    msg = f"authn_resp.url: {authn_resp.url}"
    logger.debug(msg)
    # with open("/tmp/post-passwd-authn.html", "w", encoding="utf-8") as f:
    #     print(authn_resp.text, file=f)
    browser_storage = None
    if args.duo_mfa:
        if args.client_side_duo:
            duo_url, browser_storage = parse_duo_url_from_cas(authn_resp)
            msg = f"DUO url: {duo_url}"
            logger.debug(msg)
            authn_resp = authn_duo_mfa(s, duo_login_url=duo_url)
        else:
            authn_resp = authn_duo_mfa(s, response=authn_resp)
    if args.test_auth_endpoint:
        return
    logger.debug(f"HTTP status: {authn_resp.status_code}")
    # with open("/tmp/temp.html", "w") as f:
    #     print(authn_resp.text, file=f)
    if args.duo_mfa and args.client_side_duo:
        fm1 = get_form_from_response(authn_resp, form_index=None, form_id="fm1")
        fm1 = form_to_dict(fm1)
        payload = {}
        payload[browser_storage["context"]] = browser_storage["payload"]
        fm1["browserStorage"] = json.dumps(payload)
        logger.debug(f"URL: {authn_resp.url}")
        new_resp = s.post(authn_resp.url, data=fm1)
        logger.debug(f"URL: {new_resp.url}")
        logger.debug(f"HTTPS status: {new_resp.status_code}")
        authn_resp = new_resp
    gp_resp = send_saml_response_to_globalprotect(s, authn_resp)
    log_saml_headers(gp_resp.headers)
    p = urlparse(prelogin_endpoint)
    host = p.netloc.split(":")[0]
    user = gp_resp.headers["saml-username"]
    cookie = gp_resp.headers["prelogin-cookie"]
    exports = {"VPN_HOST": host, "VPN_USER": user, "COOKIE": cookie}
    for key, value in exports.items():
        print(f"export {key}={value}")


def parse_duo_url_from_cas(resp):
    """
    Parse the Duo security URL from the CAS POST response.
    """
    html = resp.text
    prefix = "const browserStorage = "
    prefix_size = len(prefix)
    for line in html.split("\n"):
        line = line.strip()
        if line.startswith(prefix):
            line = line[prefix_size:]
            line = line.rstrip(";")
            o = json.loads(line)
            url = o["destinationUrl"]
            return url, o
    return None


def make_saml_request(s, prelogin_endpoint):
    """
    Make the SAML request on behalf of the GlobalProtect service provider.
    """
    # "Magic" data to submit to prelogin endpoint.
    data = {
        "tmp": "tmp",
        "kerberos-support": "yes",
        "ipv6-support": "yes",
        "clientVer": 4100,
        "clientos": "Linux",
    }
    resp = s.post(prelogin_endpoint, data=data)
    resp_text = resp.text
    html_str = parse_prelogin(resp_text)
    form = get_form_from_html(html_str, form_id="myform")
    payload = form_to_dict(form)
    form_action = form.attrib["action"]
    logger.debug(f"form_action: {form_action}")
    resp = s.post(form_action, data=payload)
    return resp


def make_authn_request(s, auth_endpoint):
    """
    For development.
    Make an initial request of the authN endpoint.
    """
    resp = s.get(auth_endpoint)
    return resp


def send_saml_response_to_globalprotect(s, resp):
    """
    POST the SAML response to the GlobalProtect ACS.
    """
    form = get_form_from_response(resp, form_index=0)
    form_url = resp.url
    logger.debug(f"IdP authN form URL: {form_url}")
    form_action = urljoin(
        form_url,
        form.attrib.get("action", ""),
    )
    payload = form_to_dict(form)
    payload["MIME Type"] = "application/x-www-form-urlencoded"
    logger.debug(f"POSTing SAMLResponse to '{form_action}' ...")
    user_agent = (
        "Mozilla/5.0"
        " (X11; Ubuntu; Linux x86_64; rv:109.0)"
        " Gecko/20100101 Firefox/118.0"
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": user_agent,
    }
    resp = s.post(form_action, data=payload, headers=headers, allow_redirects=False)
    logger.debug(f"GP response url: {resp.url}")
    logger.debug(f"GP response headers: {resp.headers}")
    logger.debug(f"GP response status_code: {resp.status_code}")
    return resp


def authn_user_passwd(s, resp, username):
    """
    Authenticate to the SAML2 form.
    Additionally perform any other authentication required (e.g. MFA).
    Return the SAML response.
    """
    form = get_form_from_response(resp, form_id="fm1")
    form_url = resp.url
    logger.debug(f"Form URL: {form_url}")
    form_action = urljoin(
        form_url,
        form.attrib.get("action", ""),
    )
    payload = {}
    for tag in form.findall(".//input"):
        key = tag.attrib["name"]
        value = tag.attrib.get("value", "")
        payload[key] = value
    payload["username"] = username
    passwd = getpass.getpass()
    payload["password"] = passwd
    resp = s.post(form_action, data=payload)
    return resp


def log_saml_headers(headers):
    """
    Log headers realted to a GlobalProtect SAML assertion.
    """
    saml_headers = {}
    for k, v in headers.items():
        if k.lower().startswith("saml-"):
            saml_headers[k] = v
        elif k.lower() == "prelogin-cookie":
            saml_headers[k] = v
    logger.debug(f"SAML headers: {saml_headers}")


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
        "--log-file", action="store", help="Path of the log file to send log events to."
    )
    parser.add_argument(
        "--duo-mfa",
        action="store_true",
        help="Use Duo MFA",
    )
    parser.add_argument(
        "--client-side-duo",
        action="store_true",
        help="Indicate Duo MFA uses client-side CAS integration.",
    )
    parser.add_argument(
        "-t",
        "--test-auth-endpoint",
        action="store",
        help="Test authentication endpoint, used for development.",
    )
    cli_args = parser.parse_args()
    main(cli_args)
