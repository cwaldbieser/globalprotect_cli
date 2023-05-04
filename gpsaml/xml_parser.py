import base64
import xml.etree.cElementTree as ET


def parse_prelogin(xml_str):
    """
    Parses the /prelogin.esp XML content and extracts and decodes the
    SAML request HTML.  The HTML text is returned.
    """
    xml_node = ET.fromstring(xml_str)
    saml_req = xml_node.find(".//saml-request")
    return base64.b64decode(saml_req.text.encode("utf-8")).decode("utf-8")
