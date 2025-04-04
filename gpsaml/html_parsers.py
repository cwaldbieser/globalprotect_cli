import xml.etree.cElementTree as ET
from html import escape
from html.parser import HTMLParser

from logzero import logger


class FormParserError(Exception):
    pass


class FormParser(HTMLParser):
    def __init__(self):
        """Parse an html saml login form."""
        HTMLParser.__init__(self)
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            self._current_form = dict(attrs)
        if tag == "input" and self._current_form is not None:
            self._current_form.setdefault("_fields", []).append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _dict2str(self, d):
        # When input contains things like "&amp;", HTMLParser will unescape it.
        # But we need to use escape() here to nullify the default behavior,
        # so that the output will be suitable to be fed into an ET later.
        parts = []
        for k, v in d.items():
            if v is None:
                v = ""
            escaped_value = escape(v, quote=True)
            parts.append('%s="%s"' % (k, escaped_value))
        return " ".join(sorted(parts))

    def extract_form(self, index):
        form = dict(self.forms[index])  # Will raise exception if out of bound
        fields = form.pop("_fields", [])
        return "<form %s>%s</form>" % (
            self._dict2str(form),
            "".join("<input %s/>" % self._dict2str(f) for f in fields),
        )

    def extract_form_by_id(self, form_id):
        """
        Return the form with id equal to `form_id`.
        Raise an exception if not found.
        """
        found = False
        forms = self.forms
        for n, form in enumerate(forms):
            if form.get("id") == form_id:
                found = True
                break
        if not found:
            raise Exception("Could not find form with ID `{}`.".format(form_id))
        logger.debug(f"Found for with ID '{form_id}' at index {n}.")
        return self.extract_form(n)

    def error(self, message):
        # ParserBase, the parent of HTMLParser, defines this abstract method
        # instead of just raising an exception for some silly reason,
        # so we have to implement it.
        raise FormParserError(message)


def get_form_from_response(resp, form_index=None, form_id=None):
    """
    Parse login form from response.
    """
    html = resp.text
    return get_form_from_html(html, form_index=form_index, form_id=form_id)


def get_form_from_html(html_str, form_index=None, form_id=None):
    """
    Parse login form from HTML text.
    """
    parser = FormParser()
    parser.feed(html_str)
    if parser.forms:
        if form_index is not None:
            return ET.fromstring(parser.extract_form(form_index))
        elif form_id is not None:
            return ET.fromstring(parser.extract_form_by_id(form_id))
    raise FormParserError("Unable to parse form.\n{}".format(html_str))


def form_to_dict(form):
    """
    Convert an ElementTree HTML form representation into a dict.
    """
    data = {}
    for tag in form.findall(".//input"):
        key = tag.attrib.get("name")
        if key is None:
            continue
        value = tag.attrib.get("value", "")
        data[key] = value
    return data
