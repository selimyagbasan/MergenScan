"""Small, deterministic evidence parsers (not browser execution validators)."""
from html.parser import HTMLParser
from urllib.parse import urlsplit


class ActiveReflection(HTMLParser):
    """Ignore escaped text, comments and HTML raw/inert containers."""
    INERT = {'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes',
             'noscript', 'template', 'plaintext'}

    def __init__(self, marker):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.inert = []
        self.script = False
        self.script_data = ''
        self.found = False

    def handle_starttag(self, tag, attrs):
        attributes = {}
        for name, value in attrs:
            attributes.setdefault(name, value or '')  # HTML keeps the first duplicate.
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.append(tag)
            return
        if tag in self.INERT:
            self.inert.append(tag)
            return
        if tag == 'script':
            script_type = attributes.get('type', '').lower()
            self.script = script_type in ('', 'module', 'text/javascript', 'application/javascript')
            self.script_data = ''
        if tag == 'img':
            event = attributes.get('onerror', '')
            if event.strip() == f"alert('{self.marker}')":
                self.found = True

    def handle_endtag(self, tag):
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if tag == 'script':
            if self.script and self.script_data.strip() == f"alert('{self.marker}')":
                self.found = True
            self.script = False

    def handle_data(self, data):
        if self.script and not self.inert:
            self.script_data += data


def active_html_reflection(response, marker):
    content_type = response.headers.get('Content-Type', '').split(';')[0].lower().strip()
    if content_type and content_type not in ('text/html', 'application/xhtml+xml'):
        return False
    parser = ActiveReflection(marker)
    parser.feed(response.text)
    return parser.found


def frame_policy(csp):
    """Return missing, restrictive, permissive or unknown for frame-ancestors.

    A CSP directive is interpreted by name, not by substring occurrence. Keep
    first duplicate directive, as browsers do. Multiple policies are intersected.
    """
    policies = []
    for policy in csp.split(','):
        for directive in policy.split(';'):
            words = directive.strip().split()
            if words and words[0].lower() == 'frame-ancestors':
                values = words[1:]
                if not values:
                    policies.append('unknown')
                elif any(v in ('*', 'http:', 'https:') or
                         (v.startswith(('http://', 'https://')) and urlsplit(v).hostname == '*')
                         for v in values):
                    policies.append('permissive')
                elif values == ["'none'"] or all(
                    v == "'self'" or v.startswith(('https://', 'http://')) for v in values
                ):
                    policies.append('restrictive')
                else:
                    policies.append('unknown')
                break
    if 'restrictive' in policies:
        return 'restrictive'
    return policies[0] if policies else 'missing'
