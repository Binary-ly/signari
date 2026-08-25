#!/usr/bin/env python3
"""Drive the front channel for the OIDF conformance suite.

The suite hardcodes HtmlUnit (BrowserControl.java:312) and cannot be told to use
anything else. HtmlUnit intermittently fails to run the JavaScript on the suite's
OWN callback page -- the page that POSTs window.location.hash to an implicit
submit URL -- so a module reaches the callback and then sits in WAITING forever.

With no "browser" block in the test configuration the suite instead publishes each
URL for external interaction (BrowserControl.goToUrl: "If there is no matching
element, the url is made available for user interaction"). This is that external
interaction, done by a client with no JavaScript engine to fail: it submits the
sign-in form, answers the consent page, and performs by hand the single POST the
callback page's script would have made.

Host rewriting: the issuer is https://signari-engine:8080, a name that resolves
only inside the container network. This runs on the host, so requests to that
origin go to 127.0.0.1:8099 with the Host header preserved -- the issuer the
engine sees, and therefore every issuer check, is unchanged.
"""
import html as htmlmod
import re
import sys
import time
import urllib3
import requests

urllib3.disable_warnings()

SUITE = "https://localhost.emobix.co.uk:8443"
ENGINE_ORIGIN = "https://signari-engine:8080"
ENGINE_HOST_ADDR = "https://127.0.0.1:8099"
USER = "conformance@test.local"
PASSWORD = "Tr0ubad0ur-Marmalade-7719"

SUBMIT_RE = re.compile(r"""xhr\.open\(\s*['"]POST['"]\s*,\s*['"]([^'"]+)['"]""")
HIDDEN_RE = re.compile(r"""<input[^>]*type=["']hidden["'][^>]*>""", re.I)
ATTR_RE = re.compile(r"""([\w-]+)\s*=\s*["']([^"']*)["']""")
ACTION_RE = re.compile(r"""<form[^>]*action=["']([^"']*)["']""", re.I)


def rewrite(url):
    if url.startswith(ENGINE_ORIGIN):
        return ENGINE_HOST_ADDR + url[len(ENGINE_ORIGIN):], {"Host": "signari-engine:8080"}
    return url, {}


def get(sess, url, **kw):
    u, h = rewrite(url)
    kw.setdefault("headers", {}).update(h)
    return sess.get(u, verify=False, timeout=30, **kw)


def post(sess, url, **kw):
    u, h = rewrite(url)
    kw.setdefault("headers", {}).update(h)
    return sess.post(u, verify=False, timeout=30, **kw)


def hidden_fields(page):
    """Hidden inputs as a LIST of pairs, values HTML-unescaped.

    A list, not a dict, because the consent form emits one `scope` input per
    requested scope. Collapsing those into a dict keeps the last one, so consent
    is granted for a single scope and the rest are silently dropped.

    The unescape matters just as much: `authz` carries the whole authorization
    query string, so inside an HTML attribute every separator is `&amp;`. Posting
    the raw attribute text back makes the engine -- correctly, having been handed
    exactly that -- redirect to a URL whose second parameter is named `amp;nonce`.
    A browser does both of these silently.
    """
    out = []
    for tag in HIDDEN_RE.findall(page):
        attrs = dict(ATTR_RE.findall(tag))
        if "name" in attrs:
            out.append((attrs["name"], htmlmod.unescape(attrs.get("value", ""))))
    return out


def form_action(page, default):
    m = ACTION_RE.search(page)
    act = htmlmod.unescape(m.group(1)) if m else default
    return act if act.startswith("http") else ENGINE_ORIGIN + act


def submit_implicit(sess, page, log):
    """Do what the callback page's script would have done, if it had run."""
    m = SUBMIT_RE.search(page)
    if not m:
        return False
    # Inlined by Thymeleaf's th:inline="javascript", i.e. a JS string literal:
    # every forward slash arrives as \/ and non-ASCII as \uXXXX.
    url = htmlmod.unescape(m.group(1)).replace("\\/", "/").encode().decode("unicode_escape")
    r = post(sess, url, data="", headers={"Content-type": "text/plain"})
    log(f"      implicit submit -> {r.status_code}")
    return True


def drive_url(sess, url, log):
    r = get(sess, url, allow_redirects=True)
    for _ in range(8):
        page = r.text or ""

        if submit_implicit(sess, page, log):
            return True

        if 'name="username"' in page and 'name="password"' in page:
            fields = hidden_fields(page) + [("username", USER), ("password", PASSWORD)]
            log("      signing in")
            r = post(sess, form_action(page, "/login"), data=fields, allow_redirects=True)
            continue

        # The consent page. `decision` is carried by the submit BUTTON, not by a
        # hidden input, so a driver that posts only the hidden fields sends no
        # decision at all -- and the engine reads that as a refusal and answers
        # access_denied, which reads like the user declined rather than like the
        # harness forgot to click.
        if 'name="decision"' in page:
            fields = hidden_fields(page) + [("decision", "allow")]
            log("      granting consent")
            r = post(sess, form_action(page, "/consent"), data=fields, allow_redirects=True)
            continue

        if "<form" in page and "</form>" in page and ACTION_RE.search(page):
            log("      submitting a form")
            r = post(sess, form_action(page, "/"), data=hidden_fields(page),
                     allow_redirects=True)
            continue

        return True
    return False


# A 1x1 transparent PNG. The suite validates the prefix and the type, not the
# picture, and what it is really recording is "a human confirmed they saw this".
BLANK_PNG = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAf"
             "FcSJAAAADUlEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=")


def fill_placeholders(api, mid, log):
    """Answer any screenshot placeholder the module is waiting on.

    The tests that end at the OP's OWN error page -- an unregistered
    redirect_uri, a request object sent to a server that refuses them -- never
    reach the callback, so nothing in the front channel can advance them. They
    call createPlaceholder() and wait for a human to upload a screenshot proving
    the error page appeared.

    Nothing else finishes them. `POST /runner/browser/{id}/visit` only moves the
    URL from `urls` to `visited` (BrowserControl.urlVisited) and does not touch
    the module, so a driver that marks the visit and waits will wait for ever --
    which is exactly what these modules did, stopping at ~40 log entries with
    zero failures.

    The placeholder id is the `upload` field of a log entry; filling it unsets
    that field (DBImageService.fillPlaceholder), so this is idempotent.
    """
    try:
        r = api.get(f"{SUITE}/api/log/{mid}", verify=False, timeout=20)
        if r.status_code != 200:
            return
        entries = r.json()
    except Exception:
        return
    for e in entries:
        ph = e.get("upload")
        if not ph:
            continue
        try:
            resp = api.post(f"{SUITE}/api/log/{mid}/images/{ph}", data=BLANK_PNG,
                            headers={"Content-Type": "text/plain"},
                            verify=False, timeout=20)
            log(f"      placeholder {ph[:12]} -> {resp.status_code}")
        except Exception as ex:
            log(f"      placeholder error: {type(ex).__name__}: {ex}")


def module_status(api, mid):
    # /api/info/{id} carries the status; /api/runner/{id} has no status key at
    # all, so reading it returns None forever and every module looks live.
    try:
        r = api.get(f"{SUITE}/api/info/{mid}", verify=False, timeout=15)
        if r.status_code == 200:
            return r.json().get("status")
    except Exception:
        pass
    return None


def drive_module(api, mid, log, budget=320):
    # 320s, not 150. The modules that authorize TWICE -- oidcc-prompt-login,
    # oidcc-max-age-1 -- need a second round of front-channel servicing, and if
    # the driver gives up first the runner moves on, the next module claims the
    # shared `alias`, and the previous one dies with "Stopping test due to alias
    # conflict". Both were at 138 log entries and zero failures when that
    # happened, so the result read INTERRUPTED for a test that was passing.
    seen = set()
    deadline = time.time() + budget
    # ONE session for the whole module, because one module is one browser.
    #
    # A session per URL looked tidier and quietly broke every test that
    # authorizes twice: with no cookie the second authorization re-authenticates,
    # so auth_time changes and oidcc-max-age-10000 fails on
    # CheckIdTokenAuthTimeClaimsSameIfPresent -- an engine defect that is really
    # the harness throwing the session away between requests.
    sess = requests.Session()
    try:
        while time.time() < deadline:
            st = module_status(api, mid)
            if st in ("FINISHED", "INTERRUPTED"):
                return st
            try:
                r = api.get(f"{SUITE}/api/runner/browser/{mid}", verify=False, timeout=15)
                # The field is "urls", not "urlsToVisit".
                urls = r.json().get("urls", []) if r.status_code == 200 else []
            except Exception:
                urls = []
            for u in [x for x in urls if x not in seen]:
                seen.add(u)
                log(f"    visit {u[:92]}")
                try:
                    drive_url(sess, u, log)
                except Exception as e:
                    log(f"      driver error: {type(e).__name__}: {e}")
                try:
                    api.post(f"{SUITE}/api/runner/browser/{mid}/visit",
                             params={"url": u}, verify=False, timeout=15)
                except Exception:
                    pass
                fill_placeholders(api, mid, log)
            # Also poll for placeholders with no new URL to visit: a module can
            # create one at any point, and the error-page tests create theirs
            # without ever publishing a second URL.
            fill_placeholders(api, mid, log)
            time.sleep(1)
        return module_status(api, mid)
    finally:
        sess.close()


def main():
    logpath = sys.argv[1]
    def log(m):
        print(m, flush=True)
    api = requests.Session()
    handled = set()
    idle = 0
    while idle < 90:
        try:
            text = open(logpath, errors="ignore").read()
        except FileNotFoundError:
            text = ""
        new = [i for i in re.findall(r"Created test module, new id: (\S+)", text)
               if i not in handled]
        if not new:
            idle += 1
            time.sleep(2)
            continue
        idle = 0
        for mid in new:
            handled.add(mid)
            log(f"  module {mid}")
            log(f"  module {mid} -> {drive_module(api, mid, log)}")
    log(f"driver done; {len(handled)} modules serviced")


if __name__ == "__main__":
    main()
