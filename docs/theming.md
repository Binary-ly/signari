# Theming

Every page a person sees while signing in — the login form, the consent screen,
the two-factor challenge, the error pages — is an HTML file you can replace
without a compiler.

Until now they were Go string literals inside twenty-two source files. Changing
a heading meant forking the repository and shipping a binary nobody had audited.

## The thirty-second version

```sh
signari theme eject -theme-dir ./theme -theme-page layout   # start from the real page
$EDITOR ./theme/layout.html                           # change the chrome
signari theme check -theme-dir ./theme                # exits non-zero if refused
SIGNARI_THEME_DIR=./theme signari serve
```

`signari theme list` then prints every page and where it is coming from.

## Start with the layout

There are two units you can replace, and the smaller one is the one most
deployments want.

**`layout.html` is the chrome** — the `<head>`, the logo, the footer, the shared
stylesheet — for all thirty-three pages at once. Every form, every hidden field
and every button stays ours. This is the safe case, and it is safe *structurally*:
it cannot drop a CSRF token, because it never contained one.

**An individual page is that page's content** — the form, the buttons, the
wording. Much more control, and the reason the validator below exists.

If what you want is your logo, your colours and your typeface, override
`layout.html` and stop there.

### What the layout must contain

Three placeholders, and the page will not be accepted without them:

| | |
|---|---|
| `{{template "content" .}}` | Where the page goes |
| `{{template "title" .}}` | Inside `<title>` |
| `{{template "pagecss" .}}` | The shared stylesheet |

Two more are optional and defined for you if you leave them out: `style` (rules a
single page needs) and `foot` (anything after the content).

`.BrandLogo`, `.BrandName` and the brand colours are supplied by
`signari brand set`, so an operator can change the logo without touching a file
at all. A theme that hardcodes an image is a theme that has quietly turned that
command off.

## Overriding a page

`signari theme eject -theme-dir ./theme` writes all thirty-three out. Then
**delete every file you do not intend to change.** A file left in that directory
is a fork of one page: it stops receiving upstream fixes, including security
fixes to the page it replaces. `theme list` is how you see how many you are
carrying.

A page is three blocks:

```html
{{define "title"}}Sign in{{end}}
{{define "style"}}<style>.card { max-width: 22rem }</style>{{end}}
{{define "content"}}
  <form method="post" action="/login">
    {{.CSRFField}}
    <input name="username" autocomplete="username">
    <input name="password" type="password" autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
{{end}}
```

The shared stylesheet is emitted before your `style` block, so a rule you write
wins on source order without having to out-specify anything.

## What validation actually checks

A page override is compared against **the built-in page it replaces**, rendered
side by side under fourteen different datasets. The requirements are not a list
somebody maintains by hand — they are read out of our own page every time the
binary is built, so a field added to a form next month is protected in your theme
without anyone remembering to write it down.

Three things must survive:

- **Every critical value the built-in renders.** The CSRF token, the
  authorization request, the SAML request and relay state, the continuation URL,
  the invite and reset tokens, the device user code, the record being acted on.
- **Every form target.** A `method="post"` to `/login` cannot become a `GET`, and
  cannot go somewhere else.
- **Every hidden input.** By count as well as by name.

Dropping any of them is not a cosmetic mistake. It is the specific failure that
still *looks correct on screen* — a sign-in form missing its CSRF field renders
beautifully and submits, right up until it is submitted by somebody else's page.

Fourteen datasets rather than one because a page like the consent screen shows a
different form depending on what was asked for; a single render would only ever
walk one branch of the `if`, and the requirement in the other branch would be
invisible. Fields read inside a `{{range}}` are probed too.

Two more properties are checked: the page must parse, and it must render without
crashing on empty data. The second matters because an error page is reached
*precisely when* something did not get filled in, and a theme that assumes a
value is present turns a handled error into a blank response.

## What is not checked

Contrast, spelling, whether the button is visible, whether the copy is
accurate, and whether your CSS puts the form behind a header. Nothing here is a
substitute for loading the page. Run `signari brand check` for contrast, and open
`/login`, `/consent` and `/mfa` in a browser before you ship.

## When a theme is wrong

It depends on where you are.

**In a pipeline**, `signari theme check` exits non-zero and names the file, the
page, and the specific value that went missing:

```
REFUSED  the login page no longer renders the CSRF value, the CSRFField value,
         1 of its 2 hidden inputs. The built-in page does, and losing it breaks
         the page in a way that still looks correct on screen
```

**On a running server**, nothing stops. The bad page is refused *individually*,
the built-in is served in its place, and a warning is logged. Your other
overrides — including the layout — stay in force.

That asymmetry is deliberate. Refusing to start would hand anyone editing a theme
the ability to lock every user out of every application by mistyping a filename
at four in the afternoon. The cost is that a refused theme's symptom is a page
that looks *normal*, which is why `signari doctor` reports refusals, and why
`theme check` belongs in the deploy, before the restart.

## The pages

Thirty-three, plus three shared fragments (`layout`, `pagecss`, `captcha`).

| | |
|---|---|
| Signing in | `login` `mfa` `emailotp` `smsotp` `consent` `prompt` `done` `cancelled` |
| Account | `account` `signup` `signupdone` `enrol` `changepw` `connected` `portal` |
| Recovery | `recover` `recovery` `reset` `sent` |
| Signing out | `logout` `backchannel` `fclogout` |
| Devices and access | `device` `racindex` |
| Errors | `err` `federr` `samlerr` `umaclaimserr` |
| UMA | `umaclaims` |
| Bridges | `saml` `formpost` `wsfed` `racview` |

The four bridges are the exception to everything above, for two different
reasons.

`saml`, `formpost` and `wsfed` are auto-posting forms — the SAML POST binding,
the `form_post` response mode, WS-Federation — that a browser submits inside a
redirect. The only time a person sees one is with scripting off, which is why
each carries a small self-contained stylesheet and nothing more: a logo there is
two extra requests in the middle of a sign-on, and a shared stylesheet is one
more thing that can fail to load and leave the redirect hanging.

`racview` is bare for the opposite reason. It is looked at for a long time, and
what fills it is somebody else's desktop; chrome around that competes with the
content, so it styles itself, stays dark in both themes, and carries no logo.

**`fclogout` is not a bridge**, though it was treated as one at first. It has a
heading, a sentence telling you how many applications you are being signed out
of, and a link to continue if one of them hangs. The hidden iframes are its
machinery; the page around them is read, so it carries the brand like every
other page a person sees.

## The look, and changing it without touching a page

All thirty-three share one stylesheet, `pagecss.html`, built on CSS custom
properties. Overriding *that* alone re-colours everything without going near a
form:

```css
:root{
  --page-w:26rem;          /* how wide the card is */
  --radius:10px;
  --accent:#3e63dd;        /* links and focus rings */
  --btn-bg:#18181b;        /* the primary button */
}
```

Light and dark are both defined. A page follows the reader's system setting
unless `<html>` carries `data-theme="light"` or `data-theme="dark"`, which a
layout override can set to pin one.

The greys — borders, panel fills, muted text — are **mixed from the surface and
text colours** rather than being fixed. That is what makes `signari brand set`
produce a coherent palette instead of the default greys showing through
somebody else's colours.

## Looking at what you changed

Validation proves a page still carries its CSRF token. It cannot tell you the
button is invisible against your new background.

```sh
SIGNARI_PAGE_PREVIEW_DIR=/tmp/pages go test ./internal/pages/ -run Preview
```

That writes every page rendered with realistic sample data, in four variants —
your system setting, light, dark, and one carrying brand colours — with an
`index.html` showing all of them at once. Serve the directory and open it.

## Reading, and when

Once, at startup. Not per request.

A directory somebody is editing spends part of its life holding half-written
files, and these are the pages people sign in through; serving one mid-save is
worse than asking for a restart. It also means a theme cannot slow down a
sign-in, and that what is being served is fixed for the life of the process —
which is a thing you can reason about during an incident.
