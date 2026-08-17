# Brands

An instance's appearance on the pages a user sees: a product name, a logo, a
support link, and four colours.

```sh
signari brand check \
  -brand-primary '#0b5fff' -brand-on-primary '#ffffff' \
  -brand-background '#ffffff' -brand-text '#18181b'

  text on the background       17.74:1  comfortable (AAA)
  button text on the button     5.14:1  readable (AA)

readable (WCAG 2.1 AA needs 4.5:1 for body text)
```

```sh
signari brand set -issuer https://auth.example.com \
  -brand-name "Acme Identity" \
  -brand-logo https://acme.example.com/logo.svg \
  -brand-support https://help.acme.example.com \
  -brand-primary '#0b5fff' -brand-on-primary '#ffffff' \
  -brand-background '#ffffff' -brand-text '#18181b'
```

It takes effect on the next page render. No restart.

## Tokens, never CSS

The obvious way to build this is a text box holding custom CSS, and that is what
the other products offer. It is also stored cross-site scripting aimed at the
worst page in the product.

CSS can pull resources from anywhere. Attribute selectors with `url()`
exfiltrate the page's own state a character at a time. And an administrator who
can restyle the sign-in form can restyle it into one that looks identical and
posts somewhere else — on the single page where users are asked to judge whether
a site is genuine.

So a brand is a fixed set of tokens. Every colour is validated as a hex literal
before it is stored, again by a database constraint, and a third time before it
reaches the stylesheet. There is no path from a brand to arbitrary markup or
arbitrary style rules, and a test feeds `#1a2b3c;} body{display:none` through
the emitter to prove it.

## Contrast is checked, not trusted

Every deployment that offers colour customisation eventually has a tenant whose
sign-in page is grey on white, because whoever chose the colours was matching a
brand guide printed on paper and never looked at the result on a phone outdoors.

The contrast ratio is arithmetic — WCAG 2.1 relative luminance — so it is
checked when the colours are set:

```
signari: button text on the button has a contrast ratio of 4.48:1, below the
4.5:1 needed to be readable (WCAG 2.1 AA). #ffffff against #777777. Darken one
or lighten the other
```

`#777777` fails and `#767676` passes. One shade apart, and the difference
decides whether error messages are legible. That is not a judgement anyone
should be making by eye.

The threshold is 4.5:1, the level for body text, rather than the 3:1 allowed for
large text — because the things that matter on these pages are field labels and
the reason a sign-in was refused, and an error nobody can read becomes a call.

## All four colours or none

A partial palette is refused. A custom background against a default text colour
is the most common way a page becomes unreadable, and it happens because setting
one colour feels like a small change.

## Why this is per instance

An instance is one issuer on one hostname, which is the same unit other products
key branding on when they key it on domain. Serving two brands from one hostname
means guessing which one a visitor should see before they have identified
themselves — and guessing wrong shows one customer another customer's logo.

To brand separately, run an instance per hostname. That is what the instance
model is for.

## What it touches

Every page rendered by the engine: sign-in, consent, MFA enrolment and
challenge, recovery, the device flow, the account page and the application
portal. The colours are injected into the rendered page rather than referenced
by each template, so a page cannot be missed — a sign-in page in default colours
followed by a consent page in the customer's colours reads as though one of the
two is not really theirs.

The logo appears on the sign-in page. The support link appears there too, but
**only alongside a failure**, which is the moment it is worth anything.

`img-src https:` is added to the Content-Security-Policy only when a logo is
actually configured. An unbranded deployment keeps `default-src 'none'`.
