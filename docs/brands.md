# Brands

An appearance on the pages a user sees: a product name, a logo, a support link,
and four colours. An instance has one, and each organisation on it may have its
own over it.

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

## An organisation's own

```sh
signari brand set -org <uuid> -brand-name "Bravo" -brand-logo https://bravo.example/logo.svg
signari brand show -org <uuid>
signari brand remove -org <uuid>
```

The same through `PUT /admin/organizations/{orgID}/brand`, which a token of that
organisation may call, under `brand:` in a [configuration file](config-as-code.md),
and on the console's Brand screen. Contrast is checked the same way on all of them.

What an organisation leaves out falls through to its instance: the name, the logo
and the support link one at a time, the four colours together, because a background
of one brand under the text of another is a pair nobody checked. Above, Bravo keeps
the instance's colours.

A page takes the organisation of what it is answering, in this order:

1. the client of the authorization request it is part of, so a person signed in at
   one organisation who follows another's application reads that other one's page;
2. the sign-in it is part way through, which is how the second-factor page knows;
3. the session it came with;
4. the instance's organisation, when it has only one.

A bare `/login` on a deployment of several matches none of these and wears the
instance's appearance. It does not guess: a wrong guess shows one customer another
customer's logo. Mail wears the look of the organisation it is sent for.

A separate hostname still needs [a separate instance](configuration.md#several-instances-in-one-process):
this changes what a page looks like, not whose address it is at.

## An organisation's words

```sh
signari message set -org <uuid> -locale en -message-key login.heading -message-text "Sign in to Bravo"
signari message list -org <uuid>
signari message remove -org <uuid> -locale en -message-key login.heading
```

`signari i18n keys` prints every key. The same through
`PUT /admin/organizations/{orgID}/messages/{locale}/{key}`, a token of that
organisation may call it, under `messages:` in a [configuration file](config-as-code.md),
and on the console's Messages screen. It takes effect on the next render, on the
pages and in the mail of that organisation alone.

These are a tenant's, so they are not trusted the way the catalogue is: a message
in the catalogue may carry a link, and one of these is plain text, escaped on the
way to the page, so whoever may set it can change what a page says and not what it
does. It may use the placeholders the message it replaces is given, as
`{Client}` in `consent.title`. These are refused rather than stored: a key nothing
renders, a language with no catalogue, a placeholder the message is never given, and
a message that counts something, as it has a form for each number and this is one
line. Reword those, and add a language, in a theme instead.

The pages a browser reads rather than a person do not say them: the SAML POST form,
`form_post`, WS-Federation and front-channel logout. Each is on the path that signs
somebody in to an application, and a theme can still reword them.

## An organisation's pages

A theme directory (see [theming](theming.md)) may hold a directory per organisation,
named by its slug, laid over the deployment's theme page by page and message by
message:

```
theme/
  layout.html               everybody's
  locales/en.json
  orgs/
    bravo/
      layout.html           Bravo's people, and nobody else's
      locales/en.json
      locales/de.json       a language only Bravo's readers are offered
```

```sh
signari theme eject -theme-dir ./theme/orgs/bravo -theme-page layout
signari theme check -theme-dir ./theme        # checks every organisation's too
```

It is the operator's disk rather than a tenant's token, read once at startup, and
it follows every rule of a theme. A file that fails validation is refused for that
page, and the deployment's page is served in its place. A directory that fails
altogether costs that organisation its theme and nobody else anything. A directory
naming no organisation is logged at startup. Two instances served by one process
read one theme directory, so organisations of theirs that share a slug share a
directory.

On a page, an organisation's stored words are said over its theme's. Rendering them
parses that page for the render, because a template's `T` is bound when it is parsed
and the parsed pages are shared: a page's worth of parsing, on pages people read, and
only for an organisation that has reworded something.

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
