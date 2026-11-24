# Mail

## Introduction

Signari sends people email, such as sign-in codes, invitations and password
reset links. This page covers what the engine sends, how it looks, and who it
comes from.

Every message is `multipart/alternative`: the text the engine wrote, then an
HTML page made from those same words. A mail program that shows HTML shows the
page, and one that does not shows the text. They never differ, because the page
is not written separately.

Mail goes out through one relay for the whole deployment, `SIGNARI_SMTP_HOST`.
It comes from `SIGNARI_MAIL_FROM`, unless an organisation has
[a sender of its own](#the-sender).

## The page is fixed, and has no buttons

An administrator cannot supply a mail template, and the page has no button and
no image. That is the point of it, not a gap in it.

A styled button in a message about somebody's account is the exact shape of a
"phishing" attack, a message made to trick its reader. The words on the button
say one thing, and where it goes is hidden until it has been pressed. Every
message an identity provider sends with a button teaches its people to press
them. So:

- **Each link's visible text is the whole address it goes to.** Nothing can read
  "Open your account" and go somewhere else. `TestEveryLinkShowsWhereItGoes`
  holds that. If it fails because somebody wants a button, the test is the
  argument against it.
- **There is no image**, the logo included. A remote image is fetched when the
  message is opened, which tells whoever serves it when and from where.
- **What a message says is text**. A device name or a provider's name that
  reaches a body is escaped, and a colour that is not `#rrggbb` is dropped.

## The brand

The instance's [brand](brands.md) changes three things and no others: the
product name at the top of the page, and the background, text and link colours.
There is nothing to set for mail specifically. A deployment with no brand gets a
plain white page.

## The sender

Mail comes from `SIGNARI_MAIL_FROM` and `SIGNARI_MAIL_FROM_NAME` unless an
organisation has its own. To give an organisation its own sender, name it with
`signari instance mail-sender`. The command also reports what the domain's
Domain Name System (DNS) records say:

```sh
signari instance mail-sender -org <id> -mail-from id@acme.example -mail-from-name "Acme Identity"

this organisation's mail comes from id@acme.example

  What the DNS of acme.example says:
  pass  SPF   v=spf1 include:_spf.provider.example -all
  warn  DKIM  no selector configured, so DKIM cannot be checked. ...
  pass  DMARC v=DMARC1; p=quarantine; rua=mailto:dmarc@acme.example
  pass  MX    2 mail exchanger(s)
```

In this example, the command checks four records:

- Sender Policy Framework (SPF), which lists the servers allowed to send mail
  for the domain;
- DomainKeys Identified Mail (DKIM), which publishes the key that the domain's
  mail is signed with;
- Domain-based Message Authentication, Reporting and Conformance (DMARC), the
  domain's rule for mail that fails those checks;
- the mail exchanger (MX) records, which say where the domain receives mail.

`-dkim-selector` names the selector your mail provider signs with, so the key
can be checked too. `-clear` takes the organisation back to the deployment's
sender.

The Admin API sets the same two fields, `mail_from` and `mail_from_name`, on
`PATCH /admin/organizations/{orgID}/settings`. It sets the address to `""` to
take it back.

**The address goes on the envelope as well as the From line**. The envelope is
the domain receivers check SPF against, and DMARC wants the two to agree. So the
address is also where bounces go.

The relay in `SIGNARI_SMTP_HOST` has to be allowed to send as that domain. Its
SPF has to include the relay, and the relay has to sign for it with DKIM.

The command checks the DNS and refuses nothing, since a domain can be set up
after the sender is named. But until the domain is set up, that organisation's
sign-in codes will be rejected or junked.

The relay itself, which speaks the Simple Mail Transfer Protocol (SMTP), is one
per deployment. An organisation brings an address, not a mail server.

An address is one plain address with no display name inside it. A name is at
most 100 characters, with no line breaks. Both reach a message's headers.

`org.mail_sender_set` records each change. If the sender cannot be read when a
message goes out, the message goes from the deployment's address and the engine
logs a warning. A sign-in code from the wrong address does more good than one
that never left.
