# Writing the docs

## Introduction

Documentation stays clear only while it is written one way. When one editor does
all the writing, that editor keeps the voice. Signari's pages are written by
several people, some of them helped by coding agents, so the voice has to be
written down instead.

This page is that record. Each rule is stated so that a person can follow it and
a test could later check it. The rules come from measuring the pages of a
framework whose documentation is widely called the clearest there is. They were
then adjusted for readers who have never used an identity provider.

> [!NOTE]
> The completeness of the reference pages is already checked by tests in
> `engine/internal/docsync`. This page covers what those tests cannot see: how a
> page reads.

## Who we write for

Write for a developer or an administrator who has never run an identity
provider. They know what a web application is. They may not know what an
issuer, a redirect URI or a token is, and they should not need to.

English may be their second language. Short sentences, one word for each idea and
full forms such as "do not" help them more than anything else on this page.

## The shape of a page

Every page has exactly one `#` heading, its title. Sections below it use `##`
and `###`. Use `####` only for one option among many, such as a single flag.

The first section is always `## Introduction`. It has one to three short
paragraphs and no code, in this order:

1. The reader's situation, or what the feature is for, in one or two sentences.
2. What Signari does about it.
3. Where it is configured, if it is.
4. Optionally, one NOTE with a prerequisite or a related page.

A reference page ends on its last, most specialised section, with no summary.
A tutorial or a getting-started page ends with `## Next steps`, a short list of
where to go from here.

## Sentences

- Write to the reader as "you".
- Use "you can" for an option, "you should" for advice, and "you must" for a
  requirement. Do not mix their strength: "you must" is never softened, and "you
  should" is never a hidden requirement.
- Keep sentences to about 17 words on average. On tutorials and explanation
  pages, no sentence runs past 25 words.
- Put one idea in each paragraph.
- Prefer full forms: "do not", "cannot", "is not".
- Never write `simply`, `just`, `obviously`, `easy`, `easily`, `basically` or
  `clearly`. They tell a reader who is stuck that the fault is theirs.
- Use British spelling, as the code does: organisation, colour, licence.

We write "you can" where some well-known documentation writes `you may`. That
phrase is polite, but a reader working in a second language can read it as "you
might", which is a different meaning.

## One word for each idea

A reader who meets two words assumes two things. Use these words, and only these:

| Write | Not | Notes |
|---|---|---|
| sign in, sign-in | `log in`, `login`, `log on` | `/login` stays where it is a real path |
| sign out | `log out`, `logout` | `logout.md` and `/oauth2/logout` keep their names |
| application | app, relying party, service provider | Gloss "client" once as the protocol's word. Keep `client` in commands, flags and field names |
| person, people | user, end user | Keep "user" where the code says it, as in `signari user create` |
| organisation | tenant, realm | Gloss "tenant" once where a reader expects it |
| administrator | admin, operator | `admin-token` and `/admin` keep their names |
| Signari | the IdP, the server | "The engine" is the Go server, when that distinction matters |

## New terms

Put a new term in quotes the first time it appears on a page. Explain it in plain
words in the same sentence or the next. For example: an application's "redirect
URI" is the address Signari sends the browser back to.

Spell out every abbreviation the first time it appears on each page, such as
OpenID Connect (OIDC). Then link the term to its entry in the
[glossary](glossary.md) or to the page that explains it.

## The running example

Explanations use one company throughout, so a reader never has to learn a new
example. Acme has a wiki, a chat application and a VPN. Its people sign in once
and reach all three. When someone leaves, one change ends their access to all
three.

- The company is Acme. Its sign-in address, the issuer, is
  `https://login.example.com`.
- The person signing in is Ada, `ada@example.com`.
- The wiki speaks OpenID Connect, the chat application speaks SAML, and the VPN
  speaks RADIUS.

Use `example.com` and its subdomains for every address. Use angle brackets for a
value the reader must supply, such as `<org-id>`.

## Code

Introduce every code block with a sentence that ends in a colon. The sentence says
what the block does and when you would want it:

```sh
signari doctor
```

Show the smallest command that works first. Add variations one at a time, each
with its own sentence. Never put two code blocks one after the other without a
sentence between them. If a block needs explaining, explain it after the block,
beginning "In this example".

Every command must be one you have run, or one you have read in the code. The
`docsync` tests fail when a page names a `signari` command or flag that does not
exist, so do not write one that is planned.

## Callouts

Use only two kinds, written as GitHub alerts.

A NOTE points somewhere else. It holds a prerequisite, a related page, a
shortcut, or the difference between two things a reader might confuse. A reader
can skip it and lose nothing they need:

```md
> [!NOTE]
> One or two sentences, usually with a link.
```

A WARNING states a rule, what happens if it is broken, and how to avoid that:

```md
> [!WARNING]
> The rule, its consequence, and the fix.
```

Keep each to about 25 words. A page should rarely have more than two callouts for
every thousand words. A page about a risky subject earns more warnings than a page
about a safe one.

## Troubleshooting entries

Name each entry after what the reader sees. Use the exact message as the heading
when there is one, so that a reader who pastes the message into search lands on
it. Every entry has the same four parts:

1. **Symptom.** What the reader sees, quoted exactly.
2. **Why.** The cause, in plain words.
3. **Fix.** What to change.
4. **How to confirm.** How the reader knows the fix worked.

Quote only messages the engine really returns. Find each one in the code first.

## Facts

- Check every behaviour and every message against the code, not against memory.
  Keep the file and line you checked in the review, not in the page.
- Never name another identity product, except on the `migrate-from-*` pages.
  `TestNoCompetitorIsNamedInAPublishedFile` fails the build when a page does.
  State the technical rule on its own terms instead.
- Every link must lead to a page a reader actually gets.
  `TestEveryDocumentLinkResolvesForAReader` checks this against what git tracks.
- Some files in this repository are kept on one machine and never published. Run
  `git check-ignore -v <path>` on a new page before you rely on it being
  published, and never link to a file that is ignored.

## Headings and titles

Write headings in sentence case. A heading should say what the section answers,
such as "Back up the root key", not "Root key backup considerations".

Other pages link to headings, so change a heading's words only when the old
words were wrong. When you do, search the docs for links to it.

The title a page has in the sidebar is the one a beginner would look for. "Your
first application" is a title; `first-application.md` is a file name.

## The sidebar

The sidebar is `docs/documentation.md`. Each group is a top-level item that holds
a `##` heading, and each page is an indented link beneath it:

```md
- ## Getting started
    - [Introduction](introduction.md)
```

It lists every published page exactly once, except `README.md` and itself. When
you add a page, add it to the group a beginner would look in.

## Kinds of page

Know which kind of page you are writing, and do not mix them:

| Kind | Its job | Example |
|---|---|---|
| Tutorial | Takes a beginner to a result, with no choices to make | [Your first application](first-application.md) |
| How-to guide | Solves one task for someone who knows what they want | [Quickstart: a Go application](quickstart-go.md) |
| Explanation | Builds understanding, with no steps to follow | [How Signari works](how-signari-works.md) |
| Reference | Lists every option, complete and exact | [Every command](cli.md) |

A tutorial offers no options and explains only what the reader needs to finish.
Put the options on a reference page and link to it.

## Rules a test could check

These are the rules above, written as checks for a future test:

| Rule | Check |
|---|---|
| One title | Exactly one line beginning `# ` outside code |
| Introduction first | The first `##` heading is `## Introduction` |
| Introduced code | The last line of prose before each code block ends in `:` |
| No stacked code | Some prose sits between any two code blocks |
| Two callouts | Every `> [!` is `> [!NOTE]` or `> [!WARNING]` |
| No minimisers | None of the seven words listed under [Sentences](#sentences), outside code |
| One word per idea | None of the rejected words in [One word for each idea](#one-word-for-each-idea), outside code, paths and names |
| Short sentences | On tutorial and explanation pages, no sentence over 25 words outside code and tables |
| Abbreviations | The first use of each abbreviation in the glossary is followed by its expansion, or follows it |
| Every page listed | Each published page appears once in `documentation.md` |
