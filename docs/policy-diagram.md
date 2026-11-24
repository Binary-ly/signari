# Seeing the policy: a diagram generated from the file

## Introduction

An [access policy](policy.md) is a file, which makes it exact and testable. A
reviewer reading a pull request still wants to see the shape of the rules at a
glance.

Signari draws the policy as a diagram, from the same parsed structure the engine
evaluates. So the picture cannot drift from what the policy does.

You draw it with `signari policy graph`, from the same file you test and apply.

## Draw a policy

This command draws a policy file as an SVG (Scalable Vector Graphics) image:

```sh
signari policy graph -policy-file policy.yaml -out policy.svg
```

It writes the image, and says what it drew:

```
wrote policy.svg
  5 rule(s) -- 4 restricting, 1 denying
  7 test(s), all passing (a file whose tests fail does not load)
```

The diagram for an example policy looks like this:

![An example policy rendered as a diagram](img/policy-example.svg)

## The trade, stated plainly

The usual shape for access rules is a graph builder, a canvas you draw them on.
[Access policy](policy.md#why-not-a-graph-builder) explains why Signari's rules
are a file instead. This is the opposite trade: the file comes first, and the
picture is drawn from it.

The picture cannot drift from the behaviour, because it is not a second
representation. It is a rendering of the first one, produced from the same
parsed structure the engine evaluates. A builder has the opposite property, and
that is where "the diagram says one thing and production does another" comes
from.

The cost is real and worth naming: you cannot assemble a policy by dragging
boxes. You write nine lines of YAML and its tests.

## The layout is a claim, and the first one was wrong

The first version laid each application's group of rules in a row, with arrows
between them. It rendered cleanly, and it was a lie: **arrows mean sequence, and
there is no sequence.**

A request names one application. What applies is the universal rules *plus* that
application's rules, together, not in order.

So the universal rules are a band across the top, the applications sit in a grid
beneath, and nothing points at anything.

Getting this wrong in a diagram is the same failure as getting it wrong in code.
It is harder to notice, because a tidy diagram is assumed to be right. It was
found by rendering it and looking, which no test would have done.

## A condition that is enforced and not drawn

A condition that is enforced but not drawn is a lie of omission. Somebody reads
the diagram, sees no device requirement, and cannot work out why their sign-in is
refused.

`TestEveryConditionIsDrawn` walks the `Conditions` struct by reflection, and sets
each field alone. It fails when one draws nothing, with a message like this:

```
Conditions.DeviceCompliant is enforced and draws nothing. Somebody reads the
diagram, sees no such requirement, and cannot work out why their login is
refused.
```

It also fails if the test itself leaves a new field unset. Otherwise, adding a
field would make the test pass while proving nothing about it.

An earlier version asserted particular phrases. It failed the moment the wording
improved from "phishing-resistant factor" to "a passkey or security key", which
is what an administrator should actually read.

**A test that pins prose makes the prose worse.** It now checks that each
condition changes the output, not what it says.

## Deterministic, and no JavaScript

The diagram is plain SVG, laid out in Go. Two runs over the same file are
byte-identical, so the diagram can be committed and its diff read. Applications
are sorted for the same reason.

It renders in a browser, in a README, in a pull request comment, and in any
terminal that can show an image. Nothing is fetched, and nothing executes.

Rule names are text an administrator supplies, going into markup, so they are
escaped. That is tested with a rule literally named `break <svg> & "quotes"`.

## Text that fits

Truncation is measured against the pixel width available, rather than a fixed
character count. The first version cut at 30 characters regardless.

That turned `contractors-cannot-reach-payroll`, the name that says what the rule
does, into `contractors-cannot-reach-payr…`, while a third of the card sat empty.

## Drawn only for a file that would load

`policy graph` parses the file rather than reading it, and parsing runs the
file's own tests. A policy whose tests fail cannot be drawn.

Putting a picture of something that cannot deploy in front of a reviewer is
worse than showing them nothing.

## Not in the console

This is deliberate, for now. The command line writes a file you commit, attach
to a pull request, or paste into a review. That is where the argument about a
policy actually happens.

A console page showing the *live* policy is worth adding, and is a different
job. It needs to say which version is loaded and when. Otherwise, it becomes
another thing that can silently disagree with production.
