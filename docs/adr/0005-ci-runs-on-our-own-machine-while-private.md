# ADR 0005 — CI runs on our own machine while the repository is private

**Status:** Accepted
**Date:** 2026-09-21

## Context

GitHub-hosted runners are metered on private repositories. The workflow
fired on every push to every branch and started fourteen rented machines
each time, three of them macOS and three Windows. The account carries a $0
Actions budget with stop-usage on, so once the included allowance was
consumed GitHub terminated every hosted job before its first step: no
steps, no logs, no explanation. CI stopped verifying anything, silently.

We own an always-on ARM Linux machine, which costs nothing to
run.

## Decision

Every Linux job runs on a self-hosted runner on that machine, selected by
its automatic `self-hosted`, `Linux` and `ARM64` labels. It has Python
3.9, 3.12 and 3.13 installed by uv under `~/.local/bin`;
`actions/setup-python` is not used there because it publishes no arm64
Linux build for every version the matrix needs.

The workflow has no `pull_request` trigger. A pull request run would check
out a contributor's branch and execute it on that machine, so pull requests
are read and merged to a branch here, and CI runs on the push. Removing the
trigger is not the same as making the runner safe: it only removes the one
path an outsider could use to reach it.

macOS and Windows cannot run on that machine. Those jobs stay on GitHub's
runners and fire on manual dispatch only.
While the repository is private they are expected to be held by the budget
and not to run at all. That is accepted: the product is built and proven on
Linux first.

The last mile — proving the suite passes on macOS and Windows — is a gate on
going public, not a gate on day-to-day work.

## Consequences

- Linux CI is free, unlimited, and no longer competes with an allowance.
- JSCR is unproven on macOS and Windows until the repository is public. Any
  claim of cross-platform support before then is unevidenced.
- The self-hosted runner executes whatever code reaches it. That is
  acceptable for a private repository whose contributors we control. It is
  not acceptable for a public one: even with no `pull_request` trigger, a
  workflow on a public repository is one setting away from running an
  outsider's code on our machine with our network.

## Before this repository is made public

1. Remove the self-hosted runner from that machine and deregister it.
2. Return every job to GitHub-hosted runners, which are free and unlimited
   on public repositories.
3. Confirm the suite passes on macOS and Windows on Python 3.9, 3.12 and
   3.13 — six jobs, all green — before announcing the repository.
4. Only then state that JSCR is cross-platform.
