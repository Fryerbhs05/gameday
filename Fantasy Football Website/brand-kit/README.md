# Conflicted — Brand Kit

This folder is the complete training input for a Claude design agent tasked with redesigning the Conflicted website (formerly "Game Day"). Read every file in this folder before producing design output.

## What this brand is

Conflicted is a multi-league fantasy football tracker. The product solves a specific emotional problem: when you play in three leagues, the same player is on your team in League A and on your opponent's roster in League B. You don't know who to root for. Conflicted tells you.

The name is the strategic anchor. Every design decision should reinforce the idea of *divided loyalty as the core user experience*. The brand should not look like a generic sports product — it should look like a tool for people who are too deep in fantasy football to play casually.

## Read in this order

1. `01-brand-foundation.md` — why Conflicted, target audience, brand personality, the central design idea
2. `02-color-system.md` — full palette with hex, semantic uses, do's and don'ts
3. `03-typography.md` — font choices, hierarchy, weight rules
4. `04-logo-usage.md` — when to use which mark, clear space, minimums, what not to do
5. `05-component-patterns.md` — buttons, cards, score strip, player pills, status badges
6. `06-voice-and-tone.md` — copy guidelines, taglines, what to never say
7. `08-redesign-priorities.md` — what to redesign first and why

The drop-in stylesheet lives at `07-design-tokens.css`. Logo files live in `logo/`.

## Aesthetic shift the next agent needs to understand

The current site (`/index.html` in the parent folder) is a dark-mode design with a gold accent and a sports-book / gambling-floor feel. The new brand is the opposite: **cream-paper light mode primary**, navy and coral as the brand pair, Inter as the typeface, with deliberate use of a vertical "split" motif throughout the UI to echo the bisected logo. Dark mode is supported but is no longer the default.

Treat this as a full repaint, not a tweak. Every existing CSS custom property in `index.html`'s `:root` block should be replaced with the tokens in `07-design-tokens.css`.

## Naming collision to resolve

The current CSS uses `--conflicted` as a semantic color (gold) for the player-status bucket meaning "rooting both directions for this player." Now that "Conflicted" is the brand name, this collision will confuse the next person who reads the code.

**Resolution:** rename the semantic CSS variable from `--conflicted` to `--split`. The status bucket's user-facing label can stay as "Conflicted" or change to "Split" — see `05-component-patterns.md` for the recommendation. The variable name change is non-negotiable; the label is a product call.

## What "done" looks like for the redesign

A redesigned `index.html` where:
- The cream/navy/coral palette has fully replaced the dark navy/gold palette
- Inter has fully replaced Barlow Condensed and IBM Plex Mono (or paired with one as data font — see typography doc)
- The logo files in `logo/` are referenced directly (no inline recreation)
- The split motif appears in at least three places besides the logo (see component patterns)
- The score strip, player buckets, and pills all use the new component patterns
- The CSS variable rename `--conflicted` → `--split` is complete with no stale references

## What to leave alone

- All `api/` code (Yahoo OAuth backend) — purely server-side, no styling
- All Yahoo data-shape handling logic in JS
- The site's information architecture and feature set — this is a visual rebrand, not a product redesign

If the agent finds itself wanting to add features, restructure information hierarchy, or rewrite copy beyond brand voice alignment, stop and surface it for human review.
