# Color system

## Core palette

The brand pair is **deep navy + warm coral** on a **cream paper** ground. These three colors do 90% of the work. Everything else is a supporting role.

| Token | Hex | Use |
|---|---|---|
| `--navy-900` | `#0F2235` | Logo, headlines, primary text on cream |
| `--navy-700` | `#1A3A52` | Default brand navy — used in most logo applications |
| `--navy-500` | `#2B6FA8` | Hover states, links, secondary navy |
| `--navy-300` | `#7AA8D1` | Subtle accents, divider lines on dark surfaces |
| `--coral-700` | `#B0451F` | Coral on small text where contrast is needed |
| `--coral-500` | `#D85A30` | Default brand coral — primary accent, CTAs |
| `--coral-400` | `#E26538` | Hover state for coral elements |
| `--coral-200` | `#F4C4B0` | Coral fills behind text labels |
| `--paper` | `#F5EFE4` | Primary background — the "cream" surface |
| `--paper-soft` | `#FAF6EC` | Slightly lighter for layered surfaces |
| `--paper-deep` | `#EDE5D4` | Slightly darker — recessed surfaces, dividers |
| `--ink-900` | `#15181C` | Strongest text — only for headlines |
| `--ink-700` | `#2C2C2A` | Body text |
| `--ink-500` | `#5F5E5A` | Muted text, labels |
| `--ink-300` | `#A8A6A0` | Hint text, disabled states |
| `--line` | `#D8D2C4` | Default border on cream |
| `--line-soft` | `#E5DFD0` | Subtler border |

## Status palette

These map onto the existing semantic concepts in the product (rooting for, rooting against, mixed, neutral). The fantasy-status colors are deliberately *desaturated* — they live alongside the brand pair without competing with it.

| Token | Hex | Meaning |
|---|---|---|
| `--cheer` | `#3D8B5C` | "Rooting for" — your player, your league |
| `--cheer-soft` | `#D9E8DD` | Cheer fill behind labels |
| `--enemy` | `#A33D2E` | "Rooting against" — opponent's player |
| `--enemy-soft` | `#EFD5CE` | Enemy fill behind labels |
| `--split` | `#B27F1A` | "Conflicted" status — you have skin on both sides |
| `--split-soft` | `#F0E2BF` | Split fill behind labels |
| `--neutral` | `#7A7770` | "No stake" — player not on any of your rosters |
| `--neutral-soft` | `#E8E3D5` | Neutral fill behind labels |

> **Naming note:** The brand is "Conflicted." The internal status color used to be named `--conflicted` and is now `--split` to avoid the brand-name collision. The user-facing label for that bucket can remain "Conflicted" in product copy if it reads well, but the CSS variable does not.

## Semantic system colors

| Token | Hex | Use |
|---|---|---|
| `--success` | `#3D8B5C` | Same as `--cheer` — confirmations, sync-success badges |
| `--warning` | `#B27F1A` | Same as `--split` — injury questionable, soft alerts |
| `--danger` | `#A33D2E` | Same as `--enemy` — auth errors, disconnect warnings |
| `--info` | `#2B6FA8` | Same as `--navy-500` — informational notices, tooltips |

Reusing the status palette for system semantics is intentional. The product has a unified visual vocabulary: green is good news, red is bad news, gold is "pay attention," navy is informational. The user only learns one color language.

## Dark mode pairings

Dark mode is supported but is not the default. When dark mode is on:

| Light mode | Dark mode | Notes |
|---|---|---|
| `--paper` `#F5EFE4` | `#0F1B26` | Background flips to deep desaturated navy, not pure black |
| `--paper-soft` `#FAF6EC` | `#162635` | Layered surfaces |
| `--paper-deep` `#EDE5D4` | `#0A1019` | Recessed |
| `--ink-900` `#15181C` | `#F5EFE4` | Headlines flip to cream |
| `--ink-700` `#2C2C2A` | `#E0DACA` | Body text |
| `--ink-500` `#5F5E5A` | `#9E988A` | Muted |
| `--navy-700` `#1A3A52` | `#7AA8D1` | Logo navy lightens to navy-300 in dark mode |
| `--coral-500` `#D85A30` | `#E88761` | Coral lightens slightly |
| `--line` `#D8D2C4` | `#2A3949` | Borders flip to muted navy |

The full dark-mode block lives in `07-design-tokens.css`.

## Color do's

- Pair navy and coral on the same screen. They are designed to argue.
- Use cream as the canvas — never pure white. Pure white makes the brand look like a generic SaaS dashboard.
- Use the status colors *only* for status. Do not decorate cards with green or red just because they're available.
- Keep coral as the rarer of the two brand colors. Navy carries the screen; coral punctuates.

## Color don'ts

- Do not use navy and coral as a 50/50 wash on a large surface (e.g. a hero section split down the middle as a backdrop). Reserve the bisected treatment for *meaningful* split moments — the logo, status indicators, the favicon. A literal split background is too on-the-nose.
- Do not introduce a third brand-equivalent color. No purple, no teal, no electric blue. The system has navy and coral and that's the entire brand.
- Do not use gradients between navy and coral. The point of the brand is *opposition*. Blending the two erases the idea.
- Do not use coral on coral-soft, navy on navy-300, etc. for accessibility-critical text. The combination does not meet WCAG AA. Always check contrast against the surface, not the brand swatch.
- Do not bring the previous gold (`#c5a84b`) forward into the new design. It belonged to the "Game Day" identity and pulls the brand back toward gambling-floor aesthetics.

## Accessibility floor

Every text/background pair must clear WCAG AA (4.5:1 for body text, 3:1 for large text and UI components). The pairs in this document have been chosen to meet that floor. Do not invent new color combinations without checking contrast.

Pairs that pass, for quick reference:
- `--ink-900` on `--paper` ✓ (16.8:1)
- `--navy-700` on `--paper` ✓ (8.2:1)
- `--coral-500` on `--paper` ✓ for large text only — 3.6:1; do not use for body copy
- `--coral-700` on `--paper` ✓ (5.8:1) — use this when coral text is small
- `--paper` on `--navy-700` ✓ (8.2:1)
- `--paper` on `--coral-500` ✓ (3.6:1) for large text and buttons; not body copy
