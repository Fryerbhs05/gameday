# Redesign priorities

Sequenced work plan for the Claude design agent. Do these in order. Do not skip ahead — each step assumes the prior one is complete.

## Phase 1 — foundation (must finish before anything else)

1. **Add the Google Fonts link** for Inter (400/500/700/800/900) and JetBrains Mono (400/500) to `<head>`. Remove the existing Barlow Condensed and IBM Plex Mono link.
2. **Replace the entire `:root` token block** in `index.html` with the contents of `07-design-tokens.css`. Delete every old token (`--bg`, `--gold`, `--cheer-deep`, `--enemy-deep`, `--fd`, `--fm`, etc.). The new token names do not match the old ones — the next agent must walk every CSS rule and swap variable references.
3. **Rename `--conflicted` to `--split`** everywhere it appears. Do a full-file search to make sure no stale references remain.
4. **Update the `<title>` tag** from "Game Day — Know Who To Root For" to "Conflicted — Know who to root for" (sentence case).
5. **Replace `body { background: var(--bg); }`** and friends so the page renders on cream, not on dark navy. This is the moment the site visibly flips from dark to light. After this step, expect everything to look broken — that's correct, fix it in phase 2.

## Phase 2 — chrome (header, footer, global components)

6. **Site header.** Apply the header pattern from `05-component-patterns.md`. Drop the wordmark SVG into the brand spot. Replace the current text-with-span title (`<span class="site-title">Game <span>Day</span></span>`) with `<img>`-or-inlined `logo/conflicted-wordmark-color.svg`. Remove the old gold-accented styling. Header is sticky at 64px.
7. **Buttons.** Audit every existing `.btn-gold`, `.btn-ghost`, `.btn-demo`, `.btn-live` button. Map each to one of the three new variants (`btn-primary`, `btn-secondary`, `btn-ghost`). Remove the live/pulsing-dot animation on `.btn-live` — the brand is unbothered, not theatrical. If a "live" indicator is necessary, use a static green dot.
8. **Favicon.** Add `<link rel="icon" type="image/svg+xml" href="/brand-kit/logo/conflicted-favicon.svg">`. Remove any existing favicon references.
9. **Page background and base type.** Confirm `body` uses `var(--paper)` and `var(--font-sans)` and that the cream background extends edge-to-edge.

## Phase 3 — signature modules (the score strip and player buckets)

10. **Score strip.** Reimplement using the `05-component-patterns.md` pattern. Add the thin vertical divider in each cell — this is the brand's split motif applied. Map win/loss/split status to the new status palette colors.
11. **Player buckets.** Apply the bucket pattern with the colored top border per status. Rename the gold bucket's label from "Conflicted" to whatever the product copy decides — but the *bucket itself* should be visually distinct (gold top border, possibly a subtle two-tone treatment in its pills) since it's the namesake state.
12. **Status pills.** Implement all four pill variants. Apply the two-tone gradient to the split pill specifically (this is the only place a gradient is allowed).
13. **Injury status badges (`.inj-Q`, `.inj-D`, `.inj-O`, `.inj-IR`, `.inj-SUS`).** Re-skin to use the new status palette. Q maps to split/warning, D maps to coral-500, O and IR map to enemy/danger, SUS maps to neutral.

## Phase 4 — long-tail surfaces

14. **Landing page (the marketing hero, "what is Conflicted").** Apply the new typography scale. Pick a tagline from `06-voice-and-tone.md`. Remove any "Game Day" copy.
15. **Onboarding screens / Yahoo connect flow.** Re-skin. Confirm the Yahoo OAuth consent screen's app name shows "Conflicted" not "Game Day" — this is configured in the Yahoo developer console, not in code (flag this to the human, do not attempt to change it).
16. **Empty states.** Use the microcopy bank in `06-voice-and-tone.md`. No exclamation points, no emoji.
17. **Error states.** Use the microcopy bank. The current error copy is generic "Something went wrong" — replace with the specific phrasings provided.
18. **Modals (e.g., Disconnect confirmation).** Card pattern with action buttons at bottom-right. Primary destructive action uses `--enemy` color, not `--coral-500`.

## Phase 5 — verification

19. **Search the codebase for stale strings.** Grep for "Game Day", "GameDay", "game day", "gameday" — every occurrence outside historical comments must be replaced. Also grep for old token names: `--bg`, `--gold`, `--cheer-deep`, `--enemy-deep`, `--fd`, `--fm`, `Barlow`, `IBM Plex`. Remove all.
20. **Search for the old `--conflicted` variable.** Confirm zero occurrences. Confirm `--split` exists wherever it should.
21. **Render in light mode and dark mode.** Verify both work. Verify no element is invisible in either mode (a common bug: hard-coded colors that don't flip).
22. **Verify favicon.** Check the browser tab shows the new C-mark, not a missing-image icon.
23. **Verify logo file references resolve.** If the redesign references `/brand-kit/logo/...`, confirm the path is correct relative to where `index.html` is served. If the site is served from the repo root on Vercel, paths should start with `/brand-kit/logo/...` and the `brand-kit` folder will need to be deployed alongside `index.html` — flag this to the human.
24. **Visual diff.** Take a screenshot of the redesigned site and compare side-by-side with the current site. The redesign should be unmistakably different — if it looks subtly different, something is wrong.

## What to flag for human review, not fix

The next agent should pause and surface these to Matt rather than acting on them:

- **Yahoo developer console.** The app's display name (shown to users on the OAuth consent screen) is set there, not in code. Matt needs to update it.
- **GitHub repo description and README.** If the agent is working from the deployed site only, it cannot update the repo metadata. Mention it.
- **Vercel project name.** Same — set in the Vercel dashboard, not in code.
- **Domain.** If the current production URL contains "gameday" in the hostname, that's a Vercel/DNS change Matt needs to make.
- **Any change that adds, removes, or restructures a feature.** This rebrand is visual only. If the agent finds itself thinking "while I'm here, I'll add X," stop.

## Done criteria

The redesign is complete when:

- A new visitor cannot tell the site was ever called "Game Day"
- The cream/navy/coral palette is fully applied with no leftover dark-navy/gold artifacts
- The split motif appears in the logo, the favicon, the score-strip dividers, and the split pill (minimum four occurrences)
- All copy matches the voice in `06-voice-and-tone.md`
- The site renders correctly in light and dark mode
- Every file in this `brand-kit/` folder has been used or deliberately set aside with a documented reason
