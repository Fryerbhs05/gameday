# Logo usage

The brand has two marks: the **wordmark** (full "CONFLICTED" lockup) and the **C-mark** (a single bisected C used as a monogram). Both files live in `logo/`.

## When to use which

| Surface | Mark | File |
|---|---|---|
| Site header (desktop, ≥ 200px wide for logo area) | Wordmark | `logo/conflicted-wordmark-color.svg` |
| Site header (mobile, < 200px wide for logo area) | C-mark | `logo/conflicted-mark-color.svg` |
| Browser favicon, app icon | Favicon variant | `logo/conflicted-favicon.svg` |
| Page footer | Wordmark or C-mark depending on space | either |
| Social share image (1200×630) | Wordmark, large, on cream | `logo/conflicted-wordmark-color.svg` |
| Loading state, splash screen | C-mark | `logo/conflicted-mark-color.svg` |
| Single-color contexts (print, email) | Mono variant | `logo/*-mono-*.svg` |
| Dark backgrounds | Dark-bg variant | `logo/conflicted-wordmark-dark.svg` |

## File reference

```
logo/
├── conflicted-wordmark-color.svg          Primary wordmark, navy + coral, on cream/light bg
├── conflicted-wordmark-dark.svg           Wordmark for dark backgrounds (lighter navy + coral)
├── conflicted-wordmark-mono-dark.svg      Single-color navy wordmark, for light bgs (print, email)
├── conflicted-wordmark-mono-light.svg     Single-color cream wordmark, for dark bgs
├── conflicted-mark-color.svg              The C-mark, navy + coral
├── conflicted-mark-mono-dark.svg          Single-color navy C-mark
├── conflicted-mark-mono-light.svg         Single-color cream C-mark
└── conflicted-favicon.svg                 Favicon-optimized C-mark (32×32 viewBox)
```

## Clear space

The minimum clear space around the wordmark is the **height of the letter "C"** in the wordmark. Nothing — no other graphics, no headlines, no UI chrome — may enter that area on any side.

For the C-mark, the minimum clear space is **half the height of the mark**.

## Minimum sizes

| Mark | Minimum size | Notes |
|---|---|---|
| Wordmark | 120px wide | Below this, the split divider line gets visually noisy |
| C-mark | 24px wide | Below this, switch to the favicon-optimized variant |
| Favicon variant | 16px wide | Optimized for small-size legibility |

## What not to do

The next agent should never:

- Recolor the logo. The brand pair is navy + coral, period. Do not produce green, purple, or alternate-color variants. Use the mono variants when a single color is required.
- Stretch, skew, or rotate either mark.
- Add a drop shadow, glow, gradient, or outer stroke to either mark.
- Place the wordmark over a photograph or busy texture. Both marks live on solid surfaces only.
- Recreate the logo in HTML/CSS or as inline `<text>` elements in a fresh SVG. The provided SVG files are the canonical assets. Use `<img src>` or inline-include the provided file. Do not retype the wordmark in code.
- Crop the wordmark to "CONF" or "C/D" for design effect. The wordmark is the full word.
- Animate the wordmark on page load with letters appearing sequentially or fading in. The brand is unbothered, not theatrical.
- Use the wordmark and C-mark together, side by side, in the same lockup. Pick one per surface.

## Approved size variants for the wordmark

The wordmark's tagline ("ALL YOUR LEAGUES, ONE PLACE") is appropriate at large sizes (≥ 280px wide) and should be omitted at smaller sizes. The provided `conflicted-wordmark-color.svg` includes the tagline; for headers and tight spaces, use a tagline-stripped version that the next agent can produce by deleting the tagline `<text>` element from the SVG (the file is structured for this — the tagline is a single editable element).

## A note on the C-mark and the favicon

The C-mark is two C-shaped arcs facing each other, one navy and one coral, with a small gap between them. At browser-favicon size (16px and 32px), the gap closes too much to read. The `conflicted-favicon.svg` file is optimized for that size: thicker strokes, slightly wider gap, simpler geometry. Use it for `<link rel="icon">` and for any context smaller than 24px. Do not downscale the regular C-mark for favicon use.
