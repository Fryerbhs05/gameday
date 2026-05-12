# Typography

## Typeface system

The brand uses a two-typeface system. Inter does the headlines and the UI. JetBrains Mono does the data.

| Role | Family | Weights used | Why |
|---|---|---|---|
| Display, UI, body | **Inter** | 400, 500, 700, 800, 900 | Highly legible at every size, generous weight range, neutral character. The 800/900 weights give the wordmark its display personality without needing a custom display face. |
| Numbers, stats, scoreboards, timestamps | **JetBrains Mono** | 400, 500 | Fixed-width so columns of stats align cleanly. Has a slightly humanist character that pairs with Inter rather than fighting it. |

Both are open source on Google Fonts. Load via:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
```

> **The previous fonts** (Barlow Condensed, IBM Plex Mono) should be removed entirely. Barlow Condensed in particular reads as broadcast-sports, which is the aesthetic we are deliberately moving away from.

## Type scale

| Class | Size | Weight | Line-height | Use |
|---|---|---|---|---|
| `t-display` | 56px | 900 | 1.0 | Logo wordmark only |
| `t-h1` | 36px | 800 | 1.1 | Page-defining headline (rare — once per page) |
| `t-h2` | 24px | 700 | 1.2 | Section headers |
| `t-h3` | 18px | 700 | 1.3 | Card titles, subsection headers |
| `t-body` | 15px | 400 | 1.55 | Default body copy |
| `t-body-strong` | 15px | 500 | 1.55 | Emphasized inline text |
| `t-small` | 13px | 400 | 1.5 | Secondary copy, captions |
| `t-micro` | 11px | 500 | 1.4 | Labels, badges, eyebrow text — usually tracked +0.08em |
| `t-stat-xl` | 28px | 500 | 1.0 | Hero stat number (JetBrains Mono) |
| `t-stat` | 18px | 500 | 1.1 | Inline stat number (JetBrains Mono) |
| `t-stat-sm` | 13px | 400 | 1.2 | Small stat / timestamp (JetBrains Mono) |

Sizes step by ~1.4× from one level to the next, which is wide enough that the hierarchy reads at a glance.

## Weight rules

- **400** — body copy, never headlines
- **500** — emphasized body, button labels, stats
- **700** — section and card headers
- **800** — page-level headlines
- **900** — logo wordmark only. Do not use 900 anywhere else in the UI.

The reason to keep 900 reserved: when the logo is the only place this weight appears, the wordmark has visual exclusivity. Sprinkling 900 into headlines flattens that.

## Tracking and case

- Body copy: default tracking
- Headlines (h1, h2, h3): tighten to `letter-spacing: -0.01em` — Inter looks better tightened slightly at large sizes
- Logo wordmark: `letter-spacing: -0.04em` — tight, dense, monumental
- Eyebrow / micro labels: `letter-spacing: 0.08em` and `text-transform: uppercase` — the only place uppercase is allowed
- Body / sentences: sentence case throughout. Never title case.

## Pairing rules between Inter and JetBrains Mono

- Inline a JetBrains Mono stat inside an Inter sentence by sizing the mono one step smaller and using weight 500. Example: "He scored <span class="t-stat">22.4</span> points last week."
- Score strips and stat tables should use JetBrains Mono throughout — column alignment is the entire reason this font is in the system.
- Player names use Inter (proper nouns are not data). Player stats use JetBrains Mono.
- Timestamps, week numbers, kickoff times, and clock counters use JetBrains Mono.

## Things to avoid

- Do not use italic. Inter italic and JetBrains Mono italic both look weak in this system. If emphasis is needed, use weight 500.
- Do not use underline for emphasis. Underline is reserved for actual links, and even then prefer a colored treatment over an underline at default state.
- Do not center-align body copy. Headlines occasionally yes (hero section only), body copy never.
- Do not use type smaller than 11px anywhere. If something does not deserve 11px, it does not deserve to be on the page.
