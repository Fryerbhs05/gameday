# Component patterns

These patterns are normative. The next agent should treat the provided HTML/CSS as the canonical implementation for each component and adapt the existing site to match. All tokens referenced here are defined in `07-design-tokens.css`.

## Buttons

The system has three button variants. There is no fourth. If a button does not fit one of these three roles, the role is wrong, not the button.

### Primary — `btn-primary`

Used for the single most important action on a screen. Typically "Sync now," "Connect Yahoo," "Save settings."

```css
.btn-primary {
  background: var(--coral-500);
  color: var(--paper);
  font: 500 15px/1 var(--font-sans);
  letter-spacing: -0.01em;
  border: none;
  border-radius: 8px;
  padding: 12px 20px;
  cursor: pointer;
  transition: background 120ms ease, transform 80ms ease;
}
.btn-primary:hover { background: var(--coral-400); }
.btn-primary:active { transform: scale(0.98); }
.btn-primary:disabled { background: var(--ink-300); cursor: not-allowed; }
```

There is exactly **one** primary button per screen. If the next agent is tempted to put two, one of them is actually a secondary button.

### Secondary — `btn-secondary`

Used for supporting actions. "Cancel," "View details," "Refresh."

```css
.btn-secondary {
  background: transparent;
  color: var(--navy-700);
  font: 500 15px/1 var(--font-sans);
  border: 1px solid var(--navy-700);
  border-radius: 8px;
  padding: 11px 20px;
  cursor: pointer;
  transition: background 120ms ease, transform 80ms ease;
}
.btn-secondary:hover { background: var(--navy-700); color: var(--paper); }
.btn-secondary:active { transform: scale(0.98); }
```

### Ghost — `btn-ghost`

Used for low-emphasis tertiary actions. "Skip," "Maybe later," icon buttons.

```css
.btn-ghost {
  background: transparent;
  color: var(--ink-500);
  font: 500 14px/1 var(--font-sans);
  border: none;
  border-radius: 6px;
  padding: 8px 12px;
  cursor: pointer;
}
.btn-ghost:hover { background: var(--paper-deep); color: var(--ink-700); }
```

## Cards

The card is the primary content container.

```css
.card {
  background: var(--paper-soft);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 20px 24px;
}
.card--recessed {
  background: var(--paper-deep);
  border-color: var(--line-soft);
}
.card--accent {
  background: var(--paper-soft);
  border-left: 3px solid var(--coral-500);
  border-radius: 0 12px 12px 0;
}
```

Cards have **one** border treatment, never multiple. Do not stack a left accent border with a colored top border with a shadow. Pick one device per card.

## Score strip

The score strip is the product's signature module — it shows live scores across the user's leagues. The redesign should treat it as a horizontal row of cells, each cell representing one league, with the user's score on the left and the opponent's score on the right. Below the cells, a thin strip of player pills shows which of the user's players are currently active in that game.

```html
<div class="score-strip">
  <div class="score-cell" data-status="winning">
    <div class="score-cell__league">Wagner Memorial</div>
    <div class="score-cell__row">
      <span class="score-cell__label">You</span>
      <span class="score-cell__points">112.4</span>
    </div>
    <div class="score-cell__row">
      <span class="score-cell__label">Opp</span>
      <span class="score-cell__points score-cell__points--opp">98.7</span>
    </div>
    <div class="score-cell__divider"></div>
  </div>
  <!-- repeat per league -->
</div>
```

```css
.score-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}
.score-cell {
  background: var(--paper-soft);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 14px 16px;
  position: relative;
  overflow: hidden;
}
.score-cell__league {
  font: 500 11px/1 var(--font-sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-500);
  margin-bottom: 8px;
}
.score-cell__row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font: 500 18px/1.2 var(--font-mono);
}
.score-cell__label {
  font: 400 13px/1 var(--font-sans);
  color: var(--ink-500);
}
.score-cell__points { color: var(--navy-700); }
.score-cell__points--opp { color: var(--ink-700); }
.score-cell[data-status="winning"] .score-cell__points { color: var(--cheer); }
.score-cell[data-status="losing"] .score-cell__points { color: var(--enemy); }
.score-cell[data-status="split"] .score-cell__points { color: var(--split); }

/* The split motif: thin vertical line bisecting the cell */
.score-cell__divider {
  position: absolute;
  top: 14px;
  bottom: 14px;
  left: 50%;
  width: 1px;
  background: var(--line);
  transform: translateX(-0.5px);
}
```

The thin vertical divider is the deliberate split motif applied to this module. Every score cell has it. It is decorative-but-meaningful: it physicalizes the "your side / their side" framing.

## Player pills (status pills)

These show a player's status across the user's leagues. The four states map to the status palette.

```css
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font: 500 12px/1 var(--font-sans);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding: 5px 10px;
  border-radius: 999px;
  border: 1px solid;
}
.pill--cheer  { background: var(--cheer-soft);   color: var(--cheer);  border-color: var(--cheer); }
.pill--enemy  { background: var(--enemy-soft);   color: var(--enemy);  border-color: var(--enemy); }
.pill--split  { background: var(--split-soft);   color: var(--split);  border-color: var(--split); }
.pill--neutral{ background: var(--neutral-soft); color: var(--ink-500);border-color: var(--ink-300); }
```

The "split" pill should be visually special — it represents the brand's namesake state. Consider applying a subtle two-tone treatment:

```css
.pill--split {
  background: linear-gradient(to right, var(--cheer-soft) 50%, var(--enemy-soft) 50%);
  color: var(--ink-700);
  border-color: var(--split);
}
```

This is the **one** place gradients are allowed in the system, and only because the gradient here is functional — it shows the user is on both sides of this player. Use this treatment only on the split pill, nowhere else.

## Player buckets (sections)

The dashboard groups players into status buckets. Each bucket is a card with a colored top border that matches the status:

```css
.bucket {
  background: var(--paper-soft);
  border: 1px solid var(--line);
  border-top: 3px solid;
  border-radius: 0 0 12px 12px;
  padding: 16px 20px;
}
.bucket--cheer  { border-top-color: var(--cheer); }
.bucket--enemy  { border-top-color: var(--enemy); }
.bucket--split  { border-top-color: var(--split); }
.bucket--neutral{ border-top-color: var(--neutral); }
.bucket__title {
  font: 700 18px/1.2 var(--font-sans);
  color: var(--ink-900);
  margin-bottom: 4px;
}
.bucket__count {
  font: 500 11px/1 var(--font-sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--ink-500);
  margin-bottom: 16px;
}
```

The bucket label can use the user-facing words "Cheer for," "Root against," "Conflicted," and "Neutral." (The CSS variable is `--split` but the user-facing label is "Conflicted" — see naming note in `02-color-system.md`.)

## Header

```html
<header class="site-header">
  <div class="site-header__inner">
    <a class="site-header__brand" href="/">
      <img src="/brand-kit/logo/conflicted-wordmark-color.svg" alt="Conflicted" height="28">
    </a>
    <nav class="site-header__nav">
      <span class="site-header__week">Week 14</span>
      <button class="btn-ghost">Settings</button>
    </nav>
  </div>
</header>
```

```css
.site-header {
  background: var(--paper);
  border-bottom: 1px solid var(--line);
  height: 64px;
  position: sticky;
  top: 0;
  z-index: 100;
}
.site-header__inner {
  max-width: 980px;
  margin: 0 auto;
  padding: 0 24px;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.site-header__brand img { display: block; }
.site-header__nav { display: flex; align-items: center; gap: 16px; }
.site-header__week {
  font: 500 11px/1 var(--font-mono);
  color: var(--ink-500);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: var(--paper-deep);
  padding: 6px 10px;
  border-radius: 999px;
}
```

The header is the only place the wordmark appears in product chrome. Below the header, the brand identity is carried by the type system, the cream surface, and the navy/coral accents — not by repeated logos.

## Spacing scale

Use a 4px base. Common values: 4, 8, 12, 16, 20, 24, 32, 48, 64. Avoid arbitrary values (13px, 17px, 22px) — they make the site look unintentional.

## Border radius scale

Use these three values, no others:

- `4px` — inline elements (badges, small buttons)
- `8px` — buttons, inputs, small cards
- `12px` — cards, containers

Pills are the exception: `999px` for full pill rounding.

## What does *not* belong in this system

The next agent will probably feel an urge to add at least one of the following. Resist:

- Drop shadows on cards. The brand is flat.
- Glassmorphism, frosted glass, blur effects. No.
- Gradient backgrounds, mesh gradients, or "aesthetic" gradients on hero sections. The one allowed gradient is on the split pill, full stop.
- Decorative SVG illustrations of footballs, helmets, players, or cartoon mascots. The split motif and the type system carry the brand. Illustrations dilute it.
- Animated number counters that count up on page load. The data is not the spectacle.
- "AI-generated" or "powered by AI" badges. The product is what it is.
