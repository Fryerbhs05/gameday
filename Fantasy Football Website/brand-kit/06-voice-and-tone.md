# Voice and tone

## Voice (constant)

Conflicted's voice is **direct, dry, and assumes you know what you're doing.** It does not over-explain fantasy football concepts. It does not cheer the user on. It does not apologize for itself. It speaks the way a sharp friend who runs four leagues would speak — short sentences, real terminology, occasional dry humor, no exclamation points.

A voice test: read any line of UI copy out loud. Does it sound like a person with a wry sense of humor talking to a peer? Or does it sound like an app trying to be friendly? If the latter, rewrite.

## Tone (varies by context)

Tone bends slightly across surfaces:

| Surface | Tone | Example |
|---|---|---|
| Marketing hero | Confident, slightly knowing | "Three leagues. One Sunday. We'll tell you who to root for." |
| Onboarding | Practical, brisk | "Connect your Yahoo account to pull in your leagues. We don't store your credentials." |
| Empty states | Dry, never cute | "No games today. Check back Sunday." |
| Errors | Honest, takes responsibility | "Yahoo's API isn't responding. We'll keep trying." |
| Success confirmations | Understated | "Synced. Last update 2 seconds ago." |

## Words and phrases to use

- "Your guys" / "the enemy's guys" — colloquial, fantasy-vernacular
- "On both sides" — for split-status players
- "League" not "fantasy team" or "fantasy league" — context already clear
- "Sync" not "refresh data" — shorter, more direct
- "Week 14" not "Current week"
- "Connect your Yahoo account" not "Sign in with Yahoo" — emphasizes data integration
- "Live" for in-game data
- "Locked" for players who have already played

## Words and phrases to avoid

- "Welcome back!" — generic SaaS greeting
- "Let's get started" / "Let's go!" — false energy
- "Your fantasy journey" — corporate
- "Powered by AI" / "Smart insights" — buzzword bait
- "Rooting interest" or "vested interest" — too formal; just say "your guys"
- "Game day" — old brand name; do not appear anywhere
- "Crushing it," "ballin'," "dub," "W" — sportscaster slang doesn't fit
- Exclamation points — use exactly zero in product UI. One is allowed in marketing copy if the line genuinely warrants it (almost never)
- Emoji in UI copy. Allowed sparingly in marketing/social only.

## Tagline options

The wordmark logo includes the tagline "ALL YOUR LEAGUES, ONE PLACE." Other approved short-form taglines for use on the site, in metadata, and in marketing:

- All your leagues, one place. *(provided in logo, descriptive)*
- Know who to root for. *(carries over from "Game Day," still works)*
- Fantasy football for the over-invested. *(target-audience honest)*
- Three leagues. One Sunday. *(rhythmic, confident)*

The next agent should pick one for the redesigned hero section. The first option is safest; the third is the most distinctive.

## Page titles, meta descriptions, OG tags

| Element | Example |
|---|---|
| `<title>` | Conflicted — Know who to root for |
| `<meta name="description">` | Conflicted tracks every player across every fantasy league you run, so you know who to cheer for in real time. |
| OG title | Conflicted |
| OG description | Same as meta description |
| OG image | A 1200×630 cream-background image with the wordmark centered, no other ornament |

Update these when implementing the rebrand. The current `<title>` is "Game Day — Know Who To Root For" and needs to be changed.

## Microcopy bank

A small bank of pre-approved microcopy the next agent can use as-is, so voice doesn't drift:

- Sync button (idle): "Sync"
- Sync button (working): "Syncing…"
- Sync confirmation: "Synced 2s ago" (use JetBrains Mono for the duration)
- Disconnect Yahoo: "Disconnect Yahoo"
- Disconnect confirmation modal title: "Disconnect Yahoo?"
- Disconnect confirmation modal body: "We'll forget your token and stop pulling league data. You can reconnect anytime."
- Loading state: "Pulling your leagues."
- Empty leagues: "No leagues found in your Yahoo account."
- Empty live data: "Nothing live right now."
- Generic error: "Something went wrong on our end. Refreshing usually fixes it."
- Auth error: "Your Yahoo session expired. Reconnect to keep going."
