/**
 * #540: the prebuilt-CSS build config (the choice-1 migration; the
 * runtime compiler was frozen at the dead Play-CDN channel).
 *
 * The palette lives in palette.json (the single source of truth — the Go
 * coverage test reads it too, so a palette change without a regen fails CI).
 *
 * The fonts: the TWO templates had disjoint config blocks. The overview's
 * default stack stays Tailwind's sans (untouched); the reskin's system-ui
 * stack becomes the `font-knostic` utility (the reskin template's body
 * class changes to `font-knostic` — a deliberate, visible choice, not a
 * silent preflight inheritance).
 *
 * content: the templates + types.go (the StatusColor literal source — the
 * the build review catch: the compiler must see what the checker sees).
 */
const palette = require('./palette.json')

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['../templates/overview.gohtml', '../templates/report-reskin.gohtml', '../types.go'],
  theme: {
    extend: {
      colors: {
        navy: palette.colors.navy,
        accent: palette.colors.accent,
        knostic: palette.colors.knostic,
      },
      fontFamily: {
        'knostic': palette.fontFamily['knostic-sans'],
      },
      borderRadius: {
        'card': palette.borderRadius.card,
      },
    },
  },
  plugins: [],
}
