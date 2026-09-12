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
 *
 * THE COMPLETENESS BOUNDARY (#540 review): the coverage test and this
 * build see the SAME inputs — the test harvests every class-ish token
 * from both templates and the StatusColor literals from types.go (the
 * one Go file this content list names; class-returning methods live
 * there by contract — adding one elsewhere requires updating BOTH this
 * list and the harvester, together). A class the compiler cannot see
 * here is exactly what the checker flags RED (the template uses it, the
 * CSS lacks it) — the invariant runs in that direction. Classes built
 * DYNAMICALLY in template JS (classList/className/innerHTML assembly)
 * would be invisible to BOTH — the templates contain none today
 * (grepped); if template JS ever gains one, this list must gain its
 * extraction too.
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
