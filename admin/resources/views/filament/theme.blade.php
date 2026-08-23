{{--
    Console styling, to the same idiom as the engine's sign-in pages.

    A Blade view injected at HEAD_END rather than a compiled Tailwind theme,
    because a custom Filament theme needs `npm run build` and a committed
    bundle. This file is the source and there is nothing to rebuild, which
    matters for a console whose whole job is to be running when something else
    is broken.

    What is deliberately NOT here: anything that restyles a control's shape,
    spacing or states. Filament's components are close to this idiom already;
    the further an override reaches into them, the more of it silently stops
    applying at the next upgrade. Colour and type are the parts that carry the
    identity and the parts that survive.
--}}
<style>
    /*
      The one real deviation from stock Filament.

      Filament v4 renders a primary button as a TINT: `fi-bg-color-400` behind
      `fi-text-color-900`, so an indigo primary is a pale indigo button with
      dark indigo text. Laravel's own products -- and the engine's sign-in
      pages, which this console sits beside -- put the weight in a near-black
      button and keep the accent for links, rings and active navigation.

      The utility classes are (0,1,0); these are (0,3,0), so they win without
      !important. If a future Filament renames .fi-color-primary this stops
      applying and the button goes back to a tint -- visibly wrong, not subtly
      broken, which is the failure direction to prefer.
    */
    .fi-btn.fi-color-primary:not(.fi-outlined):not(.fi-link) {
        background-color: #18181b;
        color: #fff;
    }

    .fi-btn.fi-color-primary:not(.fi-outlined):not(.fi-link):hover {
        background-color: #27272a;
    }

    /*
      Inverted in dark mode: near-black on a near-black ground is a button you
      cannot see. Same move Laravel makes on its own dark screens.
    */
    .dark .fi-btn.fi-color-primary:not(.fi-outlined):not(.fi-link) {
        background-color: #fafafa;
        color: #18181b;
    }

    .dark .fi-btn.fi-color-primary:not(.fi-outlined):not(.fi-link):hover {
        background-color: #e4e4e7;
    }

    /* Icons inside the button inherit the button's text colour, or they keep
       the tinted button's accent and read as a misprint against near-black. */
    .fi-btn.fi-color-primary:not(.fi-outlined):not(.fi-link) > .fi-icon {
        color: currentColor;
    }

    /*
      Headings tighten as they grow, which is the single most recognisable
      thing about the Laravel product pages and the same value the engine's
      stylesheet uses. Body text is left alone -- tracking that helps a 24px
      heading hurts a 14px table cell.
    */
    .fi-header-heading,
    .fi-modal-heading,
    .fi-section-header-heading,
    .fi-simple-header-heading {
        letter-spacing: -0.022em;
    }
</style>
