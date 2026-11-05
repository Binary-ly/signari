# Filament's views, copied to carry a nonce

These three views are Filament's, from `filament/filament` and `filament/support`
4.15.2, with one change: each `<script>` has `nonce="{{ … Vite::cspNonce() }}"`.
Laravel serves a view here in place of the package's own.

| Here | Filament's original, under `vendor/filament/` |
|---|---|
| `filament-panels/components/layout/base.blade.php` | `filament/resources/views/components/layout/base.blade.php` |
| `filament-panels/livewire/sidebar.blade.php` | `filament/resources/views/livewire/sidebar.blade.php` |
| `filament/assets.blade.php` | `support/resources/views/assets.blade.php` |

**Why.** The console's content policy runs an inline script only when it
carries the response's nonce (`app/Http/Middleware/SecurityHeaders.php`), so a
script injected into a screen does not run. Filament writes these seven scripts
with no way to give them one.

**Keeping them in step.** `ConsoleHardeningTest::test_the_copied_filament_views_are_their_originals_with_the_nonce`
fails when an original differs from its copy with the nonces taken out. After a
Filament upgrade that changes one, copy the new original here and add the nonce
to each `<script>` again; change nothing else.

**Licence.** Filament is MIT-licensed, as its `composer.json` declares. The
notice and copyright are in its repository, https://github.com/filamentphp/filament.
