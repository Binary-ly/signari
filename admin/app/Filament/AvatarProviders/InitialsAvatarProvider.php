<?php

namespace App\Filament\AvatarProviders;

use Filament\AvatarProviders\Contracts\AvatarProvider;
use Filament\Facades\Filament;
use Filament\Support\Colors\Color;
use Filament\Support\Facades\FilamentColor;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * An operator's initials, drawn here and handed over as a data URI.
 *
 * Filament's default provider points the avatar at ui-avatars.com, with the
 * initials in the query, so every screen with a user menu told that service the
 * address of each operator, their initials, and every page they opened, which is
 * what LocalFontProvider was chosen to stop for the typeface. Same letters, same
 * colours, and no request to anybody.
 */
class InitialsAvatarProvider implements AvatarProvider
{
    public function get(Model|Authenticatable $record): string
    {
        $initials = str(Filament::getNameForDefaultAvatar($record))
            ->trim()
            ->explode(' ')
            // Leading punctuation is no initial: "[SYSTEM] Admin" is "SA".
            ->map(fn (string $word): string => mb_substr((string) preg_replace('/^[^\p{L}\p{N}]+/u', '', $word), 0, 1))
            ->filter()
            ->take(2)
            ->join('');

        $background = Color::convertToHex(FilamentColor::getColor('gray')[950] ?? Color::Gray[950]);

        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            .'<rect width="64" height="64" fill="'.htmlspecialchars($background, ENT_XML1).'"/>'
            .'<text x="32" y="32" dy=".35em" text-anchor="middle" fill="#fff" '
            .'font-family="system-ui, sans-serif" font-size="26" font-weight="600">'
            .htmlspecialchars(mb_strtoupper($initials), ENT_XML1)
            .'</text></svg>';

        return 'data:image/svg+xml;base64,'.base64_encode($svg);
    }
}
