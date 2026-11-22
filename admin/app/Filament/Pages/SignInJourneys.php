<?php

namespace App\Filament\Pages;

use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Pages\Page;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Components\Text;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use RuntimeException;

/**
 * Every journey the organisation's sign-in flow can take, read-only, as the
 * engine's own walker finds them, so what this says is what happens.
 */
class SignInJourneys extends Page
{
    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedArrowPath;

    protected static ?string $slug = 'sign-in-journeys';

    public static function canAccess(): bool
    {
        return SignariSignIn::may('config:read');
    }

    public static function getNavigationGroup(): ?string
    {
        return __('Configuration');
    }

    public static function getNavigationLabel(): string
    {
        return __('Sign-in journeys');
    }

    public function getTitle(): string
    {
        return __('Sign-in journeys');
    }

    public function content(Schema $schema): Schema
    {
        $orgId = auth()->user()?->org_id;
        if ($orgId === null) {
            return $schema->components([Text::make(__('You are not assigned to an organisation'))]);
        }
        try {
            $flows = EngineAdminApi::fromConfig()->signInFlowPaths($orgId);
        } catch (RuntimeException $e) {
            return $schema->components([Text::make($e->getMessage())]);
        }

        $sections = [];
        if (! ($flows['applied'] ?? false)) {
            $sections[] = Text::make(__('This organisation has no flow of its own, so these are the built-in journeys.'));
        }
        foreach ($flows['flows'] ?? [] as $flow) {
            $sections[] = Section::make((string) $flow['name'])
                ->description((string) $flow['on'])
                ->schema(array_map(fn (array $path) => Text::make(
                    implode(' → ', $path['stages']).
                    ($path['when'] === [] ? '' : '   ('.__('when').' '.implode(', ', $path['when']).')')
                ), $flow['paths']));
        }

        return $schema->components($sections);
    }
}
