<?php

namespace App\Filament\Pages;

use App\Filament\Concerns\CarriesConfigVersion;
use App\Services\EngineAdminApi;
use App\Services\SignariSignIn;
use BackedEnum;
use Filament\Actions\Action;
use Filament\Forms\Components\ColorPicker;
use Filament\Forms\Components\TextInput;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Schemas\Components\Actions;
use Filament\Schemas\Components\EmbeddedSchema;
use Filament\Schemas\Components\Form;
use Filament\Schemas\Components\Section;
use Filament\Schemas\Schema;
use Filament\Support\Icons\Heroicon;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * The operator's organisation's own appearance, over its instance's.
 *
 * Read through the view, written through the engine, which refuses a palette
 * nobody can read and says why: the check has one home, and this screen shows
 * its answer rather than repeating it.
 */
class OrganisationBrand extends Page
{
    use CarriesConfigVersion;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedPaintBrush;

    protected static ?string $slug = 'brand';

    /** @var array<string, string|null> */
    public ?array $data = [];

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
        return __('Brand');
    }

    public function getTitle(): string
    {
        return __('Brand');
    }

    public function mount(): void
    {
        $this->form->fill((array) $this->stored());
    }

    /** What the organisation has set; the policy narrows the view to it. */
    private function stored(): ?object
    {
        return DB::table('core_v1.org_brands')->select([
            'product_name', 'logo_url', 'support_url',
            'colour_primary', 'colour_on_primary', 'colour_background', 'colour_text',
        ])->first();
    }

    public function form(Schema $schema): Schema
    {
        return $schema->statePath('data')->components([
            Section::make(__('Name and links'))
                ->description(__('What you leave empty is the instance\'s.'))
                ->schema([
                    TextInput::make('product_name')->label(__('Product name'))->maxLength(60),
                    TextInput::make('logo_url')->label(__('Logo URL'))->url(),
                    TextInput::make('support_url')->label(__('Support URL'))->url(),
                ]),
            Section::make(__('Colours'))
                ->description(__('All four or none. The engine refuses a palette that cannot be read.'))
                ->columns(2)
                ->schema([
                    ColorPicker::make('colour_primary')->label(__('Buttons and links')),
                    ColorPicker::make('colour_on_primary')->label(__('Text on buttons')),
                    ColorPicker::make('colour_background')->label(__('Page background')),
                    ColorPicker::make('colour_text')->label(__('Page text')),
                ]),
        ]);
    }

    public function content(Schema $schema): Schema
    {
        return $schema->components([
            Form::make([EmbeddedSchema::make('form')])
                ->id('form')
                ->livewireSubmitHandler('save')
                ->footer([
                    Actions::make([
                        Action::make('save')->label(__('Save brand'))->submit('save')
                            ->visible(fn (): bool => SignariSignIn::may('organizations:write')),
                        Action::make('remove')->label(__('Use the instance\'s brand'))
                            ->color('gray')->requiresConfirmation()
                            ->visible(fn (): bool => SignariSignIn::may('organizations:write') && $this->stored() !== null)
                            ->action(fn () => $this->remove()),
                    ]),
                ]),
        ]);
    }

    public function save(): void
    {
        $orgId = auth()->user()?->org_id;
        if ($orgId === null) {
            Notification::make()->title(__('You are not assigned to an organisation'))->danger()->send();

            return;
        }
        $brand = array_map(fn ($value): string => (string) $value, $this->form->getState());
        try {
            EngineAdminApi::fromConfig()->asOf($this->renderedConfigVersion)->setOrganisationBrand($orgId, $brand);
        } catch (RuntimeException $e) {
            Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                ->danger()->persistent()->send();

            return;
        }
        Notification::make()->title(__('Brand saved'))->success()->send();
    }

    public function remove(): void
    {
        $orgId = auth()->user()?->org_id;
        if ($orgId === null) {
            Notification::make()->title(__('You are not assigned to an organisation'))->danger()->send();

            return;
        }
        try {
            EngineAdminApi::fromConfig()->asOf($this->renderedConfigVersion)->removeOrganisationBrand($orgId);
        } catch (RuntimeException $e) {
            Notification::make()->title(__('Nothing was changed'))->body($e->getMessage())
                ->danger()->persistent()->send();

            return;
        }
        $this->form->fill([]);
        Notification::make()->title(__('Brand removed'))->success()->send();
    }
}
