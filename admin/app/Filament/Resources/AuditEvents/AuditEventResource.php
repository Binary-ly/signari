<?php

namespace App\Filament\Resources\AuditEvents;

use App\Filament\Resources\AuditEvents\Pages\ListAuditEvents;
use App\Filament\Resources\ReadOnlyResource;
use App\Models\AuditEvent;
use BackedEnum;
use Filament\Support\Icons\Heroicon;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

/**
 * The organisation's trail. Read only, and with no search over the detail: a screen
 * that scanned a trail of millions on a keystroke would be the slowest thing here.
 */
class AuditEventResource extends ReadOnlyResource
{
    protected static string $readScope = 'audit:read';

    protected static ?string $model = AuditEvent::class;

    protected static string|BackedEnum|null $navigationIcon = Heroicon::OutlinedClipboardDocumentList;

    public static function getNavigationGroup(): ?string
    {
        return __('Activity');
    }

    public static function getNavigationLabel(): string
    {
        return __('Audit trail');
    }

    public static function getModelLabel(): string
    {
        return __('audit event');
    }

    public static function getPluralModelLabel(): string
    {
        return __('Audit trail');
    }

    public static function table(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('occurred_at')->label(__('When'))->dateTime(),
                TextColumn::make('event_type')->label(__('What'))->badge(),
                TextColumn::make('subject_id')->label(__('About'))->placeholder('—'),
                TextColumn::make('client_id')->label(__('Client'))->placeholder('—'),
                TextColumn::make('correlation_id')->label(__('Request'))->placeholder('—')
                    ->toggleable(isToggledHiddenByDefault: true),
            ])
            ->defaultSort('id', 'desc')
            ->emptyStateHeading(__('Nothing recorded yet'));
    }

    public static function getPages(): array
    {
        return ['index' => ListAuditEvents::route('/')];
    }
}
