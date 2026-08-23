<?php

namespace App\Filament\Resources\AccessPolicies\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class AccessPoliciesTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('applied_at')
                    ->label(__('Applied'))
                    ->dateTime()
                    ->description(fn ($record) => trans_choice('{1}:count line|[2,*]:count lines', $record->line_count, ['count' => $record->line_count]))
                    ->sortable(),

                // Whether the file closes by default is the first thing to check,
                // and it is not obvious from reading a long document. An absent
                // `default` key means allow.
                TextColumn::make('denies_by_default')
                    ->label(__('Default'))
                    ->badge()
                    ->formatStateUsing(fn (bool $state): string => $state ? __('deny') : __('allow'))
                    ->color(fn (bool $state): string => $state ? 'success' : 'warning')
                    ->tooltip(__('What happens to a request no rule matched. Absent means allow')),

                TextColumn::make('document')
                    ->label(__('Policy'))
                    ->limit(90)
                    ->wrap()
                    ->tooltip(__('Applied verbatim with `signari policy apply`, which runs the document’s own tests before installing it')),
            ])
            ->paginated(false)
            ->emptyStateHeading(__('No access policy is in force'))
            ->emptyStateDescription(__('Every client is open to every user. That may be correct — if not, write one and apply it with `signari policy apply`.'));
    }
}
