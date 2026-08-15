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
                    ->label('Applied')
                    ->dateTime()
                    ->description(fn ($record) => $record->line_count.' lines')
                    ->sortable(),

                // Whether the file closes by default is the first thing to check,
                // and it is not obvious from reading a long document. An absent
                // `default` key means allow.
                TextColumn::make('denies_by_default')
                    ->label('Default')
                    ->badge()
                    ->formatStateUsing(fn (bool $state): string => $state ? 'deny' : 'allow')
                    ->color(fn (bool $state): string => $state ? 'success' : 'warning')
                    ->tooltip('What happens to a request no rule matched. Absent means allow'),

                TextColumn::make('document')
                    ->label('Policy')
                    ->limit(90)
                    ->wrap()
                    ->tooltip('Applied verbatim with `signari policy apply`, which runs the '
                        .'document’s own tests before installing it'),
            ])
            ->paginated(false)
            ->emptyStateHeading('No access policy is in force')
            ->emptyStateDescription('Every client is open to every user. That may be correct — '
                .'if not, write one and apply it with `signari policy apply`.');
    }
}
