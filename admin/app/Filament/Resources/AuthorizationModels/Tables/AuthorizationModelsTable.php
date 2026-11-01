<?php

namespace App\Filament\Resources\AuthorizationModels\Tables;

use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Table;

class AuthorizationModelsTable
{
    public static function configure(Table $table): Table
    {
        return $table
            ->columns([
                TextColumn::make('updated_at')
                    ->label(__('Set'))
                    ->dateTime()
                    ->description(fn ($record) => trans_choice('{1}:count line|[2,*]:count lines', (int) $record->line_count, ['count' => (int) $record->line_count]))
                    ->sortable(),

                TextColumn::make('source')
                    ->label(__('Model'))
                    ->limit(90)
                    ->wrap()
                    ->tooltip(__('Set verbatim with `signari authz set-model`, which runs its own tests first')),
            ])
            ->paginated(false)
            ->emptyStateHeading(__('No authorization model is set'))
            ->emptyStateDescription(__('Nothing is permitted: every question an application asks is answered no, and an application with no way to tell that from a refusal cannot say why.'));
    }
}
