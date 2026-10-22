<?php

namespace Tests\Feature;

use App\Filament\Resources\EngineClients\Pages\ListEngineClients;
use App\Models\EngineClient;
use App\Models\User;
use Filament\Actions\Testing\TestAction;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Tests\Concerns\SeedsEngineState;
use Tests\TestCase;

/**
 * Two people on the console's one token are two actors in the engine's trail.
 *
 * Every write names its signed-in user in Signari-Operator, which the engine
 * records on each audit record the request makes beside the token. Until
 * October 2026 the console sent nothing, so every change anybody made through
 * it was the console token's, and an investigation could not say who.
 */
class OperatorAttributionTest extends TestCase
{
    use SeedsEngineState;

    /** @var list<User> */
    private array $operators = [];

    private string $clientId = '';

    protected function setUp(): void
    {
        parent::setUp();

        $orgId = $this->plantOrganisation();
        $this->clientId = $this->plantClient($orgId);
        foreach (['First', 'Second'] as $name) {
            $u = new User();
            $u->name = $name;
            $u->email = 'op-'.Str::random(10).'@example.test';
            $u->password = bcrypt('irrelevant');
            $u->org_id = $orgId;
            $u->save();
            $this->operators[] = $u;
        }
        Http::fake(['*/admin/clients/*' => Http::response(['config_version' => 1])]);
    }

    protected function tearDown(): void
    {
        foreach ($this->operators as $u) {
            $u->delete();
        }
        $this->removePlantedEngineState();

        parent::tearDown();
    }

    public function test_each_operator_is_named_on_their_own_write(): void
    {
        foreach ($this->operators as $operator) {
            $this->actingAs($operator);
            DB::transaction(function () use ($operator) {
                DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $operator->org_id]);
                Livewire::test(ListEngineClients::class)
                    ->callAction(TestAction::make('toggleEnabled')
                        ->table(EngineClient::query()->findOrFail($this->clientId)))
                    ->assertHasNoActionErrors();
            });
        }

        foreach ($this->operators as $operator) {
            Http::assertSent(fn (Request $r) => str_contains($r->url(), '/admin/clients/')
                && $r->header('Signari-Operator') === ['console-user:'.$operator->id]);
        }
        // Never the address: the engine refuses one, and the trail keeps it forever.
        Http::assertNotSent(fn (Request $r) => str_contains(implode(',', $r->header('Signari-Operator')), '@'));
    }
}
