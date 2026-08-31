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
use Tests\TestCase;

/**
 * The console's only write path.
 *
 * The whole architecture rests on this being an HTTP call and not an UPDATE:
 * signari_admin has no privilege on schema core (ADR-004), and only the engine's
 * Admin API bumps config_version in the same transaction as the change (ADR-008).
 * A well-meaning refactor to "just save the model" would appear to work in review
 * and fail at the database, so the assertion here is specifically that a request
 * goes to the engine.
 *
 * The engine end of this contract is covered by internal/adminapi's tests against
 * a real database; this covers the half that was missing entirely -- the service
 * existed and nothing called it.
 */
class ClientEnableDisableTest extends TestCase
{
    private ?User $operator = null;

    private array $client = [];

    protected function setUp(): void
    {
        parent::setUp();

        $org = DB::selectOne('SELECT id::text AS id FROM core_v1.organizations LIMIT 1');
        if ($org === null) {
            $this->markTestSkipped('no organisation seeded in this database');
        }

        $row = DB::transaction(function () use ($org) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $org->id]);

            return DB::selectOne('SELECT client_id, enabled FROM core_v1.clients LIMIT 1');
        });
        if ($row === null) {
            $this->markTestSkipped('no client seeded in this database');
        }
        $this->client = (array) $row;

        $this->operator = new User();
        $this->operator->name = 'Operator';
        $this->operator->email = 'op-'.Str::random(10).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->org_id = $org->id;
        $this->operator->save();

        config(['app.env' => 'testing']);
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();

        parent::tearDown();
    }

    private function record(): EngineClient
    {
        return EngineClient::query()->findOrFail($this->client['client_id']);
    }

    /**
     * The action must reach the engine, and must send the INVERSE of the client's
     * current state. Sending the current value would be a no-op that still bumps
     * config_version and still reports success.
     */
    public function test_toggling_calls_the_engine_admin_api(): void
    {
        // Two requests now, not one: the console reads the configuration
        // version and sends it as If-Match, so the write is conditional. See
        // EngineAdminApi::conditionalPatch -- the engine has accepted the
        // precondition since the admin API existed and this console sent it
        // nowhere.
        Http::fake([
            '*/admin/config-version' => Http::response(['config_version' => 41], 200),
            '*/admin/clients/*' => Http::response(['config_version' => 42], 200),
        ]);

        $this->actingAs($this->operator);

        DB::transaction(function () {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->operator->org_id]);

            $record = $this->record();

            Livewire::test(ListEngineClients::class)
                ->callAction(TestAction::make('toggleEnabled')->table($record))
                ->assertHasNoActionErrors();

            Http::assertSent(function (Request $request) use ($record) {
                return $request->method() === 'PATCH'
                    && str_ends_with($request->url(), '/admin/clients/'.$record->client_id)
                    && $request->data() === ['enabled' => ! $record->enabled];
            });
        });
    }

    /**
     * When the engine is unreachable or refuses, the operator must be told the
     * change did NOT happen. A green toast over a failed write is how someone
     * walks away believing a leaked client secret has been disabled.
     */
    public function test_a_refused_write_is_reported_as_a_failure(): void
    {
        Http::fake(['*/admin/clients/*' => Http::response(['error' => 'server_error'], 500)]);

        $this->actingAs($this->operator);

        DB::transaction(function () {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->operator->org_id]);

            Livewire::test(ListEngineClients::class)
                ->callAction(TestAction::make('toggleEnabled')->table($this->record()))
                ->assertNotified();
        });

        // And nothing was written locally -- there is no local write path to take.
        $this->assertSame(
            $this->client['enabled'],
            DB::transaction(function () {
                DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->operator->org_id]);

                return $this->record()->enabled;
            }),
            'the client changed state despite the engine refusing the write'
        );
    }
}
