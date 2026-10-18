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
 * Registering applications from the console.
 *
 * The property worth protecting here is that a client secret is shown exactly
 * once. The engine stores only a hash, so if the console drops it on the floor
 * the operator has no recourse except rotating -- which is a worse outcome than
 * the one they were trying to achieve.
 */
class ClientAdministrationTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $orgId = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->orgId = $this->plantOrganisation();

        $this->operator = new User;
        $this->operator->name = 'Operator';
        $this->operator->email = 'op-'.Str::random(8).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->org_id = $this->orgId;
        $this->operator->save();
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();
        $this->removePlantedEngineState();
        parent::tearDown();
    }

    public function test_creating_a_client_sends_the_operators_org_and_the_uris(): void
    {
        Http::fake(['*/admin/clients' => Http::response(
            ['client_id' => 'newapp', 'client_secret' => 'sec-123', 'type' => 'confidential'], 201
        )]);
        $this->actingAs($this->operator);

        Livewire::test(ListEngineClients::class)
            ->callAction(TestAction::make('createClient')->table(), data: [
                'client_id' => 'newapp',
                'display_name' => 'New App',
                'public' => false,
                'redirect_uris' => "https://app.test/cb\nhttps://app.test/cb2",
                'secret' => null,
            ])
            ->assertHasNoActionErrors();

        Http::assertSent(function (Request $r) {
            $d = $r->data();

            return $r->method() === 'POST'
                && $d['org_id'] === $this->orgId          // never from the form
                && $d['redirect_uris'] === ['https://app.test/cb', 'https://app.test/cb2']
                // A blank "existing secret" must be OMITTED, not sent empty --
                // an empty string would register a secret nobody chose.
                && ! array_key_exists('secret', $d);
        });
    }

    /**
     * The secret must reach the operator. A success toast with no secret in it
     * means the only copy was discarded by the console.
     */
    public function test_the_secret_is_surfaced_when_a_client_is_created(): void
    {
        Http::fake(['*/admin/clients' => Http::response(
            ['client_id' => 'newapp', 'client_secret' => 'THE-ONLY-COPY', 'type' => 'confidential'], 201
        )]);
        $this->actingAs($this->operator);

        Livewire::test(ListEngineClients::class)
            ->callAction(TestAction::make('createClient')->table(), data: [
                'client_id' => 'newapp', 'display_name' => 'New App', 'public' => false,
                'redirect_uris' => "https://app.test/cb\nhttps://app.test/cb2",
            ])
            // The TITLE, not just any toast: the failure path also notifies, so
            // a bare assertNotified() passes when the client was never created.
            ->assertNotified(__('Client created'));
    }

    public function test_rotation_is_offered_for_a_confidential_client(): void
    {
        $client = $this->plantedClient(confidential: true);
        Http::fake(['*/rotate-secret' => Http::response(
            ['client_id' => $client->client_id, 'client_secret' => 'rotated-1'], 200
        )]);
        $this->actingAs($this->operator);

        DB::transaction(function () use ($client) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            Livewire::test(ListEngineClients::class)
                ->callAction(TestAction::make('rotateSecret')->table($client))
                ->assertNotified(__('Secret rotated'));
            Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/rotate-secret'));
        });
    }

    public function test_rotation_is_hidden_for_a_public_client(): void
    {
        $client = $this->plantedClient(confidential: false);
        $this->actingAs($this->operator);

        DB::transaction(function () use ($client) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            // A public client has no secret; offering the action would hand the
            // operator a value that authenticates nothing.
            Livewire::test(ListEngineClients::class)
                ->assertActionHidden(TestAction::make('rotateSecret')->table($client));
        });
    }

    private function plantedClient(bool $confidential): EngineClient
    {
        $clientId = $this->plantClient($this->orgId, $confidential);

        return DB::transaction(function () use ($clientId) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);

            return EngineClient::query()->findOrFail($clientId);
        });
    }
}
