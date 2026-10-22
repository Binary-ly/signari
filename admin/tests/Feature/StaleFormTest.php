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
use Livewire\Features\SupportLockedProperties\CannotUpdateLockedPropertyException;
use Livewire\Livewire;
use Tests\Concerns\SeedsEngineState;
use Tests\TestCase;

/**
 * Two tabs, one client: a form opened before somebody else's change cannot
 * write over it.
 *
 * The engine refuses a write whose If-Match is not the configuration's current
 * version. Until October 2026 the console read that version immediately before
 * each write, so a confirmation opened before another operator's change still
 * read the new version and its write won: the client that operator had just
 * disabled was enabled again, and both were told their change succeeded.
 */
class StaleFormTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $clientId = '';

    /** Writes the fake engine accepted. */
    private int $accepted = 0;

    /**
     * The configuration version, as the engine holds it: the database's, which
     * the pages read too, so a page rendered after an accepted write carries
     * the version that write made.
     */
    private function current(): int
    {
        return (int) $this->maintenance()->selectOne('SELECT version FROM core.config_version')->version;
    }

    protected function setUp(): void
    {
        parent::setUp();

        $orgId = $this->plantOrganisation();
        $this->clientId = $this->plantClient($orgId);

        $this->operator = new User();
        $this->operator->name = 'Operator';
        $this->operator->email = 'op-'.Str::random(10).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->org_id = $orgId;
        $this->operator->save();

        // The engine's precondition: If-Match must name the current version,
        // and a write it accepts moves the version in the database, as the
        // engine's mutateIf does in the write's own transaction.
        Http::fake(function (Request $r) {
            $current = $this->current();
            if (str_ends_with($r->url(), '/admin/config-version')) {
                return Http::response(['config_version' => $current]);
            }
            if ($r->header('If-Match') !== ['"'.$current.'"']) {
                return Http::response([
                    'error' => 'precondition_failed',
                    'expected_version' => trim((string) ($r->header('If-Match')[0] ?? ''), '"'),
                    'current_version' => $current,
                ], 412);
            }
            $this->accepted++;

            return Http::response(['config_version' => (int) $this->maintenance()->selectOne(
                'UPDATE core.config_version SET version = version + 1, bumped_at = now() RETURNING version'
            )->version]);
        });
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();
        $this->removePlantedEngineState();

        parent::tearDown();
    }

    private function inOrganisation(callable $fn): void
    {
        DB::transaction(function () use ($fn) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->operator->org_id]);
            $fn(EngineClient::query()->findOrFail($this->clientId));
        });
    }

    public function test_a_confirmation_opened_before_another_change_is_refused(): void
    {
        $this->actingAs($this->operator);

        $this->inOrganisation(function (EngineClient $client) {
            // The second operator opens the confirmation first.
            $stale = Livewire::test(ListEngineClients::class)
                ->mountAction(TestAction::make('toggleEnabled')->table($client));

            // The first changes the configuration while it is open.
            Livewire::test(ListEngineClients::class)
                ->callAction(TestAction::make('toggleEnabled')->table($client))
                ->assertNotified(__('Client disabled'));
            $this->assertSame(1, $this->accepted);

            $stale->callMountedAction()->assertNotified(__('Nothing was changed'));
            $this->assertSame(1, $this->accepted,
                'the stale confirmation was written over the change made while it was open');

            // The refused page has re-rendered, so it now carries the version
            // it shows, and the same confirmation goes through: refusing
            // everything after one refusal would be a console nobody could use.
            $stale->callAction(TestAction::make('toggleEnabled')->table($client))
                ->assertNotified(__('Client disabled'));
            $this->assertSame(2, $this->accepted, 'a page rendered after the change was refused');
        });
    }

    /** The browser holds the page's state, and may not move what its write is held to. */
    public function test_the_browser_cannot_move_the_carried_version(): void
    {
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            $this->expectException(CannotUpdateLockedPropertyException::class);
            Livewire::test(ListEngineClients::class)->set('renderedConfigVersion', $this->current() + 1);
        });
    }
}
