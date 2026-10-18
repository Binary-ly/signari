<?php

namespace Tests\Feature;

use App\Models\LogoutDelivery;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\Concerns\SeedsEngineState;
use Tests\TestCase;

/**
 * "Did signing out actually work?" -- a question almost no identity provider can
 * answer about itself.
 *
 * A parked delivery is not a warning. It is a specific person who believes they
 * signed out of a specific application and did not, and the whole point of this
 * screen is that somebody sees it.
 */
class LogoutDeliveryTest extends TestCase
{
    use SeedsEngineState;

    private array $ids = [];

    protected function tearDown(): void
    {
        if ($this->ids !== []) {
            DB::connection('maintenance')->table('core.outbox')
                ->whereIn('id', $this->ids)->delete();
        }
        $this->removePlantedEngineState();

        parent::tearDown();
    }

    /** Runs $fn on the console's own connection inside an organisation context. */
    private function asOrg(string $orgId, callable $fn): mixed
    {
        return DB::transaction(function () use ($orgId, $fn) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $orgId]);

            return $fn();
        });
    }

    private function queue(string $clientId, int $attempts, ?string $delivered, ?string $error): int
    {
        $id = DB::connection('maintenance')->selectOne(
            'INSERT INTO core.outbox (topic, payload, attempts, delivered_at, last_error)
             VALUES (?, ?::jsonb, ?, ?::timestamptz, ?) RETURNING id',
            ['backchannel_logout', json_encode(['client_id' => $clientId, 'sid' => 'sid-'.Str::random(6)]),
             $attempts, $delivered, $error]
        )->id;
        $this->ids[] = $id;

        return $id;
    }

    public function test_delivery_states_are_distinguished(): void
    {
        // Planted through the maintenance connection; read back as the console,
        // inside its organisation, because that is the only way the product can
        // read it (ADR-004).
        $org = $this->plantOrganisation();
        $client = $this->plantClient($org);

        $delivered = $this->queue($client, 1, '2026-01-01 00:00:00+00', null);
        $pending = $this->queue($client, 2, null, 'connection refused');
        // Eight attempts is the retry budget. Past it, nobody is coming back.
        $parked = $this->queue($client, 8, null, '502 Bad Gateway');

        $rows = $this->asOrg($org, fn () => LogoutDelivery::query()
            ->whereIn('id', [$delivered, $pending, $parked])->get()->keyBy('id'));

        $this->assertSame('delivered', $rows[$delivered]->status);
        $this->assertSame('pending', $rows[$pending]->status);
        $this->assertSame('parked', $rows[$parked]->status,
            'a notice past its retry budget must be reported as parked, not left looking pending');

        $this->assertTrue($rows[$parked]->isParked());
        $this->assertSame('502 Bad Gateway', $rows[$parked]->last_error,
            'the reason must survive to the screen; "it failed" is not actionable');
    }

    /**
     * The console must not be able to rewrite delivery state. It reads what the
     * engine recorded; a console that could mark a failure delivered would make
     * the whole screen worthless.
     */
    public function test_the_console_cannot_write_delivery_state(): void
    {
        $this->expectException(\RuntimeException::class);
        (new LogoutDelivery)->save();
    }

    /**
     * Another tenant's deliveries must be invisible, and so must deliveries with
     * no organisation context at all.
     *
     * core.outbox carries no org_id, so the view takes its tenant from the
     * client. When it LEFT JOINed core.clients, a row whose client was hidden by
     * row-level security still came through -- client id, session id, user id
     * and error intact, only the organisation columns blanked -- so every
     * tenant's sign-outs were readable from any console session.
     */
    public function test_another_tenants_deliveries_are_invisible(): void
    {
        $org = $this->plantOrganisation();
        $mine = $this->queue($this->plantClient($org), 8, null, 'mine');

        $other = $this->plantOrganisation();
        $theirs = $this->queue($this->plantClient($other), 8, null, 'theirs');

        $visible = $this->asOrg($org, fn () => LogoutDelivery::query()
            ->whereIn('id', [$mine, $theirs])->pluck('id')->all());
        $this->assertSame([$mine], $visible, 'another organisation\'s logout delivery is visible');

        $unscoped = LogoutDelivery::query()->whereIn('id', [$mine, $theirs])->count();
        $this->assertSame(0, $unscoped, 'logout deliveries are visible with no organisation context');
    }

    /** The screen renders with real rows, which the empty state never proves. */
    public function test_screen_renders_with_rows(): void
    {
        $org = $this->plantOrganisation();
        $client = $this->plantClient($org);
        $this->queue($client, 8, null, 'connection refused');

        $operator = new User;
        $operator->name = 'Operator';
        $operator->email = 'op-'.Str::random(8).'@example.test';
        $operator->password = bcrypt('irrelevant');
        $operator->org_id = $org;
        $this->enrol($operator)->save();

        try {
            $this->actingAs($operator)->get('/admin/logout-deliveries')
                ->assertOk()
                ->assertSee('connection refused');
        } finally {
            $operator->delete();
        }
    }
}
