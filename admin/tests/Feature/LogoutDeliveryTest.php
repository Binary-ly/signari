<?php

namespace Tests\Feature;

use App\Models\LogoutDelivery;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
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
    private array $ids = [];

    protected function tearDown(): void
    {
        if ($this->ids !== []) {
            DB::connection('maintenance')->table('core.outbox')
                ->whereIn('id', $this->ids)->delete();
        }

        parent::tearDown();
    }

    /** A client id, read with the boundary respected. */
    private function seededClient(): ?string
    {
        return DB::connection('maintenance')
            ->selectOne('SELECT client_id FROM core.clients LIMIT 1')?->client_id;
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
        // Read through the MAINTENANCE role, not as the console. The admin has no
        // privilege on schema core (ADR-004) -- reaching past core_v1 in a test
        // would be testing something the product cannot do.
        $client = $this->seededClient();
        if ($client === null) {
            $this->markTestSkipped('no seeded client');
        }

        $delivered = $this->queue($client, 1, '2026-01-01 00:00:00+00', null);
        $pending = $this->queue($client, 2, null, 'connection refused');
        // Eight attempts is the retry budget. Past it, nobody is coming back.
        $parked = $this->queue($client, 8, null, '502 Bad Gateway');

        $rows = LogoutDelivery::query()->whereIn('id', [$delivered, $pending, $parked])
            ->get()->keyBy('id');

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

    /** The screen renders with real rows, which the empty state never proves. */
    public function test_screen_renders_with_rows(): void
    {
        $org = DB::selectOne('SELECT id::text AS id FROM core_v1.organizations LIMIT 1');
        $client = $this->seededClient();
        if ($org === null || $client === null) {
            $this->markTestSkipped('no seeded org or client');
        }
        $this->queue($client, 8, null, 'connection refused');

        $operator = new User;
        $operator->name = 'Operator';
        $operator->email = 'op-'.Str::random(8).'@example.test';
        $operator->password = bcrypt('irrelevant');
        $operator->org_id = $org->id;
        $operator->save();

        try {
            $this->actingAs($operator)->get('/admin/logout-deliveries')->assertOk();
        } finally {
            $operator->delete();
        }
    }
}
