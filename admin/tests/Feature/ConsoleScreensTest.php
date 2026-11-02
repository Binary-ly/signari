<?php

namespace Tests\Feature;

use App\Filament\Pages\SignInJourneys;
use App\Filament\Resources\EngineUsers\Pages\ListEngineUsers;
use App\Filament\Resources\Groups\Pages\ListGroups;
use App\Filament\Resources\Sessions\Pages\ListSessions;
use App\Models\EngineSession;
use App\Models\EngineUser;
use App\Models\Group;
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
 * The screens over what used to take a shell: each with a real row in it, because
 * an empty list evaluates no column at all, and each under the tenant boundary.
 * Their writes go through the engine, held to what the page showed.
 */
class ConsoleScreensTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $orgId = '';

    private string $userId = '';

    private string $sid = '';

    private string $groupId = '';

    private const SCREENS = [
        '/admin/scopes' => 'console.scope',
        '/admin/claim-mappers' => 'console_claim',
        '/admin/attributes' => 'console_attribute',
        '/admin/directories' => 'console-directory',
        '/admin/scim-sources' => 'console-scim',
    ];

    private function plantScreens(string $orgId, string $suffix = ''): void
    {
        $db = $this->maintenance();
        $db->insert('INSERT INTO core.scopes (org_id, name) VALUES (?::uuid, ?)', [$orgId, 'console.scope'.$suffix]);
        $attribute = $db->selectOne(
            'INSERT INTO core.user_attribute_schema (org_id, name) VALUES (?::uuid, ?) RETURNING id::text AS id',
            [$orgId, 'console_attribute'.$suffix]
        )->id;
        $db->insert(
            "INSERT INTO core.claim_mappers (org_id, attribute_id, claim_name, destination)
             VALUES (?::uuid, ?::uuid, ?, 'id_token')",
            [$orgId, $attribute, 'console_claim'.$suffix]
        );
        $db->insert(
            "INSERT INTO core.directory_sources (org_id, kind, slug, display_name, credentials_enc, on_missing, dry_run)
             VALUES (?::uuid, 'google', ?, 'Dir', '\\x00'::bytea, 'deactivate', true)",
            [$orgId, 'console-directory'.$suffix]
        );
        $db->insert(
            "INSERT INTO core.scim_sources (org_id, slug, display_name, token_hash, on_delete)
             VALUES (?::uuid, ?, 'Scim', '\\x00'::bytea, 'deactivate')",
            [$orgId, 'console-scim'.$suffix]
        );
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->orgId = $this->plantOrganisation();
        $this->userId = $this->plantUser($this->orgId);
        $this->sid = 'console-'.Str::random(16);
        $this->maintenance()->insert(
            "INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after)
             VALUES (?, ?::uuid, ?::uuid, now(), now() + interval '1 hour')",
            [$this->sid, $this->orgId, $this->userId]
        );
        $this->groupId = $this->maintenance()->selectOne(
            "INSERT INTO core.groups (org_id, name, display_name) VALUES (?::uuid, 'console-group', 'Console group')
             RETURNING id::text AS id",
            [$this->orgId]
        )->id;
        $this->plantScreens($this->orgId);

        $this->operator = new User;
        $this->operator->name = 'Operator';
        $this->operator->email = 'op-'.Str::random(10).'@example.test';
        $this->operator->password = bcrypt('irrelevant');
        $this->operator->org_id = $this->orgId;
        $this->enrol($this->operator)->save();
    }

    protected function tearDown(): void
    {
        $this->operator?->delete();
        $this->maintenance()->delete('DELETE FROM core.sessions WHERE sid = ?', [$this->sid]);
        $this->removePlantedEngineState();
        parent::tearDown();
    }

    private function inOrganisation(callable $fn): void
    {
        DB::transaction(function () use ($fn) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            $fn();
        });
    }

    public function test_each_screen_shows_this_organisations_rows_and_no_others(): void
    {
        $other = $this->plantOrganisation();
        $this->plantScreens($other, 'other');

        foreach (self::SCREENS as $screen => $row) {
            $this->actingAs($this->operator)->get($screen)->assertOk()
                ->assertSee($row)->assertDontSee($row.'other');
        }
        foreach (['/admin/sessions', '/admin/audit-events'] as $screen) {
            $this->actingAs($this->operator)->get($screen)->assertOk();
        }
    }

    public function test_no_credential_is_a_column_of_what_the_console_reads(): void
    {
        $columns = fn (string $view): array => array_column(DB::select(
            "SELECT column_name FROM information_schema.columns WHERE table_schema = 'core_v1' AND table_name = ?",
            [$view]
        ), 'column_name');

        $this->assertNotContains('credentials_enc', $columns('directory_sources'));
        $this->assertNotContains('token_hash', $columns('scim_sources'));
    }

    public function test_ending_a_session_goes_through_the_engine(): void
    {
        Http::fake(['*/admin/sessions/*' => Http::response(['config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            Livewire::test(ListSessions::class)
                ->callAction(TestAction::make('end')->table(EngineSession::query()->findOrFail($this->sid)))
                ->assertNotified(__('Session ended'));
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'DELETE'
            && str_ends_with($request->url(), '/admin/sessions/'.$this->sid) && $request->hasHeader('If-Match'));
    }

    public function test_a_member_is_found_among_this_organisations_people_alone(): void
    {
        Http::fake(['*/admin/groups/*' => Http::response(['config_version' => 1], 200)]);
        $stranger = $this->plantUser($this->plantOrganisation());
        $theirs = (string) $this->maintenance()->selectOne('SELECT email FROM core.users WHERE id = ?::uuid', [$stranger])->email;
        $ours = (string) $this->maintenance()->selectOne('SELECT email FROM core.users WHERE id = ?::uuid', [$this->userId])->email;
        $this->actingAs($this->operator);

        $this->inOrganisation(function () use ($theirs, $ours) {
            $group = Group::query()->findOrFail($this->groupId);
            Livewire::test(ListGroups::class)
                ->callAction(TestAction::make('addMember')->table($group), ['email' => $theirs])
                ->assertNotified(__('Nobody here has that address'));
            Http::assertNothingSent();

            Livewire::test(ListGroups::class)
                ->callAction(TestAction::make('addMember')->table($group), ['email' => $ours])
                ->assertNotified(__('Member added'));
            Livewire::test(ListGroups::class)
                ->callAction(TestAction::make('removeMember')->table($group), ['email' => $ours])
                ->assertNotified(__('Member removed'));
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'PUT'
            && str_ends_with($request->url(), "/admin/groups/{$this->groupId}/members/{$this->userId}"));
        Http::assertSent(fn (Request $request) => $request->method() === 'DELETE'
            && str_ends_with($request->url(), "/admin/groups/{$this->groupId}/members/{$this->userId}"));
    }

    public function test_erasing_asks_for_the_address_and_goes_through_the_engine(): void
    {
        Http::fake(['*/admin/subjects/*' => Http::response(['config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            $person = EngineUser::query()->findOrFail($this->userId);
            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('erase')->table($person), ['confirm' => 'somebody-else@example.test'])
                ->assertNotified(__('Nothing was changed'));
            Http::assertNothingSent();

            Livewire::test(ListEngineUsers::class)
                ->callAction(TestAction::make('erase')->table($person), ['confirm' => $person->email])
                ->assertNotified(__('Person erased'));
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'POST'
            && str_ends_with($request->url(), "/admin/subjects/{$this->userId}/erase")
            && $request['confirm_subject_id'] === $this->userId);
    }

    public function test_the_journeys_are_the_engines_own(): void
    {
        Http::fake(['*/sign-in-flow/paths' => Http::response(['org_id' => $this->orgId, 'applied' => false, 'flows' => [
            ['name' => 'login', 'on' => 'authentication', 'paths' => [
                ['stages' => ['password', 'totp'], 'when' => ['has_totp']],
                ['stages' => ['password'], 'when' => []],
            ]],
        ]], 200)]);
        $this->actingAs($this->operator);

        Livewire::test(SignInJourneys::class)
            ->assertSee('password → totp')->assertSee('has_totp');
    }
}
