<?php

namespace Tests\Feature;

use App\Filament\Resources\OrgMessages\Pages\ListOrgMessages;
use App\Models\OrgMessage;
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
 * What an organisation has reworded: listed from the view, under the tenant
 * boundary, and changed through the engine, which is what refuses a key nothing
 * renders.
 */
class OrgMessageTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $orgId = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->orgId = $this->plantOrganisation();
        $this->plantMessage($this->orgId, 'Welcome to Acme');

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
        $this->removePlantedEngineState();
        parent::tearDown();
    }

    private function plantMessage(string $orgId, string $body): void
    {
        $this->maintenance()->insert(
            "INSERT INTO core.org_messages (org_id, locale, key, body) VALUES (?::uuid, 'en', 'login.heading', ?)",
            [$orgId, $body]
        );
    }

    private function inOrganisation(callable $fn): void
    {
        DB::transaction(function () use ($fn) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            $fn();
        });
    }

    public function test_the_screen_shows_only_this_organisations_words(): void
    {
        $other = $this->plantOrganisation();
        $this->plantMessage($other, 'Welcome to Bravo');

        $this->actingAs($this->operator)->get('/admin/org-messages')
            ->assertOk()->assertSee('Welcome to Acme')->assertDontSee('Welcome to Bravo');
    }

    public function test_rewording_goes_through_the_engine_held_to_what_was_shown(): void
    {
        Http::fake(['*/admin/organizations/*/messages/*' => Http::response(['config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            Livewire::test(ListOrgMessages::class)
                ->callAction(TestAction::make('reword')->table(), [
                    'locale' => 'ar', 'key' => 'login.submit', 'text' => 'ادخل',
                ])
                ->assertNotified(__('Message reworded'));
        });

        Http::assertSent(function (Request $request) {
            return $request->method() === 'PUT'
                && str_ends_with($request->url(), "/admin/organizations/{$this->orgId}/messages/ar/login.submit")
                && $request['text'] === 'ادخل'
                && $request->hasHeader('If-Match');
        });
    }

    public function test_removing_goes_through_the_engine(): void
    {
        Http::fake(['*/admin/organizations/*/messages/*' => Http::response(['removed' => true, 'config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            $record = OrgMessage::query()->firstOrFail();
            Livewire::test(ListOrgMessages::class)
                ->callAction(TestAction::make('remove')->table($record))
                ->assertNotified(__('Message restored'));
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'DELETE'
            && str_ends_with($request->url(), '/messages/en/login.heading')
            && $request->hasHeader('If-Match'));
    }
}
