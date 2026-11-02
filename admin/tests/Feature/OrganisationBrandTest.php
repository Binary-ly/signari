<?php

namespace Tests\Feature;

use App\Filament\Pages\OrganisationBrand;
use App\Models\User;
use Filament\Notifications\Notification;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Tests\Concerns\SeedsEngineState;
use Tests\TestCase;

/**
 * An organisation's appearance: shown from the view, under the same tenant
 * boundary as the rest of the console, and written through the engine, which is
 * what refuses a palette nobody can read.
 */
class OrganisationBrandTest extends TestCase
{
    use SeedsEngineState;

    private ?User $operator = null;

    private string $orgId = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->orgId = $this->plantOrganisation();
        $this->maintenance()->insert(
            "INSERT INTO core.org_brands (org_id, product_name, logo_url) VALUES (?::uuid, 'Acme', 'https://acme.example.test/logo.svg')",
            [$this->orgId]
        );

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

    /** The middleware's context, for a component driven outside a request. */
    private function inOrganisation(callable $fn): void
    {
        DB::transaction(function () use ($fn) {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.org_id', $this->orgId]);
            $fn();
        });
    }

    public function test_the_screen_shows_what_the_organisation_has_set(): void
    {
        $this->actingAs($this->operator)->get('/admin/brand')->assertOk()->assertSee('Acme');
    }

    public function test_another_organisations_brand_is_not_shown(): void
    {
        $other = $this->plantOrganisation();
        $this->maintenance()->insert(
            "INSERT INTO core.org_brands (org_id, product_name) VALUES (?::uuid, 'Bravo')", [$other]);

        $this->actingAs($this->operator)->get('/admin/brand')->assertOk()->assertDontSee('Bravo');
    }

    public function test_saving_goes_through_the_engine_held_to_what_was_shown(): void
    {
        Http::fake(['*/admin/organizations/*/brand' => Http::response(['config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            Livewire::test(OrganisationBrand::class)
                ->assertFormSet(['product_name' => 'Acme'])
                ->fillForm(['product_name' => 'Acme Identity'])
                ->call('save')
                ->assertNotified(__('Brand saved'));
        });

        Http::assertSent(function (Request $request) {
            return $request->method() === 'PUT'
                && str_ends_with($request->url(), "/admin/organizations/{$this->orgId}/brand")
                && $request['product_name'] === 'Acme Identity'
                && $request['logo_url'] === 'https://acme.example.test/logo.svg'
                && $request['colour_primary'] === ''
                && $request->hasHeader('If-Match');
        });
    }

    public function test_the_engines_refusal_is_what_the_operator_reads(): void
    {
        $why = 'text on the background has a contrast ratio of 1.1:1';
        Http::fake(['*/admin/organizations/*/brand' => Http::response(
            ['error' => 'invalid_brand', 'detail' => $why], 400)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () use ($why) {
            Livewire::test(OrganisationBrand::class)
                ->call('save')
                ->assertNotified(Notification::make()->title(__('Nothing was changed'))->body($why)
                    ->danger()->persistent());
        });
    }

    public function test_removing_goes_through_the_engine(): void
    {
        Http::fake(['*/admin/organizations/*/brand' => Http::response(['removed' => true, 'config_version' => 1], 200)]);
        $this->actingAs($this->operator);

        $this->inOrganisation(function () {
            Livewire::test(OrganisationBrand::class)
                ->call('remove')
                ->assertNotified(__('Brand removed'))
                ->assertFormSet(['product_name' => null]);
        });

        Http::assertSent(fn (Request $request) => $request->method() === 'DELETE'
            && $request->hasHeader('If-Match'));
    }
}
