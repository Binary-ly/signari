<?php

namespace Tests\Feature;

use App\Services\EngineAdminApi;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

/**
 * An engine with SIGNARI_ADMIN_CLIENT_CA admits nobody without a certificate, so a
 * console that did not send one would be locked out by the setting meant to protect it.
 */
class AdminClientCertificateTest extends TestCase
{
    protected function tearDown(): void
    {
        unset($_ENV['SIGNARI_ADMIN_CLIENT_CERT'], $_ENV['SIGNARI_ADMIN_CLIENT_KEY']);
        unset($_SERVER['SIGNARI_ADMIN_CLIENT_CERT'], $_SERVER['SIGNARI_ADMIN_CLIENT_KEY']);
        parent::tearDown();
    }

    private function optionsSent(): array
    {
        $seen = [];
        Http::fake(function ($request, array $options) use (&$seen) {
            $seen = $options;

            return Http::response(['config_version' => 1], 200);
        });
        (new EngineAdminApi('https://engine.test', 'token'))->configVersion();

        return $seen;
    }

    public function test_it_presents_the_certificate_it_was_given(): void
    {
        $_ENV['SIGNARI_ADMIN_CLIENT_CERT'] = $_SERVER['SIGNARI_ADMIN_CLIENT_CERT'] = '/etc/console/client.pem';
        $_ENV['SIGNARI_ADMIN_CLIENT_KEY'] = $_SERVER['SIGNARI_ADMIN_CLIENT_KEY'] = '/etc/console/client.key';

        $options = $this->optionsSent();

        $this->assertSame('/etc/console/client.pem', $options['cert'] ?? null);
        $this->assertSame('/etc/console/client.key', $options['ssl_key'] ?? null);
    }

    public function test_it_presents_none_when_it_has_none(): void
    {
        $options = $this->optionsSent();

        $this->assertArrayNotHasKey('cert', $options);
        $this->assertArrayNotHasKey('ssl_key', $options);
    }
}
