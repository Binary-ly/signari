<?php

namespace Tests\Concerns;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Plants the engine state a console test asserts against, and removes exactly
 * that state afterwards.
 *
 * The console's own connection is signari_admin, which reads core only through
 * core_v1 and only inside an organisation context. Tests that discovered their
 * fixtures with `SELECT ... FROM core_v1.organizations LIMIT 1` therefore found
 * nothing and skipped under the real role -- and had only ever passed when the
 * suite ran as a superuser, which bypasses row-level security and so proves
 * nothing about the boundary they exist to check.
 *
 * Seeding through the test-only `maintenance` connection keeps every line of
 * code under test on signari_admin while the fixture exists regardless of what
 * the database already holds. Each planted organisation gets its own instance,
 * so nothing here depends on or disturbs rows another suite wrote.
 *
 * Nothing here writes core.audit_events: the trail is append-only for tests too.
 */
trait SeedsEngineState
{
    /** @var list<array{instance: string, org: string}> */
    private array $plantedEngineState = [];

    protected function maintenance(): \Illuminate\Database\Connection
    {
        return DB::connection('maintenance');
    }

    /** A fresh organisation under a fresh instance; returns the organisation id. */
    protected function plantOrganisation(): string
    {
        $tag = Str::lower(Str::random(12));
        $instance = $this->maintenance()->selectOne(
            'INSERT INTO core.instances (issuer, display_name) VALUES (?, ?) RETURNING id::text AS id',
            ["https://console-test-{$tag}.invalid", "Console test {$tag}"]
        )->id;
        $org = $this->maintenance()->selectOne(
            'INSERT INTO core.organizations (instance_id, slug, display_name)
             VALUES (?::uuid, ?, ?) RETURNING id::text AS id',
            [$instance, "console-test-{$tag}", "Console test {$tag}"]
        )->id;

        $this->plantedEngineState[] = ['instance' => $instance, 'org' => $org];

        return $org;
    }

    /** A client in the organisation; returns its client_id. */
    protected function plantClient(string $orgId, bool $confidential = true, bool $enabled = true): string
    {
        $clientId = 'console-test-'.Str::lower(Str::random(10));
        $this->maintenance()->insert(
            'INSERT INTO core.clients (client_id, org_id, display_name, client_type, client_secret_hash, enabled)
             VALUES (?, ?::uuid, ?, ?, ?, ?)',
            [$clientId, $orgId, 'Console test client', $confidential ? 'confidential' : 'public',
             // Never verified by anything the console does; present only so the
             // row is shaped like a real confidential client.
             $confidential ? 'fixture-not-a-real-hash' : null, $enabled]
        );

        return $clientId;
    }

    /** An active user in the organisation; returns its id. */
    protected function plantUser(string $orgId): string
    {
        $tag = Str::lower(Str::random(10));

        return $this->maintenance()->selectOne(
            "INSERT INTO core.users (org_id, user_handle, username, email)
             VALUES (?::uuid, decode(?, 'hex'), ?, ?) RETURNING id::text AS id",
            // 64 bytes: the WebAuthn user handle, which users_user_handle_check pins.
            [$orgId, bin2hex(random_bytes(64)), "console-test-{$tag}", "console-test-{$tag}@example.test"]
        )->id;
    }

    /** A SAML service provider in the organisation; returns its entity id. */
    protected function plantSAMLProvider(string $orgId): string
    {
        $entityId = 'https://sp-'.Str::lower(Str::random(10)).'.example.test/metadata';
        $this->maintenance()->insert(
            'INSERT INTO core.saml_providers (org_id, entity_id, display_name) VALUES (?::uuid, ?, ?)',
            [$orgId, $entityId, 'Console test SP']
        );

        return $entityId;
    }

    /** @var list<string> */
    private array $plantedAdminTokens = [];

    /**
     * An admin token, scoped to the organisation or deployment-wide when null;
     * returns its name. The hash is random bytes: nothing here can authenticate.
     */
    protected function plantAdminToken(?string $orgId): string
    {
        $name = 'console-test-'.Str::lower(Str::random(10));
        $this->plantedAdminTokens[] = $this->maintenance()->selectOne(
            "INSERT INTO core.admin_tokens (org_id, name, token_hash, scopes)
             VALUES (?::uuid, ?, decode(?, 'hex'), ARRAY['clients:read']) RETURNING id::text AS id",
            [$orgId, $name, bin2hex(random_bytes(32))]
        )->id;

        return $name;
    }

    /**
     * Removes everything planted, children first: core.users and core.clients
     * reference organizations with ON DELETE RESTRICT.
     */
    protected function removePlantedEngineState(): void
    {
        foreach ($this->plantedAdminTokens as $id) {
            $this->maintenance()->delete('DELETE FROM core.admin_tokens WHERE id = ?::uuid', [$id]);
        }
        $this->plantedAdminTokens = [];

        foreach (array_reverse($this->plantedEngineState) as $planted) {
            $m = $this->maintenance();
            $m->delete('DELETE FROM core.saml_providers WHERE org_id = ?::uuid', [$planted['org']]);
            $m->delete('DELETE FROM core.clients WHERE org_id = ?::uuid', [$planted['org']]);
            $m->delete('DELETE FROM core.users WHERE org_id = ?::uuid', [$planted['org']]);
            $m->delete('DELETE FROM core.organizations WHERE id = ?::uuid', [$planted['org']]);
            $m->delete('DELETE FROM core.instances WHERE id = ?::uuid', [$planted['instance']]);
        }
        $this->plantedEngineState = [];
    }
}
