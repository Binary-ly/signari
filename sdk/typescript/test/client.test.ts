// The generated TypeScript client (6.18): a method sends what its operation
// says and answers the body and the version; a refused precondition is an
// error that says so; and, against a REAL Admin API when
// SIGNARI_E2E_ENDPOINT, SIGNARI_E2E_TOKEN and SIGNARI_E2E_ORG_ID are set, a
// group made, read, renamed on its version, refused on a stale one, deleted.
//
//   node --test test/client.test.ts

import { test } from "node:test"
import assert from "node:assert/strict"
import { SignariAdmin, SignariAdminError } from "../src/index.ts"

test("a method sends its operation and answers the body and the version", async () => {
  let seen: { url: string; method: string; ifMatch: string | null; body: unknown } | undefined
  const fake = (async (url: string, init: RequestInit) => {
    const headers = new Headers(init.headers)
    seen = { url, method: init.method ?? "", ifMatch: headers.get("If-Match"), body: JSON.parse(String(init.body)) }
    return new Response(JSON.stringify({ id: "u/1", config_version: 42 }), { headers: { ETag: '"42"' } })
  }) as typeof fetch
  const c = new SignariAdmin("http://admin.test/", "t", fake)
  const answer = await c.patchUsersUserID("u/1", { display_name: "Ada", active: false }, { ifMatch: 41 })
  assert.equal(answer.version, 42)
  assert.equal(answer.body.id, "u/1")
  assert.equal(seen?.url, "http://admin.test/admin/users/u%2F1")
  assert.equal(seen?.method, "PATCH")
  assert.equal(seen?.ifMatch, '"41"')
  assert.deepEqual(seen?.body, { display_name: "Ada", active: false })
})

test("a refused precondition is a conflict naming both versions", async () => {
  const fake = (async () => new Response(JSON.stringify({ error: "precondition_failed", expected_version: 3,
    current_version: 5 }), { status: 412 })) as typeof fetch
  const c = new SignariAdmin("http://admin.test", "t", fake)
  await assert.rejects(c.deleteGroupsGroupID("g", { ifMatch: 3 }), (e: unknown) => {
    assert.ok(e instanceof SignariAdminError)
    assert.ok(e.isConflict)
    assert.equal(e.expectedVersion, 3)
    assert.equal(e.currentVersion, 5)
    return true
  })
})

const endpoint = process.env.SIGNARI_E2E_ENDPOINT, token = process.env.SIGNARI_E2E_TOKEN,
  org = process.env.SIGNARI_E2E_ORG_ID

test("a group through the generated client, against a real Admin API", { skip: !endpoint || !token || !org }, async () => {
  const c = new SignariAdmin(endpoint!, token!)
  const name = `sdk-ts-${Date.now()}`
  const made = await c.postGroups({ org_id: org, name })
  try {
    const read = await c.getGroupsGroupID(made.body.id)
    assert.equal(read.body.name, name)
    assert.ok(read.version > 0)
    await c.patchGroupsGroupID(made.body.id, { display_name: "Renamed" }, { ifMatch: read.version })
    await assert.rejects(c.patchGroupsGroupID(made.body.id, { display_name: "Stale" }, { ifMatch: read.version }),
      (e: unknown) => e instanceof SignariAdminError && e.isConflict)
    assert.equal((await c.getGroupsGroupID(made.body.id)).body.display_name, "Renamed")
  } finally {
    await c.deleteGroupsGroupID(made.body.id)
  }
  await assert.rejects(c.getGroupsGroupID(made.body.id), (e: unknown) => e instanceof SignariAdminError && e.status === 404)
})
