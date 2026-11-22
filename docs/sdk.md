# Admin API clients

Two client libraries of the Admin API, in Go and TypeScript, are generated from
its OpenAPI document. The document is [admin-openapi.json](admin-openapi.json),
drawn from the router itself. Each library has one method per operation the
server registers, typed by the schemas the document carries. A route added to
the server, or a field added to one, is in the document from then on, and a
test fails until the clients are made again.

The same document is rendered as [admin-api-reference.md](admin-api-reference.md):
every operation, the scope it needs, and the fields it takes and answers.

| | Where | Needs |
|---|---|---|
| Go | `sdk/go`, the module `signari.dev/sdk/go`, package `signariadmin` | Go 1.22, nothing outside the standard library |
| TypeScript | `sdk/typescript`, the package `@signari/admin` | `fetch`; Node 23.6 or later runs the source as it is |

## Go

```go
c := &signariadmin.Client{Endpoint: "https://admin.internal.example.com", Token: os.Getenv("SIGNARI_ADMIN_TOKEN")}

group, version, err := c.GetGroupsGroupID(ctx, groupID)
if err != nil {
	return err
}
_, _, err = c.PatchGroupsGroupID(ctx, groupID,
	signariadmin.PatchGroupsGroupIDRequest{DisplayName: signariadmin.Ptr("Platform")},
	signariadmin.IfMatch(version))
if signariadmin.IsConflict(err) {
	// Something else wrote since the read. Read again, and decide again.
}
```

## TypeScript

```ts
import { SignariAdmin, SignariAdminError } from "@signari/admin"

const c = new SignariAdmin("https://admin.internal.example.com", process.env.SIGNARI_ADMIN_TOKEN!)
const { body: group, version } = await c.getGroupsGroupID(groupID)
try {
  await c.patchGroupsGroupID(groupID, { display_name: "Platform" }, { ifMatch: version })
} catch (e) {
  if (e instanceof SignariAdminError && e.isConflict) {
    // Something else wrote since the read.
  }
}
```

## What every method does

- **It is named for the operation.** `operationId` `patch_users_userID`
  becomes `PatchUsersUserID` in Go and `patchUsersUserID` in TypeScript. Path
  parameters come first and are escaped. The body follows, then the options.
- **It answers the configuration version.** The server reports it as the
  `ETag`. Send it back with `IfMatch` / `ifMatch`, and a write over a
  deployment that moved since is refused with `412` instead of overwriting the
  other change. See [admin-api.md](admin-api.md#conditional-writes).
- **A request's fields are all optional.** That lets one type serve a partial
  update. In Go each field is a pointer, set with `Ptr`; a field left nil is
  not sent, so a `PATCH` changes only what it names.
- **A refusal is an error carrying the server's reason.** It holds the status,
  the `error` code, the `detail`, and on a `412` both versions.
- **It waits out the arrival limit.** The server answers `429` with
  `Retry-After` before it authenticates a request, so nothing was done. The
  client waits as asked, up to thirty seconds a time, and sends the same
  request again, up to eight times.
- **List filters, `limit` and `cursor` go in the query option.** In Go that is
  `Query("email", "ada@example.com")`; in TypeScript, `{ query: { email: ... } }`.

## Making them again

The document first, then the clients and the reference:

```sh
cd engine
go test ./internal/adminapi -run ThePublishedOpenAPIDocumentIsCurrent -openapi-out ../docs/admin-openapi.json
go test ./internal/sdkgen -run TheClientsAreCurrent -sdk-out ..
```

`TestThePublishedOpenAPIDocumentIsCurrent` and `TestTheClientsAreCurrent` fail
whenever either is out of date. Each client has its own tests, which run
against a real Admin API when `SIGNARI_E2E_ENDPOINT`, `SIGNARI_E2E_TOKEN` and
`SIGNARI_E2E_ORG_ID` are set:

```sh
cd sdk/go && go test ./...
cd sdk/typescript && node --test test/client.test.ts
```
