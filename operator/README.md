# Kubernetes operator for Signari

Keeps an organisation's configuration file applied. A `SignariConfig` resource
holds the file that `signari apply` reads ([config-as-code](../docs/config-as-code.md)).
The operator plans it through the engine's Admin API and applies it when the plan
has changes. Every `resyncSeconds` it plans again, so a change made another way,
from the console or the CLI, is put back.

```yaml
apiVersion: signari.dev/v1alpha1
kind: SignariConfig
metadata:
  name: acme
  namespace: idp
spec:
  endpoint: https://signari-admin.idp.svc:8081
  organization: 0b6c6d3e-5f0e-4c39-9d7e-2f1f2f0c8a11
  tokenSecretRef: {name: signari-admin-token}      # key "token"
  caSecretRef: {name: signari-admin-ca}            # key "ca.crt"; omit for a public CA
  resyncSeconds: 300
  document: |
    version: 1
    groups:
      - name: engineering
```

```sh
kubectl apply -f config/crd.yaml -f config/operator.yaml
kubectl -n idp create secret generic signari-admin-token --from-literal=token=sgnadm_...
kubectl get signariconfigs -A        # Ready, Reason, Version
```

It is its own Go module, like the Terraform provider, so the engine takes no
Kubernetes dependency, and it never touches the database. Everything it knows about
configuration is the engine's: the file is planned and applied by
`POST /admin/organizations/{orgID}/config` ([Admin API](../docs/admin-api.md)), and
every refusal comes back from there, named, in the resource's `Ready` condition.

## What it does each time

1. Reads the token, and the CA if one is named, from Secrets in the resource's
   namespace. They are read from the API server each time and never cached, so the
   operator needs no right to list Secrets, and holds no copy of them.
2. Plans the file. With nothing to change, `Ready` is `True`, reason `InSync`.
3. Applies it, sending the planned configuration version as `If-Match`. If the
   deployment changed between the plan and the apply, the engine refuses with 412
   and the operator plans again at once. It never applies a plan nobody saw.
4. Writes what the apply minted (a provider's signing secret, an outpost's token)
   to a Secret the resource owns, `<name>-minted`, one key per thing, `kind.name`.
   The engine answers each once and never again, and a status is no place for a
   secret.
5. Records the version, the counts and `Ready` `True`, reason `Applied`.

A failure leaves `Ready` `False` with the reason (`TokenUnavailable`,
`CAUnavailable`, `EndpointInvalid`, `PlanFailed`, `ApplyFailed`, `MintedNotKept`)
and the engine's own message. It is tried again a minute later.

## What it does not do

- **Undo on delete.** Deleting a resource leaves what its file made, as it is left
  after `signari apply`. To remove things, take them out of the file with `prune`
  on, then delete the resource.
- **Name secrets by reference.** A file naming one as `{env: …}` or `{file: …}` is
  refused by the Admin API (`secret_reference`), because a reference is read where
  `signari apply` runs, and here that would be the engine. Leave the secret out and
  it is minted, then written to the `-minted` Secret.
- **Run the engine.** The Helm chart, `deploy/helm/signari`, does that, migrations
  included ([deployment artefacts](../docs/deployment-artefacts.md)). The key
  rotation and the janitor stay CronJobs of `signari` CLI verbs.

## Developing

```sh
go test ./...                               # the reconciler against a fake cluster and a fake Admin API
CGO_ENABLED=0 go build -o signari-operator .
docker build -t signari-operator:dev .
```
