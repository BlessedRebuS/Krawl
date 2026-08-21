### Kubernetes 

Apply all manifests with:

```bash
kubectl apply -f https://raw.githubusercontent.com/BlessedRebuS/Krawl/refs/heads/main/kubernetes/krawl-all-in-one-deploy.yaml
```

Or clone the repo and apply the manifest:

```bash
kubectl apply -f kubernetes/krawl-all-in-one-deploy.yaml
```

Access the deception server:

```bash
kubectl get svc krawl-server -n krawl-system
```

Once the EXTERNAL-IP is assigned, access your deception server at `http://<EXTERNAL-IP>:5000`

### Retrieving Dashboard Path

Check server startup logs or get the secret with

```bash
kubectl get secret krawl-server -n krawl-system \
  -o jsonpath='{.data.dashboard-path}' | base64 -d && echo
```

### Setting Dashboard Password

To set a custom password for protected dashboard panels, create a Secret and uncomment the `KRAWL_DASHBOARD_PASSWORD` env var in the deployment. If not set, a random password is auto-generated and printed in the pod logs.

```bash
kubectl create secret generic krawl-dashboard \
  --namespace krawl-system \
  --from-literal=dashboard-password='your-strong-password'
```

### Externally-Managed Secrets (Postgres / Redis / Dashboard / Dashboard Path)

The all-in-one manifest ships with a built-in `krawl-postgres` Secret holding the
default `krawl` password. To use credentials managed out-of-band (ExternalSecrets,
SealedSecrets, Vault, cloud secret stores, etc.), supply your own Secret and edit
the `secretKeyRef` entries in the manifest to point at it. The relevant locations
are the `KRAWL_POSTGRES_PASSWORD` env on both the Krawl Deployment and the
`krawl-postgres` StatefulSet, and (for the optional extras) the commented-out
`KRAWL_DASHBOARD_PASSWORD`, `KRAWL_DASHBOARD_SECRET_PATH`, and `KRAWL_REDIS_PASSWORD`
env vars on the Krawl Deployment.

Example: bring your own Postgres Secret.

```bash
kubectl create secret generic my-pg-creds \
  --namespace krawl-system \
  --from-literal=postgres-password='supersecret'
```

Then in `kubernetes/krawl-all-in-one-deploy.yaml` replace every occurrence of

```yaml
secretKeyRef:
  name: krawl-postgres
  key: postgres-password
```

with

```yaml
secretKeyRef:
  name: my-pg-creds
  key: postgres-password
```

For dashboard password / dashboard path / Redis password, create a Secret (using
keys `dashboard-password`, `dashboard-path`, and `redis-password` respectively)
and uncomment the corresponding env-var blocks already present in the deployment.

The Helm chart exposes the same flexibility via `postgres.existingSecret`,
`redis.existingSecret`, `dashboardExistingSecret`, and `dashboardPathExistingSecret`
— see the [Helm chart documentation](../helm/README.md) for the full reference.

### From Source (Python 3.13+)

Clone the repository:

```bash
git clone https://github.com/blessedrebus/krawl.git
cd krawl
```

Run the server:

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --app-dir src --no-server-header
```

Visit `http://localhost:5000` and access the dashboard at `http://localhost:5000/<dashboard-secret-path>`

For Helm-based deployment, see the [Helm chart documentation](../helm/README.md).
