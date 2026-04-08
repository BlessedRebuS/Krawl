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

To set a custom password for protected dashboard panels, create the `secret.yaml` manifest (see `kubernetes/manifests/secret.yaml`) and uncomment the `KRAWL_DASHBOARD_PASSWORD` env var in the deployment. If not set, a random password is auto-generated and printed in the pod logs.

### From Source (Python 3.13+)

Clone the repository:

```bash
git clone https://github.com/blessedrebus/krawl.git
cd krawl
```

Run the server:

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --app-dir src
```

Visit `http://localhost:5000` and access the dashboard at `http://localhost:5000/<dashboard-secret-path>`

For Helm-based deployment, see the [Helm chart documentation](../helm/README.md).
