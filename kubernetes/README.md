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

### From Source (Python 3.11+)

Clone the repository:

```bash
git clone https://github.com/blessedrebus/krawl.git
cd krawl/src
```

Run the server:

```bash
python3 server.py
```

Visit `http://localhost:5000` and access the dashboard at `http://localhost:5000/<dashboard-secret-path>`