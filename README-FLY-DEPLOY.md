# Deploying to Fly (automatic)

This repo contains a GitHub Actions workflow that can deploy the `signaltrap` Fly app automatically when you push to `main`.

Setup steps (one-time):

1. Create a Fly API token:
   - On Fly: Account > Personal Access Tokens > Create a token.

2. Add the token as a GitHub secret:
   - Repository > Settings > Secrets & variables > Actions > New repository secret
   - Name: `FLY_API_TOKEN`
   - Value: the token you created on Fly

3. Push to `main` and GitHub Actions will run the `deploy-fly` workflow. It uses `signaltrap-vm/fly.toml` and deploys to the `signaltrap` app.

Manual deploy commands (if you want to run locally):

```bash
# build & deploy (no cache)
cd signaltrap-vm
flyctl deploy --app signaltrap --no-cache
```

Notes:
- The workflow expects the app name to be `signaltrap`. If you use a different app name, update the workflow or your fly.toml.
- Keep your `FLY_API_TOKEN` secret — do not paste it into chat or commit it to the repo.
