# GitHub Pages Deployment

The OpenDR documentation website is a React and Vite app in `site/`. GitHub
Actions builds it into `build/` and deploys that artifact to GitHub Pages.

Published target:

```text
https://keaz.github.io/opendr/
```

## Repository Settings

In GitHub:

1. Open the `keaz/opendr` repository settings.
2. Go to Pages.
3. Set source to `GitHub Actions`.
4. Save.

The workflow in `.github/workflows/vite-deploy.yml` will serve the project site
from `/opendr/`:

```text
https://keaz.github.io/opendr/
```

The Vite config sets `base = "/opendr/"`, so generated assets resolve correctly
under the project Pages path. The build script also copies the Markdown runbooks
from `docs/` into the Pages artifact.

## Local Preview

From the repository root:

```bash
pnpm install
pnpm dev
```

For a production preview:

```bash
pnpm build
pnpm preview
```

Open:

```text
http://127.0.0.1:5173/opendr/
```

For `pnpm preview`, open:

```text
http://127.0.0.1:4173/opendr/
```

## Notes

- `.nojekyll` is written into the generated `build/` artifact.
- The deployed site links to Markdown runbooks copied from `docs/`.
- The GitHub Action mirrors the `keaz.github.io` Vite deployment flow: pnpm,
  Node 22, `pnpm build`, Pages artifact upload, then `actions/deploy-pages`.
