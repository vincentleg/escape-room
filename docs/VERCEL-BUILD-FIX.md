# Vercel build repair — 2026-10-09

The existing project link is `vincentleg / escape-room`. It was preserved; no project or paid service was created.

The installed Vercel CLI 63.1.0's actual `buildFileTree` function reproduced the upload defect: `.vercelignore` exceptions `!scripts/` and `!web/` did not match the bare directory names checked by the CLI walker. Only `package.json` and `vercel.json` were selected for upload. Consequently the configured build script was absent from the uploaded source, despite a successful local build.

Changed those two exceptions to `!scripts` and `!web`, keeping the child-file allowlist. The CLI now selects exactly eight files: package/config, the build script, and the five static source assets. Secrets, Docker/engine code, raw evidence, environment files and local dependencies remain excluded.

The existing correct configuration remains `node scripts/build_site.mjs` with output `web/dist`. Copied exactly the CLI-selected upload files into a clean temporary directory and ran that build successfully: five output assets, two genuine recorded runs. The build still validates and sanitizes the evidence. Original artifact hashes/probe outcomes match the public recordings. Known local credential values are absent from the public assets.

Validation: 60 Python tests PASS; 8 JavaScript tests PASS; local build PASS; clean uploaded-source build PASS; actual CLI upload allowlist PASS.

Remote log inspection was attempted using the existing CLI/login but failed (`Not able to load user ... fetch failed`). A background CLI update worker also hit a restricted cache-directory permission. No remote build logs could be retrieved; the source-upload failure above was reproduced locally, not inferred from unavailable logs. Production redeployment remains unverified because this session cannot reach Vercel. Run once from normal macOS Terminal:

```sh
cd /Users/vincentgppm/escape-room && npx --yes vercel@63.1.0 deploy --prod --scope vincentleg
```

This uses the existing `.vercel/project.json` link and saved CLI login. No cloud credentials are needed in the website or Vercel environment. The CLI will print the actual deployment URL and result; neither is claimed here before a successful deployment.
