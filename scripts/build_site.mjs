import { copyFile, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { validateManifest } from '../web/app.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'web');
const destination = path.join(source, 'dist');
const assets = ['index.html', 'styles.css', 'app.js', 'favicon.svg', 'evidence.json'];
const manifest = validateManifest(JSON.parse(await readFile(path.join(source, 'evidence.json'), 'utf8')));
// Copy only explicit static assets. Never copy the repository, .env or raw logs.
await mkdir(destination, { recursive: true });
for (const entry of await readdir(destination)) {
  if (!assets.includes(entry)) await rm(path.join(destination, entry), { recursive: true, force: true });
}
for (const file of assets.filter(file => file !== 'evidence.json')) await copyFile(path.join(source, file), path.join(destination, file));
await writeFile(path.join(destination, 'evidence.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Static build ready: web/dist (${manifest.runs.length} genuine recorded run(s)).`);
if (!manifest.runs.length) console.log('Evidence pending: the UI will not claim verified containment until a recording is exported.');
