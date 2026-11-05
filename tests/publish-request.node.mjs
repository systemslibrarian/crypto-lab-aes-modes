import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

function npmInvocation() {
  // npm tells child scripts exactly which CLI launched them. Use that instead of
  // assuming npm lives under the Node executable: Homebrew installs Node and npm in
  // separate prefixes, and the old assumption made both of these controls fail before
  // they exercised the deploy script at all. The same repair is on vdf, token-tell,
  // vigenere-break and timing-sidechannel.
  if (process.env.npm_execpath) {
    return { command: process.execPath, args: [process.env.npm_execpath] };
  }
  // Keep a direct `node --test` useful too. The original PATH is retained below, after
  // the temporary fake `gh`, so the platform's npm launcher stays discoverable.
  return { command: process.platform === 'win32' ? 'npm.cmd' : 'npm', args: [] };
}

// Replace only the external GitHub boundary; exercise the real npm script.
// Neither control dispatches a workflow or uploads any local build.
function request(exitCode) {
  const dir = mkdtempSync(join(tmpdir(), 'publish-request-control-'));
  const gh = join(dir, 'gh');
  writeFileSync(gh, '#!/usr/bin/env node\nconsole.log(JSON.stringify(process.argv.slice(2)));\nprocess.exit(Number(process.env.PUBLISH_CONTROL_EXIT));\n');
  chmodSync(gh, 0o700);
  try {
    const npm = npmInvocation();
    return spawnSync(npm.command, [...npm.args, 'run', 'deploy', '--silent'], {
      cwd: root,
      env: { ...process.env, PATH: dir + delimiter + process.env.PATH, GH_TOKEN: '', PUBLISH_CONTROL_EXIT: String(exitCode) },
      encoding: 'utf8',
      timeout: 5000,
    });
  } finally {
    rmSync(dir, { recursive: true });
  }
}

test('publishing requests the existing gated main workflow', () => {
  const result = request(0);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.deepEqual(JSON.parse(result.stdout.trim()), [
    'workflow', 'run', 'pages.yml', '--repo',
    'systemslibrarian/crypto-lab-aes-modes', '--ref', 'main',
  ]);
});

test('a rejected publishing request retains its failing exit status', () => {
  const result = request(73);
  assert.equal(result.error, undefined);
  assert.equal(result.status, 73);
});
