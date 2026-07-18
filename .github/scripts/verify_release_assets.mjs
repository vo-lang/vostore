import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  createReadStream,
  fstatSync,
  lstatSync,
  openSync,
  opendirSync,
  readSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { TextDecoder } from 'node:util';

const MAX_PROTOCOL_JSON_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_MODULE_ARTIFACT_BYTES = 256 * 1024 * 1024;
const MAX_GITHUB_RELEASE_ASSETS = 1_000;
const MAX_MODULE_ARTIFACTS = MAX_GITHUB_RELEASE_ASSETS - 3;
const OPEN_READ_ONLY_NOFOLLOW = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

function fail(message) {
  throw new Error(message);
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function validateRegularStat(stat, path, label, maxBytes) {
  if (!stat.isFile()) {
    fail(`${label} must be a regular file: ${path}`);
  }
  if (stat.size < 0n || stat.size > BigInt(maxBytes)) {
    fail(`${label} ${path} exceeds the ${maxBytes}-byte limit (got ${stat.size} bytes)`);
  }
}

function regularPathStat(path, label, maxBytes) {
  try {
    const stat = lstatSync(path, { bigint: true });
    validateRegularStat(stat, path, label, maxBytes);
    return stat;
  } catch (error) {
    fail(`could not inspect ${label} ${path}: ${errorMessage(error)}`);
  }
}

function assertStableIdentity(expected, actual, path, label) {
  for (const field of ['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
    if (expected[field] !== actual[field]) {
      fail(`${label} changed identity or contents while being inspected: ${path}`);
    }
  }
}

function openStableRegularFile(path, label, maxBytes) {
  const pathBefore = regularPathStat(path, label, maxBytes);
  let fd;
  try {
    fd = openSync(path, OPEN_READ_ONLY_NOFOLLOW);
  } catch (error) {
    fail(`could not open ${label} ${path}: ${errorMessage(error)}`);
  }

  try {
    const opened = fstatSync(fd, { bigint: true });
    validateRegularStat(opened, path, label, maxBytes);
    assertStableIdentity(pathBefore, opened, path, label);
    return { fd, stat: opened };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function readRegularFile(path, label, maxBytes) {
  const { fd, stat } = openStableRegularFile(path, label, maxBytes);
  try {
    const size = Number(stat.size);
    const bytes = Buffer.allocUnsafe(size);
    let offset = 0;
    while (offset < size) {
      const read = readSync(fd, bytes, offset, size - offset, null);
      if (read === 0) {
        fail(`${label} became shorter while being read: ${path}`);
      }
      offset += read;
    }
    if (readSync(fd, Buffer.allocUnsafe(1), 0, 1, null) !== 0) {
      fail(`${label} grew while being read: ${path}`);
    }

    const fdAfter = fstatSync(fd, { bigint: true });
    validateRegularStat(fdAfter, path, label, maxBytes);
    assertStableIdentity(stat, fdAfter, path, label);
    const pathAfter = regularPathStat(path, label, maxBytes);
    assertStableIdentity(stat, pathAfter, path, label);
    return { bytes, stat };
  } finally {
    closeSync(fd);
  }
}

function readJsonAsset(path, label) {
  const { bytes, stat } = readRegularFile(path, label, MAX_PROTOCOL_JSON_BYTES);
  let text;
  try {
    text = UTF8_DECODER.decode(bytes);
  } catch (error) {
    fail(`${label} ${path} is not valid UTF-8: ${errorMessage(error)}`);
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail(`could not parse ${label} ${path}: ${errorMessage(error)}`);
  }

  return {
    value,
    asset: {
      size: Number(stat.size),
      digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      stat,
      maxBytes: MAX_PROTOCOL_JSON_BYTES,
    },
  };
}

function sortedUnique(values, label) {
  const sorted = [...values].sort();
  if (new Set(sorted).size !== sorted.length) {
    fail(`${label} contains duplicate filenames`);
  }
  return sorted;
}

function digestRegularFile(path, label, maxBytes) {
  const { fd, stat } = openStableRegularFile(path, label, maxBytes);
  return new Promise((resolveDigest, rejectDigest) => {
    const hash = createHash('sha256');
    let bytesRead = 0n;
    let settled = false;
    const input = createReadStream(path, { fd, autoClose: false, start: 0 });

    function settle(error, result) {
      if (settled) {
        return;
      }
      settled = true;
      try {
        closeSync(fd);
      } catch (closeError) {
        if (!error) {
          error = closeError;
        }
      }
      if (error) {
        rejectDigest(error);
      } else {
        resolveDigest(result);
      }
    }

    input.on('data', (chunk) => {
      const nextSize = bytesRead + BigInt(chunk.length);
      if (nextSize > stat.size || nextSize > BigInt(maxBytes)) {
        input.destroy(new Error(`${label} grew while being hashed: ${path}`));
        return;
      }
      bytesRead = nextSize;
      hash.update(chunk);
    });
    input.once('error', (error) => {
      settle(new Error(`could not hash ${label} ${path}: ${errorMessage(error)}`));
    });
    input.once('end', () => {
      try {
        if (bytesRead !== stat.size) {
          fail(`${label} changed size while being hashed: ${path}`);
        }
        const fdAfter = fstatSync(fd, { bigint: true });
        validateRegularStat(fdAfter, path, label, maxBytes);
        assertStableIdentity(stat, fdAfter, path, label);
        const pathAfter = regularPathStat(path, label, maxBytes);
        assertStableIdentity(stat, pathAfter, path, label);
        settle(null, {
          size: Number(stat.size),
          digest: `sha256:${hash.digest('hex')}`,
          stat,
          maxBytes,
        });
      } catch (error) {
        settle(error);
      }
    });
  });
}

function validateBinding(binding, label, maxBytes) {
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) {
    fail(`vo.release.json ${label} must be an object`);
  }
  if (!Number.isSafeInteger(binding.size) || binding.size < 1 || binding.size > maxBytes) {
    fail(`vo.release.json ${label}.size must be an integer within 1..=${maxBytes}`);
  }
  if (typeof binding.digest !== 'string' || !SHA256_DIGEST.test(binding.digest)) {
    fail(`vo.release.json ${label}.digest must be a lowercase sha256 digest`);
  }
  return binding;
}

function artifactAssetName(artifact, index) {
  for (const field of ['kind', 'target', 'name']) {
    if (typeof artifact?.[field] !== 'string' || artifact[field].length === 0) {
      fail(`vo.release.json artifacts[${index}].${field} must be a non-empty string`);
    }
  }
  const identity = `vo-artifact-asset-v1\0${artifact.kind}\0${artifact.target}\0${artifact.name}`;
  const suffix = createHash('sha256').update(identity, 'utf8').digest('hex');
  return `vo-artifact-v1-${suffix}`;
}

async function inspectStage(stageDir, expectedCommit, expectedVersion) {
  const root = resolve(stageDir);
  const releasePath = join(root, 'vo.release.json');
  const releaseRead = readJsonAsset(releasePath, 'release manifest');
  const release = releaseRead.value;

  if (!release || typeof release !== 'object' || Array.isArray(release)) {
    fail('vo.release.json must contain a JSON object');
  }
  if (release.schema_version !== 2) {
    fail(`vo.release.json must use schema_version 2, got ${release.schema_version}`);
  }
  if (release.commit !== expectedCommit) {
    fail(`release commit ${release.commit} differs from source HEAD ${expectedCommit}`);
  }
  if (release.version !== expectedVersion) {
    fail(`release version ${release.version} differs from requested version ${expectedVersion}`);
  }
  if (release.source?.name !== 'source.tar.gz') {
    fail('vo.release.json source.name must be the fixed asset source.tar.gz');
  }
  if (!Array.isArray(release.artifacts)) {
    fail('vo.release.json artifacts must be an array');
  }
  if (release.artifacts.length > MAX_MODULE_ARTIFACTS) {
    fail(`vo.release.json artifacts contains more than ${MAX_MODULE_ARTIFACTS} entries`);
  }

  const packageBinding = validateBinding(
    release.package,
    'package',
    MAX_PROTOCOL_JSON_BYTES,
  );
  const sourceBinding = validateBinding(
    release.source,
    'source',
    MAX_SOURCE_ARCHIVE_BYTES,
  );
  const artifactAssets = release.artifacts.map((artifact, index) => ({
    name: artifactAssetName(artifact, index),
    binding: validateBinding(
      artifact,
      `artifacts[${index}]`,
      MAX_MODULE_ARTIFACT_BYTES,
    ),
  }));

  const expectedNames = sortedUnique([
    'vo.release.json',
    'vo.package.json',
    release.source.name,
    ...artifactAssets.map((asset) => asset.name),
  ], 'release manifest asset set');
  if (expectedNames.length > MAX_GITHUB_RELEASE_ASSETS) {
    fail(`release manifest asset set contains more than ${MAX_GITHUB_RELEASE_ASSETS} entries`);
  }

  const packagePath = join(root, 'vo.package.json');
  const packageRead = readJsonAsset(packagePath, 'package manifest');
  const packageManifest = packageRead.value;
  if (!packageManifest || typeof packageManifest !== 'object' || Array.isArray(packageManifest)) {
    fail('vo.package.json must contain a JSON object');
  }
  if (packageManifest.schema_version !== 1) {
    fail(`vo.package.json must use schema_version 1, got ${packageManifest.schema_version}`);
  }

  const rootBefore = lstatSync(root, { bigint: true });
  if (!rootBefore.isDirectory()) {
    fail(`staged release output must be a real directory: ${root}`);
  }
  const entryNames = [];
  const directory = opendirSync(root);
  try {
    for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {
      if (entryNames.length === MAX_GITHUB_RELEASE_ASSETS) {
        fail(`staged release directory contains more than ${MAX_GITHUB_RELEASE_ASSETS} entries`);
      }
      regularPathStat(
        join(root, entry.name),
        `staged release asset ${entry.name}`,
        MAX_MODULE_ARTIFACT_BYTES,
      );
      entryNames.push(entry.name);
    }
  } finally {
    directory.closeSync();
  }
  const rootAfter = lstatSync(root, { bigint: true });
  if (!rootAfter.isDirectory()) {
    fail(`staged release output changed directory type while being inspected: ${root}`);
  }
  assertStableIdentity(rootBefore, rootAfter, root, 'staged release directory');

  const actualNames = sortedUnique(entryNames, 'staged release directory');
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    fail(`staged asset set mismatch: expected [${expectedNames}], got [${actualNames}]`);
  }

  const stageAssets = new Map([
    ['vo.release.json', releaseRead.asset],
    ['vo.package.json', packageRead.asset],
  ]);
  const streamedAssets = [
    {
      name: release.source.name,
      label: 'source archive',
      maxBytes: MAX_SOURCE_ARCHIVE_BYTES,
    },
    ...artifactAssets.map((asset, index) => ({
      name: asset.name,
      label: `module artifact ${index}`,
      maxBytes: MAX_MODULE_ARTIFACT_BYTES,
    })),
  ];
  for (const asset of streamedAssets) {
    stageAssets.set(
      asset.name,
      await digestRegularFile(join(root, asset.name), asset.label, asset.maxBytes),
    );
  }

  const bindings = [
    ['vo.package.json', packageBinding],
    [release.source.name, sourceBinding],
    ...artifactAssets.map((asset) => [asset.name, asset.binding]),
  ];
  for (const [name, binding] of bindings) {
    const actual = stageAssets.get(name);
    if (binding?.size !== actual.size || binding?.digest !== actual.digest) {
      fail(`vo.release.json binding for ${name} differs from staged bytes`);
    }
  }

  for (const [name, asset] of stageAssets) {
    const path = join(root, name);
    const current = regularPathStat(path, `staged release asset ${name}`, asset.maxBytes);
    assertStableIdentity(asset.stat, current, path, `staged release asset ${name}`);
  }
  return stageAssets;
}

function verifyRemote(stageAssets, expectedTag, viewPath, expectedDraft, expectedImmutable) {
  const view = readJsonAsset(viewPath, 'GitHub release response').value;
  if (!view || typeof view !== 'object' || Array.isArray(view)) {
    fail('GitHub release response must contain a JSON object');
  }
  if (view.tag_name !== expectedTag) {
    fail(`GitHub release tag ${view.tag_name} differs from ${expectedTag}`);
  }
  if (view.draft !== expectedDraft) {
    fail(`GitHub release draft state ${view.draft} differs from ${expectedDraft}`);
  }
  if (view.immutable !== expectedImmutable) {
    fail(`GitHub release immutable state ${view.immutable} differs from ${expectedImmutable}`);
  }
  if (!Array.isArray(view.assets)) {
    fail('GitHub release assets must be an array');
  }
  if (view.assets.length > MAX_GITHUB_RELEASE_ASSETS) {
    fail(`GitHub release assets contains more than ${MAX_GITHUB_RELEASE_ASSETS} entries`);
  }

  const remoteNames = sortedUnique(view.assets.map((asset, index) => {
    if (typeof asset?.name !== 'string') {
      fail(`GitHub release assets[${index}].name must be a string`);
    }
    return asset.name;
  }), 'GitHub release asset set');
  const expectedNames = [...stageAssets.keys()].sort();
  if (JSON.stringify(remoteNames) !== JSON.stringify(expectedNames)) {
    fail(`GitHub asset set mismatch: expected [${expectedNames}], got [${remoteNames}]`);
  }

  for (const asset of view.assets) {
    const expected = stageAssets.get(asset.name);
    if (asset.state !== 'uploaded') {
      fail(`GitHub asset ${asset.name} has state ${asset.state}, expected uploaded`);
    }
    if (asset.size !== expected.size || asset.digest !== expected.digest) {
      fail(`GitHub asset ${asset.name} differs from staged bytes`);
    }
  }
}

const [mode, stageDir, expectedCommit, expectedVersion, expectedTag, viewPath] = process.argv.slice(2);
if (!['local', 'draft', 'published'].includes(mode) || !stageDir || !expectedCommit || !expectedVersion) {
  fail('usage: verify_release_assets.mjs <local|draft|published> STAGE_DIR COMMIT VERSION [TAG VIEW_JSON]');
}

const stageAssets = await inspectStage(stageDir, expectedCommit, expectedVersion);
if (mode === 'draft' || mode === 'published') {
  if (!expectedTag || !viewPath) {
    fail(`${mode} verification requires TAG and VIEW_JSON`);
  }
  verifyRemote(stageAssets, expectedTag, viewPath, mode === 'draft', mode === 'published');
}
