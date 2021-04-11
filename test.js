import resolveConfig from '.';
import { promises as fs } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const cacheDir = join(dirname(fileURLToPath(import.meta.url)), '.__test_cache__');

beforeEach(async () => {
  await fs.mkdir(cacheDir).catch(() => undefined);
});

afterAll(async () => {
  await fs.rmdir(cacheDir, { recursive: true });
});

test('reads without a cache', async () => {
  const obj = { x: 'https://myvault.vault.azure.net/secrets/foo/baadf00d' };
  let calls = 0;
  const options = {
    client: url => ({
      getSecret(name, options) {
        calls++;
        expect(url).toBe('https://myvault.vault.azure.net');
        expect(name).toBe('foo');
        expect(options.version).toBe('baadf00d');
        return Promise.resolve({ value: 'secretValue' });
      },
    }),
  };

  expect(await resolveConfig(obj, options)).toEqual({ x: 'secretValue' });
  expect(await resolveConfig(obj, options)).toEqual({ x: 'secretValue' });
  expect(calls).toBe(2);
});

test('allows version to be optional', async () => {
  const obj = { x: 'https://myvault.vault.azure.net/secrets/foo' };
  const options = {
    client: () => ({
      getSecret(name, options) {
        expect(name).toBe('foo');
        expect(options.version).toBe(undefined);
        return Promise.resolve({ value: 'secretValue' });
      },
    }),
  };

  expect(await resolveConfig(obj, options)).toEqual({ x: 'secretValue' });
});

test('does not interfere with other object properties', async () => {
  const obj = {
    a: 1,
    b: { c: 2 },
    e: null,
    d: undefined,
    f: { x: 'https://myvault.vault.azure.net/secrets/foo' },
  };
  const cloned = JSON.parse(JSON.stringify(obj));

  const options = {
    client: () => ({
      getSecret(name, options) {
        expect(name).toBe('foo');
        expect(options.version).toBe(undefined);
        return Promise.resolve({ value: 'secretValue' });
      },
    }),
  };

  expect(await resolveConfig(obj, options)).toEqual({
    a: 1,
    b: { c: 2 },
    e: null,
    d: undefined,
    f: { x: 'secretValue' },
  });
  expect(obj).toEqual(cloned);
});

test('caches', async () => {
  const obj = { x: 'https://myvault.vault.azure.net/secrets/foo/baadf00d' };
  let calls = 0;
  const options = {
    cacheDir,
    cache: true,
    client: () => ({
      getSecret(name, options) {
        calls++;
        expect(name).toBe('foo');
        expect(options.version).toBe('baadf00d');
        return Promise.resolve({ value: 'secretValue' });
      },
    }),
  };

  expect(await resolveConfig(obj, options)).toEqual({ x: 'secretValue' });
  expect(await resolveConfig(obj, options)).toEqual({ x: 'secretValue' });
  expect(calls).toBe(1);
});
