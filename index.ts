import { createCipheriv, createDecipheriv, createHash } from 'crypto';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

export type ClientLike = {
  getSecret(name: string, options: { version?: string }): Promise<{ value?: string }>;
};

export interface IKeyvaultLoaderOptions {
  /**
   * Secret client to use. A subset of the `SecretClient` from `@azure/keyvault-secrets`
   */
  client(kvBaseUrl: string): ClientLike | Promise<ClientLike>;

  /**
   * Whether the secret should be cached on-disk. Useful during development.
   * @default false
   */
  cache?: boolean;

  /**
   * Cache directory, defaults to the os tmpdir.
   */
  cacheDir?: string;
}

/**
 * Prepares the config for usage, revealing any contained keyvault secrets.
 */
export default function resolveConfig<T extends object>(
  config: T,
  options: IKeyvaultLoaderOptions
): Promise<T> {
  return resolveKeyVaultValues(options, config as SomeObject) as Promise<T>;
}

/**
 * Prepares the config for usage, revealing any contained keyvault secrets.
 */
export function resolveConfigInPlace(
  config: SomeObject,
  options: IKeyvaultLoaderOptions
): Promise<void> {
  return resolveKeyVaultValuesInPlace(options, config as SomeObject);
}

// matching a url, 1. vault base url, 2. secret name, 3. (optional) secret version
const keyVaultRe = /^(https:\/\/[^.]+\.vault\.azure\.net)\/secrets\/([^\/]+?)(?:\/(.*?))?$/;

const algorithm = 'aes-256-cbc';

const getSecret = async (
  options: IKeyvaultLoaderOptions,
  [, baseUrl, secret, version]: RegExpExecArray
) => {
  const key = createHash('sha256')
    .update(Buffer.from([baseUrl, secret, version].join('')))
    .digest()
    .slice(0, 32);
  const iv = createHash('sha256').update(key).digest().slice(0, 16);
  const filename = path.join(options.cacheDir ?? os.tmpdir(), `kv-cache-${iv.toString('hex')}`);

  if (options.cache) {
    try {
      const decipher = createDecipheriv(algorithm, key, iv);
      return decipher.update(await fs.readFile(filename), undefined, 'utf8') + decipher.final();
    } catch {
      // ignored
    }
  }

  let value: string;
  try {
    const client = await options.client(baseUrl);
    const res = await client.getSecret(secret, { version });
    if (!res.value) {
      return '';
    }
    value = res.value;
  } catch (e) {
    console.error(`Error getting secret ${secret} from keyvault: ${e.stack}`);
    throw e;
  }

  if (options.cache) {
    const encipher = createCipheriv(algorithm, key, iv);
    const contents = Buffer.concat([encipher.update(Buffer.from(value)), encipher.final()]);
    await fs.writeFile(filename, contents, { mode: '600' });
  }

  return value;
};

type SomeObject = Record<keyof any, unknown>;

async function mapValues(
  options: IKeyvaultLoaderOptions,
  target: SomeObject,
  handler: (obj: SomeObject, key: string, match: RegExpExecArray) => Promise<string>
): Promise<SomeObject> {
  const output: SomeObject = {};
  for (const key of Object.keys(target)) {
    const value = target[key];
    if (typeof value === 'object') {
      if (!!value) {
        output[key] = await mapValues(options, value as SomeObject, handler);
        continue;
      }
    } else if (typeof value === 'string') {
      const match = keyVaultRe.exec(value);
      if (match) {
        output[key] = await handler(target, key, match);
        continue;
      }
    }

    output[key] = value;
  }

  return output;
}

async function resolveKeyVaultValues(
  options: IKeyvaultLoaderOptions,
  target: SomeObject
): Promise<SomeObject> {
  return mapValues(options, target, (_obj, _key, match) => getSecret(options, match));
}

async function resolveKeyVaultValuesInPlace(
  options: IKeyvaultLoaderOptions,
  target: SomeObject
): Promise<void> {
  await mapValues(
    options,
    target,
    async (obj, key, match) => (obj[key] = await getSecret(options, match))
  );
}
