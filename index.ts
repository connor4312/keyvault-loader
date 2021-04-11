import { createCipheriv, createDecipheriv, createHash } from 'crypto';
import { promises as fs } from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface IKeyvaultLoaderOptions {
  /**
   * Secret client to use. A subset of the `SecretClient` from `@azure/keyvault-secrets`
   */
  client: { getSecret(name: string, options: { version?: string }): Promise<{ value: string }> };

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
    const res = await options.client.getSecret(secret, { version });
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

async function resolveKeyVaultValues(
  options: IKeyvaultLoaderOptions,
  target: SomeObject
): Promise<SomeObject> {
  const output: SomeObject = {};
  for (const key of Object.keys(target)) {
    const value = target[key];
    if (typeof value === 'object') {
      if (!!value) {
        output[key] = await resolveKeyVaultValues(options, value as SomeObject);
        continue;
      }
    } else if (typeof value === 'string') {
      const match = keyVaultRe.exec(value);
      if (match) {
        output[key] = await getSecret(options, match);
        continue;
      }
    }

    output[key] = value;
  }

  return output;
}
