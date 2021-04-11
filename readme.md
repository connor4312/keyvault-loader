# @c4312/keyvault-loader

Small utility library that:

- Replaces all keyvault secret URIs in the object with their value loaded from keyvault
- Can optionally cache secrets on disk. Very useful in a development environment, since otherwise loading secrets from keyvault can take several seconds.

Secrets cached on disk are appropriately permissioned and AES encrypted, but bear in mind these will have less security than a keyvault value stored only in memory.

## Usage

```ts
import { AzureCliCredential } from '@azure/identity';
import { SecretClient } from '@azure/keyvault-secrets';
import resolveConfig from '@c4312/keyvault-loader';

const secretClient = new SecretClient(keyVaultBaseUrl, new AzureCliCredential());
const myConfig = { fooSecret: 'https://myvault.vault.azure.net/secrets/foo' };}
const resolved = await resolveConfig(myConfig, { client: secretClient, cache: true });

console.log(resolved); // { fooSecret: 'mySecretValue' }
```
