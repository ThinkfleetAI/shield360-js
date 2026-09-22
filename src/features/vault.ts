import Shield360Config from '../config';
import { SHIELD360_URL } from '../constant';
import { VaultOptions } from '../types';

export default class Vault {
  static async getSecrets(options: VaultOptions) {
    const url = process.env.SHIELD360_URL || options.url || SHIELD360_URL;
    const apiKey = process.env.SHIELD360_API_KEY || options.apiKey || '';

    const metaProperties = {
      applicationName: Shield360Config.applicationName,
      environment: Shield360Config.environment,
    };

    try {
      const vaultResponse = await fetch(`${url}/api/vault/get-secrets`, {
        method: 'POST',
        body: JSON.stringify({
          key: options.key,
          tags: options.tags,
          metaProperties,
          source: 'ts-sdk',
        }),
        headers: {
          Authorization: `Bearer ${apiKey}`,
        },
      })
        .then(async (response: any) => {
          if (!response.ok) {
            return {
              err: `Shield360 Error : HTTP error! Status: ${response.status}`,
            };
          }
          return response.json();
        })
        .then((resp: any) => {
          return resp;
        });

      const { res = {} } = vaultResponse;
      if (options.shouldSetEnv) {
        Object.entries(res).forEach(([key, value]: [string, unknown]) => {
          process.env[key] = value as string;
        });
      }

      return vaultResponse;
    } catch (e: any) {
      console.log(e);
      if (e && typeof e.toString === 'function') {
        return {
          err: `Shield360 Error : ${e.toString()}`,
          data: null,
        };
      }

      return {
        err: `Shield360 Error : ${e}`,
      };
    }
  }
}
