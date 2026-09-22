import Shield360Config from '../config';
import { SHIELD360_URL } from '../constant';
import { PromptHubOptions } from '../types';

export default class PromptHub {
  static async getPrompts(options: PromptHubOptions) {
    const url = process.env.SHIELD360_URL || options.url || SHIELD360_URL;
    const apiKey = process.env.SHIELD360_API_KEY || options.apiKey || '';
    let metaProperties = {
      applicationName: Shield360Config.applicationName,
      environment: Shield360Config.environment,
    };
    if (
      options.metaProperties &&
      typeof options.metaProperties === 'object' &&
      !Array.isArray(options.metaProperties)
    ) {
      metaProperties = {
        ...metaProperties,
        ...options.metaProperties,
      };
    }

    try {
      return await fetch(`${url}/api/prompt/get-compiled`, {
        method: 'POST',
        body: JSON.stringify({
          name: options.name,
          version: options.version,
          shouldCompile: !!options.shouldCompile,
          variables: options.variables || {},
          id: options.promptId,
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
    } catch (e: any) {
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
