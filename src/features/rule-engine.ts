import Shield360Config from '../config';
import { SHIELD360_URL } from '../constant';
import { RuleEngineOptions, RuleEngineResult } from '../types';

export default class RuleEngine {
  static async evaluateRule(
    options: RuleEngineOptions
  ): Promise<RuleEngineResult | { err: string }> {
    const url = process.env.SHIELD360_URL || options.url || SHIELD360_URL;
    const apiKey = process.env.SHIELD360_API_KEY || options.apiKey || '';

    const metaProperties = {
      applicationName: Shield360Config.applicationName,
      environment: Shield360Config.environment,
    };

    try {
      const response = await fetch(`${url}/api/rule-engine/evaluate`, {
        method: 'POST',
        body: JSON.stringify({
          entity_type: options.entityType,
          fields: options.fields,
          include_entity_data: options.includeEntityData || false,
          entity_inputs: options.entityInputs,
          metaProperties,
          source: 'ts-sdk',
        }),
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
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

      return response;
    } catch (e: any) {
      console.log(e);
      if (e && typeof e.toString === 'function') {
        return {
          err: `Shield360 Error : ${e.toString()}`,
          data: null,
        } as any;
      }

      return {
        err: `Shield360 Error : ${e}`,
      };
    }
  }
}
