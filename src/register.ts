import Shield360 from './index';
import type { Shield360Options } from './types';

const GLOBAL_SENTINEL = '__shield360_register_initialized__';
const MIN_NODE_MAJOR = 18;

declare global {
  // eslint-disable-next-line no-var
  var __shield360_register_initialized__: boolean | undefined;
}

function parseCSV(value?: string): string[] | undefined {
  if (!value) return undefined;
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  return items.length > 0 ? items : undefined;
}

function parseResourceAttributes(value?: string): Record<string, string> | null {
  if (!value) return null;
  const attrs: Record<string, string> = {};
  for (const item of value.split(',')) {
    const [rawKey, ...rawValue] = item.split('=');
    const key = rawKey?.trim();
    const attrValue = rawValue.join('=').trim();
    if (key && attrValue) attrs[key] = attrValue;
  }
  return Object.keys(attrs).length > 0 ? attrs : null;
}

function nodeVersionSupported(): boolean {
  const major = Number(process.versions.node.split('.')[0]);
  return Number.isFinite(major) && major >= MIN_NODE_MAJOR;
}

function initFromEnv() {
  if ((globalThis as any)[GLOBAL_SENTINEL]) return;
  (globalThis as any)[GLOBAL_SENTINEL] = true;

  if (!nodeVersionSupported()) {
    console.error(
      `Shield360 auto-instrumentation requires Node.js ${MIN_NODE_MAJOR} or newer; current runtime is ${process.version}.`
    );
    return;
  }

  const options: Shield360Options = {
    applicationName: process.env.OTEL_SERVICE_NAME,
    environment: process.env.OTEL_DEPLOYMENT_ENVIRONMENT,
    disabledInstrumentors: parseCSV(process.env.SHIELD360_DISABLED_INSTRUMENTORS),
    customSpanAttributes: parseResourceAttributes(process.env.OTEL_RESOURCE_ATTRIBUTES),
  };

  Shield360.init(options);
}

initFromEnv();

