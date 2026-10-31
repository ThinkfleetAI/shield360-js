/**
 * Outbound HTTP sink hook (README "SSRF"): `http`/`https` `request` and
 * `get`, and the global `fetch`, are checked for SSRF and for hosts outside
 * `allow.outboundHosts` before anything is sent, and `http`/`https` again
 * at the connection's own DNS lookup (DNS rebinding). The Shield360 and OTLP
 * hosts are always allowed. Drafted with ChatGPT, reviewed and adapted by
 * the repository owner.
 */
import http = require('http');
import https = require('https');
import dns = require('dns');
import { isIP } from 'net';
import { syncBuiltinESMExports } from 'module';
import { urlToHttpOptions } from 'url';
import { currentContext, inputsOf } from '../context';
import { check, isActive, allowLists, strongest } from '../engine';
import { detectOutbound, detectSsrf } from '../detect';
import { RaspBlockedError, type RaspInput } from '../types';

type Saved = { owner: object; key: string; descriptor: PropertyDescriptor; wrapper: unknown };
type Target = { url: string; host: string; options: http.RequestOptions; callback: unknown };
let installed: Saved[] | undefined;
/** Bumped by every install and uninstall: a wrapper checks only while its generation is current. */
let generation = 0;
let checking = false;
let depth = 0;

function target(values: unknown[], protocol: string): Target | undefined {
  const first = values[0];
  const hasUrl = typeof first === 'string' || first instanceof URL;
  if (!hasUrl && (!first || typeof first !== 'object')) return;
  const base = hasUrl ? urlToHttpOptions(new URL(String(first))) : {};
  const extra = hasUrl ? values[1] : first;
  const options: http.RequestOptions = {
    ...base,
    ...(extra && typeof extra === 'object' ? extra : {}),
  };
  const host = options.hostname || options.host || 'localhost';
  const scheme = options.protocol || protocol;
  const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  const url = new URL(`${scheme}//${authority}${options.port ? `:${options.port}` : ''}`);
  // Assign path components separately: a path beginning // must not replace host.
  const path = options.path || '/';
  const split = path.indexOf('?');
  url.pathname = split < 0 ? path : path.slice(0, split);
  url.search = split < 0 ? '' : path.slice(split);
  return {
    url: url.href, host: url.hostname.replace(/^\[|\]$/g, ''), options,
    callback: hasUrl ? typeof values[1] === 'function' ? values[1] : values[2] : values[1],
  };
}

function guarded(run: () => void): void {
  const previous = checking;
  checking = true;
  try { run(); } catch (error) {
    if (error instanceof RaspBlockedError) throw error;
  } finally { checking = previous; }
}

function resolvedCheck(sink: string, url: string, inputs: RaspInput[], addresses: string[]): void {
  guarded(() => { if (isActive()) check(sink, () => detectSsrf(url, inputs, addresses)); });
}

function prepare(values: unknown[], protocol: string, sink: string, always: string[]): unknown[] {
  let result = values;
  guarded(() => {
    if (!isActive()) return;
    const parsed = target(values, protocol);
    if (!parsed) return;
    const ctx = currentContext();
    const inputs = ctx ? inputsOf(ctx).map((input: RaspInput) => ({ ...input })) : [];
    check(sink, () => strongest(detectOutbound(parsed.url, allowLists().outboundHosts, always), detectSsrf(parsed.url, inputs, [])));
    if (inputs.length && !isIP(parsed.host)) {
      const lookup = parsed.options.lookup || dns.lookup;
      parsed.options.lookup = function (this: unknown, hostname, options, callback) {
        // Keep the original lookup's arguments and callback shape, including all:true.
        const wrapped = (...args: unknown[]) => {
          if (!args[0]) {
            try {
              const answer = args[1];
              const addresses = typeof answer === 'string' ? [answer]
                : Array.isArray(answer) ? answer.map((entry: { address: string }) => entry.address) : [];
              resolvedCheck(sink, parsed.url, inputs, addresses);
            } catch (error) {
              if (error instanceof RaspBlockedError) {
                Reflect.apply(callback, undefined, [error]);
                return;
              }
            }
          }
          Reflect.apply(callback, undefined, args);
        };
        Reflect.apply(lookup, this, [hostname, options, wrapped]);
      } as typeof dns.lookup;
      result = typeof parsed.callback === 'function' ? [parsed.options, parsed.callback] : [parsed.options];
    }
  });
  return result;
}

function copyProperties(original: (...args: unknown[]) => unknown, wrapper: (...args: unknown[]) => unknown): void {
  for (const key of Reflect.ownKeys(original)) {
    if (key !== 'prototype') Object.defineProperty(wrapper, key, Object.getOwnPropertyDescriptor(original, key)!);
  }
}
/**
 * Ends this generation (every wrapper stops checking) and puts back the
 * originals where RASP's wrapper is still the current value. A wrapper put
 * on top later (tracing) stays, calling RASP's, which now only passes through.
 */
function restore(saved: Saved[]): void {
  generation++;
  for (let i = saved.length - 1; i >= 0; i--) {
    const { owner, key, descriptor, wrapper } = saved[i];
    if (Object.getOwnPropertyDescriptor(owner, key)?.value === wrapper) Object.defineProperty(owner, key, descriptor);
  }
}

export function installHttpHooks(opts: { alwaysAllowedHosts: string[] }): boolean {
  if (installed) return true;
  const saved: Saved[] = [];
  const gen = ++generation;
  try {
    const always = opts.alwaysAllowedHosts.slice();
    const replace = (owner: object, key: string, build: (original: (...args: unknown[]) => unknown) => (...args: unknown[]) => unknown) => {
      const descriptor = Object.getOwnPropertyDescriptor(owner, key);
      if (!descriptor || typeof descriptor.value !== 'function') throw new TypeError(key);
      const wrapper = build(descriptor.value);
      copyProperties(descriptor.value, wrapper);
      Object.defineProperty(owner, key, { ...descriptor, value: wrapper });
      saved.push({ owner, key, descriptor, wrapper });
    };
    for (const [owner, protocol, name] of [[http, 'http:', 'http'], [https, 'https:', 'https']] as const) {
      for (const api of ['request', 'get']) replace(owner, api, original => function (this: unknown, ...values: unknown[]) {
        const args = checking || depth || gen !== generation ? values : prepare(values, protocol, `${name}.${api}`, always);
        depth++;
        try { return Reflect.apply(original, this, args); } finally { depth--; }
      });
    }
    // fetch is optional: a runtime without it, or with fetch as an accessor
    // (a polyfill), keeps the http/https hooks.
    const fetchDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'fetch');
    if (typeof fetchDescriptor?.value === 'function' && fetchDescriptor.configurable) replace(globalThis, 'fetch', original => async function (this: unknown, ...values: unknown[]) {
      if (checking || gen !== generation) return Reflect.apply(original, this, values);
      let url: URL | undefined;
      let inputs: RaspInput[] = [];
      guarded(() => {
        if (!isActive()) return;
        const first = values[0];
        url = new URL(typeof first === 'string' || first instanceof URL ? String(first) : (first as Request).url);
        const ctx = currentContext();
        inputs = ctx ? inputsOf(ctx).map((input: RaspInput) => ({ ...input })) : [];
        check('fetch', () => strongest(detectOutbound(url!.href, allowLists().outboundHosts, always), detectSsrf(url!.href, inputs, [])));
      });
      if (url && inputs.length && !isIP(url.hostname.replace(/^\[|\]$/g, ''))) {
        try {
          const addresses = await dns.promises.lookup(url.hostname, { all: true });
          resolvedCheck('fetch', url.href, inputs, addresses.map(address => address.address));
        } catch (error) { if (error instanceof RaspBlockedError) throw error; }
      }
      // Rebinding gap: fetch may resolve again for its connection. Node exposes
      // no undici connector here without depending on the undici package.
      return Reflect.apply(original, this, values);
    });
    syncBuiltinESMExports();
    installed = saved;
    return true;
  } catch {
    try { restore(saved); } catch { /* Best effort if an external owner froze a property. */ }
    try { syncBuiltinESMExports(); } catch { /* Never throw on installation. */ }
    return false;
  }
}

export function uninstallHttpHooks(): void {
  if (!installed) return;
  restore(installed);
  installed = undefined;
  syncBuiltinESMExports();
}
