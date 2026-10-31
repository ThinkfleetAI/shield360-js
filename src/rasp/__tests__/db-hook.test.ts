import * as hooks from '../hooks/db';
import * as detect from '../detect';
import { runWithInputs } from '../context';
import { configureEngine, setEventSink } from '../engine';
import { RaspBlockedError } from '../types';
import { isWrapped } from '@opentelemetry/instrumentation';
import Shield360PgInstrumentation from '../../instrumentation/pg';

const input = "' OR '1'='1";
const query = `SELECT * FROM products WHERE name = '${input}'`;
const safe = 'SELECT * FROM products WHERE name = ?';
const request = <T>(fn: () => T, trees: unknown[] = []): T => runWithInputs(
  [{ value: input, key: 'query.q', source: 'request' }], fn, { inRequest: true, trees },
);
const configure = (mode: 'block' | 'monitor' = 'block') => configureEngine({ enabled: true, applicationName: 'a', mode, env: {} });
type Patch = (exports: unknown) => void;
const drivers: [string, string, string[], Patch, Patch, string][] = [
  ['pg', 'Client', ['query'], hooks.patchPg, hooks.unpatchPg, 'postgres'],
  ['mysql2', 'Connection', ['query', 'execute'], hooks.patchMysql2, hooks.unpatchMysql2, 'mysql'],
  ['mysql', '', ['query'], hooks.patchMysql, hooks.unpatchMysql, 'mysql'],
  ['sqlite3', 'Database', ['run', 'get', 'all', 'each', 'exec', 'prepare'], hooks.patchSqlite3, hooks.unpatchSqlite3, 'sqlite'],
  ['better-sqlite3', '', ['prepare', 'exec'], hooks.patchBetterSqlite3, hooks.unpatchBetterSqlite3, 'sqlite'],
  ['mssql', 'Request', ['query', 'batch', 'execute'], hooks.patchMssql, hooks.unpatchMssql, 'mssql'],
  ['oracledb', 'Connection', ['execute', 'executeMany', 'queryStream'], hooks.patchOracledb, hooks.unpatchOracledb, 'oracle'],
  ['ibm_db', 'Database', ['query', 'querySync', 'queryResult', 'queryResultSync', 'prepare', 'prepareSync'], hooks.patchIbmDb, hooks.unpatchIbmDb, 'db2'],
];
beforeEach(() => { configure(); setEventSink({ add: () => undefined }); });
afterEach(() => {
  hooks.uninstallDbHooks();
  jest.restoreAllMocks();
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'a', env: {} });
});

describe.each(drivers)('%s', (driver, key, methods, patch, unpatch, dialect) => {
  let original: jest.Mock;
  let ctor: { new(): Record<string, (...args: unknown[]) => unknown>; prototype: Record<string, (...args: unknown[]) => unknown> };
  let moduleExports: unknown;
  beforeEach(() => {
    original = jest.fn(function (this: unknown) { return this; });
    class Fake {}
    for (const method of methods) Object.defineProperty(Fake.prototype, method, { value: original, configurable: true, writable: true });
    ctor = Fake as unknown as typeof ctor;
    moduleExports = key ? { [key]: ctor } : ctor;
  });
  afterEach(() => unpatch(moduleExports));

  test.each(methods)('%s blocks before the original', method => {
    const detector = jest.spyOn(detect, 'detectSql');
    patch(moduleExports);
    expect(() => request(() => new ctor()[method](query))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
    expect(detector).toHaveBeenCalledWith(query, expect.any(Array), dialect);
  });

  test('bound parameters and unrelated text pass unchanged', () => {
    patch(moduleExports);
    const instance = new ctor();
    const values = [input];
    const text = driver === 'pg' ? 'SELECT * FROM products WHERE name = $1' : safe;
    expect(request(() => instance[methods[0]](text, values))).toBe(instance);
    expect(original).toHaveBeenLastCalledWith(text, values);
    expect(request(() => instance[methods[0]]('SELECT 1'))).toBe(instance);
    expect(original).toHaveBeenCalledTimes(2);
  });

  test('object query form blocks without modifying the object', () => {
    if (!['pg', 'mysql', 'mysql2', 'ibm_db'].includes(driver)) return;
    const object = driver === 'pg' ? { text: query } : { sql: query };
    Object.freeze(object);
    patch(moduleExports);
    expect(() => request(() => new ctor()[methods[0]](object))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });

  test('monitor reports and invokes original', () => {
    configure('monitor');
    const events = jest.fn();
    setEventSink({ add: events });
    patch(moduleExports);
    request(() => new ctor()[methods[0]](query));
    expect(original).toHaveBeenCalledTimes(1);
    expect(events).toHaveBeenCalledWith(expect.objectContaining({ attrs: expect.objectContaining({
      'shield360.rasp.sink': `db.${driver}.${methods[0]}`,
      'shield360.rasp.decision': 'monitored',
    }) }), expect.any(String));
  });

  test('off and absent context skip detection', () => {
    const detector = jest.spyOn(detect, 'detectSql');
    patch(moduleExports);
    new ctor()[methods[0]](query);
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    request(() => new ctor()[methods[0]](query));
    expect(detector).not.toHaveBeenCalled();
    expect(original).toHaveBeenCalledTimes(2);
  });

  test('detector errors fail open', () => {
    jest.spyOn(detect, 'detectSql').mockImplementation(() => { throw new Error('unavailable'); });
    patch(moduleExports);
    request(() => new ctor()[methods[0]](query));
    expect(original).toHaveBeenCalledTimes(1);
  });

  test('double patch wraps once and unpatch restores identity', () => {
    const detector = jest.spyOn(detect, 'detectSql');
    patch(moduleExports);
    const wrapper = ctor.prototype[methods[0]];
    patch(moduleExports);
    expect(ctor.prototype[methods[0]]).toBe(wrapper);
    request(() => new ctor()[methods[0]]('SELECT 1'));
    expect(detector).toHaveBeenCalledTimes(1);
    unpatch(moduleExports);
    for (const method of methods) expect(ctor.prototype[method]).toBe(original);
  });
});

describe('tedious', () => {
  // tedious: the SQL lives on the Request object handed to the connection.
  class Request { constructor(public sqlTextOrProcedure: string, public callback?: unknown) {} }
  const methods = ['execSql', 'execSqlBatch', 'prepare'];
  let original: jest.Mock;
  let Connection: { new(): Record<string, (...args: unknown[]) => unknown>; prototype: Record<string, unknown> };
  beforeEach(() => {
    original = jest.fn();
    class Fake {}
    for (const method of methods) Object.defineProperty(Fake.prototype, method, { value: original, configurable: true, writable: true });
    Connection = Fake as unknown as typeof Connection;
    hooks.patchTedious({ Connection, Request });
  });
  afterEach(() => hooks.unpatchTedious({ Connection, Request }));

  test.each(methods)('%s blocks the request text with the mssql dialect', method => {
    const detector = jest.spyOn(detect, 'detectSql');
    expect(() => request(() => new Connection()[method](new Request(query)))).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
    expect(detector).toHaveBeenCalledWith(query, expect.any(Array), 'mssql');
  });

  test('parameterised text passes; monitor reports; off and failures pass through', () => {
    request(() => new Connection().execSql(new Request('SELECT * FROM t WHERE name = @name')));
    configure('monitor');
    const events = jest.fn();
    setEventSink({ add: events });
    request(() => new Connection().execSql(new Request(query)));
    expect(events).toHaveBeenCalledWith(expect.objectContaining({ attrs: expect.objectContaining({
      'shield360.rasp.sink': 'db.tedious.execSql', 'shield360.rasp.decision': 'monitored',
    }) }), expect.any(String));
    configureEngine({ enabled: true, applicationName: 'a', mode: 'block', attacks: { sql_injection: 'off' }, env: {} });
    request(() => new Connection().execSql(new Request(query)));
    configure('block');
    jest.spyOn(detect, 'detectSql').mockImplementation(() => { throw new Error('unavailable'); });
    request(() => new Connection().execSql(new Request(query)));
    expect(original).toHaveBeenCalledTimes(4);
  });

  test('a query mssql checked is not checked again when mssql hands it to tedious', async () => {
    configure('monitor');
    const events = jest.fn();
    setEventSink({ add: events });
    const connection = new Connection();
    // mssql's tedious driver: Request.query runs later, asynchronously, through Connection.execSqlBatch.
    class MssqlRequest {
      query(text: string): Promise<void> {
        return Promise.resolve().then(() => { connection.execSqlBatch(new Request(text)); });
      }
    }
    hooks.patchMssql({ Request: MssqlRequest });
    try {
      await request(() => new MssqlRequest().query(query));
      expect(original).toHaveBeenCalledTimes(1);
      expect(events).toHaveBeenCalledTimes(1);
      expect(events.mock.calls[0][0].attrs['shield360.rasp.sink']).toBe('db.mssql.query');
      // A later tedious call with the same text is its own call and is checked.
      request(() => connection.execSqlBatch(new Request(query)));
      expect(events).toHaveBeenCalledTimes(2);
    } finally { hooks.unpatchMssql({ Request: MssqlRequest }); }
  });
});

describe('review fixes', () => {
  test('mssql methods inherited from the base Request are checked and block with the RASP error', async () => {
    // mssql: the exported (tedious) Request inherits query and batch from the shared base Request.
    const original = jest.fn(() => Promise.resolve('rows'));
    class BaseRequest {}
    for (const m of ['query', 'batch', 'execute']) Object.defineProperty(BaseRequest.prototype, m, { value: original, configurable: true, writable: true });
    class Request extends BaseRequest {}
    hooks.patchMssql({ Request });
    try {
      const run = async () => (new Request() as unknown as { query(q: string): Promise<unknown> }).query(query);
      await expect(request(run)).rejects.toBeInstanceOf(RaspBlockedError);
      expect(original).not.toHaveBeenCalled();
    } finally { hooks.unpatchMssql({ Request }); }
    expect(Object.getOwnPropertyDescriptor(BaseRequest.prototype, 'query')!.value).toBe(original);
    expect(Object.getOwnPropertyNames(Request.prototype)).toEqual(['constructor']);
  });

  test('mssql PreparedStatement.prepare is checked (mssql sends it through sp_prepare, not execSql)', () => {
    const prepare = jest.fn();
    class BasePreparedStatement {}
    Object.defineProperty(BasePreparedStatement.prototype, 'prepare', { value: prepare, configurable: true, writable: true });
    class PreparedStatement extends BasePreparedStatement {}
    class Request {}
    const detector = jest.spyOn(detect, 'detectSql');
    hooks.patchMssql({ Request, PreparedStatement });
    try {
      expect(() => request(() => (new PreparedStatement() as unknown as { prepare(q: string): void }).prepare(query))).toThrow(RaspBlockedError);
      expect(prepare).not.toHaveBeenCalled();
      expect(detector).toHaveBeenCalledWith(query, expect.any(Array), 'mssql');
    } finally { hooks.unpatchMssql({ Request, PreparedStatement }); }
    expect(Object.getOwnPropertyDescriptor(BasePreparedStatement.prototype, 'prepare')!.value).toBe(prepare);
  });

  test('oracledb queryStream is checked once, not again in the execute it runs on the next tick', async () => {
    configure('monitor');
    const events = jest.fn();
    setEventSink({ add: events });
    const execute = jest.fn(() => Promise.resolve({ rows: [] }));
    class Connection {}
    Object.defineProperty(Connection.prototype, 'execute', { value: execute, configurable: true, writable: true });
    Object.defineProperty(Connection.prototype, 'queryStream', {
      configurable: true, writable: true,
      value: function (this: { execute(q: string): Promise<unknown> }, sql: string) {
        return new Promise(resolve => process.nextTick(() => resolve(this.execute(sql))));
      },
    });
    hooks.patchOracledb({ Connection });
    try {
      await request(() => (new Connection() as unknown as { queryStream(q: string): Promise<unknown> }).queryStream(query));
      expect(execute).toHaveBeenCalledTimes(1);
      expect(events).toHaveBeenCalledTimes(1);
      expect(events.mock.calls[0][0].attrs['shield360.rasp.sink']).toBe('db.oracledb.queryStream');
    } finally { hooks.unpatchOracledb({ Connection }); }
  });
});

test('dialect names the lexer does not know yet still detect', () => {
  // The lexer's own oracle and db2 rules land separately; meanwhile it lexes them with the common rules.
  const inputs = [{ value: input, key: 'query.q', source: 'request' as const }];
  for (const dialect of ['mssql', 'oracle', 'db2']) {
    expect(detect.detectSql(query, inputs, dialect as detect.SqlDialect)?.rule).toBe('sqli.userinput');
  }
});

const mongoMethods = ['find', 'findOne', 'countDocuments', 'updateOne', 'updateMany', 'replaceOne',
  'deleteOne', 'deleteMany', 'findOneAndUpdate', 'findOneAndDelete', 'findOneAndReplace', 'aggregate'];
describe('mongodb', () => {
  let original: jest.Mock;
  let Collection: { new(): Record<string, (...args: unknown[]) => unknown> };
  beforeEach(() => {
    original = jest.fn(() => 'result');
    class Fake {}
    for (const method of mongoMethods) Object.defineProperty(Fake.prototype, method, { value: original, configurable: true, writable: true });
    Collection = Fake as unknown as typeof Collection;
    hooks.patchMongodb({ Collection });
  });
  afterEach(() => hooks.unpatchMongodb({ Collection }));

  test.each(mongoMethods)('%s checks the filter or pipeline stage', method => {
    const body = { name: { $ne: null } };
    const filter = { name: body.name };
    const doc = method === 'aggregate' ? [{ $match: filter }] : filter;
    expect(() => request(() => new Collection()[method](doc), [body])).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });

  test.each(['updateOne', 'updateMany', 'replaceOne', 'findOneAndUpdate', 'findOneAndReplace'])('%s checks the second document', method => {
    const body = { name: { $ne: null } };
    expect(() => request(() => new Collection()[method]({ name: 'fixture' }, { name: body.name }), [body])).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  });

  test('equality passes; monitor reports and passes operator input', () => {
    expect(request(() => new Collection().find({ name: 'fixture' }))).toBe('result');
    configure('monitor');
    const events = jest.fn();
    setEventSink({ add: events });
    const body = { name: { $ne: null } };
    expect(request(() => new Collection().find({ name: body.name }), [body])).toBe('result');
    expect(events).toHaveBeenCalled();
  });

  test('off and no context skip Mongo detection', () => {
    const detector = jest.spyOn(detect, 'detectNoSql');
    new Collection().find({});
    configureEngine({ enabled: false, applicationName: 'a', env: {} });
    request(() => new Collection().find({}));
    expect(detector).not.toHaveBeenCalled();
  });
});

test('installation and uninstallation are idempotent', () => {
  expect(hooks.installDbHooks()).toBe(true);
  expect(hooks.installDbHooks()).toBe(true);
  hooks.uninstallDbHooks();
  hooks.uninstallDbHooks();
});


test('aggregate checks stages after a safe first stage and double patch restores Mongo methods', () => {
  const original = jest.fn();
  class Collection { aggregate = original; }
  // Use a prototype method, as real drivers do.
  Object.defineProperty(Collection.prototype, 'aggregate', { value: original, configurable: true, writable: true });
  const moduleExports = { Collection };
  hooks.patchMongodb(moduleExports);
  const wrapper = Collection.prototype.aggregate;
  hooks.patchMongodb(moduleExports);
  expect(Collection.prototype.aggregate).toBe(wrapper);
  const body = { name: { $ne: null } };
  try {
    expect(() => request(() => Reflect.apply(wrapper, {}, [
      [{ $match: { name: 'fixture' } }, { $match: { name: body.name } }],
    ]), [body])).toThrow(RaspBlockedError);
    expect(original).not.toHaveBeenCalled();
  } finally {
    hooks.unpatchMongodb(moduleExports);
  }
  expect(Collection.prototype.aggregate).toBe(original);
});

describe('alongside the SDK pg tracing (shimmer)', () => {
  const tracedClient = () => {
    const original = jest.fn(() => 'rows');
    class Client {}
    Object.defineProperty(Client.prototype, 'query', { value: original, configurable: true, writable: true });
    return { original, Client: Client as unknown as { new (): { query: (...a: unknown[]) => unknown }; prototype: any } };
  };

  test.each(['tracing first', 'rasp first'])('%s: RASP still checks and tracing keeps its wrapper', (order) => {
    const { original, Client } = tracedClient();
    const tracing = new Shield360PgInstrumentation();
    if (order === 'tracing first') {
      tracing.manualPatch({ Client });
      hooks.patchPg({ Client });
    } else {
      hooks.patchPg({ Client });
      tracing.manualPatch({ Client });
    }
    try {
      expect(() => request(() => new Client().query(query))).toThrow(RaspBlockedError);
      expect(original).not.toHaveBeenCalled();
      expect(request(() => new Client().query('SELECT 1'))).toBe('rows');
      // tracing's wrapper is still in the chain
      let fn = Client.prototype.query;
      let traced = false;
      for (let i = 0; i < 4 && fn; i++) {
        if (isWrapped(fn)) traced = true;
        fn = (fn as any).__original ?? undefined;
      }
      expect(traced || isWrapped(Client.prototype.query)).toBe(true);
    } finally {
      hooks.unpatchPg({ Client });
    }
    // RASP off: the injected query reaches the driver through tracing.
    expect(request(() => new Client().query(query))).toBe('rows');
  });

  test('unpatch under another wrapper switches RASP off and patch turns it back on', () => {
    const { Client } = tracedClient();
    hooks.patchPg({ Client });
    new Shield360PgInstrumentation().manualPatch({ Client });
    hooks.unpatchPg({ Client });
    expect(request(() => new Client().query(query))).toBe('rows');
    hooks.patchPg({ Client });
    expect(() => request(() => new Client().query(query))).toThrow(RaspBlockedError);
    hooks.unpatchPg({ Client });
  });
});

test('reporter queries do not recurse and the guard resets', () => {
  const original = jest.fn();
  class Client { query(...values: unknown[]): unknown { return original(...values); } }
  const events = jest.fn(() => { new Client().query('SELECT 1'); });
  setEventSink({ add: events });
  configure('monitor');
  hooks.patchPg({ Client });
  try {
    request(() => new Client().query(query));
    request(() => new Client().query(query));
    expect(events).toHaveBeenCalledTimes(2);
    expect(original).toHaveBeenCalledTimes(4);
  } finally { hooks.unpatchPg({ Client }); }
});
