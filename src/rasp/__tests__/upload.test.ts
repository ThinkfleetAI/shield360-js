/**
 * Upload file names: read from raw multipart bodies and from a parser's file
 * objects, recorded as request input, checked by file_write.upload, and then
 * seen by file_write.script when the app writes a file named after them.
 */
import { captureBody, captureRequest, uploadNames } from '../capture';
import { detectPath, detectUpload } from '../detect';
import { configureEngine, setEventSink } from '../engine';
import { RaspBlockedError, type RaspInput } from '../types';

const multipart = (parts: { name: string; filename?: string; body: string }[]) => {
  const b = '----shield360test';
  const text = parts
    .map((p) => `--${b}\r\nContent-Disposition: form-data; name="${p.name}"${p.filename !== undefined ? `; filename="${p.filename}"` : ''}\r\n\r\n${p.body}\r\n`)
    .join('');
  return { body: `${text}--${b}--\r\n`, contentType: `multipart/form-data; boundary=${b}` };
};
const ctx = () => captureRequest({ framework: 'test', method: 'POST', url: '/upload', headers: {} });

const events: { attrs: Record<string, string> }[] = [];
beforeEach(() => {
  events.length = 0;
  configureEngine({ enabled: true, applicationName: 'a', mode: 'monitor', env: {} });
  setEventSink({ add: (e) => events.push(e) });
});
afterAll(() => {
  setEventSink(undefined);
  configureEngine({ enabled: false, applicationName: 'default', env: {} });
});

describe('uploadNames', () => {
  it('reads file names from raw multipart part headers, not plain fields', () => {
    const b = multipart([
      { name: 'title', body: 'Quarterly report' },
      { name: 'attachment', filename: 'report.pdf', body: 'fixture' },
    ]);
    expect(uploadNames(b, b.body)).toEqual([{ field: 'attachment', name: 'report.pdf' }]);
  });

  it("reads multer's req.file and req.files shapes", () => {
    expect(uploadNames({ files: { fieldname: 'avatar', originalname: 'me.png' } }, '')).toEqual([{ field: 'avatar', name: 'me.png' }]);
    expect(uploadNames({ files: [{ fieldname: 'docs', originalname: 'a.txt' }, { fieldname: 'docs', originalname: 'b.txt' }] }, '').map((u) => u.name)).toEqual(['a.txt', 'b.txt']);
    expect(uploadNames({ files: { docs: [{ originalname: 'c.txt' }] } }, '')).toEqual([{ field: 'docs', name: 'c.txt' }]);
  });

  it('caps the number of names read', () => {
    const parts = Array.from({ length: 40 }, (_, i) => ({ name: `f${i}`, filename: `x${i}.txt`, body: '1' }));
    const b = multipart(parts);
    expect(uploadNames(b, b.body)).toHaveLength(32);
  });
});

describe('detectUpload', () => {
  const input = (value: string): RaspInput => ({ value, key: 'body.file.filename', source: 'request' });
  it.each(['shell.php', 'run.sh', 'handler.JSP', 'x/../y.py', 'tool.exe'])('flags %s', (name) => {
    expect(detectUpload(input(name))?.rule).toBe('file_write.upload');
  });
  it.each(['report.pdf', 'photo.jpeg', 'notes.txt', 'archive.tar.gz', 'php.txt'])('passes %s', (name) => {
    expect(detectUpload(input(name))).toBeNull();
  });
});

describe('captured uploads', () => {
  it('records the file name as input and reports a script upload in monitor', () => {
    const c = ctx();
    const b = multipart([{ name: 'attachment', filename: 'shell.php', body: 'fixture' }]);
    captureBody(c, b);
    expect(c.inputs).toContainEqual(expect.objectContaining({ key: 'body.attachment.filename', value: 'shell.php' }));
    expect(events.map((e) => e.attrs['shield360.rasp.rule'])).toEqual(['file_write.upload']);
    expect(events[0].attrs['shield360.rasp.sink']).toBe('request.upload');
  });

  it('blocks a script upload when file_write blocks', () => {
    configureEngine({ enabled: true, applicationName: 'a', mode: 'monitor', attacks: { file_write: 'block' }, env: {} });
    expect(() => captureBody(ctx(), { body: {}, files: { fieldname: 'f', originalname: 'cmd.aspx' } })).toThrow(RaspBlockedError);
  });

  it('lets an ordinary upload through without a report', () => {
    captureBody(ctx(), multipart([{ name: 'attachment', filename: 'report.pdf', body: 'fixture' }]));
    expect(events).toHaveLength(0);
  });

  it('a later write named after the upload is caught by file_write.script', () => {
    const c = ctx();
    captureBody(c, { body: {}, files: { fieldname: 'f', originalname: 'page.php' } });
    expect(detectPath('/srv/app/public/page.php', 'write', c.inputs, [], true)?.rule).toBe('file_write.script');
  });
});
