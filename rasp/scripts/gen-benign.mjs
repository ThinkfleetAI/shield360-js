#!/usr/bin/env node
// Generates sdk/rasp/testdata/benign.json: the shared false-positive corpus
// every Shield360 SDK runs its RASP checks against (README "Fixtures").
//
// Deterministic: the same script always writes the same file. Every case is
// what a normal application does with normal input (a value bound or quoted
// correctly, a file name inside its upload root, a public URL, a model answer
// that is prose or a read-only query). No case may fire any check.
//
//   node sdk/rasp/scripts/gen-benign.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "testdata", "benign.json");

// ---- benign input values -------------------------------------------------

const names = [
	"O'Brien", "D'Angelo", "Mary-Kate O'Connor", "Conan O'Brien", "Shaquille O'Neal",
	"D'Artagnan", "L'Oréal Paris", "Siobhán Ní Bhriain", "Renée Zellweger", "José García",
	"Zoë Saldaña", "Björk Guðmundsdóttir", "Jean-Luc Picard", "Nguyễn Văn An", "Dwayne \"The Rock\" Johnson",
	"Ana María de la Cruz", "Seán Ó Súilleabháin", "Chloë Grace", "Anne-Marie d'Arc", "Patrick O'Rourke Jr.",
	"Miguel Ángel Asturias", "François Hollande", "Søren Kierkegaard", "Łukasz Żurawski", "Ma'ayan Cohen",
	"Te'o Manti", "N'Golo Kanté", "Dara Ó Briain", "Kim Jong-un Park", "Sinéad O'Connor",
];

const prose = [
	"Select the best option from the list", "Please update my order and delete the old address",
	"Union Station to Grand Central", "Drop off at the front desk", "Where is the nearest store?",
	"I want to join the group chat", "Order by phone or online", "Insert coin to continue",
	"Create an account in minutes", "Tom & Jerry", "rock and roll", "salt and pepper",
	"between 5 and 10 business days", "null and void", "Values, mission and vision",
	"Truncate long titles in the table view", "Grant writing workshop for nonprofits",
	"Alter the hem by one inch", "Exec summary for the board", "Replace the filter every 3 months",
	"Is it true or false that cats sleep 16 hours?", "Having fun in the sun", "Group by size, then colour",
	"Limit one per customer", "Like and subscribe!", "Show me shoes under $50", "Case closed",
	"Begin again", "Return policy: 30 days, no questions asked", "The table is set for six",
	"Merge the two documents into one", "Revoke my newsletter consent", "Count me in for Friday",
	"Sleep well and wake up refreshed", "Where to eat near the station", "Desc: blue cotton t-shirt",
	"From 9 to 5, Monday to Friday", "If in doubt, ask", "Like a rolling stone", "Into the wild",
];

const nonEnglish = [
	"東京タワーの近くのレストラン", "Где находится ближайшая аптека?", "مرحبا بكم في متجرنا",
	"Wie spät ist es?", "¿Dónde está la biblioteca?", "Où est la gare?", "北京市朝阳区建国路",
	"안녕하세요, 주문 확인 부탁드립니다", "Γεια σου κόσμε", "שלום עולם", "नमस्ते दुनिया", "Merhaba dünya",
	"Ça coûte combien ?", "Grüße aus München", "Cześć, jak się masz?", "Xin chào thế giới",
	"สวัสดีครับ", "Привет, мир! Как дела?", "日本語のテキストと English mixed", "Æble og pære",
];

const misc = [
	"2026-10-29", "12:30 PM", "+1 (555) 010-0199", "ryan@example.com", "first.last+tag@example.org",
	"ORD-2026-000123", "SKU 4471-B", "#hashtag", "@mention", "C++ and C# developers",
	"5 * 3 = 15", "a < b > c", "50% off everything", "100% cotton", "user_name_01",
	"Hello, world!", "I <3 cats and dogs", "TODO: buy milk", "1.5 kg", "N/A",
	"caf%C3%A9 menu", "S%C3%A3o Paulo", "New%20York", "rock%20and%20roll", "Ma%C3%B1ana",
];

const allValues = [...names, ...prose, ...nonEnglish, ...misc];

const fileNames = [
	"report.pdf", "my photo.jpg", "Résumé 2026.docx", "O'Brien notes.txt", "invoice-0042.pdf",
	"holiday (1).png", "data_export.csv", "presentation final v2.pptx", "song – live.mp3", "école.txt",
	"東京.png", "README.md", "archive.tar.gz", "budget 2027.xlsx", "scan_0001.tiff",
	"meeting-notes-2026-10-29.txt", "logo@2x.png", "Q3 results & outlook.pdf", "draft#3.docx", "photo 100%.jpg",
	"2026/10/report.pdf", "team/alice/avatar.png", "contracts/acme inc/nda.pdf", "a.b.c.txt", "notes.v1.2.txt",
	"..hidden-but-not-traversal.txt", "file..name.txt", "my...dots.txt", "x.json", "config.yaml",
];

const publicUrls = [
	["https://www.wikipedia.org/wiki/O%27Brien", ["198.35.26.96"]],
	["https://api.github.com/repos/octocat/hello-world", ["140.82.112.6"]],
	["https://example.com/", ["93.184.216.34"]],
	["https://www.example.org/path/to/page?q=rock+and+roll", ["93.184.216.34"]],
	["https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js", ["151.101.1.229"]],
	["https://images.unsplash.com/photo-1500000000000?w=800", ["151.101.2.208"]],
	["https://news.ycombinator.com/item?id=1", ["209.216.230.207"]],
	["https://docs.python.org/3/library/urllib.parse.html", ["151.101.0.223"]],
	["https://www.google.com/search?q=select+from+where", ["142.250.80.68"]],
	["https://en.wikipedia.org/wiki/Caf%C3%A9", ["198.35.26.96"]],
	["https://raw.githubusercontent.com/user/repo/main/README.md", ["185.199.108.133"]],
	["https://status.slack.com/api/v2.0.0/current", ["54.89.10.20"]],
	["https://api.openai.com/v1/models", ["104.18.7.192"]],
	["https://api.anthropic.com/v1/messages", ["160.79.104.10"]],
	["https://login.microsoftonline.com/common/oauth2/v2.0/token", ["20.190.151.68"]],
	["https://www.bbc.co.uk/news", ["151.101.0.81"]],
	["https://www.nytimes.com/section/technology", ["151.101.1.164"]],
	["https://pypi.org/simple/requests/", ["151.101.0.223"]],
	["https://registry.npmjs.org/express", ["104.16.24.34"]],
	["https://proxy.golang.org/github.com/go-chi/chi/v5/@v/list", ["142.250.80.81"]],
	["https://api.nuget.org/v3/index.json", ["152.199.4.184"]],
	["https://twitter.com/home", ["104.244.42.1"]],
	["https://www.amazon.com/dp/B000000000", ["205.251.242.103"]],
	["https://maps.googleapis.com/maps/api/geocode/json?address=S%C3%A3o+Paulo", ["142.250.80.10"]],
	["https://upload.wikimedia.org/wikipedia/commons/a/a9/Example.jpg", ["198.35.26.112"]],
	["http://www.example.net/insecure-but-public", ["93.184.216.34"]],
	["https://[2606:2800:220:1:248:1893:25c8:1946]/", ["2606:2800:220:1:248:1893:25c8:1946"]],
	["https://1.1.1.1/dns-query", ["1.1.1.1"]],
	["https://8.8.8.8/resolve?name=example.com", ["8.8.8.8"]],
	["https://shop.example.co.jp/商品/123", ["93.184.216.34"]],
];

const modelAnswers = [
	"Sure! Here is a summary of your order history.\n\n- 3 orders this month\n- Total: $120.50",
	"The capital of France is Paris. It is known for the Eiffel Tower.",
	"To list all users, you can run:\n\n```sql\nSELECT id, name FROM users ORDER BY name\n```\n\nThis returns every user sorted by name.",
	"Here is a Python function:\n\n```python\ndef add(a, b):\n    return a + b\n```",
	"| Name | Score |\n|---|---|\n| Alice | 90 |\n| Bob | 85 |",
	"I'm sorry, I can't help with that request.",
	"**Step 1:** Open settings.\n**Step 2:** Click *Privacy*.\n**Step 3:** Toggle the switch.",
	"Your meeting with O'Brien is scheduled for 2026-10-30 at 10:00.",
	"Voici la réponse : la réunion est à 15 h.",
	"答案是：明天下午三点开会。",
	"```json\n{\"status\": \"ok\", \"items\": [1, 2, 3]}\n```",
	"Use `git status` to see changed files, then `git commit -m \"message\"`.",
	"The function returns null when the list is empty, and true otherwise.",
	"Drop the eggs into boiling water and wait 7 minutes.",
	"Select a plan below and update your billing details to continue.",
];

// ---- helpers ---------------------------------------------------------------

const req = (value, key) => ({ value, key, source: "request" });
const model = (value) => ({ value, key: "model.completion", source: "model_output" });
const sqlLit = (v, dialect) => {
	let s = v.replace(/'/g, "''");
	if (dialect === "mysql") s = s.replace(/\\/g, "\\\\");
	return `'${s}'`;
};
const shQuote = (v) => `'${v.replace(/'/g, "'\\''")}'`;
const jsStr = (v) => JSON.stringify(v);
const xmlEsc = (v) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const htmlEsc = (v) => xmlEsc(v).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const dialects = ["generic", "postgres", "mysql", "sqlite", "mssql"];

// ---- SQL -------------------------------------------------------------------

const sql = [];
allValues.forEach((v, i) => {
	const d = dialects[i % dialects.length];
	const inputs = [req(v, "query.q")];
	sql.push({ name: `literal equals ${i}`, dialect: d, query: `SELECT id, name FROM customers WHERE name = ${sqlLit(v, d)}`, inputs });
	sql.push({ name: `literal like ${i}`, dialect: d, query: `SELECT id FROM products WHERE title LIKE ${sqlLit(`%${v}%`, d)} LIMIT 20`, inputs });
	sql.push({ name: `insert ${i}`, dialect: d, query: `INSERT INTO notes (owner_id, body, created_at) VALUES (42, ${sqlLit(v, d)}, CURRENT_TIMESTAMP)`, inputs: [req(v, "body.note")] });
	sql.push({ name: `update ${i}`, dialect: d, query: `UPDATE profiles SET display_name = ${sqlLit(v, d)} WHERE id = 7`, inputs: [req(v, "body.displayName")] });
	sql.push({ name: `parameterised ${i}`, dialect: d, query: d === "postgres" ? "SELECT * FROM customers WHERE name = $1 AND status = $2" : d === "mssql" ? "SELECT * FROM customers WHERE name = @name" : "SELECT * FROM customers WHERE name = ? AND status = ?", inputs });
});
for (const sort of ["name desc", "created_at asc", "price DESC", "updated_at", "name"]) {
	sql.push({ name: `sort ${sort}`, dialect: "postgres", query: `SELECT id, name FROM products ORDER BY ${sort} LIMIT 50`, inputs: [req(sort, "query.sort")] });
}
for (const cols of ["id,name,email", "id, name, created_at", "sku,price"]) {
	sql.push({ name: `column list ${cols}`, dialect: "generic", query: `SELECT ${cols} FROM products`, inputs: [req(cols, "query.fields")] });
}
for (const n of ["100", "2500", "12345678", "3.14159"]) {
	sql.push({ name: `numeric ${n}`, dialect: "mysql", query: `SELECT * FROM orders WHERE total > ${n} LIMIT 10`, inputs: [req(n, "query.min")] });
}
for (const t of ["public.users", "analytics.events_2026"]) {
	sql.push({ name: `qualified ${t}`, dialect: "postgres", query: `SELECT count(*) FROM ${t}`, inputs: [req(t, "query.table")] });
}
sql.push({ name: "model text-to-sql read-only", dialect: "postgres", query: "SELECT id, name FROM users ORDER BY name", inputs: [model(modelAnswers[2])] });
modelAnswers.forEach((a, i) => {
	sql.push({ name: `model answer bound ${i}`, dialect: "sqlite", query: "INSERT INTO chat_messages (role, content) VALUES (?, ?)", inputs: [model(a)] });
});
sql.push({ name: "console full query", dialect: "postgres", query: "SELECT id, email FROM users WHERE active = true", inputs: [req("SELECT id, email FROM users WHERE active = true", "body.sql")] });

// Oracle: q'…' alternative quoting (the value may hold a single quote),
// nq'…' and N'…' national strings, optimizer hints, :name and :1 binds,
// identifiers with # and $, no backslash escapes.
const qDelims = [["[", "]"], ["{", "}"], ["(", ")"], ["<", ">"], ["!", "!"], ["|", "|"]];
const qLit = (v, i, national = false) => {
	const [o, c] = qDelims.find(([, cl], k) => k >= i % qDelims.length && !v.includes(`${cl}'`)) ?? qDelims.find(([, cl]) => !v.includes(`${cl}'`));
	return `${national ? "nq" : "q"}'${o}${v}${c}'`;
};
allValues.forEach((v, i) => {
	const inputs = [req(v, "query.q")];
	const t = [
		{ name: `oracle q-quote hint ${i}`, query: `SELECT /*+ INDEX(c cust_name_ix) */ id, name FROM customers c WHERE name = ${qLit(v, i)} AND ROWNUM <= 20` },
		{ name: `oracle nq-quote like ${i}`, query: `SELECT id FROM products WHERE title LIKE ${qLit(`%${v}%`, i, true)} FETCH FIRST 20 ROWS ONLY` },
		{ name: `oracle national insert ${i}`, query: `INSERT INTO notes (note#, owner_id, body, created_at) VALUES (notes_seq.NEXTVAL, :1, N${sqlLit(v, "oracle")}, SYSTIMESTAMP)` },
		{ name: `oracle update bind ${i}`, query: `UPDATE profiles SET display_name = ${sqlLit(v, "oracle")} WHERE id = :id -- profile rename` },
	][i % 4];
	sql.push({ ...t, dialect: "oracle", inputs });
});
// DB2: X'…' hex, G'…' / N'…' graphic strings, ? and :host parameters.
allValues.forEach((v, i) => {
	const inputs = [req(v, "query.q")];
	const t = [
		{ name: `db2 graphic equals ${i}`, query: `SELECT id, name FROM customers WHERE name = G${sqlLit(v, "db2")} FETCH FIRST 20 ROWS ONLY WITH UR` },
		{ name: `db2 national like ${i}`, query: `SELECT id FROM products WHERE title LIKE N${sqlLit(`%${v}%`, "db2")} OPTIMIZE FOR 20 ROWS` },
		{ name: `db2 insert hex ${i}`, query: `INSERT INTO notes (owner_id, body, flags, created_at) VALUES (42, ${sqlLit(v, "db2")}, X'0A1B', CURRENT TIMESTAMP)` },
		{ name: `db2 update host variable ${i}`, query: `UPDATE profiles SET display_name = ${sqlLit(v, "db2")} WHERE id = :hvId /* rename */` },
	][i % 4];
	sql.push({ ...t, dialect: "db2", inputs });
});
const enterprise = [
	["oracle", "oracle positional binds", "SELECT * FROM customers WHERE name = :1 AND status = :2", "O'Brien"],
	["oracle", "oracle named binds", "SELECT emp#, ename FROM scott.emp WHERE deptno = :dept AND hiredate > :since", "Accounting"],
	["oracle", "oracle q-quote with quotes inside", "SELECT id FROM notes WHERE body = q'[It's O'Brien's turn]'", "It's O'Brien's turn"],
	["oracle", "oracle q-quote custom delimiter", "SELECT id FROM notes WHERE body = Q'#Don't stop#'", "Don't stop"],
	["oracle", "oracle hint and line comment", "SELECT /*+ FIRST_ROWS(10) PARALLEL(o, 4) */ o.id FROM orders o -- recent\nWHERE o.customer = 'D''Angelo'", "D'Angelo"],
	["oracle", "oracle backslash is literal", "SELECT id FROM files WHERE path = 'C:\\temp\\' AND owner = 'O''Neil'", "C:\\temp\\"],
	["oracle", "oracle dictionary view", "SELECT sid, username FROM v$session WHERE username = :usr", "SYSTEM"],
	["oracle", "oracle sort with hash column", "SELECT emp#, ename FROM scott.emp ORDER BY emp# desc", "emp# desc"],
	["oracle", "oracle q-quote multibyte delimiter", "SELECT id FROM notes WHERE body = q'§It's O'Brien's§'", "It's O'Brien's"],
	["db2", "db2 nested block comment", "SELECT id /* audit /* v2 */ it's nested */ FROM customers WHERE name = 'O''Brien'", "O'Brien"],
	["postgres", "postgres nested block comment", "SELECT id /* note /* inner */ don't drop */ FROM customers WHERE name = 'D''Angelo'", "D'Angelo"],
	["oracle", "oracle merge with binds", "MERGE INTO prices p USING (SELECT :sku AS sku FROM dual) s ON (p.sku = s.sku) WHEN MATCHED THEN UPDATE SET p.amount = :amt", "SKU 4471-B"],
	["db2", "db2 parameter markers", "SELECT * FROM customers WHERE name = ? AND status = ?", "O'Brien"],
	["db2", "db2 hex string value", "SELECT id FROM blobs WHERE digest = X'48656C6C6F'", "48656C6C6F"],
	["db2", "db2 graphic hex string", "SELECT id FROM labels WHERE code = GX'FF21FF22' AND name = G'Zoë'", "FF21FF22"],
	["db2", "db2 host variables", "SELECT id INTO :hvId FROM orders WHERE ref = :hvRef -- embedded SQL", "ORD-2026-000123"],
	["db2", "db2 escaped quote", "SELECT id FROM customers WHERE name = 'Mary-Kate O''Connor' FETCH FIRST 1 ROW ONLY", "Mary-Kate O'Connor"],
	["db2", "db2 qualified quoted identifiers", "SELECT \"ID\", \"NAME\" FROM \"PAYROLL\".\"EMP#\" WHERE dept = 'Grant writing'", "PAYROLL"],
	["db2", "db2 sort parameter", "SELECT id, name FROM products ORDER BY name desc FETCH FIRST 50 ROWS ONLY", "name desc"],
	["mssql", "mssql escaped bracket identifier", "SELECT [order]]id], [name] FROM [dbo].[orders]]2026] WHERE name = N'O''Brien'", "O'Brien"],
];
for (const [dialect, name, query, value] of enterprise) {
	sql.push({ name, dialect, query, inputs: [req(value, "query.q")] });
}

// ---- NoSQL -----------------------------------------------------------------

const nosql = [];
names.concat(misc.slice(0, 10)).forEach((v, i) => {
	nosql.push({ name: `equality ${i}`, filter: { email: v, active: true }, body: { email: v }, query: {} });
});
nosql.push({ name: "range from server constant", filter: { age: { $gte: 18 }, country: "IE" }, body: { country: "IE" }, query: {} });
nosql.push({ name: "in list from server", filter: { status: { $in: ["open", "pending"] } }, body: { status: "open" }, query: {} });
nosql.push({ name: "or of literals", filter: { $or: [{ name: "O'Brien" }, { nickname: "O'Brien" }] }, body: { name: "O'Brien" }, query: {} });
nosql.push({ name: "update set", filter: { _id: "665f1c2e9b1e8a0012345678" }, update: { $set: { title: "Rock and roll" } }, body: { title: "Rock and roll" }, query: { id: "665f1c2e9b1e8a0012345678" } });
nosql.push({ name: "regex built by server with escaped prefix", filter: { name: { $regex: "^Jos", $options: "i" } }, body: { prefix: "Jos" }, query: {} });
nosql.push({ name: "where clause constant", filter: { $where: "this.stock > this.reserved" }, body: { q: "stock" }, query: {} });

// ---- Command ---------------------------------------------------------------

const command = [];
fileNames.forEach((f, i) => {
	command.push({ name: `convert quoted ${i}`, command: `convert ${shQuote(`/srv/app/uploads/${f}`)} -resize 50% /srv/app/thumbs/out-${i}.png`, inputs: [req(f, "body.file")] });
	command.push({ name: `pdftotext quoted ${i}`, command: `pdftotext ${shQuote(f)} -`, inputs: [req(f, "query.name")] });
	command.push({ name: `argv ${i}`, argv: ["ffmpeg", "-i", `/srv/app/uploads/${f}`, "-vn", "out.mp3"], inputs: [req(f, "body.file")] });
});
names.forEach((n, i) => {
	command.push({ name: `git author argv ${i}`, argv: ["git", "log", "--author", n, "--oneline"], inputs: [req(n, "query.author")] });
	command.push({ name: `grep quoted ${i}`, command: `grep -F ${shQuote(n)} /srv/app/data/contacts.txt`, inputs: [req(n, "query.q")] });
});
command.push({ name: "grep alternation inside quotes", command: "grep -E 'error|warn' /var/log/app.log", inputs: [req("error|warn", "query.pattern")] });
command.push({ name: "double quoted with spaces", command: "zip -r \"/srv/backups/Q3 results.zip\" /srv/app/reports", inputs: [req("Q3 results", "body.label")] });
command.push({ name: "model answer prose with backticks", command: "git status --short", inputs: [model(modelAnswers[11])] });
command.push({ name: "model single command whole", command: "git status", inputs: [model("git status")] });

// ---- Path ------------------------------------------------------------------

const path = [];
const root = "/srv/app/uploads";
fileNames.forEach((f, i) => {
	path.push({ name: `read in root ${i}`, op: "read", path: `${root}/${f}`, fileRoots: [root], inputs: [req(f, "query.file")] });
	path.push({ name: `write in root ${i}`, op: "write", path: `${root}/${f}`, fileRoots: [root], inputs: [req(f, "body.file")] });
	path.push({ name: `read no roots ${i}`, op: "read", path: `/var/data/tenant-7/${f}`, fileRoots: [], inputs: [req(f, "query.file")] });
});
path.push({ name: "untainted absolute config read", op: "read", path: "/etc/app/config.yaml", fileRoots: [], inputs: [req("config", "query.section")] });
path.push({ name: "untainted system file outside request input", op: "read", path: "/etc/passwd", fileRoots: [], inputs: [req("report.pdf", "query.file")] });
path.push({ name: "listing in root", op: "list", path: `${root}/2026/10`, fileRoots: [root], inputs: [req("2026/10", "query.dir")] });

// ---- SSRF ------------------------------------------------------------------

const ssrf = [];
publicUrls.forEach(([u, addrs], i) => {
	ssrf.push({ name: `public url input ${i}`, url: u, resolved: addrs, inputs: [req(u, "body.url")] });
	const host = new URL(u).hostname.replace(/^\[|\]$/g, "");
	ssrf.push({ name: `public host input ${i}`, url: u, resolved: addrs, inputs: [req(host, "query.host")] });
});
ssrf.push({ name: "untainted internal service", url: "http://10.0.0.5:8080/internal/health", resolved: ["10.0.0.5"], inputs: [req("health", "query.check")] });
ssrf.push({ name: "untainted metadata (SDK credentials)", url: "http://169.254.169.254/latest/api/token", resolved: ["169.254.169.254"], inputs: [req("report.pdf", "query.file")] });
ssrf.push({ name: "path input on public host", url: "https://api.github.com/users/octocat", resolved: ["140.82.112.6"], inputs: [req("octocat", "query.user")] });
ssrf.push({ name: "model answer with public link", url: "https://www.wikipedia.org/wiki/Paris", resolved: ["198.35.26.96"], inputs: [model("Read more at https://www.wikipedia.org/wiki/Paris")] });

// ---- Code ------------------------------------------------------------------

const code = [];
allValues.forEach((v, i) => {
	code.push({ name: `string literal ${i}`, code: `render(${jsStr(v)})`, inputs: [req(v, "query.name")] });
});
code.push({ name: "numeric arg", code: "compute(42)", inputs: [req("42", "query.n"), model("The answer is 42.")] });
code.push({ name: "model prose", code: "summarise(items)", inputs: [model(modelAnswers[1])] });

// ---- XML -------------------------------------------------------------------

const xml = [];
allValues.forEach((v, i) => {
	const doc = `<?xml version="1.0" encoding="UTF-8"?><order><customer>${xmlEsc(v)}</customer><qty>2</qty></order>`;
	xml.push({ name: `plain document ${i}`, xml: doc, resolvesExternal: true, inputs: [req(doc, "body")] });
});
const internalDtd = '<?xml version="1.0"?><!DOCTYPE note [<!ELEMENT note (#PCDATA)>]><note>Hello</note>';
xml.push({ name: "internal subset without entities", xml: internalDtd, resolvesExternal: true, inputs: [req(internalDtd, "body")] });
const oneEntity = '<?xml version="1.0"?><!DOCTYPE note [<!ENTITY company "Acme Ltd">]><note>&company;</note>';
xml.push({ name: "one internal text entity", xml: oneEntity, resolvesExternal: true, inputs: [req(oneEntity, "body")] });

// ---- Deserialization -------------------------------------------------------

const deser = [];
names.forEach((v, i) => {
	const y = `name: ${JSON.stringify(v)}\ntags:\n  - customer\n  - vip\n`;
	deser.push({ name: `yaml config ${i}`, format: "yaml", data: y, inputs: [req(y, "body")] });
	const j = JSON.stringify({ name: v, items: [{ sku: "A1", qty: 2 }] });
	deser.push({ name: `jsonpickle plain json ${i}`, format: "jsonpickle", data: j, inputs: [req(j, "body")] });
	deser.push({ name: `typename plain json ${i}`, format: "typename", data: j, inputs: [req(j, "body")] });
	deser.push({ name: `node-serialize plain ${i}`, format: "node_serialize", data: j, inputs: [req(j, "body")] });
});
deser.push({ name: "untainted pickle (model cache from disk)", format: "pickle", data: "gASVAAAAAAAAAAA=", dataEncoding: "base64", inputs: [req("report.pdf", "query.file")] });
// Java serialization the app wrote itself (a session cache): no input in it.
deser.push({ name: "untainted java stream (session cache)", format: "java", data: "rO0ABXQABWhlbGxv", dataEncoding: "base64", inputs: [req("report.pdf", "query.file")] });
deser.push({ name: "java stream unrelated to a short input", format: "java", data: "rO0ABXQABWhlbGxv", dataEncoding: "base64", inputs: [req("en", "query.lang")] });
// SnakeYAML with standard tags, version numbers and dotted values that are not a tag.
const snake = [
	"name: !!str 12345\nqty: !!int \"2\"\n",
	"version: 1.2.3\nimage: registry.example.com/app:1.4\n",
	"price: !!float 9.99\ncreated: !!timestamp 2026-10-30\n",
	"logo: !!binary R0lGODlhAQABAAAAACw=\n",
	"items: [!!str a.b, plain.value]\nnote: Wow!!Great.news\n",
	"package: com.example.orders\nmain: com.example.orders.Main\n",
];
snake.forEach((y, i) => {
	deser.push({ name: `snakeyaml config ${i}`, format: "snakeyaml", data: y, inputs: [req(y, "body")] });
});

// ---- XSS -------------------------------------------------------------------

const xss = [];
allValues.filter((v) => v.length >= 15).forEach((v, i) => {
	xss.push({ name: `escaped reflection ${i}`, contentType: "text/html; charset=utf-8", body: `<html><body><h1>Results for ${htmlEsc(v)}</h1></body></html>`, inputs: [req(v, "query.q")] });
	xss.push({ name: `verbatim prose reflection ${i}`, contentType: "text/html", body: `<p>You searched for: ${v}</p>`, inputs: [req(v, "query.q")] });
});
modelAnswers.forEach((a, i) => {
	xss.push({ name: `json api response ${i}`, contentType: "application/json", body: JSON.stringify({ answer: a }), inputs: [model(a)] });
});

// ---- Virtual patches (requests that must not match any built-in rule) -------

const requests = [];
const bodies = [
	"", "{\"name\":\"O'Brien\"}", "[\"$K1\",\"hello\"]", "a=1&b=two", "{\"model\":\"gpt\",\"messages\":[]}",
	"{\"constructor\":\"Acme\"}", "{\"then\":\"later\"}", "{\"form\":{\"get\":true}}", "{\"resolved\":true,\"model\":\"x\"}",
];
bodies.forEach((b, i) => {
	requests.push({ name: `next server action ${i}`, method: "POST", path: "/checkout", query: "", headers: { "next-action": "7f3a9c", "content-type": "text/plain;charset=UTF-8" }, cookie: "session=abc", body: b });
	requests.push({ name: `plain post ${i}`, method: "POST", path: "/api/orders", query: "", headers: { "content-type": "application/json", "content-encoding": "gzip" }, cookie: "", body: b });
	requests.push({ name: `get ${i}`, method: "GET", path: "/api/orders/42", query: "page=2&sort=name%20desc", headers: { "user-agent": "Mozilla/5.0", "accept-encoding": "gzip, deflate, br" }, cookie: "theme=dark", body: "" });
});

// SHIELD: template section (README "Template source"); every SDK runs it with the shared engine table.
const template = [];
for (const [engine, source] of [
  ["handlebars", "Hello {{name}}"], ["ejs", "Hello <%= name %>"],
  ["pug", "p Hello #{name}"], ["nunjucks", "Hello {{ name }}"], ["lodash", "Hello <%= name %>"],
  ["jinja2", "Hello {{ name }}"], ["minijinja", "Hello {{ name }}"], ["tera", "Hello {{ name }}"],
  ["twig", "Hello {{ name }}"], ["pebble", "Hello {{ name }}"], ["django", "Hello {{ name }}"],
  ["liquid", "Hello {{ name }}"], ["scriban", "Hello {{ name }}"], ["gotemplate", "Hello {{ .name }}"],
  ["mako", "Hello ${name}"], ["freemarker", "Hello ${name}"], ["velocity", "Hello $name"],
  ["thymeleaf", "<p th:text=\"${name}\">Hello</p>"], ["smarty", "Hello {$name}"], ["blade", "Hello {{ $name }}"],
]) {
  for (const value of ["Alice", "O'Brien", "{{ 7 * 7 }}", "<%= 1 + 2 %>", "#{1 + 2}"]) {
    template.push({ name: `${engine} data ${value}`, engine, template: source, data: { name: value }, inputs: [req(value, "body.name")] });
  }
  template.push({ name: `${engine} literal prose`, engine, template: "Welcome ordinary prose", inputs: [req("ordinary prose", "query.q")] });
  template.push({ name: `${engine} fixed variable`, engine, template: source, inputs: [req("name", "query.q")] });
}
// Fixed templates whose literal (comment, raw, escaped) or single-token parts equal a data value.
for (const [engine, source, value] of [
  ["handlebars", "Hello {{user.name}}", "user.name"], ["ejs", "Hello <%= user.name %>", "user.name"],
  ["handlebars", '{{shout "a }} b"}} done', "a }} b"], ["nunjucks", '{{ "a }} b" | upper }} done', "a }} b"],
  ["handlebars", "Show \\{{name}} literally", "{{name}}"], ["nunjucks", "Hi {# note {{ a + b }} #}", "{{ a + b }}"],
  ["pug", "a(href=url) Link", "url"], ["pug", "a(title=\"O'Brien here\") Link", "O'Brien here"],
  ["nunjucks", "{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}"],
  ["jinja2", "{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}"], ["jinja2", "Hi {# note {{ a + b }} #}", "{{ a + b }}"],
  ["jinja2", '{{ "a }} b" | upper }} done', "a }} b"], ["minijinja", "{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}"],
  ["tera", "{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}"], ["twig", "{% verbatim %}{{ a + b }}{% endverbatim %}", "{{ a + b }}"],
  ["twig", "Hi {# note {{ a + b }} #}", "{{ a + b }}"], ["pebble", "{% verbatim %}{{ a + b }}{% endverbatim %}", "{{ a + b }}"],
  ["django", "{% verbatim %}{{ a + b }}{% endverbatim %}", "{{ a + b }}"],
  ["django", "{% comment %}{{ a + b }}{% endcomment %}", "{{ a + b }}"], ["django", "Hello {{ user.name }}", "user.name"],
  ["liquid", "{% raw %}{{ a + b }}{% endraw %}", "{{ a + b }}"], ["liquid", "{% comment %}{{ a + b }}{% endcomment %}", "{{ a + b }}"],
  ["scriban", "{%{ {{ a + b }} }%}", "{{ a + b }}"], ["gotemplate", "{{/* {{ a }} + b */}} done", "{{ a }} + b"],
  ["gotemplate", '{{ printf "a }} b" }} done', "a }} b"], ["gotemplate", "Hello {{ .user.name }}", "user.name"],
  ["mako", "## note ${a + b}\nHello", "${a + b}"], ["mako", "<%text>${a + b}</%text>", "${a + b}"],
  ["mako", "<%doc>${a + b}</%doc>", "${a + b}"], ["mako", "Hello ${user.name}", "user.name"],
  ["mako", "%% not code ${name}", "not code"],
  ["freemarker", "<#-- ${a + b} -->", "${a + b}"], ["freemarker", "<#noparse>${a + b}</#noparse>", "${a + b}"],
  ["freemarker", "Hello ${user.name}", "user.name"],
  ["velocity", "#* ${a + b} *#", "${a + b}"], ["velocity", "#[[ ${a + b} ]]#", "${a + b}"],
  ["velocity", "## note ${a + b}\nHello", "${a + b}"], ["velocity", "Show \\${a + b} literally", "${a + b}"],
  ["velocity", "Hello $user.name", "user.name"], ["velocity", "Mail user@example.com today", "user@example.com"],
  ["thymeleaf", "<!--/* [[${a + b}]] */--><p>x</p>", "[[${a + b}]]"], ["thymeleaf", "<p th:text=\"${user.name}\">x</p>", "user.name"],
  ["thymeleaf", "<p class=\"text here\">x</p>", "text here"],
  ["thymeleaf", "<p>${a + b}</p>", "${a + b}"], ["jinja2", "{%- raw -%}{{ a + b }}{%endraw%}", "{{ a + b }}"],
  ["nunjucks", "{%- raw %}{{ a + b }}{% endraw -%}", "{{ a + b }}"], ["liquid", "{%- comment -%}{{ a + b }}{%- endcomment -%}", "{{ a + b }}"],
  ["smarty", "{literal}{$a + $b}{/literal}", "{$a + $b}"], ["smarty", "{* {$a + $b} *}", "{$a + $b}"],
  ["smarty", "a { color: red }", "{ color: red }"], ["smarty", "Hello {$user.name}", "user.name"],
  ["blade", "@{{ a + b }}", "{{ a + b }}"], ["blade", "{{-- {{ a + b }} --}}", "{{ a + b }}"],
  ["blade", "@verbatim{{ a + b }}@endverbatim", "{{ a + b }}"], ["blade", "Mail user@example.com today", "user@example.com"],
]) {
  template.push({ name: `${engine} fixed ${source}`, engine, template: source, inputs: [req(value, "body.name")] });
}

const corpus = {
	comment:
		"Shared RASP false-positive corpus (sdk/rasp/README.md, Fixtures). Generated by sdk/rasp/scripts/gen-benign.mjs; do not edit by hand. Every case must produce no detection in every SDK. request inputs go through the SDK's input normaliser (percent-decoded forms added); model_output inputs are raw model text registered through the SDK's model-output fragmenter.",
	version: 1,
	sql, nosql, command, path, ssrf, code, template, xml, deser, xss, requests,
};
writeFileSync(out, JSON.stringify(corpus, null, 1) + "\n");
const counts = Object.fromEntries(Object.entries(corpus).filter(([, v]) => Array.isArray(v)).map(([k, v]) => [k, v.length]));
console.log(out, counts, "total", Object.values(counts).reduce((a, b) => a + b, 0));
