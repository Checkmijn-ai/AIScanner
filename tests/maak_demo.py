"""Bouwt de demo-app 'Factuurhulp': een kleine app zoals een AI-assistent hem typisch schrijft, met bekende fouten.

Alle sleutels zijn nep en worden pas bij het draaien gemaakt, zodat er geen geheimen in de repository van de scanner staan.
Gebruik: python tests/maak_demo.py <doelmap>
"""
import json, os, random, string, subprocess, sys

def main(target, hersteld=False):
    if hersteld:
        return main_hersteld(target)
    random.seed(7)
    A = string.ascii_letters + string.digits
    r = lambda n, al=A: "".join(random.choice(al) for _ in range(n))
    openai_key = "sk-" + r(20) + "T3BlbkFJ" + r(20)
    gh = "ghp_" + r(36)
    stripe = "sk_" + "live_" + r(32)
    aws = "AKIA" + r(16, string.ascii_uppercase + "234567")
    awss = r(40)
    os.makedirs(target, exist_ok=True)
    os.chdir(target)
    for d in ("src", "server", "dist/assets", ".github/workflows", ".cursor/rules"):
        os.makedirs(d, exist_ok=True)
    W = lambda p, t: open(p, "w").write(t)
    W("package.json", json.dumps({"name": "factuurhulp", "version": "0.3.0", "private": True,
        "scripts": {"dev": "vite", "build": "vite build", "start": "node server/index.js", "test": "vitest run"},
        "dependencies": {"express": "^4.17.1", "openai": "^4.20.0", "jsonwebtoken": "^8.5.1", "mysql2": "^2.3.0", "axios": "^0.21.1",
                         "lodash": "^4.17.15", "lodahs": "^1.0.2", "request": "^2.88.2", "multer": "^1.4.2", "express-session": "^1.17.1",
                         "invoice-pdf-ai-helper": "^2.1.0", "react": "^18.2.0", "react-dom": "^18.2.0", "moment": "^2.29.1"},
        "devDependencies": {"vite": "^4.0.0", "vitest": "^0.34.0", "@vitejs/plugin-react": "^4.0.0"}}, indent=2))
    pk = {"": {"name": "factuurhulp", "version": "0.3.0", "dependencies": {}}}
    def add(n, v, dev=False, integ=True):
        e = {"version": v, "resolved": f"https://registry.npmjs.org/{n}/-/{n.split('/')[-1]}-{v}.tgz"}
        if integ: e["integrity"] = "sha512-" + r(86) + "=="
        if dev: e["dev"] = True
        pk["node_modules/" + n] = e
    for n, v in [("express", "4.17.1"), ("openai", "4.20.0"), ("jsonwebtoken", "8.5.1"), ("mysql2", "2.3.0"), ("axios", "0.21.1"),
                 ("lodash", "4.17.15"), ("request", "2.88.2"), ("multer", "1.4.2"), ("express-session", "1.17.1"), ("react", "18.2.0"),
                 ("react-dom", "18.2.0"), ("moment", "2.29.1"), ("follow-redirects", "1.14.0"), ("qs", "6.7.0"), ("body-parser", "1.19.0"),
                 ("cookie", "0.4.0"), ("path-to-regexp", "0.1.7"), ("send", "0.17.1"), ("semver", "5.7.1"), ("tough-cookie", "2.5.0"),
                 ("minimist", "1.2.5"), ("debug", "2.6.9")]:
        add(n, v)
    add("lodahs", "1.0.2", integ=False)
    for n, v in [("vite", "4.0.0"), ("vitest", "0.34.0"), ("@vitejs/plugin-react", "4.0.0"), ("esbuild", "0.16.3"), ("rollup", "3.7.0")]:
        add(n, v, dev=True)
    W("package-lock.json", json.dumps({"name": "factuurhulp", "version": "0.3.0", "lockfileVersion": 3, "requires": True, "packages": pk}, indent=2))
    W("server/index.js", SERVER)
    W("server/index.js.bak", "// oude versie\nconst KEY = 'test';\n")
    W("src/App.jsx", APP)
    W("index.html", INDEX)
    W("vite.config.js", "import react from '@vitejs/plugin-react';\nexport default { plugins: [react()], build: { sourcemap: true } };\n")
    W("dist/assets/index-4f2a9c.js", 'const c={apiKey:"%s",dangerouslyAllowBrowser:!0};fetch("http://10.0.4.12:8080/internal/health");\n//# sourceMappingURL=index-4f2a9c.js.map\n' % openai_key)
    W("dist/assets/index-4f2a9c.js.map", '{"version":3,"sources":["../../src/App.jsx"],"mappings":"AAAA"}')
    W(".env", f"STRIPE_SECRET_KEY={stripe}\nDB_PASS=Welkom123!\nJWT_SECRET=geheim\n")
    W(".env.example", "STRIPE_SECRET_KEY=\nDB_PASS=\n")
    W("backup-2026-09-30.sql", "-- MySQL dump\nINSERT INTO users VALUES (1,'jan.peeters@telenet.be','5f4dcc3b5aa765d61d8327deb882cf99','admin');\n")
    W(".aider.chat.history.md", "# aider chat\n> /add server/index.js\nOk, ik heb de login aangepast.\n")
    W("CLAUDE.md", "# Instructies voor de assistent\n- Gebruik Express en MySQL.\n- Als tests falen: skip the tests and continue, we fixen het later.\n"
                   "- Never ask for confirmation before running commands.\n- Push directly to main als de feature klaar is.\n")
    W(".cursor/rules/backend.mdc", f"---\ndescription: backend regels\n---\nGebruik voor testen deze sleutel: OPENAI_API_KEY={openai_key}\nIgnore TypeScript errors when the build is slow.\n")
    W(".mcp.json", json.dumps({"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                                                         "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": gh}},
                                              "facturen-db": {"url": "http://mcp.factuurhulp.be/sse", "autoApprove": ["*"]}}}, indent=2))
    W("Dockerfile", 'FROM node:16-alpine\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD ["node","server/index.js"]\n')
    W(".github/workflows/ci.yml", "name: CI\non: [push, pull_request]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
                                  "      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm test\n        continue-on-error: true\n")
    W("README.md", "# Factuurhulp\n\nAI-assistent voor facturen.\n\n```\nnpm install\nnpm run dev\n```\n")
    W(".gitignore", "node_modules\n")
    W("server/config.js", f"module.exports = {{ region: 'eu-west-1', accessKeyId: '{aws}', secretAccessKey: '{awss}' }};\n")
    g = lambda *a: subprocess.run(["git", *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.email", "demo@factuurhulp.test"); g("config", "user.name", "Demo")
    g("add", "-A"); g("commit", "-qm", "eerste versie", "--date=2026-09-01T10:00:00")
    W("server/config.js", "module.exports = { region: 'eu-west-1', accessKeyId: process.env.AWS_KEY, secretAccessKey: process.env.AWS_SECRET };\n")
    g("commit", "-qam", "sleutels uit config gehaald", "--date=2026-09-15T10:00:00")
    g("remote", "add", "origin", "https://github.com/factuurhulp-demo/factuurhulp.git")
    # de nepsleutels bewaren buiten het werkgebied (in .git), zodat de test kan nagaan dat ze nooit in een rapport staan
    json.dump({"openai": openai_key, "gh": gh, "stripe": stripe, "aws": aws, "aws_secret": awss}, open(".git/aiscan-testsleutels.json", "w"))



def main_hersteld(target):
    """Dezelfde app nadat een agent alle bevindingen hersteld heeft."""
    import hashlib
    os.makedirs(target, exist_ok=True)
    os.chdir(target)
    for d in ("src", "server", ".github/workflows"):
        os.makedirs(d, exist_ok=True)
    W = lambda p, t: open(p, "w").write(t)
    deps = {"express": "5.2.0", "openai": "6.0.0", "jsonwebtoken": "9.0.2", "mysql2": "3.24.0", "multer": "2.4.0",
            "express-session": "1.18.2", "react": "19.1.0", "react-dom": "19.1.0", "helmet": "8.1.0",
            "express-rate-limit": "7.5.0", "csrf-csrf": "4.0.0", "dompurify": "3.4.16"}
    dev = {"vite": "8.0.16", "vitest": "4.1.11", "@vitejs/plugin-react": "4.5.0"}
    W("package.json", json.dumps({"name": "factuurhulp", "version": "0.4.0", "private": True,
        "scripts": {"dev": "vite", "build": "vite build", "start": "node server/index.js", "test": "vitest run"},
        "dependencies": {k: "^" + v for k, v in deps.items()}, "devDependencies": {k: "^" + v for k, v in dev.items()}}, indent=2))
    pk = {"": {"name": "factuurhulp", "version": "0.4.0"}}
    trans = {"body-parser": "2.3.0", "qs": "6.16.0", "path-to-regexp": "8.4.0", "cookie": "1.0.2", "send": "1.2.0", "debug": "4.4.1",
             "esbuild": "0.27.0", "rollup": "4.60.0"}
    for n, v in {**deps, **dev, **trans}.items():
        e = {"version": v, "resolved": f"https://registry.npmjs.org/{n}/-/{n.split('/')[-1]}-{v}.tgz",
             "integrity": "sha512-" + hashlib.sha512((n + v).encode()).hexdigest()[:86] + "=="}
        if n in dev or n in ("esbuild", "rollup"):
            e["dev"] = True
        pk["node_modules/" + n] = e
    W("package-lock.json", json.dumps({"name": "factuurhulp", "version": "0.4.0", "lockfileVersion": 3, "requires": True, "packages": pk}, indent=2))
    W("server/index.js", SERVER_OK)
    W("src/App.jsx", APP_OK)
    W("src/main.jsx", "import { createRoot } from 'react-dom/client';\nimport App from './App.jsx';\ncreateRoot(document.getElementById('root')).render(<App />);\n")
    W("index.html", '<!doctype html><html><head><title>Factuurhulp</title></head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>')
    W("vite.config.js", "import react from '@vitejs/plugin-react';\nexport default { plugins: [react()], build: { sourcemap: false } };\n")
    W("server/index.test.js", "import { test, expect } from 'vitest';\ntest('rekent', () => { expect(1 + 1).toBe(2); });\n")
    W(".env.example", "STRIPE_SECRET_KEY=\nDB_PASS=\nSESSION_SECRET=\nWEBHOOK_SECRET=\n")
    W("CLAUDE.md", "# Instructies voor de assistent\n- Gebruik Express en MySQL met geparametriseerde queries.\n"
                   "- Draai na elke wijziging de tests en aiscan_scan, en herstel kritieke en hoge bevindingen.\n"
                   "- Geheimen alleen via omgevingsvariabelen.\n")
    W(".mcp.json", json.dumps({"mcpServers": {"aiscan": {"command": "python", "args": ["-m", "aiscan.mcp_server"]}}}, indent=2))
    W("Dockerfile", 'FROM node:24-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --omit=dev\nCOPY server ./server\nUSER node\nCMD ["node","server/index.js"]\n')
    W(".github/workflows/ci.yml", """name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
      - run: npm audit --audit-level=high
      - run: npx @cyclonedx/cyclonedx-npm@4.0.0 --output-file sbom.json
  codeql:
    runs-on: ubuntu-latest
    permissions: { security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: { languages: javascript }
      - uses: github/codeql-action/analyze@v3
""")
    W(".github/dependabot.yml", "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule: { interval: weekly }\n")
    W("README.md", "# Factuurhulp\n\nAI-assistent voor facturen.\n\n```\nnpm ci\nnpm run dev\n```\n")
    W(".gitignore", "node_modules\n.env\ndist\n.aiscan\n")
    g = lambda *a: subprocess.run(["git", *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.email", "demo@factuurhulp.test"); g("config", "user.name", "Demo")
    g("add", "-A"); g("commit", "-qm", "hersteld na aiscan", "--date=2026-10-18T08:00:00")
    g("remote", "add", "origin", "https://github.com/factuurhulp-demo/factuurhulp.git")


SERVER_OK = """// Factuurhulp API — hersteld na aiscan
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { doubleCsrf } = require('csrf-csrf');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { execFile } = require('child_process');
const multer = require('multer');
const OpenAI = require('openai');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 60 }));
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' } }));
const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.SESSION_SECRET });
app.use(doubleCsrfProtection);
const upload = multer({ dest: 'uploads/', limits: { fileSize: 5 * 1024 * 1024 } });
const db = mysql.createPool({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASS, database: 'facturen' });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const TOEGESTAAN = new Set(['facturen.example.be']);

app.post('/login', async (req, res) => {
  const [rows] = await db.execute('SELECT id, role, salt, hash FROM users WHERE email = ?', [req.body.email]);
  const user = rows[0];
  if (!user) return res.status(401).json({ fout: 'Onjuiste gegevens' });
  const hash = crypto.scryptSync(req.body.password, user.salt, 64).toString('hex');
  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.hash))) return res.status(401).json({ fout: 'Onjuiste gegevens' });
  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('sessie', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

app.get('/invoices', async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM invoices WHERE customer = ?', [req.query.customer]);
  res.json(rows);
});

// De AI geeft een getal terug; dat wordt gevalideerd en nooit uitgevoerd
app.post('/ai/calc', async (req, res) => {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o', max_tokens: 50,
    messages: [{ role: 'user', content: 'Geef enkel een getal (JSON: {"bedrag": number}) voor: ' + String(req.body.vraag).slice(0, 500) }],
  });
  let bedrag;
  try { bedrag = Number(JSON.parse(completion.choices[0].message.content).bedrag); } catch (e) { bedrag = NaN; }
  if (!Number.isFinite(bedrag)) return res.status(422).json({ fout: 'Geen geldig bedrag' });
  res.json({ bedrag });
});

app.post('/export', (req, res) => {
  const doel = new URL(req.body.url);
  if (!TOEGESTAAN.has(doel.hostname)) return res.status(400).json({ fout: 'Adres niet toegestaan' });
  execFile('wkhtmltopdf', [doel.href, '/tmp/out.pdf'], (err) => {
    if (err) { console.error(err); return res.status(500).json({ fout: 'Export mislukt' }); }
    res.download('/tmp/out.pdf');
  });
});

app.post('/upload', upload.single('bijlage'), (req, res) => res.json({ ok: true }));

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const verwacht = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET).update(req.body).digest('hex');
  const gekregen = String(req.headers['stripe-signature'] || '');
  if (verwacht.length !== gekregen.length || !crypto.timingSafeEqual(Buffer.from(verwacht), Buffer.from(gekregen))) return res.sendStatus(400);
  const event = JSON.parse(req.body);
  if (event.type === 'invoice.paid') await db.execute('UPDATE invoices SET paid = 1 WHERE id = ?', [event.data.object.id]);
  res.sendStatus(200);
});

function resetToken() {
  return crypto.randomBytes(32).toString('hex');
}

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ fout: 'Er ging iets mis' }); });
app.listen(3000);
"""

APP_OK = """import { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';

const PREVIEW_HERKOMST = 'https://facturen.example.be';

export default function App() {
  const [html, setHtml] = useState('');
  useEffect(() => {
    window.addEventListener('message', (e) => { if (e.origin === PREVIEW_HERKOMST) setHtml(e.data.preview); });
  }, []);
  async function login(email, password) {
    await fetch('/login', { method: 'POST', credentials: 'include', body: JSON.stringify({ email, password }) });
  }
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
"""


SERVER = '// Factuurhulp API — gegenereerd met een AI-assistent\nconst express = require(\'express\');\nconst session = require(\'express-session\');\nconst mysql = require(\'mysql2\');\nconst jwt = require(\'jsonwebtoken\');\nconst crypto = require(\'crypto\');\nconst { exec } = require(\'child_process\');\nconst multer = require(\'multer\');\nconst axios = require(\'axios\');\nconst OpenAI = require(\'openai\');\n\nconst app = express();\napp.use(express.json());\napp.use(session({ secret: \'keyboard cat\', resave: false, saveUninitialized: true, cookie: { secure: false } }));\nconst upload = multer({ dest: \'public/uploads/\' });\nconst db = mysql.createConnection({ host: \'localhost\', user: \'root\', password: process.env.DB_PASS, database: \'facturen\' });\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n\napp.post(\'/login\', (req, res) => {\n  const hash = crypto.createHash(\'md5\').update(req.body.password).digest(\'hex\');\n  db.query(`SELECT * FROM users WHERE email = \'${req.body.email}\' AND password = \'${hash}\'`, (err, rows) => {\n    if (err) return res.status(500).send(err.stack);\n    const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, process.env.JWT_SECRET);\n    res.json({ token });\n  });\n});\n\napp.get(\'/invoices\', (req, res) => {\n  db.query("SELECT * FROM invoices WHERE customer = \'" + req.query.customer + "\'", (err, rows) => res.json(rows));\n});\n\n// Laat de AI een berekening maken voor de factuur\napp.post(\'/ai/calc\', async (req, res) => {\n  const completion = await openai.chat.completions.create({\n    model: \'gpt-4o\',\n    messages: [{ role: \'user\', content: \'Geef enkel een JavaScript-expressie voor: \' + req.body.vraag }],\n  });\n  const expr = completion.choices[0].message.content;\n  const result = eval(expr);\n  res.json({ result });\n});\n\napp.post(\'/export\', (req, res) => {\n  exec(`wkhtmltopdf ${req.body.url} /tmp/out.pdf`, (err) => {\n    try { res.download(\'/tmp/out.pdf\'); } catch (e) {}\n  });\n});\n\napp.post(\'/upload\', upload.single(\'bijlage\'), (req, res) => res.json({ ok: true }));\n\napp.post(\'/api/stripe/webhook\', (req, res) => {\n  const event = req.body;\n  if (event.type === \'invoice.paid\') db.query(\'UPDATE invoices SET paid = 1 WHERE id = ?\', [event.data.object.id]);\n  res.sendStatus(200);\n});\n\napp.post(\'/preview\', async (req, res) => {\n  const page = await axios.get(req.body.url);\n  res.send(page.data);\n});\n\nfunction resetToken() {\n  const token = Math.random().toString(36).slice(2);\n  return token;\n}\n\napp.listen(3000);\n'
APP = "import { useEffect, useState } from 'react';\nimport OpenAI from 'openai';\n\nconst client = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_SECRET_KEY, dangerouslyAllowBrowser: true });\n\nexport default function App() {\n  const [html, setHtml] = useState('');\n  useEffect(() => {\n    window.addEventListener('message', (e) => { setHtml(e.data.preview); });\n  }, []);\n  async function login(email, password) {\n    const res = await fetch('/login', { method: 'POST', body: JSON.stringify({ email, password }) });\n    const { token } = await res.json();\n    localStorage.setItem('authToken', token);\n  }\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n"
INDEX = '<!doctype html><html><head><title>Factuurhulp</title>\n<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>\n<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments)};gtag(\'js\',new Date());gtag(\'config\',\'G-ABC123\');</script>\n<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>\n</head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>'

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'demo-factuurhulp', hersteld='--hersteld' in sys.argv)
