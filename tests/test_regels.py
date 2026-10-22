"""Regels die de testbank aan het licht bracht: SQL via tekstopmaak, uitgezette escaping, MD5 voor wachtwoorden."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tmp = Path(tempfile.mkdtemp())
(tmp / "app.js").write_text("""const exec = require('child_process').exec;
const swig = require('swig');
var query = "SELECT name FROM Users WHERE login='" + req.body.login + "'";
exec('ping -c 2 ' + req.body.address, cb);
swig.setDefaults({ autoescape: false });
db.query("SELECT * FROM t WHERE id = $1", [id]);
""")
(tmp / "dao.py").write_text("""from hashlib import md5
q = ("INSERT INTO students (name) "
     "VALUES ('%(name)s')" % {'name': name})
ok = cur.execute('SELECT id FROM t WHERE id = %s', (sid,))
ok2 = 'VALUES (%(title)s, %(description)s)'
h = md5(password.encode()).hexdigest()
env = aiohttp_jinja2.setup(app, loader=x, autoescape=False)
""")
uit = tmp / "uit"
subprocess.run([sys.executable, "-m", "aiscan", str(tmp), "--offline", "--out", str(uit)], cwd=ROOT, capture_output=True)
d = json.loads((uit / "rapport.json").read_text())
titels = [(c["id"], b["bestand"], b["regel"], b["titel"]) for c in d["checks"] for b in c["bevindingen"] if c["id"] in ("E-04", "E-06")]
def heeft(bestand, regel, woord):
    return any(t[1] == bestand and t[2] == regel and woord.lower() in t[3].lower() for t in titels)
assert heeft("app.js", 3, "SQL"), titels
assert heeft("app.js", 4, "commando"), titels
assert heeft("app.js", 5, "escaping"), titels
assert not any(t[1] == "app.js" and t[2] == 6 for t in titels), titels          # geparametriseerd: geen melding
assert heeft("dao.py", 3, "SQL"), titels
assert not any(t[1] == "dao.py" and t[2] in (4, 5) for t in titels), titels    # geparametriseerd: geen melding
assert heeft("dao.py", 6, "MD5"), titels
assert heeft("dao.py", 7, "escaping"), titels
print("ok: regels uit de testbank")
