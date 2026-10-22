"""W-13: Row Level Security in Supabase-migraties en Firebase-regels (statisch)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def scan(bestanden: dict) -> dict:
    tmp = Path(tempfile.mkdtemp())
    for naam, inhoud in bestanden.items():
        (tmp / naam).parent.mkdir(parents=True, exist_ok=True)
        (tmp / naam).write_text(inhoud)
    uit = tmp / "uit"
    subprocess.run([sys.executable, "-m", "aiscan", str(tmp), "--offline", "--alleen", "W-13", "--out", str(uit)],
                   cwd=ROOT, capture_output=True)
    return next(c for c in json.loads((uit / "rapport.json").read_text())["checks"] if c["id"] == "W-13")


m = "supabase/migrations/"
c = scan({m + "001.sql": """
create table public.notes (id uuid primary key, user_id uuid, body text);
create table public.products (id int, name text);
create table if not exists "orders" (id int);
alter table public.products enable row level security;
alter table orders enable row level security;
create policy "read products" on public.products for select using (true);
create policy "anyone writes orders" on public.orders for insert to anon with check (true);
create policy "tmp" on public.orders for update using (true);
-- create table public.commentaar (id int);
""", m + "002.sql": """
drop policy if exists "tmp" on public.orders;
create table auth_only.secret (id int);
do $$ begin execute 'create policy "x" on public.%I using (true)'; end $$;
"""})
t = [(b["ernst"], b["bevestigen"], b["titel"]) for b in c["bevindingen"]]
assert c["status"] == "Bevinding", c
assert ("Hoog", False, "Tabel 'notes' zonder Row Level Security") in t, t          # geen RLS: zeker
assert not any("'products' zonder" in x[2] or "'orders' zonder" in x[2] for x in t), t
assert not any("commentaar" in x[2] or "secret" in x[2] for x in t), t             # commentaar en ander schema tellen niet
assert any(x[0] == "Hoog" and x[1] and "'orders'" in x[2] and "INSERT" in x[2] for x in t), t   # iedereen schrijft: nakijken
assert not any("UPDATE" in x[2] for x in t), t                                        # policy later verwijderd
assert any(x[0] == "Laag" and "lezen" in x[2] for x in t), t                          # publiek lezen: nakijken

c = scan({m + "001.sql": "create table public.a (id int);\nalter table public.a enable row level security;\n"
                          "create policy p on public.a for select to authenticated using (auth.uid() = id);\n"})
assert c["status"] == "Geen bevinding" and not c["bevindingen"], c

c = scan({"firestore.rules": "service cloud.firestore {\n match /{d=**} {\n  allow read, write: if true;\n }\n}\n"})
assert any(b["ernst"] == "Kritiek" for b in c["bevindingen"]), c

c = scan({"package.json": '{"dependencies": {"@supabase/supabase-js": "2.0.0"}}'})
assert c["status"] == "Niet gescand", c                                                # Supabase zonder migraties
assert scan({"app.py": "print(1)\n"})["status"] == "Niet van toepassing"
# databaseadres met wachtwoord in de code (E-05); lokale standaardwaarden niet
import tempfile as _t
d = Path(_t.mkdtemp())
geheim = "S3cr3t" + "Passw0rd"  # in stukken, zodat de scan van deze repository zelf er niet over valt
(d / "cfg.py").write_text('DB = "postgres://admin:' + geheim + '@db.example.com:5432/app"\n'
                          'L = "postgres://postgres:postgres@localhost:5432/dev"\n')
subprocess.run([sys.executable, "-m", "aiscan", str(d), "--offline", "--alleen", "E-05", "--out", str(d / "uit")], cwd=ROOT,
               capture_output=True)
e = next(c for c in json.loads((d / "uit" / "rapport.json").read_text())["checks"] if c["id"] == "E-05")
assert [b["regel"] for b in e["bevindingen"]] == [1], e["bevindingen"]
assert geheim not in json.dumps(e), "wachtwoord niet in het rapport"
print("ok: rechten per rij (W-13) en databaseadressen met wachtwoord (E-05)")
