"""Het publieke register: een score schorsen, intrekken of terugzetten. De scorepagina, de badge en de JSON tonen de status.

Gebruik (op de server, in de container):
  python platform/register.py toon <id>
  python platform/register.py intrekken <id> --reden "Misbruik van de badge op een andere app"
  python platform/register.py schorsen <id> --reden "Melding van een kritiek lek, in onderzoek"
  python platform/register.py herstellen <id>

Elke wijziging komt met datum en reden in de tabel register_log, zodat ze achteraf na te gaan is.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = Path(os.environ.get("AISCAN_DB", ROOT / "aiscan.db"))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("actie", choices=["toon", "intrekken", "schorsen", "herstellen"])
    p.add_argument("id")
    p.add_argument("--reden", default="")
    a = p.parse_args(argv)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    for sql in ("ALTER TABLE scores ADD COLUMN status TEXT", "ALTER TABLE scores ADD COLUMN status_reden TEXT",
                "ALTER TABLE scores ADD COLUMN status_op TEXT"):
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass
    c.execute("CREATE TABLE IF NOT EXISTS register_log (op TEXT, id TEXT, actie TEXT, reden TEXT)")
    r = c.execute("SELECT id, letter, soort, project, aangemaakt, geldig_tot, status, status_reden, status_op FROM scores WHERE id = ?",
                  (a.id,)).fetchone()
    if not r:
        print(f"Score {a.id} bestaat niet.", file=sys.stderr)
        return 1
    if a.actie == "toon":
        print(dict(r))
        return 0
    if a.actie in ("intrekken", "schorsen") and not a.reden.strip():
        print("Geef een reden (--reden): die staat op de publieke scorepagina.", file=sys.stderr)
        return 1
    op = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    status = {"intrekken": "ingetrokken", "schorsen": "geschorst", "herstellen": None}[a.actie]
    c.execute("UPDATE scores SET status = ?, status_reden = ?, status_op = ? WHERE id = ?",
              (status, a.reden.strip() or None, op if status else None, a.id))
    c.execute("INSERT INTO register_log VALUES (?,?,?,?)", (op, a.id, a.actie, a.reden.strip()))
    c.commit()
    print(f"Score {a.id}: {status or 'hersteld'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
