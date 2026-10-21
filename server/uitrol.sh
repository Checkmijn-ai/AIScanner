#!/usr/bin/env bash
# Rolt checkmijn.ai uit op de server. Wordt door GitHub Actions via SSH uitgevoerd (workflow "Uitrollen"),
# maar kan ook met de hand:  bash uitrol.sh main   of   bash uitrol.sh test
#
# De eerste keer installeert het script ook Docker, automatische beveiligingsupdates en een eenvoudige firewall.
set -euo pipefail

# Alles staat in een functie: zo leest bash het hele script in voor het iets uitvoert (het komt via SSH binnen
# op stdin, en een commando als apt-get zou anders de rest van het script kunnen opeten).
main() {
TAK="${1:-main}"
REPO="https://github.com/Checkmijn-ai/AIScanner.git"
LIVE=/opt/checkmijn
TEST=/opt/checkmijn-test
export DEBIAN_FRONTEND=noninteractive

log() { printf '\n==> %s\n' "$*"; }

if ! command -v docker >/dev/null 2>&1; then
  log "Eerste keer: Docker, beveiligingsupdates en firewall installeren"
  apt-get update -q
  apt-get install -yq ca-certificates curl git ufw unattended-upgrades
  curl -fsSL https://get.docker.com | sh
  dpkg-reconfigure -f noninteractive unattended-upgrades
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 443/udp
  ufw --force enable
fi

haal() {  # haal <map> <tak>
  if [ ! -d "$1/.git" ]; then
    git clone -q --branch "$2" "$REPO" "$1"
  else
    git -C "$1" fetch -q origin "$2"
    git -C "$1" checkout -q "$2" 2>/dev/null || git -C "$1" checkout -q -b "$2" "origin/$2"
    git -C "$1" reset -q --hard "origin/$2"
  fi
  log "$1 staat op $(git -C "$1" log -1 --format='%h %s')"
}

# De live-map levert altijd de configuratie (docker-compose.yml, Caddyfile).
haal "$LIVE" main
cd "$LIVE/server"

if [ "$TAK" = "test" ]; then
  if ! git ls-remote --exit-code --heads "$REPO" test >/dev/null 2>&1; then
    log "Er is nog geen tak 'test'; niets te doen"
    exit 0
  fi
  haal "$TEST" test
  log "Testomgeving bouwen en starten (test.checkmijn.ai)"
  docker compose --profile test up -d --build test caddy
else
  log "Live bouwen en starten (checkmijn.ai en api.checkmijn.ai)"
  docker compose up -d --build live caddy
  # Draait de test al, dan krijgt Caddy ook daarvoor de nieuwste configuratie.
  if [ -d "$TEST/.git" ]; then docker compose --profile test up -d test >/dev/null 2>&1 || true; fi
fi

# Nieuws (checkmijn.ai/nieuws): drie keer per dag ophalen, om 05:10, 11:10 en 16:10 UTC (07:10, 13:10 en 18:10 in de zomer,
# 06:10, 12:10 en 17:10 in de winter). Live en test halen elk hun eigen nieuws op.
command -v cron >/dev/null 2>&1 || apt-get install -yq cron
cat > /etc/cron.d/checkmijn-nieuws <<'CRON'
# CheckMijn.AI: nieuws ophalen voor /nieuws (geplaatst door server/uitrol.sh)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
10 5,11,16 * * * root cd /opt/checkmijn/server && timeout 600 docker compose exec -T live python /app/platform/nieuws.py >> /var/log/checkmijn-nieuws.log 2>&1
# Nieuwsbrief: elke maandag een concept in Brevo (versturen doe je zelf in Brevo)
30 5 * * 1 root cd /opt/checkmijn/server && timeout 300 docker compose exec -T live python /app/platform/nieuwsbrief.py concept >> /var/log/checkmijn-nieuws.log 2>&1
# Beveiligingsbronnen (Security.nl, NCSC, BleepingComputer, ...) daarnaast elk uur, alleen live
40 * * * * root cd /opt/checkmijn/server && timeout 300 docker compose exec -T live python /app/platform/nieuws.py --snel >> /var/log/checkmijn-nieuws.log 2>&1
14 5,11,16 * * * root cd /opt/checkmijn/server && docker compose --profile test ps --status running test 2>/dev/null | grep -q test && timeout 600 docker compose --profile test exec -T test python /app/platform/nieuws.py >> /var/log/checkmijn-nieuws-test.log 2>&1
CRON
chmod 644 /etc/cron.d/checkmijn-nieuws
cat > /etc/logrotate.d/checkmijn-nieuws <<'ROT'
/var/log/checkmijn-nieuws*.log {
  weekly
  rotate 4
  compress
  missingok
  notifempty
}
ROT

docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true
docker image prune -f >/dev/null 2>&1 || true

log "Controle"
for i in $(seq 1 30); do
  if docker compose ps --format '{{.Service}} {{.Health}}' | grep -E "^(live|test) " | grep -qv starting; then break; fi
  sleep 2
done
docker compose ps

# Nieuws meteen bijwerken met de nieuwe code (dubbels worden overgeslagen, dus dit kan altijd).
DIENST=live; [ "$TAK" = "test" ] && DIENST=test
log "Nieuws ophalen ($DIENST), op de achtergrond"
docker compose --profile test exec -d "$DIENST" python /app/platform/nieuws.py || true
}
main "$@" </dev/null
