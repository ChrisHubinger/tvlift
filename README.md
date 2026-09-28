# tvlift – Loxone ↔ monTEK TV-Lift (Tuya, lokal)

Dieser kleine Go-Service steuert den **monTEK TM1001CBE-L** (und andere Tuya-basierte TV-Lifte) direkt über das Tuya-LAN-Protokoll. Die Cloud wird dafür nicht gebraucht.
Der Miniserver ruft einfache HTTP-URLs auf, der Service setzt daraus die passenden Tuya-Datenpunkte.

- Protokollversionen 3.3, 3.4 und 3.5 (AES-ECB/HMAC bzw. AES-GCM inkl. Session-Key)
- Keine Abhängigkeiten, statisches Binary, Docker-Image auf `scratch`-Basis (~5 MB)
- Pro Befehl wird eine kurze TCP-Session aufgebaut, die Befehle laufen serialisiert und werden bei Fehlern einmal wiederholt

## 1. Vorbereitung: Device-ID, Local Key, IP, Protokollversion

1. Den Lift in der **Smart Life**- oder **Tuya Smart**-App einrichten (2,4 GHz).
2. Auf <https://iot.tuya.com> ein Cloud-Projekt anlegen. Als Rechenzentrum *Central Europe* wählen, und den App-Account über *Devices → Link App Account* per QR-Code verknüpfen.
3. Auf einem beliebigen Rechner:
   ```bash
   pip install tinytuya
   python -m tinytuya wizard     # liefert id, key, ip und ver
   ```
4. Im Router eine DHCP-Reservierung für den Lift anlegen.

> Der Local Key ändert sich bei jedem erneuten Pairing in der App.

## 2. Datenpunkte prüfen (wichtig)

Die Defaults stammen aus dem Tuya-Datenmodell für TV-Lifte (Kategorie `zndsj`), wie es vergleichbare Lifte verwenden:

| DP  | Code     | Werte |
|-----|----------|-------|
| 101 | `move`   | `move_up`, `move_down`, `cancel` (Stop) |
| 103 | `memory` | `recall1..3` (anfahren), `mem1..3` (speichern), `cancel` |
| 105 | Fehlercode | Bitmap |

Für den monTEK habe ich das nicht am Gerät verifiziert. So prüfst du es:

```bash
docker exec tvlift /tvlift status     # alle DPs mit aktuellem Wert
```

Alternativ zeigt der Tuya IoT Explorer unter *Cloud → Device Debugging* bzw. *Query Things Data Model* die DP-IDs mit den erlaubten Werten.
Weichen die IDs ab, stellst du sie über `DP_MOVE`/`DP_MEMORY` oder einzelne `CMD_<NAME>=<dp>=<wert>` um. Mit `ALLOW_RAW=true` kannst du über `/api/set?dp=103&value=recall1` frei testen.

**Positionen speichern:** mit der Fernbedienung bzw. App oder über `/api/cmd/save1..3`.

## 3. Betrieb auf der Synology

### Variante A – Container Manager (DSM 7.2+)

1. Den Ordner `tvlift/` nach z. B. `/volume1/docker/tvlift` kopieren.
2. `.env.example` nach `.env` kopieren und ausfüllen.
3. Im Container Manager unter **Projekt → Erstellen** diesen Pfad angeben. Die vorhandene `docker-compose.yml` wird übernommen, dann auf „Erstellen“ klicken. Das Image wird direkt auf dem NAS gebaut.

Per SSH geht es auch so: `cd /volume1/docker/tvlift && sudo docker compose up -d --build`

### Variante B – ohne Docker

Das passende Binary aus `dist/` nehmen. `tvlift-linux-amd64` ist für Intel/AMD-Modelle (Plus-Serie, z. B. DS920+, DS224+), `tvlift-linux-arm64` für aktuelle ARM-Modelle (z. B. DS223, DS124) und `tvlift-linux-armv7` für ältere ARM-Geräte (z. B. DS218j). Welches Modell du hast, zeigt `uname -m` per SSH.
Unter **Systemsteuerung → Aufgabenplaner → Ausgelöste Aufgabe → Hochfahren** trägst du ein:

```bash
set -a; . /volume1/scripts/tvlift/.env; set +a
/volume1/scripts/tvlift/tvlift-linux-amd64 serve >> /volume1/scripts/tvlift/tvlift.log 2>&1 &
```

Test: `curl "http://NAS:8088/api/status?token=DEIN_TOKEN"`

## 4. HTTP-API

| Methode | Pfad | Wirkung |
|---|---|---|
| GET/POST | `/api/recall/{n}` | Speicherposition *n* anfahren. Akzeptiert auch Loxone-Analogwerte wie `2.000`, `0` wird ignoriert |
| GET/POST | `/api/cmd/{name}` | `up`, `down`, `stop`, `recall1..3`, `save1..3` sowie eigene `CMD_*` |
| GET | `/api/status` | alle DPs als JSON |
| GET | `/api/status/{dp}` | Einzelwert als Klartext (für den Virtuellen HTTP-Eingang) |
| GET | `/api/commands` | konfigurierte Befehle |
| GET/POST | `/api/set?dp=&value=` | Roh-DP setzen (nur mit `ALLOW_RAW=true`) |
| GET | `/healthz` | Liveness, ohne Auth |

Für die Authentifizierung wird `API_TOKEN` akzeptiert als `?token=…`, als `Authorization: Bearer …` oder als Basic-Auth-Passwort (Benutzername beliebig).

## 5. Loxone Config

**Virtueller Ausgang** „TV-Lift“:
- Adresse: `http://tvlift:DEIN_TOKEN@192.168.1.10:8088` (NAS-IP)

**Virtuelle Ausgangsbefehle** (jeweils nur *Befehl bei EIN*, Methode GET):

| Befehl | Befehl bei EIN |
|---|---|
| Position 1 | `/api/recall/1` |
| Position 2 | `/api/recall/2` |
| Position 3 | `/api/recall/3` |
| Hoch | `/api/cmd/up` |
| Runter | `/api/cmd/down` |
| Stop | `/api/cmd/stop` |

Alternativ reicht **ein** analoger Ausgangsbefehl mit `/api/recall/<v>`, den z. B. ein Radiotasten- oder Status-Baustein (1/2/3) ansteuert. Loxone ersetzt `<v>` durch den Wert, `0` löst keine Bewegung aus.

Beispiel: TV an → `Position 1` (hoch), TV aus → `Position 2` (versenkt).

**Optional Rückmeldung:** Einen **Virtuellen HTTP-Eingang** mit `http://tvlift:TOKEN@NAS:8088/api/status/103` anlegen, Abfragezyklus z. B. 30 s, und dazu einen Befehlseingang mit Texterkennung.

## Sicherheit

- Nach dem Auslesen des Keys kannst du dem Lift den Internetzugang sperren (IoT-VLAN / Firewall). Die lokale Steuerung funktioniert weiter, die App nur noch im LAN oder gar nicht.
- Port 8088 nicht ins Internet freigeben.

## Entwicklung

```bash
go test ./...      # Protokolltests gegen ein simuliertes Gerät (3.3/3.4/3.5)
go build .
```
