<p>
  <a href="README.md">中文</a>
</p>

<p align="center">
  <img src="docs/assets/icon.svg" width="128" height="128" alt="StrikeAgent" />
  <img src="docs/assets/times.svg" width="48" height="128" alt="×" />
  <img src="docs/assets/brand.jpg" width="128" height="128" alt="Yean-Sec" />
</p>

<p align="center">
  <sub>StrikeAgent × Yean-Sec</sub>
</p>

<h1 align="center">StrikeAgent_AtkBrain-Flash</h1>

![This project proposes: self-loop · self-supervise · self-evolve](docs/assets/coined-triad.gif)

Built by Yean-Sec to explore what AI can actually do in pentesting — something with its own ideas, not another generic AI product thrown together like everything else.

The project looks simple as a whole. It is not. It went through many live engagements and a great deal of the team’s effort. The small rules are countless: staying on target while still growing a larger attack surface alone took serious work (the Flash edition). To keep AI findings from being inflated or false positives, the team added red-team re-rating and a second verification pass, so what you see is what you can use — details like that.

The team’s private Pro build has already shipped on dozens of programs and well over a thousand real authorized internet-facing environments. All of that work aims at one job: external foothold. Do one thing, and do it to the extreme.

## Architecture

The console schedules hunts; the attack graph drives the self-loop. The servant finishes a full round before asking the master. A human message in chat interrupts the current round. Runtime is Pi. Which model it loads is set in the settings JSON. Red team / blue team/SRC egress is the real IP unless the imported proxy pool is turned on.

![StrikeAgent_AtkBrain-Flash architecture](docs/assets/architecture.png)

## Product screens

Overview:

![Product overview](docs/assets/main.gif)

Home and new task: single target or cluster; red team (getshell), CTF (flag), blue team/SRC.

![Home and new task](docs/assets/ScreenShot_2026-09-19_231256_939.png)

Project console: attack graph, timeline, findings, chat.

![Project console](docs/assets/ScreenShot_2026-09-19_230912_075.png)

Vulnerability library:

![Vulnerability library](docs/assets/ScreenShot_2026-09-19_235824_031.png)

## Delivery report

<p><i>This report is from a real authorized engagement.</i></p>

[Open HTML](docs/demo/intranet-lab-report.html)

![Report cover](docs/assets/report-cover.png)

![Executive summary](docs/assets/report-body.png)

![Critical path](docs/assets/report-path.png)

![Asset picture](docs/assets/report-assets.png)

## Ranking

Tsecbench v1 **1st place** (`StrikeAgent_AtkBrain-Flash`, 97.89 / 100). Tencent Security YunDing Lab’s agent evaluation board.

![Tsecbench ranking](docs/assets/ScreenShot_2026-09-19_193220_407.png)

## What we do for platform security

An unauthorized visitor does not get a login page, an API, or a password on the wire.

- **Random entrance:** 8-character path only in `backend/data/security_entry` (`0600`). `python -m atkbrain.panel` prints the URL.
- **No leaked subpaths:** Bare `:2334/` is the product page; `/login`, `/api`, `/.env` return 404.
- **Anti capture / replay / bruteforce:** RSA-OAEP in the browser; one-shot ticket (120s); username/IP lockouts.
- **Password:** Argon2id in SQLite; a `0600` copy on disk for operators with a shell (`panel`).
- **Session:** `HttpOnly` cookie; no `?token=`; Swagger off. HTTPS on `:2334` by default.

## Environment and install

Pick one. Docker packs the console, Pi, and the usual probe tools into an image. A Linux install runs on the machine under systemd and does not use a container. Do not run both at once; they both bind `2333` and `2334`.

The model is not chosen at install time. After the console is up, set it in the Pi JSON on the settings page. `.env` is only for the local password and ports. Do not put a provider key there. Data lives in `backend/data/` (gitignored). Image upgrades and service reinstalls do not overwrite the database, the entrance file, or the saved model JSON.

### Docker

Docker and the Docker Compose plugin. Run this from the repo root (the directory that contains `compose.yaml` and `.env.example`). Linux uses host networking, so the browser must be able to reach port `2334` on that host. Docker Desktop on macOS has no host network, so add `deploy/compose.mac.yaml`. That bind is `127.0.0.1` only.

```bash
git clone <this repo URL>
cd StrikeAgent_AtkBrain-Flash
cp .env.example .env
# Leave .env at the defaults. First login is admin / admin, then you must change the password.
# Do not put a model key here.

# Linux
docker compose -f compose.yaml -f deploy/compose.build.yaml up -d --build --wait

# macOS
# docker compose -f compose.yaml -f deploy/compose.build.yaml -f deploy/compose.mac.yaml up -d --build --wait
```

`--build` builds `strikeagent-atkbrain-flash:console` from `Dockerfile.console`. `--wait` returns after the healthcheck. The containers are `strikeagent-atkbrain-flash` (API) and `strikeagent-atkbrain-caddy` (HTTPS).

```bash
docker compose -f compose.yaml ps
docker compose -f compose.yaml exec atkbrain python -m atkbrain.panel
# Print the https login URL (random entrance) and the current password. Host shell only.

# Upgrade: pull, then build again from the repo root
docker compose -f compose.yaml -f deploy/compose.build.yaml up -d --build --wait

# Stop
docker compose -f compose.yaml -f deploy/compose.build.yaml down
```

### Linux install

Runs on the host. No container. You need root, systemd, Python 3.11+ as `/usr/bin/python3`, Node.js 20+, npm, and openssl. The service unit calls system `python3`, so install the Python packages into that interpreter. A venv the unit does not use will not be picked up.

Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nodejs npm openssl ca-certificates \
  gcc pkg-config libffi-dev \
  libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0
```

RHEL / TencentOS:

```bash
sudo dnf install -y python3 python3-pip nodejs npm openssl ca-certificates gcc pkgconf-pkg-config libffi-devel cairo pango gdk-pixbuf2
```

If the distro Node is older than 20, install Node.js 20 before continuing. Then install this repo's Python packages, the frontend, and Pi:

```bash
git clone <this repo URL>
cd StrikeAgent_AtkBrain-Flash
cp .env.example .env

python3 -m pip install -r backend/requirements.txt
npm install -g @earendil-works/pi-coding-agent
cd frontend && npm install && cd ..

sudo scripts/atkbrain-up.sh
```

`atkbrain-up.sh` installs and starts two units:

- `atkbrain-flash-backend.service`: API on `2333`
- `atkbrain-flash-frontend.service`: self-signed HTTPS on `2334`, proxied to `2333`

```bash
scripts/atkbrain-panel.sh
# same as: cd backend && python3 -m atkbrain.panel

sudo scripts/atkbrain-backend.sh status
sudo scripts/atkbrain-frontend.sh status
sudo scripts/atkbrain-backend.sh logs
sudo scripts/atkbrain-frontend.sh logs
```

Logs are also in `backend/data/logs/backend.log` and `frontend.log`.

To upgrade, pull at the repo root, reinstall dependencies, and restart. Rebuild the frontend when it changed:

```bash
python3 -m pip install -r backend/requirements.txt
cd frontend && npm install && npm run build && cd ..
sudo scripts/atkbrain-backend.sh restart
sudo scripts/atkbrain-frontend.sh restart
```

Stop with `sudo scripts/atkbrain-backend.sh stop` and `sudo scripts/atkbrain-frontend.sh stop`. `uninstall` on both scripts removes the units and leaves the data directory in place.

The Docker image includes the usual probe tools. A Linux install only brings up the console and Pi. Commands the hunt calls, such as `nmap`, must be installed on the host and be on root's `PATH`.

### After it is up

Open the **https** URL `panel` prints and accept the self-signed certificate. The console is `:2334`. The API is `:2333`. Bare `:2334/` is the product page. The login URL includes the random path.

Sign in as `admin` / `admin`. The page requires a new password immediately.

Then set the model. In the console open **Settings → Model**, choose OpenAI or Anthropic, and fill in the model, base URL, and API key. OpenAI uses Chat Completions. Anthropic uses the Messages API. Saving writes `backend/data/pi-models.json`, which later Pi processes read. **Test connection** sends one short request to confirm the URL and key.

Forgot the URL or password: run `panel` for the install you used. If it says there is no plaintext copy, set `ATKBRAIN_ADMIN_PASSWORD` and `ATKBRAIN_ADMIN_PASSWORD_RESET=1` in `.env`. On Docker, run the same `docker compose ... up -d` again. On a Linux install, run `sudo scripts/atkbrain-backend.sh restart`. Set RESET back to `false` after you can sign in.

## License and disclaimer

**AGPL-3.0-only** — free for personal and open-source use. Commercial license: [gavenmiya@outlook.com](mailto:gavenmiya@outlook.com). See [LICENSE](LICENSE).

Only for environments you are explicitly authorized to test.

The chat group is full. Follow WeChat 「夜安团队SEC」 to be added.

![Yean-Sec WeChat official account](docs/assets/wechat-oa.png)
