# Bayesian IDS

A network intrusion detection system built on a Bayesian network, trained on
CIC-IDS-2017 flows. It scores network flows, raises alerts with a handling
workflow, watches for traffic drift and sends notifications. It runs on live
packet captures, on pcap files and on flow CSVs from a flow exporter.

```
packets / pcap ──► capture.py ──┐
CICFlowMeter CSV ► live_monitor ┼─► POST /api/score ─► api.py ─► SQLite (ids.db)
anything else ───────────────────┘                       │  │
                                                         │  └─► notifier (webhook / email)
                          React dashboard ◄── /ws ◄──────┘
```

## Run it

First-time setup (a terminal, once):

```
pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
```

Then start the server by **double-clicking `Start Bayesian IDS.bat`** (or
`python serve.py`). It opens http://127.0.0.1:8000 for you. A fresh install has
no trained model yet and says so: open **Operations**, upload the CIC-IDS-2017
CSVs under *Data* and press *Retrain* (about a minute). From here on everything
is done in the dashboard:

| where | what |
|---|---|
| **Monitor** | live traffic, alerts and their handling, recent flows, drift |
| **Operations** (admins) | everything below |

Operations page:

* **Model**: *Retrain* from the dataset, *Evaluate*, *Compare baselines*, *Roll
  back* to the previous model. Progress streams live; when a retraining finishes
  the new model is used at once, and its held-out precision / recall / F1 per
  class are shown. A model that fails to load never replaces the running one.
* **Data**: upload CIC-IDS-2017 CSVs (more days means more attack types) and
  pcap / CSV files for capture, with progress, size limit and checks (a CSV
  must have the columns the model needs, a pcap must be a pcap). Label counts
  per dataset file are shown, so you can see what the model will learn.
* **Capture**: choose a network interface, a pcap or a flow CSV and press
  **Start capture**. Failures are retried with a growing delay and shown with a
  hint; the panel says what the machine lacks (Npcap, raw-socket rights,
  tcpdump). Optionally start automatically with the server.
* **API ingest**: switch on or off, create or rotate an API key (shown once,
  stored hashed), copy the endpoint and an example.
* **Notifications**: webhook (Slack, Discord, Teams, Mattermost, generic) and
  email settings in a form, with a test button. Webhook URLs and passwords are
  encrypted before they are stored.
* **Server**: *Restart server* (the page reloads itself), *start when I sign in*
  (a per-user setting, no administrator rights), *Download backup*.
* **Logs and activity**: the server log, and who did what (every capture start,
  upload, retraining, settings change, login, refused request).
* **Users**: accounts and roles (see Accounts and roles).

**Demo** (Monitor page, optional): *Start demo* replays held-out dataset flows.

What still needs a terminal or a file, on purpose:

* The first start (a web page cannot start the server it is served by), unless
  you double-click the launcher.
* **Installing a system service** (starting at boot, before anyone signs in).
  Letting a web page install services would let anyone who gets admin on the
  dashboard take over the machine, so it stays a deliberate step: `deploy/`.
* Installing Python and Npcap, and rebuilding the dashboard after changing its code.

The command-line tools still work for scripting (`capture.py`, `live_monitor.py`,
`train_model.py`, `manage_users.py`); the dashboard runs the same code.

For frontend development run `npm run dev` in `frontend/` (port 5173, proxies
to the API on 8000).

### Configuration (environment variables)

| variable | purpose |
|---|---|
| `IDS_DB` | database path (default `ids.db`): alerts, users, settings |
| `IDS_DATA_DIR` | folder the Capture panel may open files from (default `./captures`) |
| `IDS_API_KEY` | key for `/api/score`; if set it cannot be changed from the dashboard |
| `IDS_ADMIN_TOKEN` | optional shared admin credential (acts as an admin); accounts are the normal way in |
| `IDS_DATASET_DIR` | folder of CIC-IDS-2017 CSVs used for training and the demo (default `./dataset`; `IDS_DEMO_DATA` still works) |
| `IDS_MODEL` | the trained model file (default `./bayesian_ids.pkl`; its `.previous` copy is kept for roll back) |
| `IDS_MAX_UPLOAD_MB` | largest file the dashboard accepts (default 4096) |
| `IDS_SECRET_KEY` | key for encrypting saved secrets; otherwise a key file is created beside the database |
| `IDS_NOTIFY_CONFIG` | notification settings file (default `notify.json`) |

## Accounts and roles

Until the first account exists the dashboard is open, which is fine on one
machine. Create the first admin from the command line (there is deliberately no
"first visitor becomes admin" page):

```
python manage_users.py add alice --role admin       # asks for a password
python manage_users.py list
```

From then on everything needs a login; admins manage the rest in the Users panel.

| role | can |
|---|---|
| viewer | look at everything |
| analyst | also handle alerts: status, assignee, notes, bulk changes |
| admin | also start/stop capture, change ingest and notification settings, run the demo, manage users |

* Passwords are 10+ characters, hashed with scrypt and a per-user salt. Sessions
  last 12 hours; the token is random and only its hash is stored. Changing a
  password, disabling or deleting an account ends its sessions at once.
* 5 wrong passwords lock that account (and that client address) for 5 minutes.
* The last enabled admin cannot be deleted, disabled or demoted, and nobody can
  disable or delete themselves.
* Every change to an alert is recorded under the signed-in user's name; a client
  cannot claim to be someone else.
* Flow exporters do not sign in: they use the API key on `/api/score`.

## Serving beyond this machine

`python serve.py --host 0.0.0.0` **refuses to start** unless both hold:

1. people can sign in (an account exists, or `IDS_ADMIN_TOKEN` is set), and
2. the connection is encrypted: `--self-signed`, `--cert FILE --key FILE`, or
   `--behind-proxy` to say a reverse proxy in front already does it.

```
python serve.py --self-signed --host 0.0.0.0            # generates certs/ids-selfsigned.pem
python serve.py --host 0.0.0.0 --cert c.pem --key k.pem
python serve.py --host 127.0.0.1 --behind-proxy         # a proxy (Caddy, nginx) terminates TLS
```

A self-signed certificate encrypts but browsers warn until you trust it; the
SHA-256 fingerprint is printed so you can check it. Use a certificate from a real
authority, or Let's Encrypt through a proxy (below), for anything other people use. Responses carry a content security
policy, `X-Frame-Options: DENY`, `nosniff`, and HSTS when the connection is
encrypted.

## A reverse proxy in front (HTTPS), managed from the dashboard

**Operations → HTTPS proxy** installs, configures, starts, stops, restarts and tests a reverse
proxy. No terminal is needed once the dashboard is running. Two engines are supported:

* **Caddy**: certificates made automatically (its own local CA, or Let's Encrypt for a public name).
* **nginx**: uses a certificate and key you upload under Operations → Files → "TLS certificates".

What the panel does:

* **Install** downloads the program into `proxy/bin/`. Caddy is checked against the published
  SHA-512; nginx against its PGP signature (needs GnuPG; without it you must tick an explicit
  "install without signature" box). The installed program's hash is rechecked before every start.
* **Settings**: address, port, whether to expose beyond this machine (refused until an account
  exists), certificate choice, autostart with the dashboard.
* **Test** makes a real HTTPS request through the proxy and reports TLS version, latency and
  whether it reached the dashboard.
* **Certificate** shows fingerprint and expiry and downloads the public certificate so you can
  trust it (Windows: open it, Install Certificate, Trusted Root). Private keys are never served.
* **Restart the dashboard in proxy mode** relaunches `serve.py` with `--behind-proxy`: the
  dashboard then believes `X-Forwarded-For` only from the proxy (127.0.0.1 / ::1; more with
  `--proxy-ip`).
* The proxy and the dashboard use the same upload limit; nginx streams bodies unbuffered.

Optional terminal route (Caddy): `proxy\install-caddy.ps1`, `proxy\Start proxy.bat`, or
`Start Bayesian IDS (HTTPS).bat`. `deploy/proxy/nginx.conf` is a hand-written nginx example
equivalent to what the panel generates.

Checked against real programs (Caddy 2.11.7, nginx 1.30.6), including driven through the
dashboard API (`tests/test_proxy_manager.py`, `tests/test_api_proxy.py`): HTTPS with TLS 1.3,
certificate verification, the real client address replacing a forged `X-Forwarded-For`, a
300 MB streamed upload, over-limit refusal, install verification (including a tampered
archive), start refusals, role gating and audit entries. Earlier manual runs with Caddy also
covered a 1.5 GB upload with flat memory, 502 while the dashboard is down, and the Restart
button through the proxy. One bug found that way: the proxy listened on IPv4 only, costing
2 seconds per connection when a client tried `::1` first; it now binds both loopback addresses.

Not verified: Let's Encrypt on a real public domain, Linux/macOS installs, and trusting the
certificate in the OS (you get the file and steps; the trust store is not changed for you).

## Hosting the pages on Netlify

Netlify can host only the dashboard's static pages. The Python backend must run on a real
server (a VPS, Fly.io, Railway, Render, or this PC) because it holds the live WebSocket, the
database, the model, long uploads and packet capture, none of which Netlify's functions can do.

1. **Backend**: deploy it as described above, over HTTPS with its own domain (for example
   `https://ids.example.com`), with an admin account created. Then set
   `IDS_CORS_ORIGINS=https://<your-site>.netlify.app` (comma-separate several; wildcards are
   refused). The sign-in token travels in an `Authorization` header, not a cookie.
2. **Netlify**: connect the repository. `netlify.toml` already sets base `frontend`, build
   `npm ci && npm run build`, publish `dist` and security headers. In Site configuration →
   Environment variables add `VITE_API_URL=https://ids.example.com`, then deploy.
3. Open the Netlify address and sign in. Browsers refuse an `https` page talking to `http`
   or `ws`, so the backend must be HTTPS (the proxy panel above can provide that).

Checked: the built pages served from one origin, backend on another, in headless Edge:
sign-in, API calls with preflight, live WebSocket and rendered data all worked
(`tests/test_cors.py` covers the CORS rules). Not checked: an actual Netlify deploy, which
needs your account and a public backend.

## Deploying so it survives reboots

All of these live in `deploy/`; none of the scripts do anything until you run them.

* **Windows**: `deploy\windows\install-service.ps1` (elevated PowerShell) registers
  a scheduled task that starts at boot as SYSTEM and is restarted every minute
  if it exits; settings go in `deploy\windows\ids.env`. Use a project `.venv`:
  SYSTEM cannot read packages installed under a user profile, and the script
  warns if that is your situation. `-DryRun` previews, `-Uninstall` removes.
* **Linux**: `sudo deploy/linux/install.sh` creates an unprivileged `ids` user,
  a virtualenv in `/opt/bayesian-ids` and a systemd unit (`Restart=always`) that
  gets `CAP_NET_RAW` and nothing else. Settings are in `/etc/bayesian-ids/env`.
* **Docker**: `deploy/docker/` has a multi-stage Dockerfile (builds the dashboard,
  runs unprivileged, has a health check) and a compose file. Live capture of the
  host's interfaces needs `network_mode: host`, which is Linux only.
* `GET /api/healthz` needs no login and answers 200 or 503, for load balancers
  and monitors.
* Install with `requirements-prod.txt` on servers (no test tools). Only load a
  `bayesian_ids.pkl` you trained yourself: a pickle can run code. The dataset is
  not needed on the server.
* Back up `ids.db`: alerts, their history, users and settings live there.

## Backups, secrets and uploads

All of this was checked against real server processes, not just unit tests.

**Backups** (Operations > Server > *Download backup*)

* A consistent copy of the whole database, taken while the server keeps working:
  five backups taken during a stream of 400-alert batches all passed SQLite's
  integrity check, and their alert counts only ever grew.
* It holds alerts and their handling history, accounts (password hashes), the
  API key hash, and settings. It does **not** hold login sessions: restoring a
  backup never brings an old session back to life (the saved sessions are removed
  from the copy, and the file is compacted so nothing lingers).
* It does **not** hold the encryption key (see below). Keep that file with your
  backups.
* **To restore** (a manual step, deliberately): stop the server, put the backup
  in place as `ids.db` (and the key file beside it as `ids.db.key`), start the
  server. Everyone signs in again with their usual passwords. Without the key
  file the server still starts and everything works except notifications, which
  show a notice asking you to enter the webhook URL / email password again.

**Saved secrets** (webhook URLs, SMTP passwords)

* Encrypted before they are stored (Fernet: AES with an integrity check). The key
  is `IDS_SECRET_KEY` if set, otherwise a file `ids.db.key` created beside the
  database, readable only by your account (and administrators / SYSTEM on Windows).
* Searched for in the database, its write-ahead log, a backup, the server log and
  every dashboard answer (settings, logs, audit trail, users): none of the
  webhook URL, SMTP password, user password, API key, session token or the key
  itself appears in any of them. Passwords are hashed, not encrypted; API keys and
  session tokens are stored only as hashes.
* What this does *not* protect against: someone who can read both the database
  and the key file (for example full access to the machine). It protects a leaked
  or stolen database or backup.
* A damaged or mismatched secret (wrong key, edited database) is detected and
  reported; it never stops the server from starting.

**Large uploads** (Operations > Data)

* Files are streamed to disk, never held in memory: a 1.5 GB dataset (3.2 million
  rows) uploaded in about 5 seconds with 1 MB of server memory growth, arrived
  bit-for-bit identical, and the server stayed responsive (worst health check
  0.03 s). Counting its labels afterwards took 4 s and 173 MB.
* Two uploads at once work. An upload that is dropped half way, or aborted while
  replacing a file, leaves no partial file and leaves the original untouched.
* The limit is `IDS_MAX_UPLOAD_MB` (default 4096). The dashboard refuses an
  oversized file before sending anything; a client that declares a too-large size
  is refused up front; a stream with no declared size is cut off just past the
  limit instead of being read to the end.
* The same 1.5 GB file was also uploaded through a real browser and the real file
  picker. Not tested: files near the 4 GB default, or a full disk.
* Behind a reverse proxy the proxy's body limit must be raised too (the nginx
  example sets `client_max_body_size 4g` and turns request buffering off).

## Notifications

Alerts at or above a risk level are sent to a webhook (Slack, Discord, Teams,
Mattermost or any JSON endpoint) and/or email. During an attack the IDS can
raise thousands of alerts, so they are collected for a short window and sent as
**one digest per channel**, never one message per alert.

Set it up under **Operations > Notifications**: pick the risk level and which
sources may notify, paste a webhook URL (Slack: *Apps > Incoming Webhooks*;
Discord: *Channel settings > Integrations > Webhooks*) and/or fill in the SMTP
details (Gmail needs an app password), press **Save** and **Send test**. It
takes effect immediately, no restart. A secret left blank keeps the stored one.

* `High` is a sensible minimum: real traffic produces some Medium alerts from
  ordinary browsing. The demo replay is not selected by default.
* The dashboard address is what links in messages point to; set it to the address
  people will actually open.
* Webhook URLs and passwords are **encrypted** before they are stored, with a key
  from `IDS_SECRET_KEY` or a key file beside the database. A copy of the
  database alone cannot reveal them; keep the key file with your backups.
* The dashboard can also raise browser notifications for Critical alerts while
  the tab is open (tick the box in the Notifications card on the Monitor page).
* Instead of the form you may use a `notify.json` file (see
  `notify.example.json`); settings saved in the dashboard take precedence.

## If nothing shows up

* **Check the Sources panel** (right of the alerts). It shows, per source, how
  many flows arrived and how long ago the last one came. "Nothing received yet"
  means the traffic never reached the server: is `capture.py` / `live_monitor.py`
  running, and pointing at the right `--api` address?
* **Benign traffic does not create alerts.** A working capture of ordinary
  traffic shows flows scored and an empty Alerts list. Open the **Recent flows**
  tab to see every scored flow, benign ones included.
* **Use the Capture panel** (or `capture.py`) and check its status badge: Error
  shows why it failed, Retrying shows the next attempt. Flows appear when they end
  (first FIN, or after `--idle-timeout` seconds of silence, 15 by default), so
  a new connection can take a few seconds to show up.
* **Wrong interface name**: copy it exactly from `python capture.py --list-interfaces`.
  If capture fails to start on Windows, install Npcap and try an administrator
  terminal.
* **The Source dropdown filters everything.** If it is set to "Demo replay",
  live capture is hidden.
* Restart the server after updating the code; the page needs a hard refresh
  (Ctrl+F5) after `npm run build`.

## Alert handling

Every alert is stored in SQLite with a status (`new`, `investigating`,
`resolved`, `false_positive`), an assignee, a note and a history of changes.
The dashboard lists open alerts by default; filter by status, risk, type,
source or free text (id, IP, note), select several and change them together.
`/?alert=<id>` opens an alert directly; notification messages link to it.

## How detection works

* **Model** (`train_model.py`, `bayesian_engine.py`): a tree-augmented naive
  Bayes network. `AttackType` is the root; each of 20 flow features (binned
  into 16 equal-frequency bins) depends on the class and on at most one other
  feature, chosen by conditional mutual information. All evidence is observed,
  so the posterior is a product of CPD lookups, computed in numpy (checked
  against pgmpy's variable elimination in the tests).
* **Calibration**: raw network probabilities are badly over-confident. A
  two-parameter correction of the log-odds, fitted on validation data, cuts the
  Brier score about five-fold and never changes the ranking of flows.
* **Alert threshold and risk bands** are tuned on a validation split, never on
  the test set. Risk bands (Medium / High / Critical) are cut on the calibrated
  log-odds so that Medium is where benign false alarms live.
* **Novelty check** (`Anomaly` alerts): a second, coarser network (4 bins) scores
  how unlike benign traffic a flow is. Flows the classifier calls benign but
  that fall beyond the 99.5th percentile of benign training traffic are
  reported as `Anomaly`: something unfamiliar, not a known attack. It is
  the only component that catches the late Bot flows (see below).
* **Drift check** (`drift.py`): per source, the bin frequencies of flows judged
  benign are compared with the benign training distribution (PSI), and the
  anomaly rate with the 0.5% it was calibrated to. Status is `stable`,
  `warning` or `drift`.

## Evaluation

`python evaluate_model.py` and `python compare_baselines.py` (writes
`reports/baselines.md`). The split is chronological **per label per capture**:
the first 56% trains the model, the next 14% tunes thresholds and calibration,
the last 30% is the test set. Random splits would hide drift, which is the main
weakness here.

Held-out test results (421,063 flows):

| | precision | recall | F1 | Brier |
|---|---|---|---|---|
| Bayesian network (classifier + novelty) | 0.970 | 0.993 | 0.982 | 0.0043 |
| Bayesian network (classifier only) | 0.988 | 0.988 | 0.988 | 0.0043 |
| Random forest, same 20 features | 0.9998 | 0.992 | 0.996 | 0.0016 |
| Gradient boosting | 0.994 | 0.992 | 0.993 | 0.0030 |

Plain tree ensembles are more accurate than the Bayesian network. What the
network offers instead: seconds to train, probabilities that can be inspected
per class, and a likelihood that powers the novelty check.

Per-class recall on the test set: DDoS 99.7%, PortScan 99.3%, Web Attack 90.5%,
**Bot 94.2%, of which 83% comes from the novelty check, not the classifier**.
The classifier alone finds 11% of Bot flows: the late Bot flows in the capture
(about one second long, no payload, port 8080) look nothing like the early ones
it trained on, and every tree-based model tried, including a random forest on
all columns, fails the same way (15-17%). Only logistic regression catches them
(83%), at the price of overall F1 0.88 and 7% recall on web attacks.

## Limits you should know about

* **Only five of CIC-IDS-2017's eight capture days are on disk** (Monday,
  Thursday morning, Friday x3), so the model knows DDoS, PortScan, web attacks
  and Bot. It has never seen DoS variants, FTP/SSH brute force, Heartbleed or
  infiltration. To add them, download the CSVs from the dataset's site
  (https://www.unb.ca/cic/datasets/ids-2017.html, "MachineLearningCSV"), put
  them in `dataset/` and run `train_model.py` again: labels are picked up
  automatically. Nothing was downloaded automatically because the site gates
  the files behind a form.
* **Four dataset columns were removed**: the ACK/SYN/RST/PSH flag counts do not
  hold real TCP flag counts in CIC-IDS-2017 (`SYN Flag Count` is identical to
  `Fwd PSH Flags`; every PortScan flow has PSH=1 and SYN=ACK=0), so a model using
  them learns dataset artefacts. Removing them cost nothing in accuracy.
* **Real-traffic features are a reimplementation.** CIC-IDS-2017 was produced by
  the Java CICFlowMeter; `flow_features.py` reimplements its definitions for
  the 20 features used (payload-based lengths, microseconds, flow ends at the
  first FIN, 120 s maximum). Definitions were verified against the dataset's
  own numbers where possible, and a synthetic nmap-style scan reproduces the
  dataset's PortScan feature values and is detected, but some quirks are
  approximated (see the module docstring), and **it has not been validated on
  real captured traffic**. Captured frames matter: the dataset counts Ethernet
  padding as payload, which only exists on frames captured as received.
  Expect domain shift on a real network; the drift check is there to tell you.
  Running the Java CICFlowMeter and pointing `live_monitor.py` at its CSV is
  the most faithful route (newer releases' column names are mapped, but that
  mapping was written from the tool's documented header and not tested).
* **Capture was tested on Windows only** (Wi-Fi adapter, Npcap, no administrator
  rights needed there): it captured, scored and stopped cleanly. The Linux and
  macOS checks (raw-socket rights, tcpdump fallback) are unit-tested against
  simulated systems but were never run on those platforms.
* **The deployment files were not run end to end.** The Windows installer was
  dry-run and parsed, the Linux installer syntax-checked, the unit, Dockerfile and
  compose file checked for the settings that matter; nothing was installed as a
  real service, built into an image, or run under systemd or Docker.
* **Authentication is local accounts** (no SSO, no two-factor). A shared
  `IDS_ADMIN_TOKEN` is accepted as an admin credential if you set one. TLS comes
  from `serve.py` or a proxy, and certificates are not renewed automatically
  unless the proxy does it.

## Tests

```
python -m pytest                 # everything, ~5 minutes (includes a real retraining and a real restart)
python -m pytest -m "not slow"   # skips the API test that loads the demo dataset
```

## Files

| | |
|---|---|
| `train_model.py` | trains, calibrates, tunes thresholds, saves `bayesian_ids.pkl` and `model_card.json` |
| `evaluate_model.py`, `compare_baselines.py` | held-out evaluation and baseline comparison |
| `data_loader.py`, `feature_extractor.py` | loading, cleaning, the feature list and binning |
| `bayesian_engine.py`, `detector.py`, `risk_engine.py`, `drift.py` | scoring, alert decision, risk bands, drift |
| `flow_features.py`, `capture_manager.py` | packets to flows; capture control (start / stop / retry / auto-start) |
| `capture.py`, `live_monitor.py`, `replay_flows.py` | command-line traffic sources and demo feed |
| `serve.py`, `api.py`, `storage.py`, `notifier.py` | launcher (HTTPS, safety checks), backend, SQLite persistence, notifications |
| `accounts.py`, `manage_users.py` | users, roles, sessions; command-line account management |
| `jobs.py`, `files.py`, `secrets_store.py` | retraining jobs, safe uploads, encryption of saved secrets |
| `lifecycle.py`, `relaunch.py`, `autostart.py`, `logbuffer.py` | restart, start-at-login, in-memory log |
| `Start Bayesian IDS.bat` | double-click launcher |
| `platform_check.py` | what capture needs on this machine |
| `deploy/` | Windows service, systemd, Docker, reverse-proxy files |
| `frontend/` | React dashboard (Vite + recharts) |
