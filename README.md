# Garlic SaveMgr for PS5

PS5 save decrypt/encrypt/browse with embedded web UI.

## Usage

1. Send `garlic-savemgr.elf` to elfldr
2. Open `http://<ps5-ip>:8082` in your browser on your PC
3. Drag and drop files into the browse tab to add/replace files

## Cloud Backups

Open the Settings tab in the web UI to edit `/data/garlic/cloud.json`.
You can also create the file manually:

```json
{
  "enabled": true,
  "provider": "ftp",
  "watch_titles": ["PPSA01234", "CUSA12345"],
  "ftp": {
    "host": "ftp.example.com",
    "port": 21,
    "user": "username",
    "pass": "password",
    "remote_path": "/ps5-saves/",
    "use_tls": false
  },
  "auto_backup": {
    "enabled": true,
    "poll_seconds": 5,
    "settle_seconds": 15,
    "queue_for_browser_drive": true
  },
  "backup_targets": {
    "local": {
      "enabled": false,
      "path": "/data/garlic/backups"
    },
    "usb": {
      "enabled": true,
      "path": "/mnt/usb0/garlic-backups"
    },
    "ftp": {
      "enabled": true
    },
    "google_drive": {
      "enabled": false
    }
  },
  "google_drive": {
    "mode": "browser",
    "folder_id": "drive_folder_id_shared_with_service_account",
    "service_account": {
      "type": "service_account",
      "project_id": "...",
      "private_key_id": "...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
      "client_email": "...",
      "client_id": "...",
      "auth_uri": "https://accounts.google.com/o/oauth2/auth",
      "token_uri": "https://oauth2.googleapis.com/token",
      "auth_provider_x509_cert_url": "...",
      "client_x509_cert_url": "...",
      "universe_domain": "googleapis.com"
    }
  }
}
```

The Browse tab exposes Cloud Backup actions for a selected save and for all saves under a title. Backups are encrypted/restorable ZIP archives. PS5 archives contain the raw save image; PS4 archives include the `sdimg_...` image and its `.bin` key companion when present.

Supported destinations:

- `local`: writes encrypted/restorable ZIP archives on the PS5, defaulting to `/data/garlic/backups`.
- `usb`: writes encrypted/restorable ZIP archives to a connected USB drive, defaulting to `/mnt/usb0/garlic-backups`.
- `ftp`: uploads from the PS5 to a passive plain FTP server.
- `google_drive` with `"mode": "browser"`: the browser fetches the backup ZIP from the PS5 and uploads it to Google Drive. Use service-account auth for Shared Drives, or Browser OAuth Token auth for normal personal My Drive folders.
- `google_drive` with `"mode": "direct"`: configurable, but disabled in this payload build because the PS5 SDK image exposes `libSceSsl.so` without public SSL headers for a safe HTTPS implementation.

The legacy top-level `provider` field still works, but `backup_targets` can enable multiple destinations at once. Manual and auto title backups package one encrypted/restorable ZIP under `/data/garlic/tmp`, then distribute that same ZIP to every enabled PS5-side destination (`local`, `usb`, `ftp`). Google Drive browser mode remains a browser/queue destination.

For Google Drive browser mode, the Drive folder ID is required. Folder names like `ps5_saves` are not accepted as IDs. Service accounts do not have storage quota in normal My Drive folders, so they can only upload to Shared Drives or Workspace delegated drives. For a personal My Drive folder, select Browser OAuth Token in Settings and paste a Drive-scoped access token. Settings -> Test Drive Access verifies the selected auth can see and upload to the folder.

When `auto_backup.enabled` is true, Garlic SaveMgr starts a watcher thread. It probes the PS5 LNC symbols for the running Big App title, snapshots watched save mtimes/sizes when a title starts, then waits `settle_seconds` after the title closes before backing up changed saves. If the LNC probe is unavailable, it falls back to mtime polling for watched titles.

Auto upload behavior:

- FTP uploads immediately from the PS5 using the same encrypted/restorable title ZIP as Cloud Backup All.
- Local and USB targets write immediately from the PS5 using the same encrypted/restorable title ZIP as Cloud Backup All. Files are written as `.tmp` first, then renamed to `.zip` when complete.
- Google Drive browser mode writes pending ZIPs to `/data/garlic/cloud_queue/`. The Settings page polls the queue and uploads pending backups when the browser is open with valid Drive auth.
- Google Drive direct mode remains unsupported, but can still queue browser uploads when `queue_for_browser_drive` is true.

The manual API endpoints are:

- `GET /api/settings/cloud`
- `POST /api/settings/cloud`
- `GET /api/cloud/status`
- `GET /api/cloud/upload?idx=N&mode=enc`
- `GET /api/cloud/upload_title?id=<title_id>&mode=enc`
- `GET /api/cloud/package?idx=N`
- `GET /api/cloud/package_title?id=<title_id>`
- `GET /api/cloud/auto_status`
- `POST /api/cloud/auto_scan`
- `GET /api/cloud/queue`
- `GET /api/cloud/queue_download?id=<queue_id>`
- `POST /api/cloud/queue_done?id=<queue_id>`

If `watch_titles` is non-empty, manual cloud uploads are limited to those title IDs. FTP `use_tls` still fails with a clear error instead of silently downgrading.

## Quick Setup: Local FTP Server (Windows & Docker)

If you want to test cloud backups locally without routing through a cloud service, you can spin up a temporary, isolated FTP server on your Windows PC using Docker.

This setup automatically bridges a local folder on your PC to the FTP server, so any files sent from your PS5 will instantly appear on your desktop.

### Prerequisites

1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. Ensure Docker Desktop is open and the Engine is running.
3. Open a **PowerShell** window.

### Step 1: Prepare your Workspace

First, create a folder where you want your saves to land, and navigate inside it using PowerShell:

```powershell
# Create the folder on your desktop and navigate to it
mkdir ~\Desktop\PS5_SAVES
cd ~\Desktop\PS5_SAVES
```

### Step 2: Spin up the FTP Server

Run the following command.

*Note: Replace `192.168.1.X` with your computer's actual local network IP address (you can find this by running `ipconfig` and looking for your IPv4 Address).*

```powershell
docker run -d -p 21:21 -p 21000-21010:21000-21010 `
  -e USERS="ps5_saves|password|/ftp/ps5_saves" `
  -e ADDRESS="192.168.1.X" `
  -v "${PWD}:/ftp/ps5_saves" `
  delfer/alpine-ftp-server
```

**What this does:**

* Creates an FTP user named `ps5_saves` with the password `password`.
* Locks the user into the `/ftp/ps5_saves` directory.
* Maps your current Windows folder (`${PWD}`) directly to that internal directory so files sync instantly.
* Broadcasts your real local IP (`ADDRESS`) so passive FTP connections don't time out.

### Step 3: Windows Firewall (Crucial)

By default, Windows aggressively blocks external devices from talking to Docker. To let your PS5 connect:

1. Ensure your Windows Network Profile is set to **Private**, not Public.
2. In your Windows Defender Firewall settings, allow the **Docker Desktop Backend** executable through the firewall on Private networks.

### Step 4: Configure Garlic SaveMgr

Open the web UI at `http://<ps5-ip>:8082`, go to **Settings**, and set the FTP provider (or edit `/data/garlic/cloud.json` directly):

```json
"ftp": {
  "host": "192.168.1.X",
  "port": 21,
  "user": "ps5_saves",
  "pass": "password",
  "remote_path": "/",
  "use_tls": false
}
```

Use **Test FTP** in Settings to verify connectivity, then run **Cloud Backup** (or **Cloud Backup All** on a title) from the save list. Files will drop into your Windows `PS5_SAVES` folder.

**Tear Down:**

When you are done testing, kill the background server by grabbing the container ID and forcing it to stop:

```powershell
docker ps
docker rm -f <CONTAINER_ID>
```

## Building

Requires the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

```sh
make PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

