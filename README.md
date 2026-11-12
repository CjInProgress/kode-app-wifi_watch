# Wi-Fi Watch

A pocket wireless intrusion detector for the Kode Dot. It listens to the Wi-Fi frames around it and raises an alert when it hears the pattern of a common attack: a deauthentication flood, an evil twin or a beacon flood. When nothing is wrong it says **All clear**.

**Receive only.** The app never transmits, injects or deauthenticates anything. It uses the C5's frames service, which puts the radio in promiscuous mode and builds no frame, and the SDK's ordinary Wi-Fi scan. It is a monitoring tool for networks you are allowed to watch.

**Not tested on hardware.** This first version was written before a Kode Dot was at hand. It builds, passes the SDK's RAM check and passes its host unit tests, but nothing in it has run on a board.

## What it detects

| Alert | How it is found | Severity |
|---|---|---|
| **Deauth flood** | Deauthentication frames (management subtype 0xC) from one sender to one target, 10 or more in one second. The row shows the sender (address 2, often a spoofed access point), the target (address 1, "everyone" for broadcast), the rate and the channel. The reason code is kept when the frame is not protected. | alert |
| **Disassoc flood** | The same for disassociation frames (subtype 0xA). | alert |
| **Beacon flood** | 15 or more BSSIDs never heard before, beaconing within two seconds. BSSIDs heard in the first second after a channel change are learnt without counting, because every channel has its own networks. | alert |
| **BSSID clone** | One BSSID whose beacon timestamps go backwards three times within ten seconds. An access point's timestamp only counts up from its start, so beacons from two transmitters using the same BSSID step back and forth. An access point that reboots steps back once and is not reported. | alert |
| **Twin: open + secured** | One network name seen both open and with a password, from the scan. The row names the open BSSID, the likely impostor. | alert |
| **Twin: new BSSID** | A network name that was in an earlier scan, now also on a BSSID that was not there before. A mesh node or a new access point does the same, so this is a warning. | warning |

An alert that stops is still listed, and it holds the all clear back for two minutes after it was last seen. Seen again after that, it is raised again.

## How it works

- The app's Active Object asks AO_Radio for the frames the C5 hears on one channel with `kode_sys_wifi_frames()`. For each 100 ms period it receives a tick with the counts (`WIFI_FRAMES_TICK_SIG`) and up to eight frame records (`WIFI_FRAME_SIG`): channel, level, frame control, addresses 1 and 2, length and the first 8 bytes after the MAC header.
- By default it hops through 22 channels, 2.5 s on each: 2.4 GHz channels 1 to 13, then the 5 GHz channels 36 to 48 and 149 to 165. A channel the radio refuses (one not allowed in its region) is skipped.
- Every two minutes it asks for a Wi-Fi scan with `kode_sys_wifi_scan()`, which gives each network's name, BSSID, channel and whether it is open. The scan is the only place the app learns names from (see Limits). The first complete scan is the baseline for the "new BSSID" warning.
- All parsing and every rule are in [`main/ww_detect.c`](main/ww_detect.c), plain C with no SDK call. The Active Object ([`main/app_ao.c`](main/app_ao.c)) only copies events into it and draws what it says.

## Using it

| Control | What it does |
|---|---|
| **TOP** | Switch between hopping and staying on the current channel. |
| **UP / DOWN** | Stay on the next or the previous channel. |
| **Tap** | When the screen says "Wi-Fi is off", turn Wi-Fi on. The setting is remembered, the same as kodeOS's own Wi-Fi switch. |
| **Hold BOT** | Back to kodeOS, as in every app. |

The screen shows the status lamp (green all clear, yellow a warning, red an alert), where the radio listens, frames per second with the management and data split, the frames this chip lost when there are any, and the alerts, the one seen last first.

## Limits

- **No board yet.** Nothing here has run on hardware. The thresholds are first guesses and will need tuning against real traffic.
- **Sampled frames.** The C5 sends at most 8 frame records per 100 ms period, so the app sees at most 80 frames a second, whatever the air carries. During a flood the attack's frames take most of those slots, so the detection still works, but the rate shown is a lower bound. The tick's counts of management and data frames include every frame.
- **No network names from frames.** The C5 keeps 8 bytes after the MAC header. In a beacon those 8 bytes are the timestamp, so the SSID (from byte 12), the capability field with its privacy bit (bytes 10 and 11) and the RSN element are cut off. The evil-twin rules that need a name use the scan instead, so they only update every two minutes, and the scan keeps the strongest 24 networks.
- **No address 3.** A record carries addresses 1 and 2 only. For a beacon address 2 is the BSSID, which is enough. For a deauthentication sent by a station, the BSSID it names is not known.
- **One channel at a time.** A flood on a channel the hop is not on is missed until the hop gets there; fix the channel with UP or DOWN to watch one network.
- **Joined to a network.** While the Dot is joined to a network the radio stays on that network's channel. The app then stops hopping and listens there only.
- **Scans move the radio.** During a scan (about 38 s) frames are heard on the channels the scan visits and are labelled with the channel at the end of each period, and the hop waits.
- **Protected management frames.** With 802.11w a deauthentication's body is encrypted: the alert still counts it, but shows no reason code. A network that uses 802.11w is not harmed by forged deauthentications in the first place.
- **Heuristics.** A busy enterprise network, a mesh, or a neighbour's access point that reboots often can raise a warning. A careful attacker who copies the real network's security and BSSID exactly, and keeps a monotonic timestamp, is not caught by these rules.

## Building

ESP-IDF v6.1, and the SDK pinned in `main/idf_component.yml` (v0.1.1):

```bash
idf.py build
```

```bash
<kode-sdk>/tools/check_ram.sh build/wifi_watch.elf ram_budget.txt
```

`sdkconfig.defaults` turns the radio and Wi-Fi on (`CONFIG_KODEOS_RADIO=y`, `CONFIG_KODEOS_WIFI=y`), which an app has off by default, and keeps the network and Bluetooth off. `ram_budget.txt` is the template's budget with the radio's and LVGL's lines from the SDK's `tests/target/ram_budget.txt` added back. The detector's tables, about 5.5 KB, are allocated in PSRAM.

## Tests

The detector runs on the host, with no ESP-IDF:

```bash
test/run.sh
```

```bash
WW_CFLAGS="-fsanitize=address,undefined" test/run.sh
```

The tests feed made-up frames and scan entries to every rule, the quiet cases that must not alert included: a few deauthentications from a client leaving, an access point that reboots, the BSSIDs heard at a channel change, a mesh of one name.

## Candidate kode-sdk issues

These were found while writing the app. None is opened.

1. **The frames record is too short for a beacon.** `KODE_SNIFF_HEAD_LEN` is 8, which in a beacon or probe response is only the timestamp. Detecting an evil twin from frames needs the SSID element and the capability field (privacy bit), and ideally the RSN element. A proposal: a longer head for beacons and probe responses only (for example 48 bytes, enough for the fixed fields and a 32-byte SSID), or a beacon summary record with the SSID, the privacy bit and whether an RSN element is present.
2. **No address 3 in a record.** A deauthentication or a data frame names its BSSID in address 3. Adding it (6 bytes) would let a detector say which network a flood targets.
3. **No per-kind counts in the tick.** The tick counts management and data frames per period, but a flood is measured only from the records, at most 80 a second. Counting deauthentications, disassociations and beacons per period on the C5 would give exact rates.
4. **No Wi-Fi on call in `kode_sys`.** The frames service is refused with "Wi-Fi off" until the C5's station is started, and the only call that starts it is `wifi_start_request()` in `kaos.h`. The app uses that call. A `kode_sys_wifi_enable(bool)` next to `kode_sys_wifi_frames()` would keep apps on the public surface.

## Before the catalog

- `appdata/screenshots/` still holds the template's placeholder: rule D9 wants screenshots taken with `kcli.py screenshot` on a board.
- The thresholds in `main/ww_detect.h` should be checked against real traffic, both quiet and under a test attack on a network you own.

## Licence

GPL-3.0-or-later, like the SDK it links, with the additional permission for RFAL: see `LICENSE` and `NOTICE.md`.
