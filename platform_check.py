"""
Can this machine capture packets, and if not, why not?

Live capture depends on things outside the project: a packet driver
(Npcap on Windows), raw-socket rights (administrator / root / the
CAP_NET_RAW capability) and, for scapy's capture filters on Linux,
tcpdump. Failing at the moment someone presses Start gives a cryptic
error, so the dashboard shows this report next to the Capture panel.

The checks take their inputs as arguments so every platform's logic can be
tested from any machine.
"""
import ctypes
import os
import shutil
import sys

CAP_NET_RAW = 13


def is_windows_admin():

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def read_proc_status():
    """Contents of /proc/self/status, or None where it does not exist."""

    try:
        with open("/proc/self/status") as f:
            return f.read()
    except OSError:
        return None


def has_capability(status_text, capability=CAP_NET_RAW):
    """True if the effective capability set (CapEff) includes the bit."""

    if not status_text:
        return None

    for line in status_text.splitlines():

        if line.startswith("CapEff:"):
            return bool(int(line.split()[1], 16) >> capability & 1)

    return None


def diagnose(
    platform=sys.platform,
    exists=os.path.exists,
    which=shutil.which,
    geteuid=getattr(os, "geteuid", lambda: None),
    access=os.access,
    proc_status=read_proc_status,
    windows_admin=is_windows_admin
):
    """
    {platform, library, privileged, can_capture, problems, hints}

    problems stop capture from working; hints are things worth knowing.
    """

    problems, hints = [], []

    if platform.startswith("win"):

        name = "windows"

        npcap = any(exists(p) for p in (
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll"
        ))

        library = "Npcap" if npcap else None

        privileged = windows_admin()

        if not npcap:
            problems.append(
                "Npcap is not installed. Install it from https://npcap.com "
                "(the default options are fine)."
            )

        if privileged is False:
            hints.append(
                "The server is not running as administrator. That works when "
                "Npcap was installed without 'Restrict to administrators'; "
                "if capture fails with a permission error, run the server "
                "as administrator."
            )

    elif platform == "darwin":

        name = "macos"

        library = "libpcap (built in)"

        privileged = geteuid() == 0 or (
            exists("/dev/bpf0") and access("/dev/bpf0", os.R_OK | os.W_OK)
        )

        if not privileged:
            hints.append(
                "Capturing needs read access to /dev/bpf*. Run the server "
                "with sudo, or install Wireshark's ChmodBPF helper."
            )

    elif platform.startswith("linux"):

        name = "linux"

        library = "AF_PACKET sockets (built in)"

        euid = geteuid()

        capable = has_capability(proc_status())

        privileged = euid == 0 or bool(capable)

        if not privileged:
            problems.append(
                "The server has no right to open raw sockets. Run it as root, "
                "or grant the capability: "
                "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3)). "
                "The systemd unit in deploy/ already does this for you."
            )

        if not which("tcpdump"):
            hints.append(
                "tcpdump is not installed. Capture still works (the server "
                "falls back to reading every packet), but install it for "
                "kernel-level filtering: sudo apt install tcpdump"
            )

    else:

        name = platform

        library = None

        privileged = None

        hints.append(f"Packet capture was not tested on {platform}.")

    return {
        "platform": name,
        "library": library,
        "privileged": privileged,
        "can_capture": not problems,
        "problems": problems,
        "hints": hints
    }
