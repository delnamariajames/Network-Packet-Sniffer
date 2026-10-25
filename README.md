# Network Packet Sniffer (Python)

A command-line IPv4 packet sniffer using Python raw sockets. Parses IPv4 headers, TCP/UDP ports, shows a short hex payload preview, and writes protocol counts to a log.

## Requirements
- Python 3.9+
- Administrator on Windows or root on Linux
- Only capture traffic on networks/devices you are authorized to monitor

## Run (Windows)
Open PowerShell **as Administrator**:

```powershell
cd path\to\network_packet_sniffer
python packet_sniffer.py --host YOUR_LOCAL_IPV4 --count 20
```

Use `ipconfig` to find your local IPv4 address. Generate network traffic by visiting a website or using `ping`. The log is written to `network_log.txt`.

## Run (Linux)
```bash
sudo python3 packet_sniffer.py --count 20
```

**Platform limitation:** The built-in Linux raw socket implementation here uses `IPPROTO_TCP` and therefore captures TCP only. For full multi-protocol capture on Linux, use an AF_PACKET socket or a packet-capture library. Windows Winsock raw socket support also varies by Windows version and adapter; it does not capture all link-layer traffic.

## Files
- `packet_sniffer.py`: packet capture and decoding
- `network_log.txt`: **illustrative sample**; replace with a real capture for submission proof

## Privacy
Logs contain IP addresses, ports, and payload previews. Review/redact sensitive information before sharing on GitHub.
