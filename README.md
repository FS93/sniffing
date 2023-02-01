# Praktikum IT-Sicherheit WS2022/23

## Projekt: Aufbau einer Toolchain zum automatischen Aufzeichnen, Labeln und Klassifizieren von IoT-Netzwerktraffic

### Gruppe 4 (WLAN-Bridge, Aufzeichnen, Labeln)

#### Anleitung

1) Access point (ap0) erstellen mit <https://github.com/lakinduakash/linux-wifi-hotspot>
2) Virtuelle Umgebung erstellen & aktivieren: `python -m venv VirtEnv_sniffing; source VirtEnv_sniffing/bin/activate`
3) Pakete installieren: `pip install -r requirements.txt; sudo pip install -r requirements.txt` (zum Live Sniffing werden root Rechte benötigt)
4) `cd src`
5) Anwendungsfall
   1) PCAP vorhanden: `./process_pcap.py --in_pcap <Dateipfad PCAP-File> --out_csv <Dateipfad CSV-Output>`
   2) PCAP nicht vorhanden (Live Sniffing): `sudo ./live_sniffer.py --count <Anzahl Pakete> --out_name <Präfix für PCAP- und CSV-Output>`

#### Erstellte Dateien

1) CSV Datei mit diesen Columns
    * `frame_number`
    * `frame_time_epoch`
    * `frame_len`
    * `eth_src`
    * `device_name_src`
    * `eth_dst`
    * `device_name_dst`
    * `eth_type`
    * `ip_src`
    * `srcport`
    * `ip_dst`
    * `dstport`
    * `ip_proto`
    * `payload_utf8`
    * `action`
    * `attack`
2) bei Live Sniffing: PCAP-Datei
3) `config.txt`: Scapy config zum Debuggen
