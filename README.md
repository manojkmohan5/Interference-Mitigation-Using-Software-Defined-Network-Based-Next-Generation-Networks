# Interference Mitigation Using SDN-Based Next-Generation Networks

**ARP poisoning detection and mitigation on a software-defined network.**

An [Ryu](https://ryu-sdn.org/) OpenFlow 1.3 controller that inspects every ARP packet
crossing the switch, holds each MAC address to the IP and physical port it first claimed,
and drops the port of any host that contradicts itself. The network runs under
[Mininet](http://mininet.org/); the attack is generated with `ettercap`.

Two browser pages ship with the project, neither of which needs Linux, Docker or an
install — open them directly:

- **[`guide.html`](guide.html)** — start here if you don't work with networks. Explains the
  attack as a story, labels every panel of the simulator, and gives you five things to try
  in order. No jargon, with a glossary.
- **[`simulator.html`](simulator.html)** — interactive simulation. Launch the attack
  yourself and watch the flow table, `mac_to_ip`, `mac_to_port` and every host's ARP cache
  change in real time, with the two feature flags wired to live toggles.
- **[`index.html`](index.html)** — illustrated walkthrough: architecture diagrams, the
  packet pipeline, and the reasoning behind the design.

---

## Contents

- [The problem](#the-problem)
- [How the detection works](#how-the-detection-works)
- [Topology](#topology)
- [Flow table](#flow-table)
- [Requirements](#requirements)
- [Running it](#running-it)
- [Expected output](#expected-output)
- [Repository layout](#repository-layout)
- [Known limitations](#known-limitations)

---

## The problem

ARP has no authentication. A host broadcasts *"who has 192.168.1.4?"*, and whatever reply
comes back is believed — there is no signature to check and no rule against a later answer
overwriting an earlier one.

An attacker exploits that by sending unsolicited replies in both directions: telling h3
*"I am h4"* and telling h4 *"I am h3"*. Both victims update their ARP caches, and every
packet between them is then relayed through the attacker, who can read it in full. Nothing
appears to break — pings still succeed — which is what makes it worth detecting.

## How the detection works

A single ARP packet carries no evidence of its own truthfulness, so it cannot be validated
in isolation. It can, however, be validated **against history**.

A legitimate host's identity is a triple that does not change during a session:

```
MAC address  ·  IP address  ·  ingress switch port
```

The controller records that triple the first time it sees a MAC, then holds the sender to
it on every subsequent ARP packet. A forged reply has to lie about at least one leg of the
triple, so it cannot match.

| Stage | `mac_to_ip[dpid]` state | Result |
| --- | --- | --- |
| First sighting of a MAC | entry created | packet allowed |
| Same MAC, same IP, same port | matches | packet allowed |
| Same MAC, **different IP or port** | mismatch | **attack — port blocked** |

The implementation is `arp_process()` in [`app.py`](app.py) (lines 60–89). Mitigation is
`block_port()` (lines 93–98): a priority-101 flow rule matching the attacker's ingress
port with an empty action list, which in OpenFlow means *drop*.

Two module-level flags at the top of `app.py` control the behaviour:

```python
ARP_POSION_DETECTION  = 1   # log ARP inconsistencies
ARP_POSION_MITIGATION = 1   # also block the offending port
```

Setting both to `0` lets the attack run unimpeded, which is useful for demonstrating the
difference.

## Topology

Built by [`topology.py`](topology.py) — one switch, four hosts, all on `192.168.1.0/24`
with fixed MAC addresses so the bindings are predictable.

```
                  ┌─────────────────────────────┐
                  │  Ryu controller — app.py    │
                  │  127.0.0.1:6653             │
                  └──────────────┬──────────────┘
                                 │  OpenFlow 1.3
                  ┌──────────────┴──────────────┐
                  │      Open vSwitch  s1       │
                  └──┬────────┬────────┬───────┬┘
                port 1   port 2   port 3   port 4
                     │        │        │       │
                  ┌──┴──┐  ┌──┴──┐  ┌──┴──┐ ┌──┴──┐
                  │ h1  │  │ h2  │  │ h3  │ │ h4  │
                  └─────┘  └─────┘  └─────┘ └─────┘
                 .1.1     .1.2     .1.3    .1.4
              (attacker)                (victims: h3 ⇄ h4)
```

| Host | IP | MAC | Switch port |
| --- | --- | --- | --- |
| h1 | 192.168.1.1 | `00:00:00:00:00:01` | 1 |
| h2 | 192.168.1.2 | `00:00:00:00:00:02` | 2 |
| h3 | 192.168.1.3 | `00:00:00:00:00:03` | 3 |
| h4 | 192.168.1.4 | `00:00:00:00:00:04` | 4 |

## Flow table

The switch checks rules in priority order and stops at the first match.

| Priority | Match | Action | Installed |
| --- | --- | --- | --- |
| 101 | `in_port = <attacker>` | *(none — drop)* | on detection, `idle_timeout=300` |
| 100 | `eth_type = 0x0806` (ARP) | send to controller | at switch connect |
| 1 | `in_port`, `eth_src`, `eth_dst` | output to port | per flow, `idle_timeout=10` |
| 0 | table-miss | send to controller | at switch connect |

The priority-100 rule is what makes the whole thing work: it forces **every** ARP packet
up to the controller instead of letting the switch forward it at line rate. Ordinary IPv4
traffic gets a priority-1 shortcut after its first packet, so the controller does not
become a bottleneck.

## Requirements

Linux only — Mininet needs kernel network namespaces. On macOS or Windows, run it inside a
Linux VM.

- Python 3
- [Mininet](http://mininet.org/download/) with Open vSwitch
- [Ryu](https://ryu.readthedocs.io/en/latest/getting_started.html) SDN framework
- `ettercap` (to generate the attack)
- `tcpdump` / Wireshark (to inspect the capture)

```bash
sudo apt update
sudo apt install mininet openvswitch-switch tcpdump ettercap-text-only
pip3 install ryu
```

> **Note:** Ryu is not maintained against recent Python releases. If `pip3 install ryu`
> fails on Python 3.11+, use Python 3.9 in a virtualenv, or run the whole lab in a
> Mininet VM image, which ships a compatible stack.

## Running it

Three terminals.

**1 — Start the controller**

```bash
ryu-manager app.py
```

It stays in the foreground and logs every ARP packet it sees.

**2 — Build the network**

```bash
sudo python3 topology.py
```

This creates `s1` and the four hosts, connects to the controller on localhost, runs
`pingAll` once, and leaves you at the `mininet>` prompt. It also starts `tcpdump` on h1
writing to `test.pcap`.

**3 — Generate traffic between the victims**

At the Mininet prompt:

```
mininet> h3 ping 192.168.1.4
```

**4 — Attack from h1**

```
mininet> xterm h1
```

Then, inside the h1 window:

```bash
ettercap -T -i h1-eth1 -w test1.pcap -M ARP /192.168.1.3// /192.168.1.4//
```

Press `q` to stop the attack.

**Comparing the three modes.** Edit the flags at the top of `app.py`, restart
`ryu-manager`, and repeat:

| `DETECTION` | `MITIGATION` | Behaviour |
| --- | --- | --- |
| `0` | `0` | The attack succeeds silently. h1 relays and reads all h3↔h4 traffic. |
| `1` | `0` | The attack is logged as it happens, but still works. |
| `1` | `1` | The attack is logged and h1's port is dropped. Traffic stops. |

## Expected output

Normal ARP traffic, as bindings are learned:

```
Received ARP Packet from dpid 1 Port No 3: Opcode 1 srcmac: 00:00:00:00:00:03 ...
Added entry.....new mac ip table {'00:00:00:00:00:03': {'ip': '192.168.1.3', 'port': 3}}
```

The moment ettercap starts forging:

```
****** Error: ARP Poisoning attack *** Attacker MAC 00:00:00:00:00:01 sniffing IP 192.168.1.3
Existing Entry for this MAC 00:00:00:00:00:01 IP Address is {'ip': '192.168.1.1', 'port': 1}
Blocking the Port
```

Confirm the drop rule landed, from another terminal:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

You should see a `priority=101,in_port=1` entry with no actions listed. The `h3 ping`
stops returning through the attacker, and `test.pcap` opened in Wireshark shows the
forged replies — Wireshark flags them as *duplicate use of 192.168.1.3 detected*.

## Repository layout

| File | What it is |
| --- | --- |
| `app.py` | The Ryu controller. A learning switch with the ARP binding check layered on it. |
| `topology.py` | Mininet lab — one switch, four hosts, remote controller. |
| `guide.html` | Plain-English guide to the simulator. No networking background needed. |
| `simulator.html` | Interactive simulation of the controller. No install needed. |
| `index.html` | Illustrated walkthrough of the design. Open in a browser. |
| `logic.txt` | The detection algorithm in prose, written before the code. |
| `readme.txt` | Original run notes. Superseded by this file. |
| `test.pcap` | A captured run, openable in Wireshark. |
| `Finaloutput.pdf` | Project report. |

Key functions in `app.py`:

| Function | Lines | Role |
| --- | --- | --- |
| `switch_features_handler` | 27–41 | Installs the table-miss and priority-100 ARP rules on connect. |
| `add_flow` | 44–57 | Builds and sends a `flow_mod`. The only place rules are pushed. |
| `arp_process` | 60–89 | The detection — records or validates the MAC/IP/port triple. |
| `block_port` | 93–98 | The mitigation — priority-101 drop rule on the ingress port. |
| `_packet_in_handler` | 101–180 | Filter LLDP → learn MAC → validate ARP → forward or block. |

## Known limitations

This is a working demonstration, not a hardened defence. The gaps are worth stating plainly:

- **MAC spoofing defeats it.** The binding table is keyed by MAC. An attacker that forges
  the source MAC as well as the IP creates a fresh entry, and first sightings are always
  trusted. Closing this needs a statically configured port-to-address table.
- **First speaker wins.** Bindings come from whatever the controller sees first. An
  attacker present at boot poisons the table itself, and the legitimate host is the one
  flagged.
- **The block is coarse.** Mitigation drops the entire switch port, not just the offending
  traffic. Fine for one host per port; not fine if a downstream switch sits behind it.
- **The block expires quietly.** `idle_timeout=300` removes the drop rule after five
  minutes of silence, with no notification. An attacker that pauses is readmitted.
- **The MAC is learned before validation.** `mac_to_port` is updated at line 134, before
  the ARP check runs, so a rejected packet still leaves its source MAC in the forwarding
  table.
- **`if buffer_id:` at line 50 is a bug.** OpenFlow buffer ID `0` is valid and falsy in
  Python, so that flow takes the wrong branch. It should be `if buffer_id is not None:`.

## About the name

The repository is titled *Interference Mitigation Using Software-Defined Network Based
Next-Generation Networks*, from the academic framing around the project. The code is
narrower and more concrete than that suggests: it detects and mitigates ARP poisoning on
an SDN. This README describes the code.
