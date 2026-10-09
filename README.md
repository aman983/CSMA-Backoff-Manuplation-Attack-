# CSMA Backoff Manipulation Attack

A research project studying **MAC-layer misbehavior in IEEE 802.15.4 networks**:
a selfish node manipulates its CSMA backoff timing to gain an unfair share of the
wireless channel, increasing collisions and end-to-end latency for well-behaved
nodes. The project is built on [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
and includes both the attack implementation and a lightweight detection defence.

Developed as part of a network security project at **TU/e (Eindhoven University of
Technology)**. The attack is **fully protocol-compliant** — it sends no malformed
packets and breaks no framing rules; it only changes *when* the node contends for
the channel, which makes it hard to catch with signature-based defences.

> ⚠️ **For research and education only.** This code is intended to be run in
> simulation (Cooja / Renode) or on an isolated testbed of boards you own, for
> studying MAC-layer robustness and defences. Do not deploy it against networks
> or spectrum you are not authorized to test.

---

## Background

In IEEE 802.15.4 non-beacon CSMA/CA, a node that wants to transmit waits a random
backoff before sensing the channel. The backoff window is `2^BE − 1` backoff
periods, where the backoff exponent `BE` starts at `macMinBE` and grows (up to
`macMaxBE`) with each collision. Honest nodes that follow the standard share the
channel fairly because they all draw from the same distribution.

A **selfish/misbehaving node** can bias this in its favor by shrinking its backoff
window — effectively sensing and transmitting sooner than compliant neighbors.
The result is that the misbehaving node wins the channel more often, while honest
nodes see more collisions, more retransmissions, and higher latency.

This project demonstrates that effect, measures it, and then detects it.

---

## How it works

### The attack

The misbehaving node is built from a modified CSMA layer
(`csma-output.c` / `csma-output.h`) and an aggressive backoff configuration in
`ATTK_CSMA/project-conf.h`:

```c
#define CSMA_CONF_MIN_BE            3   // smaller -> more aggressive
#define CSMA_CONF_MAX_BE            5   // limit exponential growth
#define CSMA_CONF_MAX_BACKOFF       5
#define CSMA_CONF_MAX_FRAME_RETRIES 7
```

Lowering the minimum/maximum backoff exponent and the number of backoffs shortens
the random wait the node draws before accessing the channel, so it contends more
aggressively than standard-compliant neighbors. The same application image is
compiled into different roles via build flags:

- `N1`, `N2` — normal (honest) nodes
- `ATTK` — the misbehaving node (sends payload `A1`)

The modified CSMA layer also adds instrumentation (`print_csma_stats()`) that
tracks total collisions, retransmissions, and a running average of per-packet
queueing delay, so the impact of the attack can be quantified from the logs.

### The defence

`defence/csma.c` adds a detector that runs at the receiver (e.g. the border
router / DAG root). For each sending neighbor it tracks the **inter-arrival time
(IAT)** of received frames and maintains an exponentially weighted moving average
(EWMA):

```
ewma = (iat + (ewma << ALPHA_SHIFT) - ewma) >> ALPHA_SHIFT   // ALPHA_SHIFT = 3
```

If a node's smoothed IAT stays below a threshold (`CHEAT_THRESHOLD_TICKS`), its
**suspicion score** is incremented (and decremented when it behaves). Once the
score crosses `MAX_SUSPICIOUS_SCORE`, the node is flagged, blacklisted, and its
subsequent frames are dropped:

```
[Backoff Detection] Violating node detected. Blacklisting node. ...
[Backoff Detection] Dropped N total packets from flagged nodes
```

Tunable parameters at the top of `defence/csma.c`: `NUMBER_OF_ALLOWED_NODES`,
`ALPHA_SHIFT`, `MAX_VALID_IAT`, `CHEAT_THRESHOLD_TICKS`, `MAX_SUSPICIOUS_SCORE`.

---

## Results

Measured on a CC2650 SensorTag testbed, a **single protocol-compliant** attacker
was enough to degrade a legitimate node substantially — without sending any
malformed packets:

| Metric (legitimate node)        | Baseline | Under attack |
| ------------------------------- | -------- | ------------ |
| Packet delivery ratio           | 92%      | 46%          |
| Collisions per 100 transmissions | 2        | 48           |

The EWMA-based detector on the border router identified and blacklisted the
attacker, allowing the legitimate node's metrics to recover.

---

## Repository layout

```
.
├── csma-output.c / csma-output.h   # Modified CSMA output layer (attack + stats)
├── ATTK_CSMA/                      # Experiment application (RPL + UDP)
│   ├── udp-client.c                # Node firmware; role set by build flag (N1/N2/ATTK)
│   ├── udp-server.c                # DAG root / UDP server
│   ├── project-conf.h              # Aggressive CSMA backoff configuration
│   ├── rpl-udp-cooja.csc           # Cooja simulation (cooja motes)
│   ├── rpl-udp-sky.csc             # Cooja simulation (sky motes)
│   ├── rpl-udp.resc / .robot       # Renode emulation script + Robot test
│   └── Makefile
├── defence/                        # Detection defence
│   ├── csma.c                      # EWMA-based backoff-misbehavior detector
│   ├── framer-802154.c
│   └── border-router.c
├── rpl-border-router/              # Border router (with simple webserver)
└── Bin/                            # Prebuilt firmware images (cc26x0-cc13x0)
    ├── N1 / N2                     #   honest nodes
    ├── ATTK                        #   misbehaving node
    └── sensniff                    #   802.15.4 sniffer firmware
```

Target hardware for the prebuilt images: **TI CC26x0 / CC13x0** (e.g. SensorTag
CC2650). The project also runs fully in simulation.

---

## Requirements

- [Contiki-NG](https://docs.contiki-ng.org/) (this project is meant to sit inside
  a Contiki-NG tree; the Makefile uses `CONTIKI=../..`)
- ARM GCC toolchain (`arm-none-eabi-gcc`) for the CC26x0/CC13x0 target
- [Cooja](https://docs.contiki-ng.org/en/develop/doc/tutorials/Running-Contiki-NG-in-Cooja.html)
  for network simulation, and/or
  [Renode](https://docs.contiki-ng.org/en/develop/doc/tutorials/Running-Contiki-NG-in-Renode.html)
  for emulation

## Build & run

### Simulation (Cooja)

Open one of the simulation configs in Cooja:

```
ATTK_CSMA/rpl-udp-cooja.csc     # cooja motes
ATTK_CSMA/rpl-udp-sky.csc       # sky motes
```

Start the simulation and watch the mote output. The attacker's effect shows up as
rising collision/retransmission counts and latency on the honest nodes; with the
defence enabled, the detector logs when it blacklists the misbehaving node.

### Emulation (Renode)

```bash
cd ATTK_CSMA
make TARGET=cc2538dk
renode-test rpl-udp.robot        # Robot-framework test
# or run the scenario directly:
renode rpl-udp.resc
```

### Hardware (TI CC26x0 / CC13x0)

Build each role from the same application using the build flags, then flash:

```bash
cd ATTK_CSMA
make TARGET=cc26x0-cc13x0 BOARD=sensortag/cc2650         # honest node (default N1)
make TARGET=cc26x0-cc13x0 BOARD=sensortag/cc2650 DEFINES=ATTK   # misbehaving node
```

Prebuilt images are also provided in `Bin/` (`N1`, `N2`, `ATTK`, and `sensniff`
for packet capture).

### Suggested experiment

1. Run a baseline with only honest nodes (`N1`, `N2`) and record collisions,
   retransmissions, and average delay from `print_csma_stats()`.
2. Add the `ATTK` node and compare the same metrics — latency and collisions for
   the honest nodes should rise.
3. Enable the defence (`defence/csma.c`) on the receiver and confirm the attacker
   is detected and blacklisted, and that honest-node metrics recover.

---

## Notes

- `csma-output.c`/`.h` are derived from Contiki's CSMA layer (SICS / Simon
  Duquennoy, BSD-3-Clause) with project-specific modifications marked `/* my code */`.
- The attack logic and backoff manipulation were implemented by the author; the
  defence module lives under `defence/`.

## License

The Contiki-NG-derived sources retain their original BSD-3-Clause license headers.
