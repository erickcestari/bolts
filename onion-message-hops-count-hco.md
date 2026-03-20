# BOLT #4 Amendment: Hop Count Onion for Onion Messages

## Overview

Onion messages (`option_onion_messages`) allow routes of up to ~350 hops
(with `len` = 32834), creating a denial-of-service amplification vector:
an attacker constructs long paths that cause targeted peers to flood each
other with traffic. Existing mitigations (rate limiting, message
dropping) bound the damage but do not limit the amplification factor.

This amendment introduces a **Hop Count Onion (HCO)** — a compact,
fixed-size structure that travels alongside each onion message to cap
route length at 20 hops, reducing worst-case amplification from ~350x to
20x without changing the main onion's payload capacity.

The HCO uses the same construction as Sphinx: a fixed-size buffer of
layered-encrypted HMAC slots, built backwards by the sender, peeled one
layer per hop. Because the buffer fits exactly `MAX_HCO_HOPS` slots, the
sender physically cannot construct a valid packet for more hops — the
same property that limits HTLC payment routes today. No new
cryptographic mechanisms are required beyond the existing Sphinx
construction.

The HCO reuses the main onion's shared secrets (with distinct key
labels), uses truncated 8-byte HMACs (justified below), and is
HMAC-bound to the main onion packet. At 168 bytes total, it adds minimal
overhead. No per-hop TLV fields are required in the main onion.

Loop prevention and replay detection are out of scope; per-peer rate
limiting addresses both.

## Constants

| Name                     | Value | Description                           |
|--------------------------|-------|---------------------------------------|
| `MAX_HCO_HOPS`          | 20    | Maximum number of hops                |
| `HCO_HMAC_SIZE`         | 8     | Truncated HMAC size per slot          |
| `HCO_ROUTING_INFO_SIZE` | 160   | Routing info size (20 × 8 bytes)      |
| `HCO_SIZE`              | 168   | Total: routing info + 8-byte HMAC     |

## Packet Structure

The HCO has no embedded ephemeral key (it reuses the main onion's):

1. type: `hop_count_onion`
2. data:
   * [`HCO_ROUTING_INFO_SIZE*byte`:`routing_info`]
   * [`HCO_HMAC_SIZE*byte`:`hmac`]

Each slot in the routing info is an 8-byte truncated HMAC for the next
hop. Since per-hop payloads are always empty, no length prefix is
needed — the main onion carries all routing instructions.

## Key Derivation

All keys derive from the main onion's Sphinx shared secrets (`ss_i`)
using distinct `"hco_"` labels:

| Key            | Derivation                       | Purpose                      |
|----------------|----------------------------------|------------------------------|
| `hco_rho_key`  | `HMAC256("hco_rho", ss_i)`      | Stream cipher key            |
| `hco_mu_key`   | `HMAC256("hco_mu", ss_i)`       | HMAC key                     |
| `hco_pad_key`  | `HMAC256("hco_pad", sessionKey)` | Initial routing info padding |

No additional ECDH is required. Each relay blinds the ephemeral key
once; both packets use the result. Blinded hops work automatically.

## Updated `onion_message` Format

1. type: 513 (`onion_message`) (`option_onion_messages`)
2. data:
   * [`point`:`path_key`]
   * [`u16`:`len`]
   * [`len*byte`:`onion_message_packet`]
   * [`HCO_SIZE*byte`:`hop_count_onion`]

No TLV fields are added to `onionmsg_tlv`. The HCO is self-contained.

## Packet Construction

### Requirements

The sender:

- MUST compute the standard Sphinx shared secrets for all hops.
- MUST NOT construct a route with more than `MAX_HCO_HOPS` hops.
- MUST construct the HCO as specified below.
- MUST include the HCO (as seen by each hop) in the corresponding
  hop's HMAC computation for the main onion.

### HMAC Binding to Main Onion

The HCO is bound to the main onion by inclusion in each hop's HMAC:

```
main_hmac_k = HMAC256(main_mu_key_k,
    main_routing_info || associated_data || hco_seen_by_hop_k)
```

Tampering with or stripping the HCO causes the main onion's HMAC to
fail. The sender constructs both packets backwards in parallel,
recording each hop's view of the HCO at HMAC computation time.

### Construction Pseudocode

```
function constructHCO(route, sessionKey, assocData):
    n = len(route)
    assert n <= MAX_HCO_HOPS

    ss = computeSphinxSharedSecrets(route, sessionKey)

    // Initialize with pseudo-random padding
    padKey = HMAC256("hco_pad", sessionKey)
    routingInfo = generateCipherStream(padKey, HCO_ROUTING_INFO_SIZE)

    // Standard Sphinx filler generation using hco_rho keys
    // and HCO_HMAC_SIZE as the per-hop shift
    filler = generateFiller(ss, "hco_rho", HCO_HMAC_SIZE,
                            HCO_ROUTING_INFO_SIZE)

    var nextHmac [HCO_HMAC_SIZE]byte  // zero for final hop
    hcoSeen = new array[n] of byte[HCO_SIZE]

    for i = n-1 downto 0:
        rhoKey = HMAC256("hco_rho", ss[i])
        muKey  = HMAC256("hco_mu", ss[i])

        // Shift right and place next hop's HMAC
        rightShift(routingInfo, HCO_HMAC_SIZE)
        copy(routingInfo[0:HCO_HMAC_SIZE], nextHmac)

        // Layered encryption
        stream = generateCipherStream(rhoKey, HCO_ROUTING_INFO_SIZE)
        xor(routingInfo, routingInfo, stream)

        // Apply filler at last hop
        if i == n-1:
            copy(routingInfo[HCO_ROUTING_INFO_SIZE - len(filler):],
                 filler)

        // Truncated HMAC
        nextHmac = HMAC256(muKey,
            routingInfo || assocData)[:HCO_HMAC_SIZE]

        hcoSeen[i] = routingInfo || nextHmac

    return hcoSeen
```

The sender then constructs the main onion using standard Sphinx,
including `hcoSeen[k]` in each hop's HMAC computation.

## Packet Verification

### Requirements

A reader of an `onion_message` with `hop_count_onion`:

- MUST derive HCO keys from the Sphinx shared secret `ss`:
  - `hco_mu_key = HMAC256("hco_mu", ss)`
  - `hco_rho_key = HMAC256("hco_rho", ss)`
- MUST verify:
  `HMAC256(hco_mu_key, routing_info || associated_data)[:HCO_HMAC_SIZE]`
  equals `hmac` (constant-time). If not: MUST ignore the message.
- MUST generate a cipher stream of
  `HCO_ROUTING_INFO_SIZE + HCO_HMAC_SIZE` bytes using `hco_rho_key`.
- MUST decrypt: XOR `routing_info` with the first
  `HCO_ROUTING_INFO_SIZE` bytes of the stream.
- MUST extract `next_hmac` from `routing_info[0:HCO_HMAC_SIZE]`.
- MUST left-shift `routing_info` by `HCO_HMAC_SIZE` and fill the
  trailing `HCO_HMAC_SIZE` bytes with
  `stream[HCO_ROUTING_INFO_SIZE : HCO_ROUTING_INFO_SIZE + HCO_HMAC_SIZE]`.
- MUST forward the updated `[routing_info || next_hmac]` as the
  `hop_count_onion` for the next hop.

### Pseudocode

```
function processHCO(hco, ss, assocData):
    mu  = HMAC256("hco_mu", ss)
    rho = HMAC256("hco_rho", ss)

    // Verify truncated HMAC
    expected = HMAC256(mu, hco.routingInfo || assocData)[:HCO_HMAC_SIZE]
    if not constantTimeEqual(expected, hco.hmac):
        return REJECT

    // Decrypt and generate padding in one stream
    stream = generateCipherStream(rho,
        HCO_ROUTING_INFO_SIZE + HCO_HMAC_SIZE)
    xor(hco.routingInfo, hco.routingInfo,
        stream[:HCO_ROUTING_INFO_SIZE])

    // Extract next HMAC
    nextHmac = hco.routingInfo[0:HCO_HMAC_SIZE]

    // Shift left and pad with stream tail
    leftShift(hco.routingInfo, HCO_HMAC_SIZE)
    copy(hco.routingInfo[HCO_ROUTING_INFO_SIZE - HCO_HMAC_SIZE:],
         stream[HCO_ROUTING_INFO_SIZE:])

    return ACCEPT, HCO{routingInfo: hco.routingInfo, hmac: nextHmac}
```

## Security Considerations

### Hop count enforcement

The routing info fits exactly `MAX_HCO_HOPS` slots of `HCO_HMAC_SIZE`
bytes. During construction, the sender right-shifts by `HCO_HMAC_SIZE`
per hop. After 20 shifts the buffer is full; any additional hop shifts
valid data off the end, breaking the HMAC chain. This is the same
fixed-size enforcement that limits HTLC payment routes.

### Truncated HMACs

The HCO uses 8-byte (64-bit) truncated HMACs rather than Sphinx's
standard 32 bytes. This is appropriate because:

1. **The main onion provides full integrity.** The HCO bytes are
   included in the main onion's 32-byte HMAC chain via the HMAC binding.
   Any tampering with the HCO causes the main HMAC to fail at the
   receiving hop. The HCO's own HMAC chain exists solely to enforce hop
   count, not to provide standalone integrity.

2. **Forgery is computationally infeasible.** Brute-forcing an 8-byte
   truncated HMAC requires `2^{64}` operations — not achievable with
   current or foreseeable hardware.

3. **The payoff is negligible.** A successful forgery extends the route
   by one hop (21x instead of 20x amplification).

4. **Birthday attacks are irrelevant.** Finding collisions (`2^{32}`
   operations) requires the HMAC key, which is derived from the Sphinx
   shared secret known only to the sender and that specific hop.

### Privacy

Layered encryption (ChaCha20, one layer per hop) transforms every byte
of the routing info at every hop, preventing cross-hop correlation. Slot
positions are opaque — a relay cannot determine its position in the
route.

### Non-goals

Loop prevention and replay prevention are out of scope, consistent with
the base onion message spec. A sender can visit the same node multiple
times (each visit uses a different Sphinx shared secret), bounded by the
20-hop cap. Rate limiting addresses both.

### Computational cost

Per hop: 1 HMAC256 + 1 ChaCha20 over 160 bytes. No additional ECDH.
Negligible compared to the main Sphinx point multiplication.

## Deployment

### Feature Bit

| Bits  | Name         | Description                 | Context |
|-------|--------------|-----------------------------|---------|
| 56/57 | `option_hco` | Hop count onion support     | IN      |

A sender:
- SHOULD include `hop_count_onion` if all hops advertise `option_hco`.
- MUST NOT include it if any hop lacks support.

A relay supporting `option_hco`:
- If present: MUST verify and process as specified.
- If absent: MAY accept with stricter rate limiting.

### Migration

1. Nodes advertise `option_hco`.
2. Relays apply preferential rate limits to messages with valid HCO.
3. Once adoption is sufficient, relays require HCO.

## Rationale

### Why a separate structure instead of reducing the main onion?

Shrinking the main onion's routing info limits payload capacity for
blinded paths, BOLT 12 invoices, and reply paths. The HCO decouples
hop enforcement from payload capacity: the main onion retains full
flexibility while the HCO independently enforces the hop limit.

### Why Sphinx-like construction?

The fixed-size routing info with layered encryption and HMAC chain is a
proven construction. The hop limit emerges naturally from the buffer
size — no custom mechanism (commitment slots, encrypted counters) is
needed. Implementations can adapt their existing Sphinx code with
minimal changes (different key labels, smaller buffer, truncated HMACs).

### Why reuse shared secrets?

Avoids additional ECDH (one point multiplication per hop) and additional
public keys in the packet (33 bytes that would serve as correlators).
Distinct `"hco_"` labels prevent key reuse.

### Why truncated HMACs?

Full 32-byte HMACs with a 1-byte length prefix per hop produce a
692-byte HCO (20 × 33 + 32). Since the main onion's full-strength
HMAC already provides integrity over the HCO bytes, and the hop limit
is enforced by buffer size rather than HMAC strength, 8-byte truncated
HMACs are sufficient. This reduces the HCO to 168 bytes — a 76%
reduction. The empty payloads also make the length prefix redundant,
saving another 20 bytes.

### Why 20 hops?

Matches the payment onion error attribution limit. Sufficient for
realistic paths including blinded route segments.

### Why not a simple counter?

A plaintext counter reveals position and is trivially manipulated. An
encrypted counter requires state mutation and complex HMAC anticipation.
The Sphinx-like construction provides cryptographic enforcement with
zero new complexity.

### Why not prevent loops?

Loop prevention requires per-hop state modification combined with
sender-anticipated header states for HMAC consistency. This adds
complexity and fails across blinded segments where the same node derives
different keys. The 20-hop cap bounds loop damage; rate limiting handles
the rest.
