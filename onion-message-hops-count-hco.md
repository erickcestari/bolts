# BOLT #4 Amendment: Hop Count Onion for Onion Messages

## Overview

This amendment introduces a **Hop Count Onion (HCO)** — a second,
smaller Sphinx packet that travels alongside each onion message to
cryptographically enforce a maximum number of forwarding hops.

The HCO is a standard Sphinx packet whose routing info area is sized to
fit exactly `MAX_HCO_HOPS` hop payloads. Because the Sphinx construction
physically cannot encode more hops than fit in its routing info, the hop
count limit is enforced by the packet's fixed size — no new
cryptographic mechanisms are required.

The HCO shares the same ephemeral key progression and shared secrets as
the main onion message packet, using distinct key derivation labels to
avoid key reuse. Each relay peels one layer from both the main onion and
the HCO. If the HCO's HMAC verification fails, the message is rejected.

The HCO does NOT attempt to prevent routing loops or replay attacks. Its
sole purpose is to cap route length at `MAX_HCO_HOPS`, reducing the
amplification factor available to denial-of-service attackers who
construct long onion message paths.

## Motivation

Onion messages (`option_onion_messages`) allow routes of up to
approximately 350 hops (when using `len` = 32834), creating a significant
denial-of-service amplification vector. An attacker can construct long
onion paths that cause targeted peers to flood each other with traffic.

Existing mitigations (rate limiting, message dropping) bound the damage
but do not limit the amplification factor. The Hop Count Onion provides
a cryptographic mechanism to cap the maximum number of hops, reducing the
worst-case amplification from ~350x to 20x — without changing the main
onion's maximum payload size.

Loop prevention and replay detection are explicitly out of scope. These
problems are better addressed by per-peer rate limiting, which nodes
SHOULD apply regardless.

## Constants

| Name                     | Value | Description                                |
|--------------------------|-------|--------------------------------------------|
| `MAX_HCO_HOPS`          | 20    | Maximum number of hops                     |
| `HCO_HOP_SIZE`          | 33    | Per-hop data: 1 byte length + 32 byte HMAC |
| `HCO_ROUTING_INFO_SIZE` | 660   | Routing info size (20 × 33 bytes)          |
| `HCO_SIZE`              | 692   | Total HCO size: routing info + 32-byte HMAC|

## Packet Structure

The Hop Count Onion is a Sphinx packet that reuses the main onion's
ephemeral key (no embedded key of its own):

1. type: `hop_count_onion`
2. data:
   * [`HCO_ROUTING_INFO_SIZE*byte`:`routing_info`]
   * [`32*byte`:`hmac`]

The HCO is appended after the `onion_message_packet` in the
`onion_message`.

Each hop's payload within the HCO routing info is empty (zero-length
TLV):

```
[0x00: payload_length] [32 bytes: next_hmac]
```

No per-hop data is communicated through the HCO — the main onion
carries all routing instructions. The HCO exists solely to enforce hop
count via the fixed routing info size.

## Key Derivation

The HCO reuses the Sphinx shared secrets from the main onion packet. To
avoid key reuse, all HCO key derivations use distinct labels prefixed
with `"hco_"`:

```
hco_rho_key_i = HMAC256("hco_rho", ss_i)       // stream cipher key for routing info
hco_mu_key_i  = HMAC256("hco_mu", ss_i)        // HMAC key
hco_pad_key   = HMAC256("hco_pad", sessionKey)  // initial padding key
```

Where `ss_i` is the standard Sphinx shared secret for hop `i`, already
computed for the main onion.

No additional ECDH operations are required. The ephemeral key blinding
follows the main onion — each relay blinds the ephemeral key once and
the result applies to both packets.

### Blinded Hops

No special handling is needed. Blinded hops derive the same Sphinx
shared secret using their blinded private key. HCO keys follow
automatically from distinct labels.

## Integration with `onion_message`

### Updated Message Format

1. type: 513 (`onion_message`) (`option_onion_messages`)
2. data:
   * [`point`:`path_key`]
   * [`u16`:`len`]
   * [`len*byte`:`onion_message_packet`]
   * [`HCO_SIZE*byte`:`hop_count_onion`]

The `hop_count_onion` is appended after the `onion_message_packet`.

No TLV fields are added to `onionmsg_tlv`. The HCO is entirely
self-contained.

## Packet Construction

### Requirements

The sender:

- MUST compute the standard Sphinx shared secrets for all hops.
- MUST NOT construct a route with more than `MAX_HCO_HOPS` hops.
- MUST construct the HCO as described below, using key labels prefixed
  by `"hco_"`.
- MUST include the HCO (as seen by each hop) in the corresponding hop's
  HMAC computation for the main onion.

### Construction

The HCO is constructed using standard Sphinx backwards construction:

1. Initialize routing info with pseudo-random padding:
   ```
   hco_pad_key = HMAC256("hco_pad", sessionKey)
   routingInfo = generateCipherStream(hco_pad_key, HCO_ROUTING_INFO_SIZE)
   ```

2. Generate filler from the hop stream keys (standard Sphinx filler
   generation, using `hco_rho` keys).

3. For each hop from `n-1` down to `0`:
   ```
   hco_rho_key = HMAC256("hco_rho", ss[i])
   hco_mu_key  = HMAC256("hco_mu", ss[i])

   // Shift routing info right by HCO_HOP_SIZE
   rightShift(routingInfo, HCO_HOP_SIZE)

   // Write this hop's (empty) payload + next HMAC
   routingInfo[0] = 0x00  // zero-length payload
   copy(routingInfo[1:33], nextHmac)

   // Encrypt routing info
   streamBytes = generateCipherStream(hco_rho_key, HCO_ROUTING_INFO_SIZE)
   xor(routingInfo, routingInfo, streamBytes)

   // Apply filler for last hop
   if i == n-1:
       copy(routingInfo[HCO_ROUTING_INFO_SIZE - fillerLen:], filler)

   // Compute HMAC for this hop
   nextHmac = HMAC256(hco_mu_key, routingInfo || associatedData)
   ```

4. The final `nextHmac` is the HCO's outer HMAC. The final `routingInfo`
   is the HCO's routing info.

### HMAC Binding to Main Onion

The HCO (as seen by each hop) is included in the main onion's HMAC
computation:

```
main_nextHmac_k = HMAC256(main_mu_key_k,
    main_routing_info || associated_data || hco_seen_by_hop_k)
```

This binds the HCO to the main onion: tampering with or stripping the
HCO causes the main onion's HMAC to fail at the receiving hop.

Since the sender constructs both packets backwards in parallel, it knows
each hop's view of the HCO at HMAC computation time.

### Construction Pseudocode

```
function constructOnionWithHCO(route, sessionKey, assocData):
    n = len(route)
    assert n <= MAX_HCO_HOPS

    sphinxSS = computeSphinxSharedSecrets(route, sessionKey)

    // ---- Build HCO (backwards) ----
    hcoPadKey = HMAC256("hco_pad", sessionKey)
    hcoRoutingInfo = generateCipherStream(hcoPadKey, HCO_ROUTING_INFO_SIZE)
    hcoFiller = generateHCOFiller(sphinxSS)

    var hcoNextHmac [32]byte  // starts as zero for final hop
    hcoSeen = new array[n] of byte[HCO_SIZE]

    for i = n-1 downto 0:
        rhoKey = HMAC256("hco_rho", sphinxSS[i])
        muKey  = HMAC256("hco_mu", sphinxSS[i])

        rightShift(hcoRoutingInfo, HCO_HOP_SIZE)
        hcoRoutingInfo[0] = 0x00
        copy(hcoRoutingInfo[1:33], hcoNextHmac)

        streamBytes = generateCipherStream(rhoKey, HCO_ROUTING_INFO_SIZE)
        xor(hcoRoutingInfo, hcoRoutingInfo, streamBytes)

        if i == n-1:
            copy(hcoRoutingInfo[HCO_ROUTING_INFO_SIZE - len(hcoFiller):],
                 hcoFiller)

        hcoNextHmac = HMAC256(muKey, hcoRoutingInfo || assocData)

        // Record HCO as seen by hop i
        hcoSeen[i] = hcoRoutingInfo || hcoNextHmac

    // ---- Build main onion (backwards), binding HCO ----
    padKey = generateKey("pad", sessionKey)
    var mixHeader [routingInfoSize]byte
    copy(mixHeader[:], generateCipherStream(padKey, routingInfoSize))
    filler = generateFiller(sphinxSS)

    var nextHmac [32]byte

    for k = n-1 downto 0:
        rhoKey = generateKey("rho", sphinxSS[k])
        muKey  = generateKey("mu", sphinxSS[k])

        hopsData[k].HMAC = nextHmac

        streamBytes = generateCipherStream(rhoKey, numStreamBytes)
        rightShift(mixHeader[:], hopDataSize)
        buf = encode(hopsData[k])
        copy(mixHeader[:], buf)
        xor(mixHeader[:], mixHeader[:], streamBytes[:routingInfoSize])

        if k == n-1:
            copy(mixHeader[len(mixHeader)-len(filler):], filler)

        // Include HCO in main HMAC
        packet = append(mixHeader[:], assocData...)
        packet = append(packet, hcoSeen[k]...)
        nextHmac = calcMac(muKey, packet)

    return OnionPacket{
        Version:      0x00,
        EphemeralKey: sessionKey.PubKey(),
        RoutingInfo:  mixHeader,
        HeaderMAC:    nextHmac,
    }, hcoSeen[0]
```

## Packet Verification

### Requirements

A reader of an `onion_message` with `hop_count_onion`:

- MUST already have computed the Sphinx shared secret `ss` for this hop
  (from the main onion's ephemeral key).
- MUST derive HCO keys:
  - `hco_mu_key = HMAC256("hco_mu", ss)`
  - `hco_rho_key = HMAC256("hco_rho", ss)`
- MUST verify the HCO HMAC:
  - `expected = HMAC256(hco_mu_key, routing_info || associated_data)`
  - If `expected != hmac` (constant-time comparison):
    MUST ignore the message.
- MUST decrypt the routing info:
  - `stream = generateCipherStream(hco_rho_key, HCO_ROUTING_INFO_SIZE)`
  - `xor(routing_info, routing_info, stream)`
- MUST read the next hop's HMAC from `routing_info[1:33]`.
- MUST left-shift the routing info by `HCO_HOP_SIZE` and pad the
  trailing bytes with pseudo-random stream (standard Sphinx processing).
- MUST forward the updated `[routing_info || next_hmac]` as the
  `hop_count_onion` for the next hop.
- MUST continue processing the main onion as specified in
  [Onion Messages](04-onion-routing.md#onion-messages).

### Verification Pseudocode

```
function processHCO(hco, sphinxSS, assocData):
    mu_key  = HMAC256("hco_mu", sphinxSS)
    rho_key = HMAC256("hco_rho", sphinxSS)

    // Verify HMAC
    expected = HMAC256(mu_key, hco.routingInfo || assocData)
    if not constantTimeEqual(expected, hco.hmac):
        return REJECT, nil

    // Decrypt routing info
    stream = generateCipherStream(rho_key, HCO_ROUTING_INFO_SIZE)
    xor(hco.routingInfo, hco.routingInfo, stream)

    // Extract next HMAC (skip 1-byte length prefix)
    nextHmac = hco.routingInfo[1:33]

    // Shift routing info left and pad end (standard Sphinx)
    leftShift(hco.routingInfo, HCO_HOP_SIZE)
    padStream = generateCipherStream(rho_key, HCO_HOP_SIZE)
    copy(hco.routingInfo[HCO_ROUTING_INFO_SIZE - HCO_HOP_SIZE:],
         padStream)

    return ACCEPT, HCO{routingInfo: hco.routingInfo, hmac: nextHmac}
```

## Processing Order

At each hop:

1. Receive onion message with hop count onion.
2. Derive Sphinx shared secret from the main onion's ephemeral key.
3. Verify main onion HMAC (which covers the HCO).
4. If main HMAC fails: ignore message.
5. Process HCO: verify HCO HMAC, decrypt routing info, extract next
   HMAC, shift and pad.
6. If HCO verification fails: ignore message.
7. Process main onion normally.
8. Forward both the peeled main onion and the peeled HCO to next hop.

## Security Considerations

### What this provides

- **Hop count cap**: The HCO routing info has space for exactly
  `MAX_HCO_HOPS` hop payloads. The Sphinx construction requires the
  sender to embed one hop payload per forwarding hop. A route exceeding
  `MAX_HCO_HOPS` hops cannot fit in the routing info — the sender
  physically cannot construct a valid packet.

- **Full Sphinx privacy**: The HCO is a standard Sphinx packet. All
  Sphinx privacy properties apply automatically: layered encryption
  (every byte changes at every hop), no cross-hop correlation, and
  position hiding.

- **HMAC binding**: The HCO is included in the main onion's HMAC chain.
  Tampering with or stripping the HCO breaks the main onion's integrity
  check.

- **No new cryptographic mechanisms**: The entire enforcement relies on
  the fixed size of a Sphinx routing info area — the same property that
  implicitly limits HTLC payment routes today.

### What this does NOT provide

- **Loop prevention**: A sender can construct a route that visits the
  same node multiple times (e.g., A → B → A → B), limited only by the
  20-hop cap. At each visit the node derives a different Sphinx shared
  secret (because the ephemeral key is blinded at each hop), so it
  processes a valid HCO layer. This is an explicit non-goal. Rate
  limiting addresses loops.

- **Replay prevention**: The same onion message can be forwarded to a
  node multiple times. The node has no state to detect this. This is
  consistent with the base onion message specification, which already
  tolerates replays.

### Why this works

Sphinx routing info has a fixed size. During construction, the sender
shifts the routing info right by one hop-payload size for each hop,
embedding that hop's data. After `MAX_HCO_HOPS` shifts, the entire
routing info is filled. Any additional hop would require shifting valid
data off the end, breaking the HMAC chain for subsequent hops. This is
not a new security property — it is the same constraint that limits
HTLC onion routes to ~20 hops.

### Computational Cost

Per hop: 1 HMAC256 (HMAC verification) + 1 ChaCha20 stream generation
over 660 bytes (routing info decryption). No additional ECDH beyond what
the main Sphinx already requires. Total HCO overhead is negligible
compared to the main Sphinx point multiplication.

## Deployment

### Feature Bit

| Bits  | Name         | Description                 | Context |
|-------|--------------|-----------------------------|---------|
| 56/57 | `option_hco` | Hop count onion support     | IN      |

### Requirements

A sender:
- SHOULD include the `hop_count_onion` if all hops in the route
  advertise `option_hco`.
- MUST NOT include it if any hop lacks `option_hco` support.

A relay supporting `option_hco`:
- If HCO present: MUST verify and process as specified.
- If HCO absent: MAY accept with stricter rate limiting.

A relay not supporting `option_hco`:
- Will ignore trailing bytes. Sender MUST NOT include the HCO when any
  hop lacks support.

### Migration Path

1. Nodes implement and advertise `option_hco`.
2. Relays apply preferential rate limits to messages with valid HCO.
3. Once adoption is sufficient, relays reject messages without HCO.

## Rationale

### Why a second Sphinx packet?

A second Sphinx packet reuses the existing, well-understood Sphinx
construction with all its privacy properties. The hop count limit
emerges naturally from the fixed routing info size — no new mechanism
is needed. This avoids inventing custom cryptographic constructions
(commitment slots, encrypted counters, etc.) when the problem is already
solved by Sphinx's inherent design.

### Why not reduce the main onion's payload size?

Reducing the main onion's routing info area would limit hop count but
also reduce the payload capacity available for legitimate use (blinded
paths, TLV extensions, reply paths). A separate HCO decouples
hop-count enforcement from payload capacity: the main onion retains
full flexibility while the HCO independently enforces the hop limit.

### Why reuse the main onion's shared secrets?

Avoids additional ECDH operations (one point multiplication per hop) and
additional public keys in the packet (which would add 33 bytes and
serve as potential correlators). Distinct key labels (`"hco_"` prefix)
prevent key reuse while sharing the same secret material.

### Why empty hop payloads?

The HCO exists solely to enforce hop count. No per-hop data needs to be
communicated — the main onion carries all routing instructions. Empty
payloads minimize the HCO's size to
`MAX_HCO_HOPS × 33 + 32 = 692` bytes.

### Why 20 hops?

Aligns with the maximum hop count used in payment onion error
attribution. Provides sufficient flexibility for realistic network paths
including blinded route segments.

### Why not use a simple hop counter?

A plaintext counter that each hop decrements reveals position
information and can be trivially manipulated by any hop. An encrypted
counter that each hop decrypts, modifies, and re-encrypts requires
state mutation and complex HMAC anticipation. A second Sphinx packet
provides cryptographic enforcement with zero new complexity — only
reuse of an existing, proven construction.

### Why not prevent loops?

Loop prevention requires per-hop state modification combined with
sender-anticipated header states at each hop for HMAC consistency. This
adds complexity and still fails across blinded route segments where the
same physical node derives different keys. Capping hop count to 20
limits loop damage to 20x amplification. Combined with per-peer rate
limiting, this is sufficient in practice.
