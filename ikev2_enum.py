#!/usr/bin/env python3
"""
ikev2_enum.py - IKEv2 algorithm suite enumerator for penetration testing

Core insight: An IKEv2 IKE_SA_INIT packet contains BOTH an SA proposal
(listing acceptable algorithms) AND a KE payload (a DH public key for ONE
specific group). When a tool sends proposals with multiple DH groups but a
KE for only one, a conformant server returns INVALID_KE_PAYLOAD; a buggy or
strict server returns NO_PROPOSAL_CHOSEN — masking the real acceptance status.

This script fixes that by always matching the KE group to the single DH group
in each probe, one probe per (DH group, cipher type) combination.

Usage:
    python3 ikev2_enum.py TARGET_IP [options]

Options:
    --port N        Target port (default: 500)
    --timeout N     Per-probe timeout in seconds (default: 1.5)
    --delay N       Delay between probes in seconds (default: 0.1)
    --dh-only       Only run the DH group phase, skip cipher drill-down
    --dh GROUPS     Comma-separated DH groups to test (default: all)
    --verbose       Show each probe sent/received

Requires root (or CAP_NET_RAW) to bind source port 500.
If no root: falls back to ephemeral source port (some servers reject this).
"""

import struct, socket, os, sys, time, argparse, random

# ---------------------------------------------------------------------------
# IKEv2 constants
# ---------------------------------------------------------------------------
PAYLOAD_NONE  = 0
PAYLOAD_SA    = 33
PAYLOAD_KE    = 34
PAYLOAD_NONCE = 40
PAYLOAD_NOTIFY = 41

XCHG_SA_INIT  = 34
FLAG_INITIATOR = 0x08
VERSION_V2     = 0x20

TRANS_ENCR  = 1
TRANS_PRF   = 2
TRANS_INTEG = 3
TRANS_DH    = 4

NOTIFY_NO_PROPOSAL_CHOSEN  = 14
NOTIFY_INVALID_KE_PAYLOAD  = 17
NOTIFY_COOKIE              = 16388  # RFC 7296 §2.6

# ---------------------------------------------------------------------------
# Algorithm tables
# ---------------------------------------------------------------------------

# ENCR: (id, name, aead, key_lengths_bits)  key_lengths=[] means no key attr
ENCR_ALGS = [
    # AEAD ciphers — no INTEG transform needed
    (20, 'AES-GCM-16',       True,  [256, 192, 128]),
    (19, 'AES-GCM-12',       True,  [256, 192, 128]),
    (18, 'AES-GCM-8',        True,  [256, 192, 128]),
    (16, 'AES-CCM-16',       True,  [256, 192, 128]),
    (15, 'AES-CCM-12',       True,  [256, 192, 128]),
    (14, 'AES-CCM-8',        True,  [256, 192, 128]),
    (28, 'ChaCha20-Poly1305', True, []),   # fixed 256-bit key, no attr
    (21, 'NULL+AES-GMAC',    True,  [256, 192, 128]),
    # Non-AEAD ciphers — INTEG transform required
    (12, 'AES-CBC',          False, [256, 192, 128]),
    (23, 'Camellia-CBC',     False, [256, 192, 128]),
    (24, 'Camellia-CTR',     False, [256, 192, 128]),
    (13, 'AES-CTR',          False, [256, 192, 128]),
    ( 3, '3DES',             False, []),
    ( 2, 'DES',              False, []),
    (11, 'NULL',             False, []),
]

PRF_ALGS = [
    (5, 'HMAC-SHA2-256'),
    (6, 'HMAC-SHA2-384'),
    (7, 'HMAC-SHA2-512'),
    (2, 'HMAC-SHA1'),
    (8, 'AES128-CMAC'),
    (4, 'AES128-XCBC'),
    (1, 'HMAC-MD5'),
]

INTEG_ALGS = [
    (12, 'HMAC-SHA2-256-128'),
    (13, 'HMAC-SHA2-384-192'),
    (14, 'HMAC-SHA2-512-256'),
    ( 2, 'HMAC-SHA1-96'),
    ( 8, 'AES-CMAC-96'),
    ( 5, 'AES-XCBC-96'),
    ( 9, 'AES-128-GMAC'),
    (10, 'AES-192-GMAC'),
    (11, 'AES-256-GMAC'),
    ( 1, 'HMAC-MD5-96'),
]

DH_GROUPS = [
    (14, 'MODP-2048',      256),   # RFC 3526 — minimum recommended (RFC 8247)
    (19, 'ECP-256',         64),   # RFC 5903 — most common ECP group
    (20, 'ECP-384',         96),   # RFC 5903
    (21, 'ECP-521',        132),   # RFC 5903
    (31, 'Curve25519',      32),   # RFC 8031
    (32, 'Curve448',        56),   # RFC 8031
    (15, 'MODP-3072',      384),   # RFC 3526
    (16, 'MODP-4096',      512),   # RFC 3526
    (18, 'MODP-8192',     1024),   # RFC 3526
    ( 5, 'MODP-1536',      192),   # RFC 3526
    ( 2, 'MODP-1024',      128),   # RFC 2409 — weak
    (22, 'MODP-1024/160',  128),   # RFC 5114
    (23, 'MODP-2048/224',  256),   # RFC 5114
    (24, 'MODP-2048/256',  256),   # RFC 5114
    (28, 'BP-P256',         64),   # RFC 6954 Brainpool
    (29, 'BP-P384',         96),   # RFC 6954
    (30, 'BP-P512',        128),   # RFC 6954
    ( 1, 'MODP-768',        96),   # RFC 2409 — very weak
]

WEAK_DH = {1, 2, 5, 22, 23}   # DH groups considered weak/legacy

# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def build_transform(t_type, t_id, attrs=b'', last=False):
    """Build one IKEv2 transform payload (RFC 7296 §3.3.2)."""
    length = 8 + len(attrs)
    return struct.pack('!BBHBBH',
                       0 if last else 3, 0, length,
                       t_type, 0, t_id) + attrs

def key_length_attr(bits):
    """Build key-length attribute in TV format."""
    return struct.pack('!HH', 0x800e, bits)

def build_proposal(num, transforms, last=True):
    """Build one IKEv2 proposal payload (RFC 7296 §3.3.1)."""
    body = b''.join(transforms)
    length = 8 + len(body)
    return struct.pack('!BBHBBBB',
                       0 if last else 2, 0, length,
                       num, 1, 0, len(transforms)) + body

def build_sa_payload(proposals_data, next_payload):
    """Build SA payload (generic header + raw proposal bytes)."""
    length = 4 + len(proposals_data)
    return struct.pack('!BBH', next_payload, 0, length) + proposals_data

def build_ke_payload(dh_group, ke_size, next_payload):
    """Build KE payload with random key data of the correct length."""
    ke_data = os.urandom(ke_size)
    length = 8 + len(ke_data)
    return struct.pack('!BBHHH', next_payload, 0, length, dh_group, 0) + ke_data

def build_nonce_payload(size=20):
    """Build Nonce payload."""
    data = os.urandom(size)
    length = 4 + size
    return struct.pack('!BBH', PAYLOAD_NONE, 0, length) + data

def build_isakmp_header(spi_i, first_payload_type, total_length):
    """Build IKEv2 ISAKMP header (RFC 7296 §3.1)."""
    return (spi_i + b'\x00' * 8 +
            struct.pack('!BBBBII',
                        first_payload_type, VERSION_V2,
                        XCHG_SA_INIT, FLAG_INITIATOR, 0, total_length))

def build_sa_init(dh_group, ke_size, encr_transforms, prf_transforms,
                  integ_transforms=None, spi_i=None):
    """
    Build a complete IKEv2 IKE_SA_INIT packet.

    The proposal contains only the DH group specified; the KE payload
    uses the same group. This avoids the SA/KE mismatch that causes
    some servers to return NO_PROPOSAL_CHOSEN instead of INVALID_KE_PAYLOAD.
    """
    if spi_i is None:
        spi_i = os.urandom(8)

    # Assemble transforms: ENCR, then PRF, then INTEG (if non-AEAD), then DH
    all_trans = list(encr_transforms) + list(prf_transforms)
    if integ_transforms:
        all_trans += list(integ_transforms)
    dh_trans = build_transform(TRANS_DH, dh_group, last=True)

    # Mark last transform
    trans_payloads = []
    for i, t in enumerate(all_trans):
        # Re-mark last byte (next field) appropriately
        trans_payloads.append(t)
    trans_payloads.append(dh_trans)

    # Fix "last" marker on all-but-last
    fixed = []
    for i, t in enumerate(trans_payloads):
        is_last = (i == len(trans_payloads) - 1)
        # next field is first byte; 0=last, 3=more
        fixed.append(bytes([0 if is_last else 3]) + t[1:])

    prop = build_proposal(1, fixed, last=True)
    sa   = build_sa_payload(prop, PAYLOAD_KE)
    ke   = build_ke_payload(dh_group, ke_size, PAYLOAD_NONCE)
    nc   = build_nonce_payload()

    body = sa + ke + nc
    total = 28 + len(body)
    hdr = build_isakmp_header(spi_i, PAYLOAD_SA, total)
    return hdr + body

# ---------------------------------------------------------------------------
# Probe presets
# ---------------------------------------------------------------------------

def aead_probe_transforms(encr_id, key_bits, prf_ids):
    """Returns (encr_transforms, prf_transforms, None) for an AEAD probe."""
    if key_bits:
        encr = [build_transform(TRANS_ENCR, encr_id, key_length_attr(key_bits))]
    else:
        encr = [build_transform(TRANS_ENCR, encr_id)]
    prf  = [build_transform(TRANS_PRF, p) for p in prf_ids]
    return encr, prf, None

def nonaead_probe_transforms(encr_id, key_bits, prf_ids, integ_ids):
    """Returns (encr_transforms, prf_transforms, integ_transforms) for non-AEAD."""
    if key_bits:
        encr = [build_transform(TRANS_ENCR, encr_id, key_length_attr(key_bits))]
    else:
        encr = [build_transform(TRANS_ENCR, encr_id)]
    prf   = [build_transform(TRANS_PRF, p) for p in prf_ids]
    integ = [build_transform(TRANS_INTEG, i) for i in integ_ids]
    return encr, prf, integ

def all_prf_ids():
    return [p[0] for p in PRF_ALGS]

def all_integ_ids():
    return [i[0] for i in INTEG_ALGS]

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def open_socket(port=500):
    """Open a UDP socket, trying to bind to port (root needed for 500) else ephemeral."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.01)
    try:
        sock.bind(('', port))
        src_port = port
    except (PermissionError, OSError):
        sock.bind(('', 0))
        src_port = sock.getsockname()[1]
        print(f'[!] Cannot bind to port {port} (need root/CAP_NET_RAW): using ephemeral port {src_port}',
              file=sys.stderr)
        print(f'[!] Many IKE servers require the source port to be 500 — responses may not arrive.',
              file=sys.stderr)
    return sock, src_port

def send_recv(sock, packet, target, port, timeout=1.5):
    """Send packet and collect all UDP replies within the timeout window."""
    sock.sendto(packet, (target, port))
    deadline = time.monotonic() + timeout
    replies = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            data, addr = sock.recvfrom(65535)
            replies.append((data, addr))
        except socket.timeout:
            break
    return replies

# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def parse_ikev2_response(data):
    """
    Parse an IKEv2 response packet. Returns a dict with:
      type: 'sa_init' | 'no_proposal' | 'invalid_ke' | 'other_notify' | 'unknown'
      notifies: list of (notify_type, data) tuples
      invalid_ke_group: int (only when type='invalid_ke')
      sa_chosen: dict (only when type='sa_init', if parseable)
    """
    result = {'type': 'unknown', 'notifies': [], 'raw': data}
    if len(data) < 28:
        return result

    try:
        spi_i, spi_r, np, ver, xchg, flags, msgid, length = \
            struct.unpack_from('!8s8sBBBBII', data, 0)
    except struct.error:
        return result

    if ver != VERSION_V2:
        result['type'] = 'ikev1'
        return result

    # Walk payloads
    cur_type = np
    off = 28
    sa_init_response = False
    notifies = []

    while cur_type != 0 and off + 4 <= len(data):
        next_type, crit, plen = struct.unpack_from('!BBH', data, off)
        body = data[off + 4: off + plen]

        if cur_type == PAYLOAD_SA:
            sa_init_response = True  # got an SA payload back = success

        elif cur_type == PAYLOAD_NOTIFY:
            if len(body) >= 4:
                proto, spi_sz = struct.unpack_from('!BB', body, 0)
                notify_type   = struct.unpack_from('!H', body, 2)[0]
                notify_data   = body[4 + spi_sz:]
                notifies.append((notify_type, notify_data))

        cur_type = next_type
        off += plen

    result['notifies'] = notifies

    if sa_init_response:
        result['type'] = 'sa_init'
        return result

    # Check notifies
    for ntype, ndata in notifies:
        if ntype == NOTIFY_NO_PROPOSAL_CHOSEN:
            result['type'] = 'no_proposal'
            return result
        if ntype == NOTIFY_INVALID_KE_PAYLOAD:
            result['type'] = 'invalid_ke'
            if len(ndata) >= 2:
                result['invalid_ke_group'] = struct.unpack_from('!H', ndata)[0]
            return result

    if notifies:
        result['type'] = 'other_notify'
    return result

# ---------------------------------------------------------------------------
# Security rating
# ---------------------------------------------------------------------------

BROKEN_ENCR  = {2, 11}          # DES, NULL
WEAK_ENCR    = {3}               # 3DES
MODERN_ENCR  = {18, 19, 20, 28} # AES-GCM variants, ChaCha20

def rate_finding(encr_id, dh_id, integ_id=None):
    """Return (severity, reason) for a successful cipher suite."""
    issues = []
    if encr_id in BROKEN_ENCR:
        return 'CRITICAL', 'Broken cipher (DES/NULL)'
    if encr_id in WEAK_ENCR:
        issues.append('3DES encryption (vulnerable to Sweet32)')
    if dh_id in WEAK_DH:
        issues.append(f'Weak DH group {dh_id} (<= 1024-bit or subgroup)')
    if integ_id in {1}:  # MD5-96
        issues.append('MD5 integrity (broken)')
    if issues:
        return 'HIGH' if dh_id in {1, 2} else 'MEDIUM', '; '.join(issues)
    return 'INFO', 'Modern cipher suite'

# ---------------------------------------------------------------------------
# Enumeration phases
# ---------------------------------------------------------------------------

def phase1_dh_groups(sock, target, port, dh_list, timeout, delay, verbose):
    """
    Phase 1: for each DH group, send four probes (≤8 transforms each):

      AEAD-primary   : GCM-16-256/128, ChaCha20          + SHA2-256/512/SHA1/MD5     (3+4+1=8)
      AEAD-extended  : GCM-12-256, GCM-8-256, CCM-16-256 + SHA2-384/XCBC/CMAC/SHA2-256 (3+4+1=8)
      non-AEAD-prim  : AES-CBC-256/128                   + SHA2-256/SHA1 + SHA2-256-128/SHA2-512-256/SHA1-96 (2+2+3+1=8)
      non-AEAD-ext   : AES-CBC-256, 3DES                 + SHA2-384/CMAC + SHA2-384-192/CMAC-96/XCBC-96     (2+2+3+1=8)

    Keeping ≤8 transforms per probe avoids server-side parse limits (e.g. Check Point).

    Returns (results, stats) where:
      results: list of (dh_id, dh_name, ke_size, label, tag, r) for non-no_proposal responses
      stats:   dict with keys 'sent', 'no_response', 'no_proposal'
    """
    # ── AEAD primary (3 ENCR + 4 PRF + 1 DH = 8) ────────────────────────────
    aead_prim_encr = [
        build_transform(TRANS_ENCR, 20, key_length_attr(256)),  # AES-GCM-16-256
        build_transform(TRANS_ENCR, 20, key_length_attr(128)),  # AES-GCM-16-128
        build_transform(TRANS_ENCR, 28),                         # ChaCha20-Poly1305
    ]
    aead_prim_prf = [
        build_transform(TRANS_PRF, 5),  # HMAC-SHA2-256
        build_transform(TRANS_PRF, 7),  # HMAC-SHA2-512
        build_transform(TRANS_PRF, 2),  # HMAC-SHA1
        build_transform(TRANS_PRF, 1),  # HMAC-MD5
    ]

    # ── AEAD extended (3 ENCR + 4 PRF + 1 DH = 8) ───────────────────────────
    aead_ext_encr = [
        build_transform(TRANS_ENCR, 19, key_length_attr(256)),  # AES-GCM-12-256
        build_transform(TRANS_ENCR, 18, key_length_attr(256)),  # AES-GCM-8-256
        build_transform(TRANS_ENCR, 16, key_length_attr(256)),  # AES-CCM-16-256
    ]
    aead_ext_prf = [
        build_transform(TRANS_PRF, 6),  # HMAC-SHA2-384  ← previously missing
        build_transform(TRANS_PRF, 4),  # AES128-XCBC    ← previously missing
        build_transform(TRANS_PRF, 8),  # AES128-CMAC    ← previously missing
        build_transform(TRANS_PRF, 5),  # HMAC-SHA2-256  (fallback anchor)
    ]

    # ── non-AEAD primary (2 ENCR + 2 PRF + 3 INTEG + 1 DH = 8) ─────────────
    nonaead_prim_encr = [
        build_transform(TRANS_ENCR, 12, key_length_attr(256)),  # AES-CBC-256
        build_transform(TRANS_ENCR, 12, key_length_attr(128)),  # AES-CBC-128
    ]
    nonaead_prim_prf = [
        build_transform(TRANS_PRF, 5),  # HMAC-SHA2-256
        build_transform(TRANS_PRF, 2),  # HMAC-SHA1
    ]
    nonaead_prim_integ = [
        build_transform(TRANS_INTEG, 12),  # HMAC-SHA2-256-128
        build_transform(TRANS_INTEG, 14),  # HMAC-SHA2-512-256
        build_transform(TRANS_INTEG,  2),  # HMAC-SHA1-96
    ]

    # ── non-AEAD extended (2 ENCR + 2 PRF + 3 INTEG + 1 DH = 8) ────────────
    nonaead_ext_encr = [
        build_transform(TRANS_ENCR, 12, key_length_attr(256)),  # AES-CBC-256
        build_transform(TRANS_ENCR,  3),                         # 3DES
    ]
    nonaead_ext_prf = [
        build_transform(TRANS_PRF, 6),  # HMAC-SHA2-384  ← previously missing
        build_transform(TRANS_PRF, 8),  # AES128-CMAC    ← previously missing
    ]
    nonaead_ext_integ = [
        build_transform(TRANS_INTEG, 13),  # HMAC-SHA2-384-192  ← previously missing
        build_transform(TRANS_INTEG,  8),  # AES-CMAC-96        ← previously missing
        build_transform(TRANS_INTEG,  5),  # AES-XCBC-96        ← previously missing
    ]

    probe_types = [
        ('AEAD-primary',     aead_prim_encr,    aead_prim_prf,    None),
        ('AEAD-extended',    aead_ext_encr,     aead_ext_prf,     None),
        ('non-AEAD-primary', nonaead_prim_encr, nonaead_prim_prf, nonaead_prim_integ),
        ('non-AEAD-extended',nonaead_ext_encr,  nonaead_ext_prf,  nonaead_ext_integ),
    ]

    results = []
    stats = {'sent': 0, 'no_response': 0, 'no_proposal': 0}

    for dh_id, dh_name, ke_size in dh_list:
        for label, encr_t, prf_t, integ_t in probe_types:
            pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, integ_t)
            stats['sent'] += 1
            if verbose:
                ntrans = len(encr_t) + len(prf_t) + (len(integ_t) if integ_t else 0) + 1
                print(f'  → DH-{dh_id} ({dh_name}) [{label}] {len(pkt)}B ({ntrans} transforms) ...')

            replies = send_recv(sock, pkt, target, port, timeout)
            time.sleep(delay)

            if not replies:
                stats['no_response'] += 1
                if verbose:
                    print(f'    ← no response')
                continue

            for raw, addr in replies:
                r = parse_ikev2_response(raw)
                tag = r['type']
                if verbose:
                    extra = ''
                    if tag == 'invalid_ke':
                        extra = f" (wants DH-{r.get('invalid_ke_group','?')})"
                    print(f'    ← {tag}{extra}')

                if tag == 'no_proposal':
                    stats['no_proposal'] += 1
                else:
                    results.append((dh_id, dh_name, ke_size, label, tag, r))

    return results, stats


def phase1_fallback_minimal(sock, target, port, dh_list, timeout, delay, verbose):
    """
    Phase 1b fallback: called when phase 1 gets all NO_PROPOSAL_CHOSEN but server IS responding
    (no_response == 0).  Sends minimal 3–4 transform probes (1 ENCR + 1 PRF [+ 1 INTEG] + 1 DH)
    to bypass strict transform-count limits and cover vendor-specific algorithm variants.

    Returns same (results, stats) format as phase1_dh_groups.
    """
    # Every AEAD ENCR variant, probed as: 1 ENCR + 1 PRF(SHA2-256) + 1 DH = 3 transforms
    aead_single = [
        (20, 256),   # AES-GCM-16-256
        (20, 128),   # AES-GCM-16-128
        (19, 256),   # AES-GCM-12-256
        (18, 256),   # AES-GCM-8-256
        (28, None),  # ChaCha20-Poly1305
        (16, 256),   # AES-CCM-16-256
        (21, 256),   # NULL+AES-GMAC-256
    ]
    # Every non-AEAD ENCR variant, probed as: 1 ENCR + 1 PRF + 1 INTEG(SHA2-256-128) + 1 DH = 4 transforms
    nonaead_single = [
        (12, 256),   # AES-CBC-256
        (12, 128),   # AES-CBC-128
        (12, 192),   # AES-CBC-192
        (13, 256),   # AES-CTR-256
        (23, 256),   # Camellia-CBC-256
        ( 3, None),  # 3DES
        ( 2, None),  # DES
        (11, None),  # NULL
    ]
    # Cycle through all PRFs for each ENCR to avoid missing a PRF-only mismatch
    fallback_prfs = [5, 2, 7, 6, 4, 8, 1]  # SHA2-256, SHA1, SHA2-512, SHA2-384, XCBC, CMAC, MD5
    common_integ = build_transform(TRANS_INTEG, 12)   # SHA2-256-128

    results = []
    stats = {'sent': 0, 'no_response': 0, 'no_proposal': 0}

    for dh_id, dh_name, ke_size in dh_list:
        # AEAD single-encr probes — try each PRF to cover PRF-specific rejections
        for eid, kbits in aead_single:
            for prf_id in fallback_prfs:
                encr_t = ([build_transform(TRANS_ENCR, eid, key_length_attr(kbits))]
                          if kbits else [build_transform(TRANS_ENCR, eid)])
                prf_t  = [build_transform(TRANS_PRF, prf_id)]
                pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, None)
                stats['sent'] += 1
                if verbose:
                    prf_name = next((n for i, n in PRF_ALGS if i == prf_id), str(prf_id))
                    ename = next((n for i, n, a, _ in ENCR_ALGS if i == eid), str(eid))
                    print(f'  [1b] → DH-{dh_id} AEAD [{ename}+{prf_name}] 3 transforms ...')

                replies = send_recv(sock, pkt, target, port, timeout)
                time.sleep(delay)

                if not replies:
                    stats['no_response'] += 1
                    continue
                for raw, addr in replies:
                    r = parse_ikev2_response(raw)
                    tag = r['type']
                    if verbose:
                        print(f'  [1b] ← {tag}')
                    if tag == 'no_proposal':
                        stats['no_proposal'] += 1
                    else:
                        results.append((dh_id, dh_name, ke_size, f'1b-AEAD', tag, r))

        # non-AEAD single-encr probes
        for eid, kbits in nonaead_single:
            for prf_id in fallback_prfs:
                encr_t = ([build_transform(TRANS_ENCR, eid, key_length_attr(kbits))]
                          if kbits else [build_transform(TRANS_ENCR, eid)])
                prf_t  = [build_transform(TRANS_PRF, prf_id)]
                pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, [common_integ])
                stats['sent'] += 1
                if verbose:
                    prf_name = next((n for i, n in PRF_ALGS if i == prf_id), str(prf_id))
                    ename = next((n for i, n, a, _ in ENCR_ALGS if i == eid), str(eid))
                    print(f'  [1b] → DH-{dh_id} non-AEAD [{ename}+{prf_name}+SHA2-256-128] 4 transforms ...')

                replies = send_recv(sock, pkt, target, port, timeout)
                time.sleep(delay)

                if not replies:
                    stats['no_response'] += 1
                    continue
                for raw, addr in replies:
                    r = parse_ikev2_response(raw)
                    tag = r['type']
                    if verbose:
                        print(f'  [1b] ← {tag}')
                    if tag == 'no_proposal':
                        stats['no_proposal'] += 1
                    else:
                        results.append((dh_id, dh_name, ke_size, f'1b-nonAEAD', tag, r))

    return results, stats

def phase2_cipher_drill(sock, target, port, dh_id, dh_name, ke_size,
                        timeout, delay, verbose):
    """
    Phase 2: given a DH group that didn't get NO_PROPOSAL_CHOSEN, enumerate
    individual cipher suites to find exactly what the server accepts.

    Returns list of accepted (encr_name, key_bits, prf_name, integ_name) tuples.
    """
    accepted = []

    for eid, ename, aead, keys in ENCR_ALGS:
        key_list = keys if keys else [None]
        for key_bits in key_list:
            for pid, pname in PRF_ALGS:
                if aead:
                    # AEAD probe: no INTEG
                    if key_bits:
                        encr_t = [build_transform(TRANS_ENCR, eid, key_length_attr(key_bits))]
                    else:
                        encr_t = [build_transform(TRANS_ENCR, eid)]
                    prf_t  = [build_transform(TRANS_PRF, pid)]
                    pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, None)
                    replies = send_recv(sock, pkt, target, port, timeout)
                    time.sleep(delay)

                    for raw, _ in replies:
                        r = parse_ikev2_response(raw)
                        if r['type'] == 'sa_init':
                            label = f'{ename}' + (f'-{key_bits}b' if key_bits else '')
                            entry = (label, pname, 'AEAD', f'DH-{dh_id}')
                            if entry not in accepted:
                                accepted.append(entry)
                                sev, reason = rate_finding(eid, dh_id)
                                print(f'  [ACCEPT][{sev}] {label} + PRF-{pname} + DH-{dh_id}({dh_name}) — {reason}')
                    if verbose and not replies:
                        print(f'  [{ename}{"-"+str(key_bits)+"b" if key_bits else ""}+{pname}+DH-{dh_id}] no response')

                else:
                    # non-AEAD: need INTEG
                    for iid, iname in INTEG_ALGS:
                        if key_bits:
                            encr_t = [build_transform(TRANS_ENCR, eid, key_length_attr(key_bits))]
                        else:
                            encr_t = [build_transform(TRANS_ENCR, eid)]
                        prf_t   = [build_transform(TRANS_PRF,   pid)]
                        integ_t = [build_transform(TRANS_INTEG, iid)]
                        pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, integ_t)
                        replies = send_recv(sock, pkt, target, port, timeout)
                        time.sleep(delay)

                        for raw, _ in replies:
                            r = parse_ikev2_response(raw)
                            if r['type'] == 'sa_init':
                                kb_str = f'-{key_bits}b' if key_bits else ''
                                entry  = (f'{ename}{kb_str}', pname, iname, f'DH-{dh_id}')
                                if entry not in accepted:
                                    accepted.append(entry)
                                    sev, reason = rate_finding(eid, dh_id, iid)
                                    print(f'  [ACCEPT][{sev}] {ename}{kb_str} + PRF-{pname} + INTEG-{iname} + DH-{dh_id}({dh_name}) — {reason}')
    return accepted

# ---------------------------------------------------------------------------
# Packet dump helpers (--dump-packet)
# ---------------------------------------------------------------------------

def _hex_dump(data, indent='    '):
    """Return a formatted hex + ASCII dump string."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{indent}{i:04x}  {hex_part:<47}  {asc_part}')
    return '\n'.join(lines)


def _write_pcap(filepath, records):
    """
    Write records to a pcap file (linktype=ETHERNET / IPv4 / UDP).
    records: list of (src_ip_str, dst_ip_str, src_port, dst_port, payload_bytes, timestamp_float)
    """
    global_hdr = struct.pack('<IHHiIII',
                             0xa1b2c3d4,   # magic (native byte-order mark)
                             2, 4,          # major, minor version
                             0, 0,          # timezone, timestamp accuracy
                             65535,         # snaplen
                             1)             # link type: ETHERNET
    with open(filepath, 'wb') as f:
        f.write(global_hdr)
        for src_ip, dst_ip, src_port, dst_port, payload, ts in records:
            udp_len = 8 + len(payload)
            ip_len  = 20 + udp_len
            udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
            ip_hdr  = struct.pack('!BBHHHBBH4s4s',
                                  0x45, 0, ip_len,
                                  0, 0, 64, 17, 0,          # TTL=64, proto=UDP, cksum=0
                                  socket.inet_aton(src_ip),
                                  socket.inet_aton(dst_ip))
            eth_hdr = (b'\x00\x00\x00\x00\x00\x02'  # dst MAC (placeholder)
                     + b'\x00\x00\x00\x00\x00\x01'  # src MAC (placeholder)
                     + b'\x08\x00')                  # ethertype: IPv4
            frame   = eth_hdr + ip_hdr + udp_hdr + payload
            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)


def cmd_dump_packet(args):
    """
    Send 3 representative probes (DH-14), capture responses, write pcap + hex dump.

    Probe set:
      1. minimal-AEAD (3 transforms): AES-GCM-16-256 + SHA2-256 + DH-14
      2. full-AEAD-primary (8 transforms): phase-1 AEAD-primary preset + DH-14
      3. minimal-nonAEAD (4 transforms): AES-CBC-256 + SHA2-256 + SHA2-256-128 + DH-14
    """
    dh_id, ke_size = 14, 256   # MODP-2048

    probes = [
        ('minimal-AEAD (3 transforms)',
         [build_transform(TRANS_ENCR, 20, key_length_attr(256))],   # AES-GCM-16-256
         [build_transform(TRANS_PRF,  5)],                           # HMAC-SHA2-256
         None),

        ('full-AEAD-primary (8 transforms)',
         [build_transform(TRANS_ENCR, 20, key_length_attr(256)),
          build_transform(TRANS_ENCR, 20, key_length_attr(128)),
          build_transform(TRANS_ENCR, 28)],
         [build_transform(TRANS_PRF, 5),
          build_transform(TRANS_PRF, 7),
          build_transform(TRANS_PRF, 2),
          build_transform(TRANS_PRF, 1)],
         None),

        ('minimal-nonAEAD (4 transforms)',
         [build_transform(TRANS_ENCR, 12, key_length_attr(256))],   # AES-CBC-256
         [build_transform(TRANS_PRF,  5)],                           # HMAC-SHA2-256
         [build_transform(TRANS_INTEG, 12)]),                        # HMAC-SHA2-256-128
    ]

    sock, src_port = open_socket(500)
    try:
        src_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        src_ip = '127.0.0.1'

    print(f'Dump mode — target={args.target}:{args.port}  src={src_ip}:{src_port}  uid={os.getuid()}')
    print(f'Output: {args.dump_packet}')

    records = []

    for label, encr_t, prf_t, integ_t in probes:
        pkt = build_sa_init(dh_id, ke_size, encr_t, prf_t, integ_t)
        ntrans = len(encr_t) + len(prf_t) + (len(integ_t) if integ_t else 0) + 1
        ts_send = time.time()
        records.append((src_ip, args.target, src_port, args.port, pkt, ts_send))

        print(f'\n── {label} ──')
        print(f'  sent {len(pkt)} bytes ({ntrans} transforms):')
        print(_hex_dump(pkt))

        # Collect replies, recording each timestamp as it arrives
        sock.sendto(pkt, (args.target, args.port))
        deadline = time.monotonic() + args.timeout
        got_reply = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                raw, addr = sock.recvfrom(65535)
                ts_recv = time.time()
                records.append((addr[0], src_ip, addr[1], src_port, raw, ts_recv))
                r = parse_ikev2_response(raw)
                rtt_ms = (ts_recv - ts_send) * 1000
                print(f'  response from {addr[0]}:{addr[1]}  {len(raw)} bytes  → {r["type"]}  rtt={rtt_ms:.1f}ms:')
                print(_hex_dump(raw))
                got_reply = True
            except socket.timeout:
                break
        if not got_reply:
            print('  response: none')

    sock.close()
    _write_pcap(args.dump_packet, records)
    print(f'\n[+] pcap written to {args.dump_packet}')
    print('    Open in Wireshark — IKEv2 dissector activates automatically on UDP/500')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='IKEv2 algorithm suite enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--port',    type=int,   default=500,  help='UDP port (default: 500)')
    parser.add_argument('--timeout', type=float, default=1.5,  help='Per-probe timeout (default: 1.5)')
    parser.add_argument('--delay',   type=float, default=0.1,  help='Inter-probe delay (default: 0.1s)')
    parser.add_argument('--dh-only', action='store_true',      help='Only run phase 1 (DH enumeration)')
    parser.add_argument('--dh',      default='',               help='Comma-separated DH group IDs to test')
    parser.add_argument('--verbose', action='store_true',      help='Show each probe')
    parser.add_argument('--dump-packet', metavar='FILE',
                        help='Send 3 representative probes, write pcap + hex dump, then exit')
    args = parser.parse_args()

    # Build DH list
    if args.dh:
        requested = set(int(x) for x in args.dh.split(','))
        dh_list = [(g, n, s) for g, n, s in DH_GROUPS if g in requested]
        missing = requested - {g for g, _, _ in dh_list}
        if missing:
            print(f'[!] Unknown DH group(s): {missing}', file=sys.stderr)
    else:
        dh_list = list(DH_GROUPS)

    if args.dump_packet:
        cmd_dump_packet(args)
        return

    sock, src_port = open_socket(500)

    is_root       = (os.getuid() == 0)
    using_port500 = (src_port == 500)

    print(f'ikev2_enum.py — target={args.target}:{args.port}  source-port={src_port}  uid={os.getuid()}')
    print(f'Testing {len(dh_list)} DH groups × 4 probe types = {len(dh_list)*4} phase-1 packets')
    print(f'Phase-1 probe sizes: ≤8 transforms per probe (avoids strict server parse limits)')
    print()

    # ---- Phase 1: DH group enumeration ----
    print('=== Phase 1: DH group discovery ===')
    phase1_results, stats = phase1_dh_groups(
        sock, args.target, args.port, dh_list,
        args.timeout, args.delay, args.verbose)

    print(f'  Probes sent: {stats["sent"]}  |  No response: {stats["no_response"]}  |  NO_PROPOSAL_CHOSEN: {stats["no_proposal"]}')

    if not phase1_results:
        # If the server IS responding but rejecting everything, try the single-transform fallback
        # before giving up — phase 1 multi-transform probes may have hit a server parse limit.
        if stats['no_response'] == 0 and stats['no_proposal'] > 0:
            print()
            print('[*] Server responded to all probes with NO_PROPOSAL_CHOSEN.')
            print('[*] Trying phase 1b: single-transform probes to bypass strict parse limits ...')
            print(f'    ({len(dh_list)} DH × 15 ENCR × 7 PRF = up to {len(dh_list)*15*7} probes)')
            print()
            phase1_results, fb_stats = phase1_fallback_minimal(
                sock, args.target, args.port, dh_list,
                args.timeout, args.delay, args.verbose)
            print(f'  Phase-1b probes: {fb_stats["sent"]}  |  No response: {fb_stats["no_response"]}  |  NO_PROPOSAL_CHOSEN: {fb_stats["no_proposal"]}')
            if phase1_results:
                # Merge stats for the summary line that follows
                stats = fb_stats

    if not phase1_results:
        print('[!] All DH groups returned NO_PROPOSAL_CHOSEN or no response.')
        print('    Possible causes:')
        if stats['no_response'] == stats['sent']:
            print('    - ALL probes got no response — server may be firewalled or IP-whitelisted')
            print('    - Verify with: tcpdump -n -i any udp port 500')
        elif stats['no_proposal'] > 0:
            print('    - Server is responding but rejecting ALL proposed algorithm suites')
            print('    - Server may require certificate authentication (not PSK/anonymous)')
            print('    - Server may use proprietary or non-RFC algorithms')
            print('    - Single-transform probes also exhausted (phase 1b ran above)')
        if not using_port500:
            print(f'    *** Source port is {src_port}, NOT 500 — many IKE servers require src port 500')
            print(f'        Re-run as root (or with Docker --privileged) to bind port 500')
        else:
            print('    - Source port 500 is in use (good) — not a port binding issue')
        print('    - Try port 4500 (NAT-T): --port 4500')
        print('    - Use Wireshark/tcpdump to confirm packets reach the server and inspect replies')
        sock.close()
        return

    print(f'\n[+] Phase 1 findings ({len(phase1_results)} interesting responses):')
    interesting_dh = set()
    for dh_id, dh_name, ke_size, label, tag, r in phase1_results:
        print(f'  DH-{dh_id} ({dh_name}) [{label}] → {tag}', end='')
        if tag == 'invalid_ke':
            wants = r.get('invalid_ke_group', '?')
            print(f' (server wants DH-{wants})', end='')
        if tag == 'sa_init':
            print(f' *** HANDSHAKE ACCEPTED ***', end='')
            interesting_dh.add((dh_id, dh_name, ke_size))
        elif tag == 'invalid_ke':
            wants = r.get('invalid_ke_group')
            if wants:
                # Server told us which group it wants — add it
                match = [(g, n, s) for g, n, s in DH_GROUPS if g == wants]
                if match:
                    interesting_dh.add(match[0])
        elif tag not in ('no_proposal', 'unknown'):
            interesting_dh.add((dh_id, dh_name, ke_size))
        print()

    if args.dh_only or not interesting_dh:
        sock.close()
        return

    # ---- Phase 2: cipher drill-down ----
    print(f'\n=== Phase 2: Cipher enumeration for {len(interesting_dh)} DH group(s) ===')
    all_accepted = []
    for dh_id, dh_name, ke_size in sorted(interesting_dh):
        print(f'\n  DH-{dh_id} ({dh_name}):')
        found = phase2_cipher_drill(
            sock, args.target, args.port, dh_id, dh_name, ke_size,
            args.timeout, args.delay, args.verbose)
        all_accepted.extend(found)

    print('\n=== Summary ===')
    if all_accepted:
        print(f'Accepted cipher suites ({len(all_accepted)}):')
        for entry in all_accepted:
            print(f'  ENCR={entry[0]}  PRF={entry[1]}  INTEG={entry[2]}  DH={entry[3]}')
    else:
        print('No cipher suite fully accepted (server responded but rejected all individual probes).')
        print('Consider: vendor-specific algorithms, certificate requirements, or IP whitelisting.')

    sock.close()

if __name__ == '__main__':
    main()
