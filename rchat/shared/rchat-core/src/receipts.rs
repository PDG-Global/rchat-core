//! In-band receipts (spec §5.4): `03 || kind || count || count × id(16)`,
//! sent as an ordinary sealed ratchet message.

pub const RECEIPT_TYPE: u8 = 0x03;
pub const DELIVERED: u8 = 1;
pub const READ: u8 = 2;
pub const MAX_IDS: usize = 32;

pub fn encode(kind: u8, ids: &[[u8; 16]]) -> Option<Vec<u8>> {
    if !(kind == DELIVERED || kind == READ) || ids.is_empty() || ids.len() > MAX_IDS {
        return None;
    }
    let mut out = Vec::with_capacity(3 + 16 * ids.len());
    out.push(RECEIPT_TYPE);
    out.push(kind);
    out.push(ids.len() as u8);
    for id in ids {
        out.extend_from_slice(id);
    }
    Some(out)
}

pub fn decode(plaintext: &[u8]) -> Option<(u8, Vec<[u8; 16]>)> {
    let (&ty, rest) = plaintext.split_first()?;
    let (&kind, rest) = rest.split_first()?;
    let (&count, rest) = rest.split_first()?;
    let count = count as usize;
    if ty != RECEIPT_TYPE
        || !(kind == DELIVERED || kind == READ)
        || count == 0
        || count > MAX_IDS
        || rest.len() != 16 * count
    {
        return None;
    }
    Some((
        kind,
        rest.chunks_exact(16)
            .map(|c| c.try_into().expect("16-byte chunk"))
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trip_and_bounds() {
        let ids = [[1u8; 16], [2u8; 16]];
        let pt = encode(DELIVERED, &ids).unwrap();
        assert_eq!(pt[..3], [RECEIPT_TYPE, DELIVERED, 2]);
        assert_eq!(pt.len(), 3 + 32);
        assert_eq!(decode(&pt), Some((DELIVERED, ids.to_vec())));
        assert_eq!(
            encode(READ, &[[0u8; 16]; 32]).map(|v| v.len()),
            Some(3 + 512)
        );
        assert_eq!(encode(READ, &[[0u8; 16]; 33]), None);
        assert_eq!(encode(READ, &[]), None);
        assert_eq!(encode(9, &ids), None);
        assert_eq!(decode(&[RECEIPT_TYPE, 3, 1]), None, "unknown kind");
        assert_eq!(decode(&pt[..pt.len() - 1]), None, "truncated");
        assert_eq!(decode(&[0x01, 1, 1]), None, "not a receipt");
    }
}
