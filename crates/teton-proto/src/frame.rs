//! Message framing over GATT writes/notifications (SPEC.md §4.1).
//!
//! Each chunk is `[header][payload]`, where header bit 7 marks the final chunk
//! and bits 0–6 carry the chunk index, starting at 0 and incrementing by one
//! (mod 128) within a message.

/// Largest reassembled message accepted from the peer.
pub const MAX_MESSAGE_LEN: usize = 4096;

const FINAL: u8 = 0x80;
const INDEX_MASK: u8 = 0x7f;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("chunk size must be at least 2 bytes")]
    ChunkTooSmall,
    #[error("empty chunk")]
    EmptyChunk,
    #[error("chunk index {got}, expected {expected}")]
    OutOfOrder { expected: u8, got: u8 },
    #[error("message exceeds {MAX_MESSAGE_LEN} bytes")]
    TooLarge,
}

/// Splits `msg` into chunks of at most `max_chunk_len` bytes (header included).
pub fn chunk(msg: &[u8], max_chunk_len: usize) -> Result<Vec<Vec<u8>>, FrameError> {
    if max_chunk_len < 2 {
        return Err(FrameError::ChunkTooSmall);
    }
    if msg.len() > MAX_MESSAGE_LEN {
        return Err(FrameError::TooLarge);
    }
    let parts: Vec<&[u8]> = if msg.is_empty() {
        vec![&[]]
    } else {
        msg.chunks(max_chunk_len - 1).collect()
    };
    let last = parts.len() - 1;
    Ok(parts
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let mut header = (i % 128) as u8;
            if i == last {
                header |= FINAL;
            }
            let mut c = Vec::with_capacity(part.len() + 1);
            c.push(header);
            c.extend_from_slice(part);
            c
        })
        .collect())
}

/// Reassembles chunks into messages. Any error resets the state; callers end
/// the session on error.
#[derive(Debug, Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    next: u8,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one chunk; returns the message once its final chunk arrives.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        let result = self.push_inner(chunk);
        if result.is_err() {
            *self = Self::default();
        }
        result
    }

    fn push_inner(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        let (&header, payload) = chunk.split_first().ok_or(FrameError::EmptyChunk)?;
        let index = header & INDEX_MASK;
        if index != self.next {
            return Err(FrameError::OutOfOrder {
                expected: self.next,
                got: index,
            });
        }
        if self.buf.len() + payload.len() > MAX_MESSAGE_LEN {
            return Err(FrameError::TooLarge);
        }
        self.buf.extend_from_slice(payload);
        if header & FINAL != 0 {
            self.next = 0;
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        self.next = (self.next + 1) & INDEX_MASK;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reassemble(chunks: &[Vec<u8>]) -> Result<Option<Vec<u8>>, FrameError> {
        let mut r = Reassembler::new();
        let mut out = None;
        for c in chunks {
            out = r.push(c)?;
        }
        Ok(out)
    }

    proptest! {
        #[test]
        fn round_trip(msg in proptest::collection::vec(any::<u8>(), 0..=MAX_MESSAGE_LEN),
                      max in 2usize..600) {
            let chunks = chunk(&msg, max).unwrap();
            prop_assert!(chunks.iter().all(|c| c.len() <= max));
            prop_assert_eq!(reassemble(&chunks).unwrap(), Some(msg));
        }

        #[test]
        fn arbitrary_input_never_panics(chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..40), 0..300)) {
            let mut r = Reassembler::new();
            for c in &chunks {
                if let Ok(Some(m)) = r.push(c) {
                    prop_assert!(m.len() <= MAX_MESSAGE_LEN);
                }
            }
        }

        #[test]
        fn dropped_chunk_is_detected(msg in proptest::collection::vec(any::<u8>(), 40..400),
                                     drop in any::<prop::sample::Index>()) {
            let mut chunks = chunk(&msg, 20).unwrap();
            let i = drop.index(chunks.len() - 1); // never drop the final chunk
            chunks.remove(i);
            prop_assert!(reassemble(&chunks).is_err());
        }
    }

    #[test]
    fn index_wraps_after_128_chunks() {
        let msg = vec![7u8; 300];
        let chunks = chunk(&msg, 2).unwrap();
        assert_eq!(chunks[127][0], 127);
        assert_eq!(chunks[128][0], 0);
        assert_eq!(chunks[299][0], (299 % 128) as u8 | FINAL);
        assert_eq!(reassemble(&chunks).unwrap(), Some(msg));
    }

    #[test]
    fn rejects_oversize_input_and_output() {
        assert_eq!(
            chunk(&[0; MAX_MESSAGE_LEN + 1], 20),
            Err(FrameError::TooLarge)
        );
        let mut r = Reassembler::new();
        let mut result = Ok(None);
        for i in 0..=MAX_MESSAGE_LEN / 100 {
            let mut c = vec![(i % 128) as u8];
            c.extend_from_slice(&[0; 100]);
            result = r.push(&c);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(FrameError::TooLarge));
    }

    #[test]
    fn error_resets_state() {
        let mut r = Reassembler::new();
        assert!(r.push(&[0x05, 1]).is_err());
        assert_eq!(r.push(&[FINAL, 9]).unwrap(), Some(vec![9]));
    }

    #[test]
    fn empty_chunk_and_tiny_mtu() {
        assert_eq!(Reassembler::new().push(&[]), Err(FrameError::EmptyChunk));
        assert_eq!(chunk(b"x", 1), Err(FrameError::ChunkTooSmall));
    }
}
