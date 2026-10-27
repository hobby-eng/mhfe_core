//! A share of the full-size vector replay, so that several processes replay it at once on a
//! computer with the memory for it: `MHFE_VECTOR_SHARE=k/n` replays every n-th item, the
//! transcripts then the recovery cases, starting at item k (from 0). Without it every item is
//! replayed.

/// Whether the item at `index` of the replay belongs to this process.
pub(crate) fn mine(index: usize) -> bool {
    let Ok(share) = std::env::var("MHFE_VECTOR_SHARE") else {
        return true;
    };
    let (part, parts) = share
        .split_once('/')
        .and_then(|(part, parts)| Some((part.parse::<usize>().ok()?, parts.parse::<usize>().ok()?)))
        .filter(|&(part, parts)| parts > 0 && part < parts)
        .unwrap_or_else(|| panic!("MHFE_VECTOR_SHARE must be k/n with k < n, not {share:?}"));
    index % parts == part
}
