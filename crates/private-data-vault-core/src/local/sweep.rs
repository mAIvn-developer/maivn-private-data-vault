//! Retention: removing sealed objects older than a cutoff without ever
//! destroying a newer object written to the same path.

use std::{fs, path::Path, time::SystemTime};

use super::{remove_file_if_present, sync_parent_directory};
use crate::StorageError;

/// Removes every file in one directory older than `cutoff`.
///
/// A file whose modification time cannot be read is left alone rather than
/// deleted. Retention deleting something it could not evaluate would be a
/// silent data loss, and the sweep runs again shortly.
pub(super) fn sweep_directory(directory: &Path, cutoff: SystemTime) -> Result<usize, StorageError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|data| data.modified()) else {
            continue;
        };
        if modified < cutoff {
            // Claim the path by renaming BEFORE deciding, rather than
            // re-checking the timestamp and then deleting.
            //
            // A stat-then-delete is racy however tightly it is written: the
            // storage key derives from the record identity, so a re-seal of the
            // same record lands at exactly this path, and a replacement written
            // between the check and the unlink is destroyed while well inside
            // its retention period. Rename is atomic, so moving the file aside
            // first takes ownership of whichever version was there; anything
            // written afterwards lands on a now-empty path and is untouched.
            // If what we claimed turns out to be fresh, it goes back.
            if claim_and_remove_if_expired(&entry.path(), cutoff)? {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Atomically claims `path` and removes it only if it is genuinely expired.
///
/// Returns whether an object was removed. A file that turns out to be inside
/// its retention period is put back where it came from.
///
/// The `.sweeping` suffix cannot collide with a stored object: storage names
/// are hex of a 32-byte key plus `.pvm`/`.pvd`, and this adds a suffix no
/// storage path produces. A crash between the two renames leaves one such file
/// behind, which the next sweep re-evaluates on its own age -- material is
/// never lost, at worst it lingers one interval longer.
fn claim_and_remove_if_expired(path: &Path, cutoff: SystemTime) -> Result<bool, StorageError> {
    let claimed = path.with_extension("sweeping");
    match fs::rename(path, &claimed) {
        Ok(()) => {}
        // Already gone: another sweep, or a purge, got there first.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    }

    let expired = fs::metadata(&claimed)
        .and_then(|data| data.modified())
        .is_ok_and(|modified| modified < cutoff);

    if expired {
        remove_file_if_present(&claimed)?;
        sync_parent_directory(&claimed)?;
        return Ok(true);
    }

    // Fresh after all. Put it back. If a newer write has already taken the
    // path, keep that one and drop this older copy rather than overwriting
    // current material with what we moved aside.
    if path.exists() {
        remove_file_if_present(&claimed)?;
    } else {
        fs::rename(&claimed, path)?;
    }
    Ok(false)
}
