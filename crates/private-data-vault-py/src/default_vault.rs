use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{AdapterError, VaultAdapter};

const CREDENTIAL_SERVICE: &str = "com.maivn.private-data-vault";
const STATE_FILE: &str = "vault.state";
const SCOPE_FILE: &str = "vault.scope";
const INITIALIZED_FILE: &str = "vault.initialized";
const INITIALIZATION_LOCK: &str = ".initialize.lock";
const MASTER_SECRET_BYTES: usize = 32;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefaultVaultError {
    CredentialUnavailable,
}

pub(crate) trait CredentialStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DefaultVaultError>;
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), DefaultVaultError>;
}

pub(crate) struct OsCredentialStore;

impl CredentialStore for OsCredentialStore {
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DefaultVaultError> {
        let entry = keyring::Entry::new(CREDENTIAL_SERVICE, account)
            .map_err(|_| DefaultVaultError::CredentialUnavailable)?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(DefaultVaultError::CredentialUnavailable),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), DefaultVaultError> {
        let entry = keyring::Entry::new(CREDENTIAL_SERVICE, account)
            .map_err(|_| DefaultVaultError::CredentialUnavailable)?;
        entry
            .set_secret(secret)
            .map_err(|_| DefaultVaultError::CredentialUnavailable)
    }
}

pub(crate) fn open_default(
    scope: &str,
    path: Option<&Path>,
    explicit_secret: Option<&[u8]>,
) -> Result<VaultAdapter, AdapterError> {
    if let Some(path) = path {
        open_default_with_store(
            scope,
            Some(path),
            explicit_secret,
            Path::new(""),
            &OsCredentialStore,
        )
    } else {
        let base = platform_vault_root()?;
        open_default_with_store(scope, None, explicit_secret, &base, &OsCredentialStore)
    }
}

pub(crate) fn default_exists(
    scope: Option<&str>,
    path: Option<&Path>,
) -> Result<bool, AdapterError> {
    if let Some(path) = path {
        default_exists_with_base(scope, Some(path), Path::new(""))
    } else {
        let base = platform_vault_root()?;
        default_exists_with_base(scope, None, &base)
    }
}

fn platform_vault_root() -> Result<PathBuf, AdapterError> {
    ProjectDirs::from("com", "maivn", "maivn")
        .map(|directories| directories.data_local_dir().join("private-data-vaults"))
        .ok_or_else(|| {
            AdapterError::StorageUnavailable(
                "the platform user-data directory is unavailable".to_owned(),
            )
        })
}

pub(crate) fn scoped_path(base: &Path, scope: &str) -> PathBuf {
    base.join(scope_identifier(scope))
}

fn scope_identifier(scope: &str) -> String {
    hex::encode(Sha256::digest(scope.as_bytes()))
}

fn vault_path(base: &Path, scope: &str, explicit: Option<&Path>) -> PathBuf {
    scoped_path(explicit.unwrap_or(base), scope)
}

pub(crate) fn open_default_with_store(
    scope: &str,
    path: Option<&Path>,
    explicit_secret: Option<&[u8]>,
    base: &Path,
    credentials: &dyn CredentialStore,
) -> Result<VaultAdapter, AdapterError> {
    if scope.is_empty() {
        return Err(AdapterError::Vault(
            "vault scope must not be empty".to_owned(),
        ));
    }
    if explicit_secret.is_some() && path.is_none() {
        return Err(AdapterError::Vault(
            "an explicit vault secret requires an explicit path".to_owned(),
        ));
    }
    if path.is_some_and(|value| !value.is_absolute()) {
        return Err(AdapterError::Vault(
            "the explicit vault storage parent must be an absolute path".to_owned(),
        ));
    }
    if explicit_secret.is_some_and(|value| value.len() != MASTER_SECRET_BYTES) {
        return Err(AdapterError::Vault(
            "an explicit vault secret must be exactly 32 bytes".to_owned(),
        ));
    }
    let root = vault_path(base, scope, path);
    create_private_directory(&root)?;
    let lock = open_private_file(&root.join(INITIALIZATION_LOCK))?;
    lock.lock_exclusive().map_err(storage_io)?;

    let scope_identifier = scope_identifier(scope);
    let state_exists = valid_state_exists(&root)?;
    reject_missing_initialized_state(&root, state_exists)?;
    verify_or_initialize_scope(&root, &scope_identifier, state_exists)?;
    let identifier = credential_identifier(scope, &root)?;

    let result = if let Some(secret) = explicit_secret {
        VaultAdapter::open(&root, secret)
    } else {
        match credentials.get(&identifier) {
            Ok(Some(secret)) if secret.len() == MASTER_SECRET_BYTES => {
                VaultAdapter::open(&root, &secret)
            }
            Ok(Some(_)) => Err(AdapterError::StorageUnavailable(
                "vault credential is unavailable".to_owned(),
            )),
            Ok(None) if state_exists => Err(AdapterError::StorageUnavailable(
                "vault credential is unavailable".to_owned(),
            )),
            Ok(None) => {
                let mut secret = Zeroizing::new(vec![0_u8; MASTER_SECRET_BYTES]);
                OsRng.fill_bytes(&mut secret);
                credentials.set(&identifier, &secret).map_err(|_| {
                    AdapterError::StorageUnavailable(
                        "operating-system credential store is unavailable".to_owned(),
                    )
                })?;
                VaultAdapter::open(&root, &secret)
            }
            Err(_) => Err(AdapterError::StorageUnavailable(
                "operating-system credential store is unavailable".to_owned(),
            )),
        }
    }
    .and_then(|adapter| {
        ensure_initialized_marker(&root)?;
        Ok(adapter)
    });
    fs2::FileExt::unlock(&lock).map_err(storage_io)?;
    result
}

pub(crate) fn default_exists_with_base(
    scope: Option<&str>,
    path: Option<&Path>,
    base: &Path,
) -> Result<bool, AdapterError> {
    if path.is_some_and(|value| !value.is_absolute()) {
        return Err(AdapterError::Vault(
            "the explicit vault storage parent must be an absolute path".to_owned(),
        ));
    }
    if let Some(path) = path {
        if let Some(scope) = scope {
            let path = scoped_path(path, scope);
            return scoped_metadata_exists(&path);
        }
        return any_vault_exists(path);
    }
    if let Some(scope) = scope {
        let path = scoped_path(base, scope);
        return scoped_metadata_exists(&path);
    }
    any_vault_exists(base)
}

fn any_vault_exists(base: &Path) -> Result<bool, AdapterError> {
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(storage_io(error)),
    };
    for entry in entries {
        let entry = entry.map_err(storage_io)?;
        if entry.file_type().map_err(storage_io)?.is_dir() && scoped_metadata_exists(&entry.path())?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn scoped_metadata_exists(root: &Path) -> Result<bool, AdapterError> {
    if !path_is_directory(root)? {
        return Ok(false);
    }
    Ok(path_is_file(&root.join(STATE_FILE))?
        || path_is_file(&root.join(SCOPE_FILE))?
        || path_is_file(&root.join(INITIALIZED_FILE))?
        || path_is_file(&root.join(INITIALIZATION_LOCK))?)
}

fn valid_state_exists(root: &Path) -> Result<bool, AdapterError> {
    match fs::metadata(root.join(STATE_FILE)) {
        Ok(metadata) if !metadata.is_file() => Err(AdapterError::StorageUnavailable(
            "vault state is unavailable".to_owned(),
        )),
        Ok(metadata) => Ok(metadata.len() > 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_io(error)),
    }
}

fn reject_missing_initialized_state(root: &Path, state_exists: bool) -> Result<(), AdapterError> {
    if state_exists {
        return Ok(());
    }
    if path_is_file(&root.join(INITIALIZED_FILE))? || has_persisted_records(root)? {
        return Err(AdapterError::StorageUnavailable(
            "vault state is unavailable".to_owned(),
        ));
    }
    Ok(())
}

fn has_persisted_records(root: &Path) -> Result<bool, AdapterError> {
    for directory in ["values", "documents", "originals", "generations"] {
        let mut entries = match fs::read_dir(root.join(directory)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(storage_io(error)),
        };
        if let Some(entry) = entries.next() {
            entry.map_err(storage_io)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_initialized_marker(root: &Path) -> Result<(), AdapterError> {
    let marker = root.join(INITIALIZED_FILE);
    match fs::metadata(&marker) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(AdapterError::StorageUnavailable(
            "vault initialization metadata is unavailable".to_owned(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = private_create_new(&marker)?;
            file.write_all(b"1").map_err(storage_io)?;
            file.sync_all().map_err(storage_io)
        }
        Err(error) => Err(storage_io(error)),
    }
}

fn verify_or_initialize_scope(
    root: &Path,
    identifier: &str,
    state_exists: bool,
) -> Result<(), AdapterError> {
    let marker = root.join(SCOPE_FILE);
    match fs::read_to_string(&marker) {
        Ok(stored) if stored == identifier => Ok(()),
        Ok(_) => Err(AdapterError::StorageUnavailable(
            "vault scope does not match the existing storage".to_owned(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && state_exists => Err(
            AdapterError::StorageUnavailable("vault scope metadata is unavailable".to_owned()),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut file = private_create_new(&marker)?;
            file.write_all(identifier.as_bytes()).map_err(storage_io)?;
            file.sync_all().map_err(storage_io)
        }
        Err(error) => Err(storage_io(error)),
    }
}

fn path_is_file(path: &Path) -> Result<bool, AdapterError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_io(error)),
    }
}

fn path_is_directory(path: &Path) -> Result<bool, AdapterError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_io(error)),
    }
}

fn credential_identifier(scope: &str, root: &Path) -> Result<String, AdapterError> {
    let canonical = fs::canonicalize(root).map_err(storage_io)?;
    let mut digest = Sha256::new();
    digest.update(scope.as_bytes());
    digest.update([0]);
    digest.update(canonical.to_string_lossy().as_bytes());
    Ok(hex::encode(digest.finalize()))
}

fn create_private_directory(path: &Path) -> Result<(), AdapterError> {
    fs::create_dir_all(path).map_err(storage_io)?;
    reject_linked_directory(path)?;
    set_private_directory_permissions(path)
}

fn reject_linked_directory(path: &Path) -> Result<(), AdapterError> {
    let metadata = fs::symlink_metadata(path).map_err(storage_io)?;
    if metadata.file_type().is_symlink() {
        return Err(AdapterError::StorageUnavailable(
            "the vault directory must not be a symbolic link".to_owned(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AdapterError::StorageUnavailable(
                "the vault directory must not be a reparse point".to_owned(),
            ));
        }
    }
    Ok(())
}

fn open_private_file(path: &Path) -> Result<File, AdapterError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(storage_io)?;
    set_private_file_permissions(path)?;
    Ok(file)
}

fn private_create_new(path: &Path) -> Result<File, AdapterError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(storage_io)?;
    set_private_file_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(storage_io)
}

#[cfg(windows)]
fn set_private_directory_permissions(path: &Path) -> Result<(), AdapterError> {
    restrict_windows_directory(path)
}

#[cfg(all(not(unix), not(windows)))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), AdapterError> {
    Err(AdapterError::StorageUnavailable(
        "automatic vault storage is unsupported on this platform".to_owned(),
    ))
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), AdapterError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(storage_io)
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the Unix implementation, which can fail"
)]
fn set_private_file_permissions(_path: &Path) -> Result<(), AdapterError> {
    Ok(())
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as the mapping function for owned I/O errors"
)]
fn storage_io(error: std::io::Error) -> AdapterError {
    AdapterError::StorageUnavailable(format!("vault storage is unavailable: {error}"))
}

#[cfg(windows)]
fn restrict_windows_directory(path: &Path) -> Result<(), AdapterError> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    use winapi::um::winnt::{CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, OBJECT_INHERIT_ACE};
    use windows_acl::{
        acl::{ACL, AceType},
        helper::{current_user, name_to_sid, sid_to_string, string_to_sid},
    };

    let user = current_user().ok_or_else(|| {
        AdapterError::StorageUnavailable("the current Windows identity is unavailable".to_owned())
    })?;
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        AdapterError::StorageUnavailable("the Windows system directory is unavailable".to_owned())
    })?;
    let executable = PathBuf::from(system_root)
        .join("System32")
        .join("icacls.exe");
    let grant = format!("{user}:(OI)(CI)F");
    let mut command = Command::new(executable);
    command
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(grant)
        .arg("/Q")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    let status = command.status().map_err(storage_io)?;
    if !status.success() {
        return Err(AdapterError::StorageUnavailable(
            "the vault directory permissions could not be restricted".to_owned(),
        ));
    }

    let user_sid = name_to_sid(&user, None).map_err(|_| {
        AdapterError::StorageUnavailable("the current Windows identity is unavailable".to_owned())
    })?;
    let user_sid = sid_to_string(user_sid.as_ptr().cast_mut().cast()).map_err(|_| {
        AdapterError::StorageUnavailable("the current Windows identity is unavailable".to_owned())
    })?;
    let path_text = path.to_str().ok_or_else(|| {
        AdapterError::StorageUnavailable("the vault path is not valid Unicode".to_owned())
    })?;
    let mut acl = ACL::from_file_path(path_text, false).map_err(|_| {
        AdapterError::StorageUnavailable(
            "the vault directory permissions could not be verified".to_owned(),
        )
    })?;
    // icacls removes inherited grants but preserves other explicit identities.
    // Windows temporary directories can carry explicit SYSTEM, Administrators,
    // and OWNER RIGHTS entries even under a private parent directory.
    let restriction_failed = || {
        AdapterError::StorageUnavailable(
            "the vault directory permissions could not be restricted".to_owned(),
        )
    };
    for entry in acl.all().map_err(|_| restriction_failed())? {
        if !matches!(entry.entry_type, AceType::AccessAllow | AceType::AccessDeny) {
            return Err(restriction_failed());
        }
        if !entry.string_sid.eq_ignore_ascii_case(&user_sid) {
            let other_sid = string_to_sid(&entry.string_sid).map_err(|_| restriction_failed())?;
            let removed = acl
                .remove(
                    other_sid.as_ptr().cast_mut().cast(),
                    Some(entry.entry_type),
                    None,
                )
                .map_err(|_| restriction_failed())?;
            if removed == 0 {
                return Err(restriction_failed());
            }
        }
    }
    let entries = acl.all().map_err(|_| {
        AdapterError::StorageUnavailable(
            "the vault directory permissions could not be verified".to_owned(),
        )
    })?;
    let inherit_flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let mut full_control = false;
    for entry in entries {
        if !matches!(entry.entry_type, AceType::AccessAllow | AceType::AccessDeny) {
            return Err(restriction_failed());
        }
        if !entry.string_sid.eq_ignore_ascii_case(&user_sid) {
            return Err(AdapterError::StorageUnavailable(
                "the vault directory grants access to another Windows identity".to_owned(),
            ));
        }
        if entry.entry_type == AceType::AccessAllow
            && entry.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
            && entry.flags & inherit_flags == inherit_flags
        {
            full_control = true;
        }
    }
    if !full_control {
        return Err(AdapterError::StorageUnavailable(
            "the vault directory does not grant inheritable full control to the current Windows identity"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        path::Path,
        sync::{Arc, Barrier, Mutex},
        thread,
    };

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::{
        CredentialStore, DefaultVaultError, default_exists_with_base, open_default_with_store,
    };
    use crate::AdapterError;

    const EXPLICIT_SECRET: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    #[cfg(windows)]
    #[test]
    fn explicit_windows_grants_are_removed_before_the_directory_is_used() {
        use winapi::um::winnt::FILE_GENERIC_READ;
        use windows_acl::{
            acl::{ACL, AceType},
            helper::{current_user, name_to_sid, sid_to_string, string_to_sid},
        };

        let base = tempdir().expect("base directory");
        let vault = base.path().join("vault");
        std::fs::create_dir(&vault).expect("vault directory");
        let path = vault.to_str().expect("Unicode test path");
        let mut acl = ACL::from_file_path(path, false).expect("directory ACL");
        let everyone_sid = string_to_sid("S-1-1-0").expect("Everyone SID");
        acl.allow(
            everyone_sid.as_ptr().cast_mut().cast(),
            true,
            FILE_GENERIC_READ,
        )
        .expect("temporary test grant");
        assert!(acl.all().expect("test ACL").iter().any(|entry| {
            entry.entry_type == AceType::AccessAllow && entry.string_sid == "S-1-1-0"
        }));

        super::restrict_windows_directory(&vault).expect("private vault directory");

        let user = current_user().expect("current user");
        let user_sid = name_to_sid(&user, None).expect("current user SID");
        let user_sid = sid_to_string(user_sid.as_ptr().cast_mut().cast()).expect("SID string");
        let entries = ACL::from_file_path(path, false)
            .expect("restricted directory ACL")
            .all()
            .expect("restricted entries");
        assert!(entries.iter().all(|entry| {
            matches!(entry.entry_type, AceType::AccessAllow | AceType::AccessDeny)
                && entry.string_sid.eq_ignore_ascii_case(&user_sid)
        }));
    }

    #[derive(Default)]
    struct FakeCredentialStore {
        secrets: Mutex<BTreeMap<String, Vec<u8>>>,
        writes: Mutex<usize>,
        unavailable: bool,
    }

    impl CredentialStore for FakeCredentialStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DefaultVaultError> {
            if self.unavailable {
                return Err(DefaultVaultError::CredentialUnavailable);
            }
            Ok(self
                .secrets
                .lock()
                .expect("fake store lock")
                .get(account)
                .cloned()
                .map(Zeroizing::new))
        }

        fn set(&self, account: &str, secret: &[u8]) -> Result<(), DefaultVaultError> {
            if self.unavailable {
                return Err(DefaultVaultError::CredentialUnavailable);
            }
            self.secrets
                .lock()
                .expect("fake store lock")
                .insert(account.to_owned(), secret.to_vec());
            *self.writes.lock().expect("fake write lock") += 1;
            Ok(())
        }
    }

    #[test]
    fn explicit_secret_requires_an_explicit_durable_path() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();

        assert!(matches!(
            open_default_with_store("scope-a", None, Some(EXPLICIT_SECRET), base.path(), &store),
            Err(AdapterError::Vault(message)) if message.contains("explicit path")
        ));
    }

    #[test]
    fn an_explicit_storage_parent_must_be_absolute() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();

        assert!(matches!(
            open_default_with_store(
                "scope-a",
                Some(Path::new("relative-vault")),
                Some(EXPLICIT_SECRET),
                base.path(),
                &store,
            ),
            Err(AdapterError::Vault(message)) if message.contains("absolute")
        ));
    }

    #[test]
    fn an_explicit_secret_must_be_a_256_bit_key() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();

        assert!(matches!(
            open_default_with_store(
                "scope-a",
                Some(base.path()),
                Some(b"too short"),
                Path::new(""),
                &store,
            ),
            Err(AdapterError::Vault(message)) if message.contains("exactly 32 bytes")
        ));
    }

    #[test]
    fn concurrent_first_open_creates_one_credential_and_reopens_the_same_vault() {
        let base = tempdir().expect("base directory");
        let store = Arc::new(FakeCredentialStore::default());
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for index in 0..2 {
            let base = base.path().to_owned();
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                let vault = open_default_with_store("scope-a", None, None, &base, &*store)
                    .expect("default vault opens");
                vault
                    .merge_value_map(
                        "tenant",
                        "record",
                        format!(r#"{{"key-{index}":"value-{index}"}}"#).as_bytes(),
                    )
                    .expect("value merges");
            }));
        }
        for worker in workers {
            worker.join().expect("worker succeeds");
        }

        assert_eq!(*store.writes.lock().expect("fake write lock"), 1);
        let reopened = open_default_with_store("scope-a", None, None, base.path(), &*store)
            .expect("default vault reopens");
        let loaded = reopened
            .load_value_map("tenant", "record")
            .expect("merged record loads");
        assert_eq!(
            loaded.as_slice(),
            br#"{"key-0":"value-0","key-1":"value-1"}"#
        );
    }

    #[test]
    fn an_existing_vault_without_its_credential_fails_closed() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        let vault = open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");
        vault
            .store_value_map("tenant", "record", br#"{"private":"value"}"#)
            .expect("record stores");
        store.secrets.lock().expect("fake store lock").clear();

        assert!(matches!(
            open_default_with_store("scope-a", None, None, base.path(), &store),
            Err(AdapterError::StorageUnavailable(message))
                if message == "vault credential is unavailable"
        ));
        assert_eq!(*store.writes.lock().expect("fake write lock"), 1);
    }

    #[test]
    fn an_existing_vault_without_scope_metadata_fails_closed() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");
        let root = super::scoped_path(base.path(), "scope-a");
        std::fs::remove_file(root.join(super::SCOPE_FILE)).expect("scope marker removes");

        assert!(matches!(
            open_default_with_store("scope-a", None, None, base.path(), &store),
            Err(AdapterError::StorageUnavailable(message))
                if message == "vault scope metadata is unavailable"
        ));
        assert!(!root.join(super::SCOPE_FILE).exists());
    }

    #[test]
    fn an_existing_vault_with_missing_state_fails_before_reinitialization() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        let vault = open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");
        vault
            .store_value_map("tenant", "record", br#"{"private":"value"}"#)
            .expect("record stores");
        let state = super::scoped_path(base.path(), "scope-a").join(super::STATE_FILE);
        std::fs::remove_file(&state).expect("state removes");

        assert!(matches!(
            open_default_with_store("scope-a", None, None, base.path(), &store),
            Err(AdapterError::StorageUnavailable(message))
                if message == "vault state is unavailable"
        ));
        assert!(!state.exists(), "a failed reopen must not recreate state");
    }

    #[test]
    fn an_existing_vault_with_empty_state_fails_before_reinitialization() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        let vault = open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");
        vault
            .store_value_map("tenant", "record", br#"{"private":"value"}"#)
            .expect("record stores");
        let state = super::scoped_path(base.path(), "scope-a").join(super::STATE_FILE);
        std::fs::write(&state, []).expect("state truncates");

        assert!(matches!(
            open_default_with_store("scope-a", None, None, base.path(), &store),
            Err(AdapterError::StorageUnavailable(message))
                if message == "vault state is unavailable"
        ));
        assert_eq!(
            std::fs::metadata(state).expect("state metadata").len(),
            0,
            "a failed reopen must preserve the damaged state"
        );
    }

    #[test]
    fn interrupted_first_setup_without_state_or_records_can_recover() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        let root = super::scoped_path(base.path(), "scope-a");
        std::fs::create_dir_all(&root).expect("scope directory creates");
        std::fs::write(
            root.join(super::SCOPE_FILE),
            super::scope_identifier("scope-a"),
        )
        .expect("scope marker writes");
        std::fs::write(root.join(super::INITIALIZATION_LOCK), []).expect("lock file writes");

        open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("interrupted setup recovers");

        assert!(root.join(super::STATE_FILE).is_file());
        assert!(root.join(super::INITIALIZED_FILE).is_file());
    }

    #[test]
    fn an_unavailable_credential_store_is_sanitized() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore {
            unavailable: true,
            ..FakeCredentialStore::default()
        };

        assert!(matches!(
            open_default_with_store("scope-a", None, None, base.path(), &store),
            Err(AdapterError::StorageUnavailable(message))
                if message == "operating-system credential store is unavailable"
        ));
    }

    #[test]
    fn one_explicit_parent_isolates_scopes_in_separate_vaults() {
        let base = tempdir().expect("base directory");
        let explicit = base.path().join("durable-vault");
        let store = FakeCredentialStore::default();
        let first = open_default_with_store("scope-a", Some(&explicit), None, base.path(), &store)
            .expect("first scope opens");
        first
            .store_value_map("tenant", "record", br#"{"private":"first"}"#)
            .expect("first scope stores");
        let second = open_default_with_store("scope-b", Some(&explicit), None, base.path(), &store)
            .expect("second scope opens");
        assert!(matches!(
            second.load_value_map("tenant", "record"),
            Err(AdapterError::RecordNotFound)
        ));
        assert_ne!(
            super::scoped_path(&explicit, "scope-a"),
            super::scoped_path(&explicit, "scope-b")
        );
    }

    #[test]
    fn the_same_scope_in_two_roots_gets_two_independent_credentials() {
        let first_parent = tempdir().expect("first parent");
        let second_parent = tempdir().expect("second parent");
        let store = FakeCredentialStore::default();

        open_default_with_store(
            "scope-a",
            Some(first_parent.path()),
            None,
            Path::new(""),
            &store,
        )
        .expect("first root opens");
        open_default_with_store(
            "scope-a",
            Some(second_parent.path()),
            None,
            Path::new(""),
            &store,
        )
        .expect("second root opens");

        assert_eq!(*store.writes.lock().expect("fake write lock"), 2);
        assert_eq!(store.secrets.lock().expect("fake store lock").len(), 2);
    }

    #[test]
    fn existence_checks_read_metadata_without_touching_credentials() {
        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        assert!(!default_exists_with_base(None, None, base.path()).expect("empty root checks"));
        assert!(
            !default_exists_with_base(Some("scope-a"), None, base.path())
                .expect("missing scope checks")
        );

        open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");

        assert!(default_exists_with_base(None, None, base.path()).expect("root checks"));
        assert!(
            default_exists_with_base(Some("scope-a"), None, base.path())
                .expect("existing scope checks")
        );
        assert!(
            !default_exists_with_base(Some("scope-b"), None, base.path())
                .expect("other scope checks")
        );
        assert_eq!(*store.writes.lock().expect("fake write lock"), 1);

        let configured_parent = tempdir().expect("configured parent");
        open_default_with_store(
            "scope-c",
            Some(configured_parent.path()),
            Some(EXPLICIT_SECRET),
            base.path(),
            &store,
        )
        .expect("configured vault opens");
        assert!(
            default_exists_with_base(None, Some(configured_parent.path()), base.path())
                .expect("configured parent checks")
        );
        assert!(
            default_exists_with_base(Some("scope-c"), Some(configured_parent.path()), base.path(),)
                .expect("configured scope checks")
        );

        let interrupted = super::scoped_path(configured_parent.path(), "scope-interrupted");
        std::fs::create_dir_all(&interrupted).expect("interrupted scope directory");
        std::fs::write(interrupted.join(super::SCOPE_FILE), b"truncated")
            .expect("partial marker writes");
        assert!(
            default_exists_with_base(
                Some("scope-interrupted"),
                Some(configured_parent.path()),
                base.path(),
            )
            .expect("partial metadata checks")
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_storage_is_private_to_the_current_user() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempdir().expect("base directory");
        let store = FakeCredentialStore::default();
        open_default_with_store("scope-a", None, None, base.path(), &store)
            .expect("default vault opens");
        let vault_path = super::scoped_path(base.path(), "scope-a");

        assert_eq!(
            std::fs::metadata(&vault_path)
                .expect("vault metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(vault_path.join("vault.state"))
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[allow(dead_code)]
    fn _path_contract(path: &Path) -> bool {
        path.is_absolute()
    }
}
