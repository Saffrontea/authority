use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use ::ssh_key::{Algorithm, LineEnding, PrivateKey, rand_core::OsRng};

pub fn load_or_generate(path: &Path) -> Result<PrivateKey, String> {
    match fs::read_to_string(path) {
        Ok(pem) => PrivateKey::from_openssh(&pem).map_err(display),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(display)?;
            }
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(display)?;
            let pem = key.to_openssh(LineEnding::LF).map_err(display)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(display)?;
            file.write_all(pem.as_bytes()).map_err(display)?;
            Ok(key)
        }
        Err(error) => Err(display(error)),
    }
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
