use std::env;
use std::str;
use std::{io, io::Read, io::Write};

use ssh_key::private::{Ed25519Keypair, Ed25519PrivateKey};
use ssh_key::PrivateKey;

use pgp::composed::{Deserializable, SignedSecretKey, SignedSecretSubKey};
use pgp::crypto::ecdh::SecretKey::Curve25519;
use pgp::packet::SecretKey;
use pgp::types::PlainSecretParams::{Ed25519, Ed25519Legacy, ECDH};
use pgp::types::SecretParams::Plain;
use pgp::types::{KeyDetails, SecretParams};

fn main() -> Result<(), &'static str> {
    let g_k_id = env::args().nth(1);

    let mut g_ks = Vec::new();
    io::stdin()
        .read_to_end(&mut g_ks)
        .map_err(|_| "failed to read from standard input")?;

    let g_ssk =
        SignedSecretKey::from_bytes(&*g_ks).map_err(|_| "failed to parse signed secret key")?;

    let comment = g_ssk
        .details
        .users
        .first()
        .map_or(Ok(""), |u| str::from_utf8(u.id.id()))
        .map_err(|_| "invalid utf-8 sequence in user comment")?;

    let g_sp =
        find_secret_param_by_key_id(g_k_id.as_deref(), &g_ssk.primary_key, &g_ssk.secret_subkeys)?;

    let secret = gpg_extract_sp(g_sp)?;

    let s_pk = gpg_sp_to_ssh_pk(&comment, secret)?;

    io::stdout()
        .write_all(
            s_pk.to_openssh(ssh_key::LineEnding::LF)
                .map_err(|_| "failed to serialise to openssh format")?
                .as_bytes(),
        )
        .map_err(|_| "failed to write to standard output")?;

    Ok(())
}

fn find_secret_param_by_key_id<'a>(
    g_k_id: Option<&str>,
    pk: &'a SecretKey,
    s_subks: &'a [SignedSecretSubKey],
) -> Result<&'a SecretParams, &'static str> {
    match g_k_id {
        None => Ok(pk.secret_params()),
        Some(id) => {
            let clean_id = id.trim_start_matches("0x").trim_start_matches("0X");

            if pk.key_id().to_string().eq_ignore_ascii_case(clean_id) {
                Ok(pk.secret_params())
            } else {
                s_subks
                    .iter()
                    .find(|subk| subk.key.key_id().to_string().eq_ignore_ascii_case(clean_id))
                    .ok_or("key identifier not found")
                    .map(|subk| subk.secret_params())
            }
        }
    }
}

fn gpg_extract_sp(g_sp: &SecretParams) -> Result<&[u8; 32], &'static str> {
    match g_sp {
        Plain(Ed25519Legacy(gpg_sk)) | Plain(Ed25519(gpg_sk)) => Ok(gpg_sk.as_bytes()),
        Plain(ECDH(Curve25519(gpg_sk))) => Ok(gpg_sk.as_bytes()),
        _ => Err("unsupported key type"),
    }
}

fn gpg_sp_to_ssh_pk(comment: &str, secret: &[u8; 32]) -> Result<PrivateKey, &'static str> {
    let s_kp: Ed25519Keypair = Ed25519PrivateKey::from_bytes(secret).into();

    let s_pk =
        PrivateKey::new(s_kp.into(), comment).map_err(|_| "failed to construct private ssh key")?;

    Ok(s_pk)
}
