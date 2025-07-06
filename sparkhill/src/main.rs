use std::env;
use std::{
    io,
    io::Read,
    io::prelude::*,
};

use ssh_key::PrivateKey;
use ssh_key::private::{
    Ed25519Keypair,
    Ed25519PrivateKey,
};

use pgp::composed::{
    Deserializable,
    SignedSecretKey,
    SignedSecretSubKey,
};
use pgp::crypto::ecdh::SecretKey::Curve25519;
use pgp::packet::SecretKey;
use pgp::types::{
    KeyDetails,
    SecretParams,
};
use pgp::types::PlainSecretParams::{
    ECDH,
    Ed25519,
    Ed25519Legacy,};
use pgp::types::SecretParams::Plain;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let g_k_id = env::args().nth(1);

    let mut g_ks = Vec::new();
    io::stdin().read_to_end(&mut g_ks)?;

    let g_ssk =
        SignedSecretKey::from_bytes(
            &*g_ks)?;
    
    let comment = 
        g_ssk.details.users.first()
        .map_or(Ok(""),|u| str::from_utf8(u.id.id()))?;

    let g_sp = find_secret_param_by_key_id(
        &g_k_id,
        &g_ssk.primary_key,
        &g_ssk.secret_subkeys,
    )?;
    
    let secret = gpg_extract_sp(g_sp)?;
    
    let s_pk = gpg_sp_to_ssh_pk(
        &comment, &secret);

    io::stdout().write(
        s_pk?.to_openssh(ssh_key::LineEnding::LF)?.as_bytes())?;

    Ok(())
}

fn find_secret_param_by_key_id<'a>(
    g_k_id: &Option<String>,
    pk: &'a SecretKey,
    s_subks: &'a Vec<SignedSecretSubKey>,
) -> Result<&'a SecretParams, &'a str> {
    match g_k_id {
        None => Ok(pk.secret_params()),
        Some(id) if pk.key_id().to_string() == id.to_lowercase()
            => Ok(pk.secret_params()),
        Some(id) => {
            Ok(s_subks.iter().filter(
                |subk| subk.key.key_id().to_string() == id.to_lowercase())
               .collect::<Vec<_>>()
               .first().ok_or("key id not found")?
               .secret_params())
        },
    }
}

fn gpg_extract_sp(
    g_sp: &SecretParams,
) -> Result<&[u8; 32], &str> {
    match g_sp {
        Plain(Ed25519Legacy(gpg_sk)) |
        Plain(Ed25519(gpg_sk)) => {
            Ok(gpg_sk.as_bytes())
        },
        Plain(ECDH(Curve25519(gpg_sk))) => {
            Ok(gpg_sk.as_bytes())
        }
        /* for RSA see openssl/monkeysphere */
        _ => Err("unsupported key")
    }
}

fn gpg_sp_to_ssh_pk(
    comment: &str,
    secret: &[u8; 32],
) -> Result<PrivateKey, ssh_key::Error> {
    let s_kp: Ed25519Keypair =
        Ed25519PrivateKey::from_bytes(
            &secret).into();

    let s_pk = PrivateKey::new(
        s_kp.into(), comment)?;

    return Ok(s_pk)
}
