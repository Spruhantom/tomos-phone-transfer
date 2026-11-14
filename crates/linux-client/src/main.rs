use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use tokio::net::TcpListener;
use tomos_transfer_core::{
    identity::{LocalIdentity, PublicIdentity},
    pairing::{OneTimePairingToken, PairingInvitation},
    tcp::{accept_one_resumable, connect_and_send_with_id},
    tls::DeviceTlsIdentity,
};
use uuid::Uuid;

const SECRET_APP: &str = "tomos-transfer";

#[derive(Serialize, Deserialize)]
struct IdentityRecord {
    device_id: Uuid,
    seed_b64: String,
}

#[derive(Serialize, Deserialize)]
struct TlsRecord {
    certificate_b64: String,
    private_key_b64: String,
}

fn secret_tool_lookup(record: &str) -> Result<Option<String>, Box<dyn Error>> {
    let output = Command::new("secret-tool")
        .args(["lookup", "application", SECRET_APP, "record", record])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    if value.is_empty() { Ok(None) } else { Ok(Some(value)) }
}

fn secret_tool_store(record: &str, label: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("secret-tool")
        .args(["store", "--label", label, "application", SECRET_APP, "record", record])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().ok_or("secret-tool stdin unavailable")?
        .write_all(value.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "Secret Service rejected the {record} record: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ).into());
    }
    Ok(())
}

fn load_or_create_identity() -> Result<LocalIdentity, Box<dyn Error>> {
    if let Some(value) = secret_tool_lookup("identity")? {
        let record: IdentityRecord = serde_json::from_str(&value)?;
        let mut seed = STANDARD.decode(record.seed_b64)?;
        let secret: [u8; 32] = seed.as_slice().try_into()
            .map_err(|_| "stored Ed25519 seed is not 32 bytes")?;
        seed.fill(0);
        return Ok(LocalIdentity::from_secret(record.device_id, secret));
    }

    let identity = LocalIdentity::generate();
    let seed = identity.secret_bytes();
    let record = IdentityRecord {
        device_id: identity.device_id,
        seed_b64: STANDARD.encode(seed),
    };
    secret_tool_store("identity", "TomOS Transfer device identity", &serde_json::to_string(&record)?)?;
    Ok(identity)
}

fn load_or_create_tls_identity() -> Result<DeviceTlsIdentity, Box<dyn Error>> {
    if let Some(value) = secret_tool_lookup("tls-identity")? {
        let record: TlsRecord = serde_json::from_str(&value)?;
        return Ok(DeviceTlsIdentity::from_der(
            STANDARD.decode(record.certificate_b64)?,
            STANDARD.decode(record.private_key_b64)?,
        ));
    }

    let tls = DeviceTlsIdentity::generate()?;
    let record = TlsRecord {
        certificate_b64: STANDARD.encode(&tls.certificate_der),
        private_key_b64: STANDARD.encode(tls.private_key_der()),
    };
    secret_tool_store(
        "tls-identity",
        "TomOS Transfer TLS private identity",
        &serde_json::to_string(&record)?,
    )?;
    Ok(tls)
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N]: ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).is_ok()
        && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm_peer(peer: &PublicIdentity) -> bool {
    println!(
        "\nIncoming device pairing request\nDevice ID: {}\nPublic key: {}",
        peer.device_id,
        peer.public_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
    );
    confirm("Trust and pair with this device?")
}

async fn send_file(
    invitation_payload: &str,
    source_path: &Path,
    remote_name: &str,
    transfer_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let invitation = PairingInvitation::parse_qr_payload(invitation_payload)?;
    let identity = load_or_create_identity()?;
    println!("Sending {} to {}…", source_path.display(), invitation.identity.device_id);
    connect_and_send_with_id(
        &invitation,
        &identity,
        source_path,
        remote_name,
        transfer_id,
        |progress| {
            eprint!("\rSent {} / {} bytes", progress.bytes_received, progress.total_bytes);
            let _ = io::stderr().flush();
        },
    ).await?;
    eprintln!("\nTransfer complete. Transfer ID: {transfer_id}");
    Ok(())
}

async fn receive_files(
    advertised_host: &str,
    destination: PathBuf,
) -> Result<(), Box<dyn Error>> {
    let identity = load_or_create_identity()?;
    let tls = load_or_create_tls_identity()?;
    let acceptor = tls.server_acceptor()?;
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();

    let invitation = PairingInvitation::create(
        identity.public_identity(),
        advertised_host.to_owned(),
        port,
        tls.fingerprint.clone(),
        tls.certificate_der.clone(),
        600,
    )?;
    let payload = invitation.to_qr_payload()?;
    let qr = invitation.qr_code()?;

    println!("\nTomOS Transfer is ready to receive.");
    println!("Advertised address: {advertised_host}:{port}");
    println!("Scan this QR code from the sending device:\n");
    println!("{}", qr.render::<char>().quiet_zone(true).build());
    println!("Pairing payload (manual copy fallback):\n{payload}\n");
    println!("Waiting for an authenticated sender…");

    let state_dir = destination.join(".tomos-transfer-state");
    let token_guard = OneTimePairingToken::from_invitation(&invitation);
    let (_, result) = accept_one_resumable(
        &listener,
        &acceptor,
        &identity,
        &token_guard,
        &destination,
        &state_dir,
        |peer| {
            let peer = peer.clone();
            async move {
                tokio::task::spawn_blocking(move || confirm_peer(&peer))
                    .await
                    .unwrap_or(false)
            }
        },
        |name, size, checksum| {
            println!(
                "\nIncoming file: {name}\nSize: {size} bytes\nSHA-256: {checksum}"
            );
            confirm("Accept this file?")
        },
        |progress| {
            eprint!(
                "\rReceived {} / {} bytes",
                progress.bytes_received, progress.total_bytes
            );
            let _ = io::stderr().flush();
        },
    ).await?;

    println!(
        "\nReceived {} bytes successfully: {}",
        result.bytes_received,
        result.path.display()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("send") if args.len() >= 4 => {
            let source = PathBuf::from(&args[3]);
            let name = args.get(4).map(String::as_str)
                .or_else(|| source.file_name().and_then(|name| name.to_str()))
                .ok_or("could not determine remote file name")?;
            let transfer_id = match args.get(5) {
                Some(value) => Uuid::parse_str(value)?,
                None => Uuid::new_v4(),
            };
            send_file(&args[2], &source, name, transfer_id).await
        }
        Some("receive") if args.len() >= 4 => {
            receive_files(&args[2], PathBuf::from(&args[3])).await
        }
        _ => {
            eprintln!(
                "TomOS Transfer Linux client\n\n\
                 Usage:\n\
                 tomos-transfer receive <advertised-host-or-ip> <destination-directory>\n\
                 tomos-transfer send <pairing-qr-payload> <file> [remote-name] [transfer-id]\n\n\
                 Requires a logged-in desktop Secret Service and the secret-tool utility."
            );
            Err("invalid command line".into())
        }
    }
}
