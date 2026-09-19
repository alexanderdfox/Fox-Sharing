//! Fox Sharing
//!
//! A modern, secure, simple network file-sharing system inspired by the Aether design.
//! Single binary that acts as both server and client.
//!
//! Features in this prototype:
//! - Async TCP + length-prefixed binary framing (bincode)
//! - Password authentication (SHA-256)
//! - Operations: LIST, STAT, READ, WRITE, MKDIR, DELETE, RENAME, PING
//! - Path sanitization (no traversal)
//! - Structured logging + clap CLI
//!
//! Future evolution: replace TCP framing with QUIC, add mandatory TLS 1.3,
//! leases/delegations, multichannel, RDMA, capability tokens, etc.
//!
//! Examples:
//!   cargo run --release -- server --port 4242 --root ./share --password "s3cret"
//!   cargo run --release -- client --addr 127.0.0.1:4242 --password "s3cret" ls /
//!   cargo run --release -- client --addr 127.0.0.1:4242 --password "s3cret" get /file.txt ./local.txt
//!   cargo run --release -- client --addr 127.0.0.1:4242 --password "s3cret" put ./local.txt /remote.txt

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn, Level};

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

const PROTOCOL_MAGIC: u32 = 0x464F5853; // "FOXS"
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Auth { password_hash: String },
    List { path: String },
    Stat { path: String },
    Read { path: String, offset: u64, length: u64 },
    Write {
        path: String,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    },
    Mkdir { path: String },
    Delete { path: String },
    Rename { from: String, to: String },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Ok,
    AuthOk { session_id: String },
    AuthFail,
    Error { message: String },
    List { entries: Vec<DirEntry> },
    Stat { entry: DirEntry },
    Read { data: Vec<u8>, eof: bool },
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

async fn write_frame<T: Serialize>(stream: &mut TcpStream, msg: &T) -> Result<()> {
    let payload = bincode::serialize(msg).context("serialize")?;
    if payload.len() > MAX_FRAME_SIZE {
        bail!("frame too large");
    }
    let mut header = [0u8; 8];
    header[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_be_bytes());
    header[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await.context("read header")?;
    let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
    if magic != PROTOCOL_MAGIC {
        bail!("invalid protocol magic");
    }
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if len > MAX_FRAME_SIZE {
        bail!("frame too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.context("read payload")?;
    bincode::deserialize(&buf).context("deserialize")
}

// ---------------------------------------------------------------------------
// Path safety
// ---------------------------------------------------------------------------

fn sanitize_path(root: &Path, requested: &str) -> Result<PathBuf> {
    let req = Path::new(requested);
    if req.is_absolute() {
        bail!("absolute paths are not allowed");
    }
    for component in req.components() {
        match component {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            _ => bail!("illegal path component: {:?}", component),
        }
    }
    let full = root.join(req);
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    if full.exists() {
        let canonical = full.canonicalize().context("canonicalize")?;
        if !canonical.starts_with(&canonical_root) {
            bail!("path traversal detected");
        }
        Ok(canonical)
    } else {
        if let Some(parent) = full.parent() {
            if parent.exists() {
                let can_parent = parent.canonicalize().context("canonicalize parent")?;
                if !can_parent.starts_with(&canonical_root) {
                    bail!("path traversal detected");
                }
            }
        }
        Ok(full)
    }
}

fn make_entry(root: &Path, full: &Path) -> Result<DirEntry> {
    let meta = std::fs::metadata(full).context("metadata")?;
    let rel = full.strip_prefix(root).unwrap_or(full);
    let modified = meta.modified().ok().map(DateTime::<Utc>::from);
    let created = meta.created().ok().map(DateTime::<Utc>::from);
    Ok(DirEntry {
        name: full
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "/".into()),
        path: rel.to_string_lossy().into_owned(),
        is_dir: meta.is_dir(),
        size: meta.len(),
        modified,
        created,
    })
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct ServerState {
    root: PathBuf,
    password_hash: String,
}

fn hash_password(pw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pw.as_bytes());
    hex::encode(hasher.finalize())
}

async fn handle_client(mut stream: TcpStream, state: Arc<ServerState>) -> Result<()> {
    let peer = stream.peer_addr().ok();
    info!(?peer, "new connection");

    // First message must be Auth
    let req: Request = read_frame(&mut stream).await?;
    match req {
        Request::Auth { password_hash } => {
            if password_hash == state.password_hash {
                let session_id = hex::encode(rand::random::<[u8; 16]>());
                write_frame(&mut stream, &Response::AuthOk { session_id }).await?;
                info!(?peer, "authenticated");
            } else {
                write_frame(&mut stream, &Response::AuthFail).await?;
                warn!(?peer, "authentication failed");
                return Ok(());
            }
        }
        _ => {
            write_frame(
                &mut stream,
                &Response::Error {
                    message: "first message must be Auth".into(),
                },
            )
            .await?;
            return Ok(());
        }
    }

    // Request loop
    loop {
        let req: Request = match read_frame(&mut stream).await {
            Ok(r) => r,
            Err(e) => {
                info!(?peer, "connection closed: {}", e);
                break;
            }
        };

        let response = match process_request(&state, req).await {
            Ok(r) => r,
            Err(e) => Response::Error {
                message: e.to_string(),
            },
        };

        if let Err(e) = write_frame(&mut stream, &response).await {
            error!(?peer, "write failed: {}", e);
            break;
        }
    }
    Ok(())
}

async fn process_request(state: &ServerState, req: Request) -> Result<Response> {
    match req {
        Request::Auth { .. } => Ok(Response::Error {
            message: "already authenticated".into(),
        }),
        Request::Ping => Ok(Response::Pong),
        Request::List { path } => {
            let full = sanitize_path(&state.root, &path)?;
            if !full.is_dir() {
                bail!("not a directory");
            }
            let mut entries = Vec::new();
            let mut rd = fs::read_dir(&full).await?;
            while let Some(ent) = rd.next_entry().await? {
                if let Ok(entry) = make_entry(&state.root, &ent.path()) {
                    entries.push(entry);
                }
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(Response::List { entries })
        }
        Request::Stat { path } => {
            let full = sanitize_path(&state.root, &path)?;
            let entry = make_entry(&state.root, &full)?;
            Ok(Response::Stat { entry })
        }
        Request::Read { path, offset, length } => {
            let full = sanitize_path(&state.root, &path)?;
            if !full.is_file() {
                bail!("not a file");
            }
            let mut file = fs::File::open(&full).await?;
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; length.min(8 * 1024 * 1024) as usize];
            let n = file.read(&mut buf).await?;
            buf.truncate(n);
            let eof = (offset + n as u64) >= fs::metadata(&full).await?.len();
            Ok(Response::Read { data: buf, eof })
        }
        Request::Write {
            path,
            offset,
            data,
            create,
            truncate,
        } => {
            let full = sanitize_path(&state.root, &path)?;
            if let Some(parent) = full.parent() {
                let _ = fs::create_dir_all(parent).await;
            }
            let mut opts = fs::OpenOptions::new();
            opts.write(true);
            if create {
                opts.create(true);
            }
            if truncate {
                opts.truncate(true);
            }
            let mut file = opts.open(&full).await.context("open for write")?;
            use tokio::io::AsyncSeekExt;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            file.write_all(&data).await?;
            file.flush().await?;
            Ok(Response::Ok)
        }
        Request::Mkdir { path } => {
            let full = sanitize_path(&state.root, &path)?;
            fs::create_dir_all(&full).await?;
            Ok(Response::Ok)
        }
        Request::Delete { path } => {
            let full = sanitize_path(&state.root, &path)?;
            if full.is_dir() {
                fs::remove_dir(&full).await?;
            } else {
                fs::remove_file(&full).await?;
            }
            Ok(Response::Ok)
        }
        Request::Rename { from, to } => {
            let src = sanitize_path(&state.root, &from)?;
            let dst = sanitize_path(&state.root, &to)?;
            fs::rename(&src, &dst).await?;
            Ok(Response::Ok)
        }
    }
}

async fn run_server(port: u16, root: PathBuf, password: String) -> Result<()> {
    let root = root.canonicalize().context("canonicalize root")?;
    info!(?root, "serving directory");

    let state = Arc::new(ServerState {
        root,
        password_hash: hash_password(&password),
    });

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!("Fox Sharing server listening on 0.0.0.0:{}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, state).await {
                error!("client error: {:#}", e);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Client {
    stream: TcpStream,
}

impl Client {
    async fn connect(addr: &str, password: &str) -> Result<Self> {
        let mut stream = TcpStream::connect(addr).await.context("connect")?;
        let password_hash = hash_password(password);
        write_frame(&mut stream, &Request::Auth { password_hash }).await?;
        let resp: Response = read_frame(&mut stream).await?;
        match resp {
            Response::AuthOk { session_id } => {
                info!("authenticated, session {}", session_id);
                Ok(Client { stream })
            }
            Response::AuthFail => bail!("authentication failed"),
            Response::Error { message } => bail!("auth error: {}", message),
            _ => bail!("unexpected auth response"),
        }
    }

    async fn request(&mut self, req: Request) -> Result<Response> {
        write_frame(&mut self.stream, &req).await?;
        read_frame(&mut self.stream).await
    }

    async fn list(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        match self.request(Request::List { path: path.into() }).await? {
            Response::List { entries } => Ok(entries),
            Response::Error { message } => bail!("{}", message),
            _ => bail!("unexpected response"),
        }
    }

    async fn stat(&mut self, path: &str) -> Result<DirEntry> {
        match self.request(Request::Stat { path: path.into() }).await? {
            Response::Stat { entry } => Ok(entry),
            Response::Error { message } => bail!("{}", message),
            _ => bail!("unexpected response"),
        }
    }

    async fn read_file(&mut self, remote: &str, local: &Path) -> Result<()> {
        let mut offset = 0u64;
        let mut file = fs::File::create(local).await?;
        loop {
            let resp = self
                .request(Request::Read {
                    path: remote.into(),
                    offset,
                    length: 4 * 1024 * 1024,
                })
                .await?;
            match resp {
                Response::Read { data, eof } => {
                    if data.is_empty() && eof {
                        break;
                    }
                    file.write_all(&data).await?;
                    offset += data.len() as u64;
                    if eof {
                        break;
                    }
                }
                Response::Error { message } => bail!("{}", message),
                _ => bail!("unexpected response"),
            }
        }
        file.flush().await?;
        Ok(())
    }

    async fn write_file(&mut self, local: &Path, remote: &str) -> Result<()> {
        let meta = fs::metadata(local).await?;
        let mut file = fs::File::open(local).await?;
        let mut offset = 0u64;
        let mut first = true;
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let resp = self
                .request(Request::Write {
                    path: remote.into(),
                    offset,
                    data: buf[..n].to_vec(),
                    create: first,
                    truncate: first,
                })
                .await?;
            match resp {
                Response::Ok => {}
                Response::Error { message } => bail!("{}", message),
                _ => bail!("unexpected response"),
            }
            offset += n as u64;
            first = false;
        }
        if meta.len() == 0 {
            let _ = self
                .request(Request::Write {
                    path: remote.into(),
                    offset: 0,
                    data: vec![],
                    create: true,
                    truncate: true,
                })
                .await?;
        }
        Ok(())
    }

    async fn mkdir(&mut self, path: &str) -> Result<()> {
        match self.request(Request::Mkdir { path: path.into() }).await? {
            Response::Ok => Ok(()),
            Response::Error { message } => bail!("{}", message),
            _ => bail!("unexpected response"),
        }
    }

    async fn delete(&mut self, path: &str) -> Result<()> {
        match self.request(Request::Delete { path: path.into() }).await? {
            Response::Ok => Ok(()),
            Response::Error { message } => bail!("{}", message),
            _ => bail!("unexpected response"),
        }
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        match self
            .request(Request::Rename {
                from: from.into(),
                to: to.into(),
            })
            .await?
        {
            Response::Ok => Ok(()),
            Response::Error { message } => bail!("{}", message),
            _ => bail!("unexpected response"),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "fox-sharing", about = "Fox Sharing – modern network file sharing", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the Fox Sharing server
    Server {
        #[arg(short, long, default_value = "4242")]
        port: u16,
        #[arg(short, long, default_value = ".")]
        root: PathBuf,
        #[arg(short, long)]
        password: String,
    },
    /// Run a client command
    Client {
        #[arg(short, long, default_value = "127.0.0.1:4242")]
        addr: String,
        #[arg(short, long)]
        password: String,
        #[command(subcommand)]
        action: ClientAction,
    },
}

#[derive(Subcommand, Debug)]
enum ClientAction {
    Ls { #[arg(default_value = "/")] path: String },
    Stat { path: String },
    Get { remote: String, local: PathBuf },
    Put { local: PathBuf, remote: String },
    Mkdir { path: String },
    Rm { path: String },
    Mv { from: String, to: String },
    Ping,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port, root, password } => {
            run_server(port, root, password).await?;
        }
        Commands::Client { addr, password, action } => {
            let mut client = Client::connect(&addr, &password).await?;
            match action {
                ClientAction::Ls { path } => {
                    let entries = client.list(&path).await?;
                    for e in entries {
                        let kind = if e.is_dir { "DIR " } else { "FILE" };
                        let size = if e.is_dir {
                            "-".to_string()
                        } else {
                            e.size.to_string()
                        };
                        println!("{:<5} {:>12}  {}", kind, size, e.path);
                    }
                }
                ClientAction::Stat { path } => {
                    let e = client.stat(&path).await?;
                    println!("Path     : {}", e.path);
                    println!("Name     : {}", e.name);
                    println!("Type     : {}", if e.is_dir { "directory" } else { "file" });
                    println!("Size     : {}", e.size);
                    if let Some(m) = e.modified {
                        println!("Modified : {}", m);
                    }
                    if let Some(c) = e.created {
                        println!("Created  : {}", c);
                    }
                }
                ClientAction::Get { remote, local } => {
                    info!("downloading {} → {:?}", remote, local);
                    client.read_file(&remote, &local).await?;
                    println!("OK");
                }
                ClientAction::Put { local, remote } => {
                    info!("uploading {:?} → {}", local, remote);
                    client.write_file(&local, &remote).await?;
                    println!("OK");
                }
                ClientAction::Mkdir { path } => {
                    client.mkdir(&path).await?;
                    println!("OK");
                }
                ClientAction::Rm { path } => {
                    client.delete(&path).await?;
                    println!("OK");
                }
                ClientAction::Mv { from, to } => {
                    client.rename(&from, &to).await?;
                    println!("OK");
                }
                ClientAction::Ping => match client.request(Request::Ping).await? {
                    Response::Pong => println!("PONG"),
                    other => println!("{:?}", other),
                },
            }
        }
    }
    Ok(())
}