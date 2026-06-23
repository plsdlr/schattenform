#![feature(mapped_lock_guards)]

mod pod;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use pod2::{
    frontend::SerializedMainPod,
    middleware::Params,
};
use serde::{Deserialize, Serialize};
use tower_http::services::{ServeDir, ServeFile};
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::pod::{create_genesis, state_to_json, write_step, Participant};

fn parse_args() -> bool {
    // Returns `mock` flag: true = MockProver (default), false = real Plonky2 prover.
    !std::env::args().any(|a| a == "--real-proofs")
}

// ── Threading ─────────────────────────────────────────────────────────────────

// pod2's sparse Merkle tree recurses up to 256 levels per Dict operation.
// tokio's spawn_blocking pool uses std::thread with the default stack (~2 MB),
// which thread_stack_size() on the runtime builder does NOT affect.
// We spawn explicit threads so the stack size is guaranteed.
const POD_STACK_SIZE: usize = 64 * 1024 * 1024;

async fn run_pod<F, T>(f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new()
        .name("run_pod".to_string())
        .stack_size(POD_STACK_SIZE)
        .spawn(move || { let _ = tx.send(f()); })
        .map_err(|e| anyhow::anyhow!("thread spawn failed: {e}"))?;
    rx.await.map_err(|_| anyhow::anyhow!("pod thread panicked"))?
}

// ── Shared application state ──────────────────────────────────────────────────

struct AppState {
    params: Params,
    mock: bool,
    current_state: Option<pod2::frontend::SignedDict>,
    participants: HashMap<String, Participant>,
    history: Vec<HistoryEntry>,
}

impl AppState {
    fn new(mock: bool) -> Self {
        Self {
            params: Params::default(),
            mock,
            current_state: None,
            participants: HashMap::new(),
            history: Vec::new(),
        }
    }
}

type SharedState = Arc<Mutex<AppState>>;

// ── API types ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterReq {
    name: String,
}

#[derive(Serialize)]
struct RegisterResp {
    name: String,
    public_key: String,
}

#[derive(Deserialize)]
struct GenesisReq {
    fields: HashMap<String, i64>,
    first_writer: String,
}

#[derive(Serialize)]
struct GenesisResp {
    state: serde_json::Value,
    first_writer: String,
}

#[derive(Deserialize)]
struct WriteReq {
    writer: String,
    next_writer: String,
    updates: HashMap<String, i64>,
}

#[derive(Serialize, Clone)]
struct HistoryEntry {
    version: i64,
    writer: String,
    next_writer: String,
    updates: HashMap<String, i64>,
    proof: SerializedMainPod,
    state: serde_json::Value,
}

#[derive(Serialize)]
struct WriteResp {
    proof: SerializedMainPod,
    state: serde_json::Value,
    version: i64,
}

#[derive(Serialize)]
struct ParticipantInfo {
    name: String,
    public_key: String,
}

#[derive(Serialize)]
struct StatusResp {
    has_genesis: bool,
    current_version: Option<i64>,
    current_writer: Option<String>,
    participants: Vec<String>,
    history_len: usize,
    current_state: Option<serde_json::Value>,
}

// ── Handler helpers ───────────────────────────────────────────────────────────

fn seed_participants(app: &mut AppState) {
    for name in ["alice", "bob", "charlie"] {
        app.participants.entry(name.to_string()).or_insert_with(Participant::new);
    }
}

fn current_writer_name(app: &AppState) -> Option<String> {
    let state = app.current_state.as_ref()?;
    let writer_pk_val = state.dict.get(&"writer_pk".into()).ok()??;
    for (name, p) in &app.participants {
        if pod2::middleware::Value::from(p.pk) == writer_pk_val {
            return Some(name.clone());
        }
    }
    None
}

fn internal_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    let msg = e.to_string();
    error!("{}", msg);
    (StatusCode::INTERNAL_SERVER_ERROR, msg)
}

fn bad_req(msg: impl Into<String>) -> (StatusCode, String) {
    let msg = msg.into();
    error!("{}", msg);
    (StatusCode::BAD_REQUEST, msg)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_register(
    State(shared): State<SharedState>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    info!("POST /api/register  name={}", req.name);
    let p = Participant::new();
    let pk_str = format!("{:?}", p.pk);
    shared.lock().unwrap().participants.insert(req.name.clone(), p);
    let resp = RegisterResp { name: req.name.clone(), public_key: pk_str.clone() };
    info!("  → registered {} pk={}", req.name, pk_str);
    Json(resp)
}

async fn handle_genesis(
    State(shared): State<SharedState>,
    Json(req): Json<GenesisReq>,
) -> Result<Json<GenesisResp>, (StatusCode, String)> {
    info!("POST /api/genesis  first_writer={} fields={:?}", req.first_writer, req.fields);

    // Validate and extract what we need, then drop the lock before the crypto work
    let (params, first_pk) = {
        let app = shared.lock().unwrap();
        if app.current_state.is_some() {
            return Err(bad_req("genesis already exists — call /api/reset first"));
        }
        let first_pk = app
            .participants
            .get(&req.first_writer)
            .map(|p| p.pk)
            .ok_or_else(|| bad_req(format!("unknown participant: {}", req.first_writer)))?;
        (app.params.clone(), first_pk)
    };

    let fields = req.fields.clone();
    let first_writer = req.first_writer.clone();

    let state = run_pod(move || create_genesis(&params, &fields, first_pk))
        .await
        .map_err(|e| internal_err(e))?;

    let state_json = state_to_json(&state);
    shared.lock().unwrap().current_state = Some(state);

    info!("  → genesis created  first_writer={} state={}", first_writer, state_json);
    Ok(Json(GenesisResp { state: state_json, first_writer }))
}

async fn handle_write(
    State(shared): State<SharedState>,
    Json(req): Json<WriteReq>,
) -> Result<Json<WriteResp>, (StatusCode, String)> {
    info!("POST /api/write  writer={} next={} updates={:?}", req.writer, req.next_writer, req.updates);

    // Only cheap ops on the tokio thread: HashMap lookups and string comparisons.
    // current_state.clone() is intentionally NOT done here — cloning the sparse
    // Merkle tree is recursive and overflows the 2 MB tokio worker stack.
    let (params, writer_sk, next_pk) = {
        let app = shared.lock().unwrap();

        let expected = current_writer_name(&app); // dict.get() only — safe
        if expected.as_deref() != Some(req.writer.as_str()) {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "baton held by {}, not {}",
                    expected.as_deref().unwrap_or("nobody"),
                    req.writer
                ),
            ));
        }

        let writer_sk = app
            .participants
            .get(&req.writer)
            .map(|p| p.sk.clone())
            .ok_or_else(|| bad_req(format!("unknown participant: {}", req.writer)))?;

        let next_pk = app
            .participants
            .get(&req.next_writer)
            .map(|p| p.pk)
            .ok_or_else(|| bad_req(format!("unknown participant: {}", req.next_writer)))?;

        (app.params.clone(), writer_sk, next_pk)
    };

    let updates = req.updates.clone();
    let writer = req.writer.clone();
    let next_writer = req.next_writer.clone();
    let writer_log = writer.clone();
    let next_writer_log = next_writer.clone();
    let shared2 = shared.clone();

    // Everything Dict-touching runs on the large-stack thread:
    // clone, write_step, version lookup, state_to_json, history push.
    let (serialized_proof, version, state_json) = run_pod(move || {
        info!("  [run_pod] cloning prev_state");
        let prev_state = shared2
            .lock()
            .unwrap()
            .current_state
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no genesis yet"))?;

        let mock = shared2.lock().unwrap().mock;
        info!("  [run_pod] calling write_step (mock={})", mock);
        let (proof, new_state) = write_step(&params, &prev_state, writer_sk, next_pk, &updates, mock)?;
        info!("  [run_pod] write_step returned");

        info!("  [run_pod] extracting version from new_state");
        let version: i64 = new_state
            .dict
            .get(&"version".into())
            .ok()
            .flatten()
            .and_then(|v| v.as_int())
            .unwrap_or(0);
        info!("  [run_pod] version={}", version);

        info!("  [run_pod] state_to_json");
        let state_json = state_to_json(&new_state);
        info!("  [run_pod] state_to_json done");

        info!("  [run_pod] SerializedMainPod::from(proof)");
        let serialized_proof = SerializedMainPod::from(proof);
        info!("  [run_pod] serialization done");

        info!("  [run_pod] updating shared state");
        {
            let mut app = shared2.lock().unwrap();
            app.history.push(HistoryEntry {
                version,
                writer: writer.clone(),
                next_writer: next_writer.clone(),
                updates: updates.clone(),
                proof: serialized_proof.clone(),
                state: state_json.clone(),
            });
            app.current_state = Some(new_state);
        }
        info!("  [run_pod] shared state updated");

        Ok((serialized_proof, version, state_json))
    })
    .await
    .map_err(|e| internal_err(e))?;

    info!("  → write done  version={} writer={} next={}", version, writer_log, next_writer_log);
    Ok(Json(WriteResp { proof: serialized_proof, state: state_json, version }))
}

async fn handle_status(State(shared): State<SharedState>) -> Json<StatusResp> {
    let (has_genesis, current_version, current_writer, participants, history_len, state_snap) = {
        let app = shared.lock().unwrap();
        let current_version = app.current_state.as_ref().and_then(|s| {
            s.dict.get(&"version".into()).ok()?.and_then(|v| v.as_int())
        });
        (
            app.current_state.is_some(),
            current_version,
            current_writer_name(&app),
            app.participants.keys().cloned().collect::<Vec<_>>(),
            app.history.len(),
            app.current_state.clone(),
        )
    };
    let current_state = match state_snap {
        Some(snap) => run_pod(move || Ok(state_to_json(&snap))).await.ok(),
        None => None,
    };
    Json(StatusResp { has_genesis, current_version, current_writer, participants, history_len, current_state })
}

async fn handle_participants(State(shared): State<SharedState>) -> Json<Vec<ParticipantInfo>> {
    let app = shared.lock().unwrap();
    let mut list: Vec<ParticipantInfo> = app.participants.iter().map(|(name, p)| {
        ParticipantInfo {
            name: name.clone(),
            public_key: format!("{}", pod2::middleware::Value::from(p.pk)),
        }
    }).collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    Json(list)
}

async fn handle_history(State(shared): State<SharedState>) -> Json<Vec<HistoryEntry>> {
    let history = shared.lock().unwrap().history.clone();
    Json(history)
}

async fn handle_reset(State(shared): State<SharedState>) -> Json<serde_json::Value> {
    info!("POST /api/reset");
    let mock = shared.lock().unwrap().mock;
    let mut fresh = AppState::new(mock);
    seed_participants(&mut fresh);
    *shared.lock().unwrap() = fresh;
    info!("  → state cleared, participants re-seeded");
    Json(serde_json::json!({ "ok": true }))
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let mock = parse_args();

    rayon::ThreadPoolBuilder::new()
        .stack_size(POD_STACK_SIZE)
        .build_global()
        .expect("failed to configure rayon thread pool");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if mock {
        tracing::info!("Prover mode: MockProver (instant, no real ZK) — pass --real-proofs for the real Plonky2 prover");
    } else {
        tracing::info!("Prover mode: Plonky2 (real ZK proofs, slow) — prebuilding circuits on first write...");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(mock));
}

async fn run(mock: bool) {
    let shared = {
        let mut app = AppState::new(mock);
        seed_participants(&mut app);
        Arc::new(Mutex::new(app))
    };

    let app = Router::new()
        .route("/api/register",     post(handle_register))
        .route("/api/genesis",      post(handle_genesis))
        .route("/api/write",        post(handle_write))
        .route("/api/status",       get(handle_status))
        .route("/api/history",      get(handle_history))
        .route("/api/participants",  get(handle_participants))
        .route("/api/reset",        post(handle_reset))
        .route_service("/alice",    ServeFile::new("static/wallet.html"))
        .route_service("/bob",      ServeFile::new("static/wallet.html"))
        .route_service("/charlie",  ServeFile::new("static/wallet.html"))
        .fallback_service(ServeDir::new("static"))
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    info!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
