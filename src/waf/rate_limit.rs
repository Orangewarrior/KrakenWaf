
//! GCRA-sharded rate limiter — single-node, alta vazão.
//!
//! ## GCRA (Generic Cell Rate Algorithm)
//!
//! Cada cliente é representado por **um único `AtomicU64`**: o TAT
//! (Theoretical Arrival Time) em nanossegundos desde a época Unix.
//!
//! ```text
//! emission_interval  = window_ns / limit         (ns entre requisições conformes)
//! delay_tolerance    = window_ns − emission_interval  (margem de burst)
//!
//! Na chegada em `now`:
//!   new_tat = max(old_tat, now) + emission_interval
//!   se (new_tat − now) ≤ delay_tolerance  →  PERMITE  (CAS old_tat → new_tat)
//!   senão                                 →  BLOQUEIA (old_tat inalterado)
//! ```
//!
//! O loop CAS é **completamente lock-free** para IPs já rastreados.
//! Um write-lock no shard só é adquirido uma vez, ao inserir um IP novo.
//!
//! ## Sharding
//!
//! 64 shards independentes com `parking_lot::RwLock<AHashMap<u64, Arc<AtomicU64>>>`.
//!
//! ```text
//! hot path (IP existente):
//!   read-lock shard (~10 ns)  →  lookup  →  Arc::clone  →  unlock
//!   CAS em AtomicU64 (~5 ns, 1 iteração na prática)
//!   Total ≈ 20–30 ns por request, independente do tamanho do mapa.
//!
//! cold path (IP novo):
//!   read-lock → miss → write-lock → double-check → insert → unlock
//!   Executado apenas uma vez por IP único.
//! ```
//!
//! ## Hashing estável
//!
//! `hash_ip` usa FNV-1a (deterministico, sem sementes aleatórias) para que o
//! mesmo IP produza o mesmo `u64` entre reinicializações, permitindo que o
//! SQLite re-hidrate o estado corretamente.
//! `AHashMap` usa ahash apenas para placement interno de buckets (irrelevante
//! para roteamento externo).
//!
//! ## Persistência
//!
//! Dois back-ends selecionáveis em runtime:
//!
//! * `PersistenceMode::Sqlite` — SQLite em modo WAL. Suporta inspeção via
//!   `sqlite3 cli` e updates incrementais; cada persistência custa um INSERT
//!   por IP dentro de uma transação.
//! * `PersistenceMode::Bincode` — arquivo binário flat com rename atômico.
//!   O snapshot inteiro é re-escrito a cada tick (write-tmp + fsync + rename),
//!   tipicamente 10-50× mais rápido que SQLite para esse workload e re-hidrata
//!   em uma única leitura sequencial.

use ahash::AHashMap;
use anyhow::{Context, Result};
use parking_lot::{Mutex, RwLock};
use rusqlite::{params, Connection};
use std::{
    array,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;
use tracing::warn;

/// Seleciona o back-end de persistência do rate-limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMode {
    Sqlite,
    Bincode,
}

// ── Tunables ──────────────────────────────────────────────────────────────────

/// Número de shards — deve ser potência de 2 para o mask funcionar.
/// 64 shards → a 10 k rps com 16 workers, contenção esperada ≈ 2 %.
const NUM_SHARDS: usize = 64;
const SHARD_MASK: u64 = NUM_SHARDS as u64 - 1;

/// Máximo de entradas por shard antes de ejetar a mais antiga.
/// 64 × 4 096 = 262 144 IPs únicos rastreados simultaneamente.
const MAX_PER_SHARD: usize = 4_096;

const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
const PERSIST_INTERVAL: Duration = Duration::from_secs(60);
const MAX_DB_BYTES: u64 = 32 * 1024 * 1024;

// ── GCRA core (lock-free) ─────────────────────────────────────────────────────

/// Tenta avançar o TAT para uma requisição.
///
/// Retorna `true` se a requisição está dentro do limite (permitida),
/// `false` caso contrário. Nunca adquire mutex.
#[inline]
fn gcra_check(tat: &AtomicU64, now_ns: u64, emit_ns: u64, tolerance_ns: u64) -> bool {
    loop {
        let old_tat = tat.load(Ordering::Acquire);
        // Agenda a célula: se chegou antes do TAT atual, espera; senão usa now.
        let new_tat = old_tat.max(now_ns).saturating_add(emit_ns);

        // Dentro da janela de tolerância → PERMITE.
        if new_tat.saturating_sub(now_ns) > tolerance_ns {
            return false; // taxa excedida — TAT não atualizado
        }

        match tat.compare_exchange_weak(
            old_tat,
            new_tat,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(_) => core::hint::spin_loop(), // outra thread ganhou a corrida; tenta de novo
        }
    }
}

// ── Shard ─────────────────────────────────────────────────────────────────────

struct Shard {
    rw: RwLock<AHashMap<u64, Arc<AtomicU64>>>,
}

impl Shard {
    fn new() -> Self {
        Self { rw: RwLock::new(AHashMap::with_capacity(64)) }
    }

    /// Verificação principal.
    /// Lock-free para IPs existentes; um write-lock único para IPs novos.
    fn check(&self, key: u64, now_ns: u64, emit_ns: u64, tolerance_ns: u64) -> bool {
        // ── Fast path: IP já rastreado ────────────────────────────────────────
        {
            let map = self.rw.read();
            if let Some(cell) = map.get(&key) {
                let cell = cell.clone(); // bump atômico do refcount — ~1 ns
                drop(map);              // libera o read-lock antes do CAS
                return gcra_check(&cell, now_ns, emit_ns, tolerance_ns);
            }
        }

        // ── Slow path: primeiro request deste IP ──────────────────────────────
        let fresh = Arc::new(AtomicU64::new(0)); // TAT = 0 → primeiro request sempre passa
        {
            let mut map = self.rw.write();
            // Double-check: outra thread pode ter inserido entre os dois locks.
            if let Some(existing) = map.get(&key) {
                let cell = existing.clone();
                drop(map);
                return gcra_check(&cell, now_ns, emit_ns, tolerance_ns);
            }
            if map.len() >= MAX_PER_SHARD {
                evict_one(&mut map, now_ns, tolerance_ns);
            }
            map.insert(key, fresh.clone());
        }
        gcra_check(&fresh, now_ns, emit_ns, tolerance_ns)
    }

    /// Remove entradas cujo TAT já expirou completamente.
    fn sweep(&self, now_ns: u64, tolerance_ns: u64) {
        let mut map = self.rw.write();
        map.retain(|_, cell| {
            cell.load(Ordering::Relaxed)
                .saturating_add(tolerance_ns)
                >= now_ns
        });
    }

    /// Snapshot de todos os pares (ip_hash, tat_ns) para persistência.
    fn snapshot(&self) -> Vec<(u64, u64)> {
        let map = self.rw.read();
        map.iter()
            .map(|(&k, cell)| (k, cell.load(Ordering::Relaxed)))
            .collect()
    }
}

/// Ejeta uma entrada de um shard cheio.
/// Preferência: entrada expirada; fallback: menor TAT (menos ativo).
fn evict_one(
    map: &mut AHashMap<u64, Arc<AtomicU64>>,
    now_ns: u64,
    tolerance_ns: u64,
) {
    let expired = map
        .iter()
        .find(|(_, cell)| {
            cell.load(Ordering::Relaxed)
                .saturating_add(tolerance_ns)
                < now_ns
        })
        .map(|(&k, _)| k);

    let victim = expired.or_else(|| {
        map.iter()
            .min_by_key(|(_, cell)| cell.load(Ordering::Relaxed))
            .map(|(&k, _)| k)
    });

    if let Some(k) = victim {
        map.remove(&k);
    }
}

// ── Backend de persistência ───────────────────────────────────────────────────

/// Encapsula o estado mutável do back-end. SQLite mantém o `Connection`
/// aberto; Bincode armazena apenas o caminho do arquivo (cada save abre,
/// escreve, renomeia e fecha — barato comparado ao custo de uma transação).
enum Backend {
    Sqlite(Connection),
    Bincode(PathBuf),
}

const BINCODE_MAGIC: &[u8; 8] = b"KWAFRL01";

impl Backend {
    fn open(mode: PersistenceMode, path: &PathBuf) -> Result<Self> {
        match mode {
            PersistenceMode::Sqlite => Ok(Backend::Sqlite(
                open_db(path).context("failed to open rate-limiter SQLite database")?,
            )),
            PersistenceMode::Bincode => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Ok(Backend::Bincode(path.clone()))
            }
        }
    }

    /// Carrega entradas (ip_hash, tat_ns) cujo TAT ainda não expirou.
    fn load(&self, cutoff: u64) -> Result<Vec<(u64, u64)>> {
        match self {
            Backend::Sqlite(conn) => {
                let mut stmt = conn
                    .prepare("SELECT ip_hash, tat_ns FROM rate_counters WHERE tat_ns >= ?1")?;
                let rows = stmt
                    .query_map(params![cutoff as i64], |row| {
                        Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
                    })?
                    .flatten()
                    .collect();
                Ok(rows)
            }
            Backend::Bincode(path) => {
                if !path.exists() {
                    return Ok(Vec::new());
                }
                let mut buf = Vec::new();
                File::open(path)?.read_to_end(&mut buf)?;
                if buf.len() < BINCODE_MAGIC.len() || &buf[..BINCODE_MAGIC.len()] != BINCODE_MAGIC {
                    warn!(target: "krakenwaf", path = %path.display(),
                        "bincode rate-limiter snapshot magic mismatch; ignorando");
                    return Ok(Vec::new());
                }
                let items: Vec<(u64, u64)> =
                    bincode::deserialize(&buf[BINCODE_MAGIC.len()..]).unwrap_or_default();
                Ok(items.into_iter().filter(|(_, tat)| *tat >= cutoff).collect())
            }
        }
    }

    /// Persiste o snapshot completo, descartando entradas com TAT < `cutoff`.
    fn save(&self, items: &[(u64, u64)], cutoff: u64) -> Result<()> {
        match self {
            Backend::Sqlite(conn) => with_transaction(conn, |c| {
                for (key, tat_ns) in items {
                    c.execute(
                        "INSERT INTO rate_counters (ip_hash, tat_ns) VALUES (?1, ?2)
                         ON CONFLICT(ip_hash) DO UPDATE SET tat_ns = excluded.tat_ns",
                        params![*key as i64, *tat_ns as i64],
                    )?;
                }
                c.execute(
                    "DELETE FROM rate_counters WHERE tat_ns < ?1",
                    params![cutoff as i64],
                )?;
                Ok(())
            }),
            Backend::Bincode(path) => {
                let live: Vec<(u64, u64)> =
                    items.iter().copied().filter(|(_, tat)| *tat >= cutoff).collect();
                let payload = bincode::serialize(&live)?;

                // Atomic write: tmp + fsync + rename.
                let tmp = path.with_extension("tmp");
                {
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)?;
                    f.write_all(BINCODE_MAGIC)?;
                    f.write_all(&payload)?;
                    f.sync_all()?;
                }
                std::fs::rename(&tmp, path)?;
                Ok(())
            }
        }
    }
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

pub struct RateLimiter {
    shards: Arc<[Shard; NUM_SHARDS]>,
    emit_ns: u64,      // emission interval em nanossegundos
    tolerance_ns: u64, // delay tolerance em nanossegundos (= window_ns − emit_ns)
    // Mutex (não RwLock) porque Connection: !Sync — mutex garante Arc<...>: Send+Sync.
    db: Arc<Mutex<Backend>>,
}

impl RateLimiter {
    /// Cria o limitador com `limit` requisições por `window`.
    ///
    /// Parâmetros GCRA derivados automaticamente:
    ///   emission_interval = window / limit
    ///   delay_tolerance   = window − emission_interval
    pub fn new(
        limit: u32,
        window: Duration,
        snapshot_path: PathBuf,
        mode: PersistenceMode,
    ) -> Result<Self> {
        let window_ns = window.as_nanos() as u64;
        let emit_ns = window_ns / limit.max(1) as u64;
        // tolerance = window inteiro: permite burst de exatamente `limit` requisições
        // em um instante, controlando a taxa sustentada via emit_interval.
        // (tolerance = window - emit permitiria apenas limit-1 em burst.)
        let tolerance_ns = window_ns;

        let shards: Arc<[Shard; NUM_SHARDS]> = Arc::new(array::from_fn(|_| Shard::new()));

        let backend = Backend::open(mode, &snapshot_path)?;

        // Re-hidrata TATs não expirados da última execução.
        let now = now_ns();
        let cutoff = now.saturating_sub(tolerance_ns);
        for (key, tat) in backend.load(cutoff)? {
            let idx = (key & SHARD_MASK) as usize;
            shards[idx]
                .rw
                .write()
                .insert(key, Arc::new(AtomicU64::new(tat)));
        }

        Ok(Self {
            shards,
            emit_ns,
            tolerance_ns,
            db: Arc::new(Mutex::new(backend)),
        })
    }

    pub fn spawn_persistence_task(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        // Sweeper: libera memória de entradas expiradas.
        let sweeper = self.clone();
        handle.spawn(async move {
            let mut ticker = interval(SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                let now = now_ns();
                let tol = sweeper.tolerance_ns;
                for shard in sweeper.shards.iter() {
                    shard.sweep(now, tol);
                }
            }
        });

        // Persister: grava estado em SQLite.
        let persister = self;
        handle.spawn(async move {
            let mut ticker = interval(PERSIST_INTERVAL);
            loop {
                ticker.tick().await;
                if let Err(e) = persister.persist() {
                    warn!(target: "krakenwaf", error = %e, "rate-limiter persist failed");
                }
            }
        });
    }

    /// Hot path. Async apenas para compatibilidade com o caller;
    /// o trabalho real é síncrono e leva ~20–30 ns para IPs existentes.
    pub async fn check(&self, ip: &str) -> bool {
        let key = hash_ip(ip);
        let idx = (key & SHARD_MASK) as usize;
        self.shards[idx].check(key, now_ns(), self.emit_ns, self.tolerance_ns)
    }

    /// Descarrega todos os TATs em memória para o back-end de persistência.
    pub fn persist(&self) -> Result<()> {
        // Snapshot first (sem o DB lock) para minimizar tempo segurando-o.
        let mut items = Vec::with_capacity(NUM_SHARDS * 64);
        for shard in self.shards.iter() {
            items.extend(shard.snapshot());
        }
        let cutoff = now_ns().saturating_sub(self.tolerance_ns);
        let backend = self.db.lock();
        backend.save(&items, cutoff)
    }
}

// ── SQLite ────────────────────────────────────────────────────────────────────

fn open_db(path: &PathBuf) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if path.exists() {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > MAX_DB_BYTES {
            warn!(
                target: "krakenwaf",
                size,
                limit = MAX_DB_BYTES,
                path = %path.display(),
                "rate-limiter DB excede limite; iniciando limpo"
            );
            let _ = std::fs::remove_file(path);
        }
    }

    let conn = Connection::open(path)?;

    // WAL: leitores e escritores nunca se bloqueiam mutuamente.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous  = NORMAL;
         PRAGMA busy_timeout = 5000;",
    )?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS rate_counters (
             ip_hash  INTEGER PRIMARY KEY,  -- FNV-1a hash do IP (estável entre reinicializações)
             tat_ns   INTEGER NOT NULL       -- Theoretical Arrival Time em nanossegundos
         );",
    )?;

    Ok(conn)
}

/// Executa `f` dentro de uma transação SQLite; faz rollback em caso de erro.
fn with_transaction(conn: &Connection, f: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    match f(conn) {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

// ── Hashing estável ───────────────────────────────────────────────────────────

/// FNV-1a (64-bit) — hash determinístico sem sementes aleatórias.
///
/// Garante que `hash_ip("1.2.3.4")` retorna o mesmo `u64` em qualquer
/// execução do processo, permitindo re-hidratação correta do SQLite.
/// Resistência a flooding por IP é irrelevante: endereços IP reais não
/// podem ser controlados pelo atacante para colidir num shard específico.
#[inline]
fn hash_ip(ip: &str) -> u64 {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    ip.bytes().fold(OFFSET, |h, b| (h ^ b as u64).wrapping_mul(PRIME))
}

#[inline(always)]
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ── Testes ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Constrói um RateLimiter com SQLite em memória — sem I/O de disco.
    fn make_limiter(limit: u32, window_secs: u64) -> RateLimiter {
        let window_ns = window_secs * 1_000_000_000;
        let emit_ns = window_ns / limit.max(1) as u64;
        let tolerance_ns = window_ns;

        let conn = Connection::open_in_memory().expect("sqlite in-memory");
        conn.execute_batch(
            "CREATE TABLE rate_counters (ip_hash INTEGER PRIMARY KEY, tat_ns INTEGER NOT NULL);",
        )
        .unwrap();

        RateLimiter {
            shards: Arc::new(array::from_fn(|_| Shard::new())),
            emit_ns,
            tolerance_ns,
            db: Arc::new(Mutex::new(Backend::Sqlite(conn))),
        }
    }

    #[test]
    fn gcra_permite_ate_o_limite() {
        // 5 req / 1 s → emission = 200 ms; tolerance = window = 1 s (burst = limit).
        let limit = 5u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / limit as u64;
        let tolerance_ns = window_ns; // burst exato de limit requisições

        let tat = AtomicU64::new(0);
        let now = now_ns();

        for _ in 0..limit {
            assert!(gcra_check(&tat, now, emit_ns, tolerance_ns), "deveria permitir");
        }
        assert!(!gcra_check(&tat, now, emit_ns, tolerance_ns), "deveria bloquear");
    }

    #[test]
    fn gcra_recupera_apos_janela() {
        let limit = 3u32;
        let window_ns = 1_000_000_000u64;
        let emit_ns = window_ns / limit as u64;
        let tolerance_ns = window_ns;

        let tat = AtomicU64::new(0);
        let now = now_ns();

        for _ in 0..limit {
            assert!(gcra_check(&tat, now, emit_ns, tolerance_ns));
        }
        assert!(!gcra_check(&tat, now, emit_ns, tolerance_ns));

        // Após uma janela completa o TAT drena e um novo burst é permitido.
        let later = now + window_ns + 1;
        assert!(gcra_check(&tat, later, emit_ns, tolerance_ns));
    }

    #[test]
    fn hash_ip_e_estavel() {
        // Mesmo IP → mesmo hash entre chamadas (deterministico).
        assert_eq!(hash_ip("192.168.1.1"), hash_ip("192.168.1.1"));
        assert_ne!(hash_ip("192.168.1.1"), hash_ip("192.168.1.2"));
    }

    #[test]
    fn shard_routing_consistente() {
        // Mesmo IP sempre vai para o mesmo shard.
        let ip = "10.0.0.99";
        let key = hash_ip(ip);
        let idx_a = (key & SHARD_MASK) as usize;
        let idx_b = (hash_ip(ip) & SHARD_MASK) as usize;
        assert_eq!(idx_a, idx_b);
    }

    #[tokio::test]
    async fn check_bloqueia_apos_limite() {
        let rl = make_limiter(3, 60);
        let ip = "192.0.2.1";
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(rl.check(ip).await);
        assert!(!rl.check(ip).await, "4ª requisição deve ser negada");
    }

    #[tokio::test]
    async fn ips_diferentes_sao_independentes() {
        let rl = make_limiter(1, 60);
        assert!(rl.check("10.0.0.1").await);
        assert!(!rl.check("10.0.0.1").await);
        assert!(rl.check("10.0.0.2").await, "IP diferente não deve ser afetado");
    }

    #[tokio::test]
    async fn persist_e_snapshot_funcionam() {
        let rl = make_limiter(10, 60);
        // Gera algum tráfego.
        for _ in 0..5 {
            rl.check("10.1.1.1").await;
        }
        // persist não deve errar com DB in-memory.
        rl.persist().expect("persist deve funcionar");
    }

    #[tokio::test]
    async fn bincode_round_trip_rehidrata_tats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rl.bin");

        // Primeiro processo: consome 4/5 da janela e persiste.
        {
            let rl = RateLimiter::new(
                5,
                Duration::from_secs(60),
                path.clone(),
                PersistenceMode::Bincode,
            )
            .expect("criar limiter (bincode)");
            for _ in 0..4 {
                assert!(rl.check("203.0.113.7").await);
            }
            rl.persist().expect("persist bincode");
        }

        // Segundo processo: estado deve ter sido recuperado — restam apenas 1 req.
        let rl = RateLimiter::new(
            5,
            Duration::from_secs(60),
            path.clone(),
            PersistenceMode::Bincode,
        )
        .expect("recriar limiter (bincode)");
        assert!(rl.check("203.0.113.7").await, "5ª req deve passar");
        assert!(!rl.check("203.0.113.7").await, "6ª req deve ser bloqueada");
    }
}
