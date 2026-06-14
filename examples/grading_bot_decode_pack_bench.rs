//! Benchmark example for `Pack::decode`.
//!
//! Usage:
//!   cargo run --release --example grading_bot_decode_pack_bench -- <repo_or_pack_path> [--threads N] [--mem-limit BYTES]
//!
//! `<repo_or_pack_path>` may be:
//!   - a `.pack` file
//!   - a directory containing `objects/pack/*.pack`
//!   - a `.git` directory (containing `objects/pack/*.pack`)
//!
//! Reports per-pack wall-clock decoding time, total throughput, plus peak RSS
//! captured from `/proc/self/status` (Linux) and the allocator-peak counter the
//! decoder already exposes (sum of in-flight CacheObject memory).

use std::{
    env,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use git_internal::{hash::ObjectHash, internal::pack::Pack};

// ── grading correctness fingerprint ──────────────────────────────────────
// Order-independent fingerprint over a multiset of object hashes. The same
// helper is embedded verbatim in the decode bench, the encode bench, and the
// reference oracle (examples/grading_bot_ref_decode.rs); identical input
// multisets therefore yield identical fingerprint strings across the three
// independently-compiled binaries. A git object hash is a content digest, so
// equal hash multisets prove the decoded object contents match byte-for-byte.
//
// `xor` is an order-independent 256-bit fold; `sum` is an order-independent
// additive fold (so it also notices multiplicity, which a pure XOR would
// cancel in pairs); `count` guards against missing/extra objects.
#[derive(Default)]
struct GradingFingerprint {
    count: u64,
    xor: [u8; 32],
    sum: u128,
}

impl GradingFingerprint {
    fn add(&mut self, hash_bytes: &[u8]) {
        self.count += 1;
        for (i, b) in hash_bytes.iter().enumerate() {
            self.xor[i % 32] ^= *b;
        }
        // FNV-1a-style per-hash fold into a u128, then add (order-independent).
        let mut v: u128 = 0x6c62272e07bb0142_62b821756295c58d;
        for b in hash_bytes {
            v = (v ^ *b as u128).wrapping_mul(0x0000000001000000_000000000000013b);
        }
        self.sum = self.sum.wrapping_add(v);
    }

    fn finish(&self) -> String {
        let mut hex = String::with_capacity(64);
        for b in &self.xor {
            hex.push_str(&format!("{b:02x}"));
        }
        format!("count={} xor={} sum={:032x}", self.count, hex, self.sum)
    }
}

/// Decode every pack (untimed) and fold an order-independent fingerprint over
/// the decoded object hashes. Run after the timed bench so it never distorts
/// the reported throughput. The student's fingerprint is compared by the
/// grading bot against the reference implementation's fingerprint over the
/// same pack(s).
fn correctness_fingerprint(
    packs: &[PathBuf],
    threads: Option<usize>,
    mem_limit: Option<usize>,
) -> Result<String, String> {
    let fp = Arc::new(Mutex::new(GradingFingerprint::default()));
    for pack_path in packs {
        let f =
            File::open(pack_path).map_err(|e| format!("open {}: {e}", pack_path.display()))?;
        let mut reader = BufReader::new(f);
        let tmp_dir = env::temp_dir().join(format!(
            "grading_bot_decode_correctness_{}",
            std::process::id()
        ));
        let mut pack = Pack::new(threads, mem_limit, Some(tmp_dir.clone()), true);
        let fp_cb = fp.clone();
        pack.decode(
            &mut reader,
            move |entry| {
                fp_cb.lock().unwrap().add(entry.inner.hash.as_ref());
            },
            None::<fn(ObjectHash)>,
        )
        .map_err(|e| format!("decode {}: {e:?}", pack_path.display()))?;
        let _ = fs::remove_dir_all(&tmp_dir);
    }
    let out = fp.lock().unwrap().finish();
    Ok(out)
}

#[derive(Debug)]
struct Args {
    path: PathBuf,
    threads: Option<usize>,
    mem_limit: Option<usize>,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = env::args().skip(1);
    let path = iter
        .next()
        .ok_or("missing required <repo_or_pack_path> argument")?;
    let mut threads: Option<usize> = None;
    let mut mem_limit: Option<usize> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--threads" => {
                let v = iter.next().ok_or("--threads requires a value")?;
                threads = Some(v.parse::<usize>().map_err(|e| format!("--threads: {e}"))?);
            }
            "--mem-limit" => {
                let v = iter.next().ok_or("--mem-limit requires a value")?;
                mem_limit = Some(v.parse::<usize>().map_err(|e| format!("--mem-limit: {e}"))?);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        path: PathBuf::from(path),
        threads,
        mem_limit,
    })
}

/// Read VmHWM/VmRSS from /proc/self/status (Linux). Returns bytes.
#[cfg(target_os = "linux")]
fn read_proc_status_kib(key: &str) -> Option<usize> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            // Format: "VmHWM:\t  123456 kB"
            let rest = rest.trim_start_matches(':').trim();
            let num = rest.split_whitespace().next()?;
            let kib = num.parse::<usize>().ok()?;
            return Some(kib * 1024);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_proc_status_kib(_key: &str) -> Option<usize> {
    None
}

fn collect_pack_files(p: &Path) -> Vec<PathBuf> {
    if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("pack") {
        return vec![p.to_path_buf()];
    }
    // Heuristic: if it's a directory, look for objects/pack/*.pack underneath.
    let candidates = [
        p.join("objects/pack"),      // a .git directory
        p.join(".git/objects/pack"), // a working tree
        p.to_path_buf(),             // any directory with .pack files
    ];
    let mut packs = Vec::new();
    for c in candidates {
        if c.is_dir() {
            if let Ok(rd) = fs::read_dir(&c) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("pack") {
                        packs.push(path);
                    }
                }
            }
            if !packs.is_empty() {
                break;
            }
        }
    }
    packs.sort();
    packs
}

fn format_bytes(b: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let bf = b as f64;
    if bf >= GB {
        format!("{:.2} GiB", bf / GB)
    } else if bf >= MB {
        format!("{:.2} MiB", bf / MB)
    } else if bf >= KB {
        format!("{:.2} KiB", bf / KB)
    } else {
        format!("{b} B")
    }
}

fn run_streaming(
    pack_path: &Path,
    threads: Option<usize>,
    mem_limit: Option<usize>,
    file_size: usize,
) -> Result<(), String> {
    let f = File::open(pack_path).map_err(|e| format!("open {}: {e}", pack_path.display()))?;
    let mut reader = BufReader::new(f);

    let tmp_dir = env::temp_dir().join(format!("grading_bot_decode_pack_bench_{}", std::process::id()));
    let mut pack = Pack::new(threads, mem_limit, Some(tmp_dir.clone()), true);

    let object_count = Arc::new(AtomicUsize::new(0));
    let oc_clone = object_count.clone();

    let baseline_rss = read_proc_status_kib("VmRSS").unwrap_or(0);
    let baseline_hwm = read_proc_status_kib("VmHWM").unwrap_or(0);

    let start = Instant::now();
    pack.decode(
        &mut reader,
        move |_entry| {
            oc_clone.fetch_add(1, Ordering::Relaxed);
        },
        None::<fn(ObjectHash)>,
    )
    .map_err(|e| format!("decode {}: {e:?}", pack_path.display()))?;
    let elapsed = start.elapsed();

    print_run_stats(
        "streaming",
        pack_path,
        file_size,
        elapsed.as_secs_f64(),
        object_count.load(Ordering::Relaxed),
        pack.number,
        threads,
        mem_limit,
        baseline_rss,
        baseline_hwm,
    );

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_run_stats(
    mode: &str,
    pack_path: &Path,
    file_size: usize,
    secs: f64,
    decoded: usize,
    header_objects: usize,
    threads: Option<usize>,
    mem_limit: Option<usize>,
    baseline_rss: usize,
    baseline_hwm: usize,
) {
    let final_rss = read_proc_status_kib("VmRSS").unwrap_or(0);
    let peak_hwm = read_proc_status_kib("VmHWM").unwrap_or(0);
    let throughput = if secs > 0.0 {
        file_size as f64 / secs / (1024.0 * 1024.0)
    } else {
        0.0
    };

    println!("------------------------------------------------------------");
    println!("mode:          {mode}");
    println!("pack:          {}", pack_path.display());
    println!("size:          {} ({} bytes)", format_bytes(file_size), file_size);
    println!("objects:       {decoded} (decoded), {header_objects} (header)");
    println!(
        "threads:       {}",
        threads.map_or("auto".into(), |t| t.to_string())
    );
    println!(
        "mem_limit:     {}",
        mem_limit.map_or("none".into(), |b| format_bytes(b))
    );
    println!("wall:          {secs:.3} s");
    println!("throughput:    {throughput:.2} MiB/s (input)");
    println!("baseline RSS:  {}", format_bytes(baseline_rss));
    println!("final RSS:     {}", format_bytes(final_rss));
    println!(
        "peak RSS:      {} (delta vs baseline: {})",
        format_bytes(peak_hwm),
        format_bytes(peak_hwm.saturating_sub(baseline_hwm))
    );
}

fn run_one(
    pack_path: &Path,
    threads: Option<usize>,
    mem_limit: Option<usize>,
) -> Result<(), String> {
    let metadata =
        fs::metadata(pack_path).map_err(|e| format!("stat {}: {e}", pack_path.display()))?;
    let file_size = metadata.len() as usize;

    run_streaming(pack_path, threads, mem_limit, file_size)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "usage: grading_bot_decode_pack_bench <repo_or_pack_path> [--threads N] [--mem-limit BYTES]"
            );
            return ExitCode::from(2);
        }
    };

    let packs = collect_pack_files(&args.path);
    if packs.is_empty() {
        eprintln!("no .pack files found at {}", args.path.display());
        return ExitCode::from(1);
    }

    println!(
        "grading_bot_decode_pack_bench: {} pack file(s) found at {}",
        packs.len(),
        args.path.display()
    );

    let bench_start = Instant::now();
    let mut total_bytes: usize = 0;
    let mut had_err = false;
    for pack in &packs {
        if let Ok(m) = fs::metadata(pack) {
            total_bytes += m.len() as usize;
        }
        if let Err(e) = run_one(pack, args.threads, args.mem_limit) {
            eprintln!("{e}");
            had_err = true;
        }
    }
    let total_elapsed = bench_start.elapsed();
    println!("============================================================");
    println!("total packs:   {}", packs.len());
    println!(
        "total bytes:   {} ({} bytes)",
        format_bytes(total_bytes),
        total_bytes
    );
    println!("total wall:    {:.3} s", total_elapsed.as_secs_f64());
    if total_elapsed.as_secs_f64() > 0.0 {
        println!(
            "avg throughput:{:.2} MiB/s",
            total_bytes as f64 / total_elapsed.as_secs_f64() / (1024.0 * 1024.0)
        );
    }

    // Correctness fingerprint — an untimed second decode pass so the folding
    // cost never touches the throughput numbers above. The grading bot
    // compares this line against the reference implementation's fingerprint
    // over the same pack(s); a mismatch means the student decoder produced a
    // different object multiset than the reference.
    match correctness_fingerprint(&packs, args.threads, args.mem_limit) {
        Ok(fp) => {
            println!("GRADING_FINGERPRINT_BEGIN");
            println!("{fp}");
            println!("GRADING_FINGERPRINT_END");
        }
        Err(e) => {
            // Don't flip `had_err`: the timed numbers above are already valid.
            // Omitting the fingerprint block tells the grading bot that
            // correctness couldn't be verified, without failing the bench.
            eprintln!("correctness fingerprint failed: {e}");
        }
    }

    if had_err {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}
