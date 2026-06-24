use std::{
    io::{self, IsTerminal, Write},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    thread,
    time::{Duration, Instant},
};

use indicatif::HumanBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct ClientStatus {
    inner: Arc<Mutex<StatusLine>>,
    stop_ticker: Arc<AtomicBool>,
}

impl ClientStatus {
    pub fn new() -> Self {
        let interactive = io::stderr().is_terminal();
        let inner = Arc::new(Mutex::new(StatusLine::new(interactive)));
        let stop_ticker = Arc::new(AtomicBool::new(false));

        if interactive {
            let inner = inner.clone();
            let stop_ticker = stop_ticker.clone();
            thread::spawn(move || {
                while !stop_ticker.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(1));
                    if stop_ticker.load(Ordering::Relaxed) {
                        break;
                    }
                    inner.lock().expect("status lock poisoned").draw_now();
                }
            });
        }

        Self { inner, stop_ticker }
    }

    pub fn phase(&mut self, message: impl Into<String>) {
        self.inner
            .lock()
            .expect("status lock poisoned")
            .phase(message);
    }

    pub fn clear_phase(&mut self) {
        self.inner.lock().expect("status lock poisoned").clear();
    }

    pub fn transfer(&mut self, message: impl Into<String>) -> TransferProgress {
        let progress = TransferProgress::new(self.inner.clone());
        self.inner
            .lock()
            .expect("status lock poisoned")
            .transfer(message, progress.bytes.clone());
        progress
    }

    pub fn suspend<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        self.inner
            .lock()
            .expect("status lock poisoned")
            .clear_line();
        let result = f();
        self.inner.lock().expect("status lock poisoned").draw_now();
        result
    }
}

impl Drop for ClientStatus {
    fn drop(&mut self) {
        self.stop_ticker.store(true, Ordering::Relaxed);
        self.clear_phase();
    }
}

struct StatusLine {
    interactive: bool,
    visible: bool,
    current: Option<Status>,
    last_draw: Instant,
}

impl StatusLine {
    fn new(interactive: bool) -> Self {
        Self {
            interactive,
            visible: false,
            current: None,
            last_draw: Instant::now(),
        }
    }

    fn phase(&mut self, message: impl Into<String>) {
        self.current = Some(Status::Phase {
            message: message.into(),
            started: Instant::now(),
        });
        self.draw_now();
    }

    fn transfer(&mut self, message: impl Into<String>, bytes: Arc<AtomicU64>) {
        self.current = Some(Status::Transfer {
            message: message.into(),
            started: Instant::now(),
            bytes,
        });
        self.draw_now();
    }

    fn transfer_message(&mut self, message: impl Into<String>) {
        if let Some(Status::Transfer {
            message: current, ..
        }) = &mut self.current
        {
            *current = message.into();
            self.draw_now();
        }
    }

    fn add_transfer_bytes(&mut self, bytes: u64) {
        if bytes == 0 || self.last_draw.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.draw_now();
    }

    fn clear(&mut self) {
        self.current = None;
        self.clear_line();
    }

    fn clear_line(&mut self) {
        if !self.interactive || !self.visible {
            return;
        }
        eprint!("\r\x1b[2K");
        let _ = io::stderr().flush();
        self.visible = false;
    }

    fn draw_now(&mut self) {
        if !self.interactive {
            return;
        }
        self.clear_line();
        let Some(current) = &self.current else {
            return;
        };
        eprint!("\r{}", fit_line(current.render()));
        let _ = io::stderr().flush();
        self.visible = true;
        self.last_draw = Instant::now();
    }
}

#[derive(Clone)]
pub struct TransferProgress {
    inner: Arc<Mutex<StatusLine>>,
    bytes: Arc<AtomicU64>,
}

impl TransferProgress {
    fn new(inner: Arc<Mutex<StatusLine>>) -> Self {
        Self {
            inner,
            bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn message(&self, message: impl Into<String>) {
        self.inner
            .lock()
            .expect("status lock poisoned")
            .transfer_message(message);
    }

    pub fn add_bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.inner
            .lock()
            .expect("status lock poisoned")
            .add_transfer_bytes(bytes);
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn finish_and_clear(self) {
        self.inner.lock().expect("status lock poisoned").clear();
    }
}

pub struct ProgressReader<R> {
    inner: R,
    progress: TransferProgress,
}

impl<R> ProgressReader<R> {
    pub fn new(inner: R, progress: TransferProgress) -> Self {
        Self { inner, progress }
    }
}

impl<R> AsyncRead for ProgressReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(before) as u64;
            this.progress.add_bytes(read);
        }
        result
    }
}

pub struct ProgressWriter<W> {
    inner: W,
    progress: TransferProgress,
}

impl<W> ProgressWriter<W> {
    pub fn new(inner: W, progress: TransferProgress) -> Self {
        Self { inner, progress }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W> AsyncWrite for ProgressWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            this.progress.add_bytes(*written as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

enum Status {
    Phase {
        message: String,
        started: Instant,
    },
    Transfer {
        message: String,
        started: Instant,
        bytes: Arc<AtomicU64>,
    },
}

impl Status {
    fn render(&self) -> String {
        match self {
            Self::Phase { message, started } => {
                format!(
                    "drv-thru: {message} [{}]",
                    format_elapsed(started.elapsed())
                )
            }
            Self::Transfer {
                message,
                started,
                bytes,
            } => {
                let bytes = bytes.load(Ordering::Relaxed);
                let elapsed = started.elapsed();
                let rate = bytes / elapsed.as_secs().max(1);
                format!(
                    "drv-thru: {message}: {} ({}/s) {}",
                    HumanBytes(bytes),
                    HumanBytes(rate),
                    format_elapsed(elapsed)
                )
            }
        }
    }
}

fn fit_line(line: String) -> String {
    let columns = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(80)
        .saturating_sub(1);

    if line.chars().count() <= columns {
        return line;
    }

    let keep = columns.saturating_sub(1);
    let mut line = line.chars().take(keep).collect::<String>();
    line.push('…');
    line
}

fn format_elapsed(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}
