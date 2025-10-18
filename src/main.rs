use anyhow::Context;
use anyhow::Result;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use macaddr::MacAddr;
use rustc_hash::FxHasher;
use serde::Serialize;
use std::hash::BuildHasher;
use std::hash::BuildHasherDefault;
use std::str::FromStr;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry;

const REFRESH_RATE_DEFAULT: u64 = 130;
const IMAGE_URL_TIMEOUT_DEFAULT: u64 = 0;
static SPECIAL_FUNCTION_DEFAULT: &str = "sleep";
const SERVER_PORT_DEFAULT: u16 = 2443;

#[tokio::main]
async fn main() -> Result<()> {
    let tracing_subscriber = registry::Registry::default()
        .with(tracing_journald::layer().context("failed to create journald layer")?);
    tracing::subscriber::set_global_default(tracing_subscriber).context("failed to set tracing")?;

    let app = Router::new()
        .route("/api/setup", get(setup))
        .route("/api/display", get(display))
        .route("/api/log", get(log))
        .layer(tower_http::catch_panic::CatchPanicLayer::new());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", SERVER_PORT_DEFAULT))
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(listener, app)
        .await
        .context("failed to start axum")?;

    info!("Server started");

    Ok(())
}

#[derive(Serialize, Debug)]
struct SetupResponse {
    api_key: u64,
    friendly_id: String,
    image_url: String,
    message: String,
}

async fn setup(headers: HeaderMap) -> Result<(StatusCode, Json<SetupResponse>), AppError> {
    info!("Received setup request");

    let device_mac_address = get_device_mac_address(&headers)?;
    let response = SetupResponse {
        api_key: generate_api_key(device_mac_address).context("failed to generate API key")?,
        friendly_id: generate_friendly_id(device_mac_address)
            .context("failed to generate friendly ID")?,
        image_url: generate_image_url().context("failed to generate image URL")?,
        message: generate_message().context("failed to generate message")?,
    };

    info!("Sending setup response: {:?}", response);

    Ok((StatusCode::OK, Json(response)))
}

fn generate_api_key(device_mac_address: MacAddr) -> anyhow::Result<u64> {
    let hasher_builder = BuildHasherDefault::<FxHasher>::default();
    let deterministic_hash = hasher_builder.hash_one(device_mac_address);

    Ok(deterministic_hash)
}

fn generate_friendly_id(device_mac_address: MacAddr) -> anyhow::Result<String> {
    // Deterministic 6-char Base36 (0-9, A-Z) using FxHasher.
    // Replace the hashed seed with your desired input to derive the ID from.
    let hasher_builder = BuildHasherDefault::<FxHasher>::default();
    let mut n = hasher_builder.hash_one(device_mac_address);

    let mut buf = [b'0'; 6];
    for i in (0..6).rev() {
        let d = (n % 36) as u8;
        n /= 36;
        buf[i] = if d < 10 { b'0' + d } else { b'A' + (d - 10) };
    }

    Ok(buf.iter().map(|&b| b as char).collect())
}

fn generate_image_url() -> anyhow::Result<String> {
    Ok("https://localhost:2443/assets/welcome_screen.bmp".to_string())
}

fn generate_message() -> anyhow::Result<String> {
    Ok("Welcome to MNFRM".to_string())
}

#[derive(Serialize, Debug)]
struct DisplayResponse {
    filename: String,
    firmware_url: String,
    image_url: String,
    image_url_timeout: u64,
    refresh_rate: u64,
    reset_firmware: bool,
    special_function: String,
    update_firmware: bool,
}

struct DisplayImage {
    filename: String,
    image_url: String,
    image_url_timeout: u64,
}

struct DeviceFirmware {
    firmware_url: String,
    reset_firmware: bool,
    update_firmware: bool,
}

async fn display(_: HeaderMap) -> Result<(StatusCode, Json<DisplayResponse>), AppError> {
    info!("Received display request");

    let device_firmware = DeviceFirmware {
        firmware_url: get_latest_firmware_url(),
        reset_firmware: false,
        update_firmware: false,
    };
    let display_image = DisplayImage {
        filename: "welcome_screen.bmp".to_string(),
        image_url: "https://localhost:2443/assets/screens/welcome_screen.bmp".to_string(),
        image_url_timeout: IMAGE_URL_TIMEOUT_DEFAULT,
    };

    let resp = DisplayResponse {
        filename: display_image.filename,
        firmware_url: device_firmware.firmware_url,
        image_url: display_image.image_url,
        image_url_timeout: display_image.image_url_timeout,
        refresh_rate: REFRESH_RATE_DEFAULT,
        reset_firmware: device_firmware.reset_firmware,
        special_function: SPECIAL_FUNCTION_DEFAULT.to_string(),
        update_firmware: device_firmware.update_firmware,
    };

    info!("Sending display response: {:?}", resp);

    // Implement your display logic here
    Ok((StatusCode::OK, Json(resp)))
}

fn get_latest_firmware_url() -> String {
    // In a real implementation, this would query a database or configuration
    // to find the latest firmware URL for the device.
    "https://localhost:2443/assets/firmware/latest.bin".to_string()
}

#[derive(serde::Deserialize)]
struct LogRequest {
    logs: Vec<LogEntry>,
}

#[derive(serde::Deserialize, Debug)]
struct LogEntry {
    id: u64,
    message: String,
    wifi_status: String,
    created_at: u64,
    sleep_duration: u64,
    refresh_rate: u64,
    free_heap_size: u64,
    max_alloc_size: u64,
    source_path: String,
    wake_reason: String,
    firmware_version: String,
    retry: u64,
    battery_voltage: f64,
    source_line: u64,
    special_function: String,
    wifi_signal: i64,
}

async fn log(Json(payload): Json<LogRequest>) -> Result<StatusCode, AppError> {
    info!("Received log request");
    for log_entry in payload.logs {
        info!(
            "Log Entry - id: {}, message: {}, wifi_status: {}, created_at: {}, sleep_duration: {}, refresh_rate: {}, free_heap_size: {}, max_alloc_size: {}, source_path: {}, wake_reason: {}, firmware_version: {}, retry: {}, battery_voltage: {}, source_line: {}, special_function: {}, wifi_signal: {}",
            log_entry.id,
            log_entry.message,
            log_entry.wifi_status,
            log_entry.created_at,
            log_entry.sleep_duration,
            log_entry.refresh_rate,
            log_entry.free_heap_size,
            log_entry.max_alloc_size,
            log_entry.source_path,
            log_entry.wake_reason,
            log_entry.firmware_version,
            log_entry.retry,
            log_entry.battery_voltage,
            log_entry.source_line,
            log_entry.special_function,
            log_entry.wifi_signal
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

fn get_device_mac_address(headers: &HeaderMap) -> Result<MacAddr, AppError> {
    let id_header = headers
        .get("ID")
        .context("missing ID header")?
        .to_str()
        .context("invalid ID header")?;
    let device_mac_address = MacAddr::from_str(id_header).context("invalid MAC address format")?;
    Ok(device_mac_address)
}

struct AppError(anyhow::Error);

// This allows ? to automatically convert anyhow::Error to AppError
impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}
