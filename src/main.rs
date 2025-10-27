use anyhow::Context;
use anyhow::Result;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose;
use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use image::ImageFormat;
use macaddr::MacAddr;
use rustc_hash::FxHasher;
use serde::Serialize;
use std::env;
use std::fs::File;
use std::hash::BuildHasher;
use std::hash::BuildHasherDefault;
use std::io::Cursor;
use std::io::Read;
use std::process;
use std::str::FromStr;
use std::time::Duration;
use tower_http::services::ServeDir;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::Span;
use tracing::info;
use tracing_subscriber::prelude::*;
use url::Url;

const REFRESH_RATE_DEFAULT: u64 = 130;
const IMAGE_URL_TIMEOUT_DEFAULT: u64 = 0;
static SPECIAL_FUNCTION_DEFAULT: &str = "none";
const SERVER_PORT_DEFAULT: u16 = 2443;

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing()?;

    let static_files = ServeDir::new("/assets");

    let app = Router::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|_: &Request<Body>| tracing::info_span!("http-request"))
                .on_request(|request: &Request<Body>, _span: &Span| {
                    info!("started {} {}", request.method(), request.uri().path())
                })
                .on_response(
                    |response: &Response<Body>, _latency: Duration, _span: &Span| {
                        info!(status_code = %response.status(), "response generated");
                    },
                )
                .on_body_chunk(|chunk: &Bytes, _latency: Duration, _span: &Span| {
                    tracing::info!("sending {} bytes", chunk.len())
                })
                .on_eos(
                    |_trailers: Option<&HeaderMap>, stream_duration: Duration, _span: &Span| {
                        tracing::debug!("stream closed after {:?}", stream_duration)
                    },
                )
                .on_failure(
                    |error: ServerErrorsFailureClass, latency: Duration, _span: &Span| {
                        info!(
                            error = %error,
                            latency = ?latency,
                            "request failed with server error",
                        );
                    },
                ),
        )
        .route("/api/setup/", get(setup))
        .route("/api/display/", get(display))
        .route("/api/log/", get(log))
        .nest_service("/assets", static_files);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", SERVER_PORT_DEFAULT))
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(listener, app)
        .await
        .context("failed to start axum")?;

    Ok(())
}

fn setup_tracing() -> Result<()> {
    let (layer, task) = tracing_loki::builder()
        .label("host", "mine")?
        .label("service_name", "mnfrm")?
        .extra_field("pid", format!("{}", process::id()))?
        .build_url(Url::parse("http://loki:3100").unwrap())?;

    // We need to register our layer with `tracing`.
    tracing_subscriber::registry()
        .with(layer)
        // One could add more layers here, for example logging to stdout:
        // .with(tracing_subscriber::fmt::Layer::new())
        .init();

    // The background task needs to be spawned so the logs actually get
    // delivered.
    tokio::spawn(task);

    info!(
        task = "tracing_setup",
        result = "success",
        "tracing successfully set up",
    );

    Ok(())
}

#[derive(Serialize, Debug)]
struct SetupResponse {
    api_key: u64,
    friendly_id: String,
    image_url: String,
    message: String,
}

async fn setup(
    headers: axum::http::HeaderMap,
) -> Result<(StatusCode, Json<SetupResponse>), AppError> {
    let device_mac_address = get_device_mac_address(&headers)?;
    let api_key = generate_api_key(device_mac_address)?;
    let friendly_id = generate_friendly_id(device_mac_address)?;

    info!(device_mac_address = %device_mac_address, device_api_key = %api_key, device_friendly_id = %friendly_id, "Received setup request");

    let image_url = generate_image_url()
        .inspect_err(|e| tracing::error!(error = %e, "Failed to generate image URL"))
        .context("failed to generate image URL")?;
    let message = generate_message().context("failed to generate message")?;

    let response = SetupResponse {
        api_key,
        friendly_id,
        image_url,
        message,
    };

    info!(response = ?response, "Sending setup response");

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
    Ok("http://192.168.68.94:9878/assets/screens/output_resized.png".to_string())
}

#[allow(dead_code)]
fn generate_image_url_base64() -> anyhow::Result<String> {
    // 1. Read the BMP file into a byte vector
    let mut file =
        File::open("../assets/screens/default_display.bmp").context("failed to open BMP file")?;
    let mut bmp_data = Vec::new();
    file.read_to_end(&mut bmp_data)
        .context("failed to read bmp data")?;

    // 2. Decode the BMP data into a DynamicImage
    // Some versions of the `image` crate don't expose `with_format` on
    // `ImageReader` for certain cursor types; use `load_from_memory_with_format`
    // which accepts a slice and an explicit format.
    let header_hex = bmp_data.get(0..16).map(|b| {
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b.iter() {
            use std::fmt::Write as _;
            write!(&mut s, "{:02x}", byte).ok();
        }
        s
    });
    tracing::debug!(header = ?header_hex, "decoding BMP with explicit format");
    let img = image::load_from_memory_with_format(&bmp_data, ImageFormat::Bmp)
        .inspect_err(
            |e| tracing::error!(error = %e, header = ?header_hex, "ImageError decoding BMP"),
        )
        .context("failed to decode BMP data")?;

    // 3. (Optional but recommended for web) Convert to PNG bytes
    //    Directly encoding raw BMP bytes might not be what you want for
    //    embedding in HTML, as browsers expect a data URI with a specific image type.
    let mut png_bytes = Vec::new();
    img.write_to(&mut Cursor::new(&mut png_bytes), ImageFormat::Png)
        .context("failed to encode into PNG")?;

    // 4. Base64 encode the PNG bytes
    let encoded_base64 = general_purpose::STANDARD.encode(&png_bytes);

    Ok(format!("data:image/png;base64,{}", encoded_base64))
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

async fn display(headers: HeaderMap) -> Result<(StatusCode, Json<DisplayResponse>), AppError> {
    let device_mac_address = get_device_mac_address(&headers)?;
    let device_api_key = generate_api_key(device_mac_address)?;
    let device_friendly_id = generate_friendly_id(device_mac_address)?;

    info!(device_mac_address = %device_mac_address, device_api_key = %device_api_key, device_friendly_id = %device_friendly_id, "Received display request");

    let device_firmware = DeviceFirmware {
        firmware_url: get_latest_firmware_url(),
        reset_firmware: false,
        update_firmware: false,
    };
    let display_image = DisplayImage {
        filename: "output_resized.png".to_string(),
        image_url: generate_image_url().context("failed to generate image URL")?,
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

    info!(response = ?resp, "Sending display response");

    // Implement your display logic here
    Ok((StatusCode::OK, Json(resp)))
}

fn get_latest_firmware_url() -> String {
    // In a real implementation, this would query a database or configuration
    // to find the latest firmware URL for the device.
    format!(
        "http://{}:{}/assets/firmware/latest.bin",
        env::var("MNFRM_URL").unwrap(),
        env::var("MNFRM_PORT").unwrap_or_else(|_| SERVER_PORT_DEFAULT.to_string()),
    )
}

#[derive(serde::Deserialize)]
struct LogRequest {
    logs: Vec<LogEntry>,
}

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
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
        info!(log_entry = ?log_entry, "Log entry");
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
