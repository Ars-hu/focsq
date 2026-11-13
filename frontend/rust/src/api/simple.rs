// SPDX-FileCopyrightText: 2026 luminescq
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use csqtt_core::ClientConfig;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio_util::sync::CancellationToken;

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();
}

static CANCEL_TOKEN: OnceLock<Mutex<Option<CancellationToken>>> = OnceLock::new();
static EXTRA_CONFIG: OnceLock<Mutex<ExtraClientConfig>> = OnceLock::new();

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default)]
pub struct ExtraClientConfig {
    #[serde(default)]
    pub custom_turn_ips: String,
    #[serde(default = "default_turn_transport")]
    pub turn_transport: String,
    #[serde(default = "default_srtp_mode")]
    pub srtp_mode: String,
    #[serde(default)]
    pub domain_routing: bool,
    #[serde(default)]
    pub exclude_ru_zones: bool,
    #[serde(default)]
    pub template_domains: bool,
    #[serde(default)]
    pub domain_whitelist: bool,
    #[serde(default)]
    pub direct_domains: String,
    #[serde(default)]
    pub ip_routing: bool,
    #[serde(default)]
    pub ip_whitelist: bool,
    #[serde(default)]
    pub direct_ips: String,
    #[serde(default)]
    pub runtime_threads: usize,
    #[serde(default)]
    pub exact_workers: bool,
}

fn default_turn_transport() -> String {
    "udp".to_string()
}

fn default_srtp_mode() -> String {
    "auto".to_string()
}

pub fn setup_log_stream(sink: crate::frb_generated::StreamSink<String>) {
    csqtt_core::set_log_callback(Box::new(move |log_line| {
        let _ = sink.add(log_line);
    }));
}

pub fn stop_csqtt_client() {
    if let Some(guard) = CANCEL_TOKEN.get() {
        if let Some(token) = guard.lock().unwrap().take() {
            token.cancel();
        }
    }
}

/// [FOCSQ] Путь к wintun.dll, распакованному Flutter-стороной
/// в %LOCALAPPDATA%\FOCSQ — паттерн WireGuard/Amnezia.
pub fn set_wintun_dll_path(path: String) {
    #[cfg(windows)]
    csqtt_core::tun_win::set_dll_path_override(path);
    #[cfg(not(windows))]
    let _ = path;
}

/// Команда управления ядром ("PAUSE", "RESUME", "PATH_VALIDATE:", "CAPTCHA_RESULT|...", "CONFIG_EXTRA|...")
pub fn send_control_command(command: String) -> bool {
    if let Some(extra_json) = command.strip_prefix("CONFIG_EXTRA|") {
        if let Ok(extra) = serde_json::from_str::<ExtraClientConfig>(extra_json) {
            let guard = EXTRA_CONFIG.get_or_init(|| Mutex::new(ExtraClientConfig::default()));
            if let Ok(mut lock) = guard.lock() {
                *lock = extra;
                return true;
            }
        }
    }
    csqtt_core::submit_control_line(command)
}

/// Пауза/возобновление обработки трафика воркерами
pub fn set_client_paused(paused: bool) -> bool {
    csqtt_core::submit_control_line(if paused { "PAUSE".to_owned() } else { "RESUME".to_owned() })
}

/// Передать результат решения WebView-капчи в ядро (success_token или "error:...")
pub fn submit_captcha_result(result: String) -> bool {
    csqtt_core::submit_captcha_result(result)
}

pub struct AppClientConfig {
    pub turn: String,
    pub port: String,
    pub listen: String,
    pub vk: String,
    pub vk_hash_mode: String,
    pub peer: String,
    pub workers: usize,
    pub allow_hash_redistribution: bool,
    pub device_id: String,
    pub password: String,
    pub vk_auth_mode: String,
    pub captcha_mode: String,
    pub fingerprint: String,
    pub client_ids: String,
    pub obfs: String,
    pub generation: u64,
    pub salt: String,
    pub tun_uds: String,
    pub validate_vk_hashes: bool,
    pub vk_js_token: String,
}

impl Into<ClientConfig> for AppClientConfig {
    fn into(self) -> ClientConfig {
        let extra = EXTRA_CONFIG
            .get()
            .and_then(|m| m.lock().ok().map(|g| g.clone()))
            .unwrap_or_default();

        let mut direct_domains = extra.direct_domains;
        let mut domains_file = Vec::new();
        if std::path::Path::new("domains.txt").exists() {
            domains_file.push("domains.txt".to_string());
        }

        ClientConfig {
            turn: self.turn,
            custom_turn_ips: extra.custom_turn_ips,
            port: self.port,
            listen: self.listen,
            vk: self.vk,
            vk_hash_mode: self.vk_hash_mode,
            peer: self.peer,
            workers: self.workers,
            runtime_threads: extra.runtime_threads,
            exact_workers: extra.exact_workers,
            allow_hash_redistribution: self.allow_hash_redistribution,
            device_id: self.device_id,
            password: self.password,
            vk_auth_mode: self.vk_auth_mode,
            captcha_mode: self.captcha_mode,
            fingerprint: self.fingerprint,
            client_ids: self.client_ids,
            obfs: self.obfs,
            turn_transport: if extra.turn_transport.is_empty() {
                "udp".to_string()
            } else {
                extra.turn_transport
            },
            srtp_mode: if extra.srtp_mode.is_empty() {
                "auto".to_string()
            } else {
                extra.srtp_mode
            },
            generation: self.generation,
            salt: self.salt,
            tun_uds: self.tun_uds,
            validate_vk_hashes: self.validate_vk_hashes,
            vk_js_token: self.vk_js_token,
            domain_routing: extra.domain_routing,
            exclude_ru_zones: extra.exclude_ru_zones,
            template_domains: extra.template_domains,
            domain_whitelist: extra.domain_whitelist,
            direct_domains,
            domains_file,
            ip_routing: extra.ip_routing,
            ip_whitelist: extra.ip_whitelist,
            direct_ips: extra.direct_ips,
        }
    }
}

pub async fn start_csqtt_client(config: AppClientConfig) -> anyhow::Result<()> {
    // Embedded-режим: включаем структурированные события (__CSQTT_EVENT__|...)
    csqtt_core::set_events_enabled(true);

    let cancel = CancellationToken::new();
    
    {
        let mut guard = CANCEL_TOKEN.get_or_init(|| Mutex::new(None)).lock().unwrap();
        *guard = Some(cancel.clone());
    }
    
    let result = csqtt_core::run_client(config.into(), Some(cancel)).await;
    
    {
        let mut guard = CANCEL_TOKEN.get_or_init(|| Mutex::new(None)).lock().unwrap();
        *guard = None;
    }
    
    result?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn focsq_decrypt_csqtt_link(
    input_ptr: *const std::os::raw::c_char,
    out_buf: *mut u8,
    out_cap: usize,
) -> i32 {
    if input_ptr.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(input_ptr) };
    let input = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    if let Some(decrypted) = csqtt_core::link::decrypt_csqtt_link(input) {
        let bytes = decrypted.as_bytes();
        if bytes.len() > out_cap {
            return -3;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        }
        bytes.len() as i32
    } else {
        -4
    }
}

#[no_mangle]
pub extern "C" fn focsq_encrypt_csqtt_link(
    input_ptr: *const std::os::raw::c_char,
    out_buf: *mut u8,
    out_cap: usize,
) -> i32 {
    if input_ptr.is_null() || out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(input_ptr) };
    let input = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let encrypted = csqtt_core::link::encrypt_csqtt_link(input);
    let bytes = encrypted.as_bytes();
    if bytes.len() > out_cap {
        return -3;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    }
    bytes.len() as i32
}

