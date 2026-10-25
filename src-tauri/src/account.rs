use futures::FutureExt;
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        sideloader::Sideloader,
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::debug;

use crate::{
    error::AppError,
    secure_storage::create_sideloading_storage,
    sideload::{SideloaderGuard, SideloaderMutex},
};
use isideload::sideload::cert_identity::CertificateIdentity;

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    if save_credentials {
        let pass_entry = Entry::new("iloader", &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new("iloader", &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .map(|account| account.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
}

#[tauri::command]
pub fn reset_anisette_state() -> Result<bool, AppError> {
    let state_entry = Entry::new("iloader", "anisette_state").map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for anisette".into(),
            e.to_string(),
        )
    })?;

    match state_entry.delete_credential() {
        Ok(_) => {
            debug!("Anisette state deleted from keyring.");
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No existing anisette state found in keyring, nothing to delete.");
            Ok(false)
        }
        Err(e) => Err(AppError::KeyringWithMessage(
            "Failed to delete anisette state".into(),
            e.to_string(),
        )),
    }
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();

            async move {
                window_clone
                    .emit("2fa-required", params)
                    .context("Failed to emit 2fa-required event")?;

                let (tx, rx) = std::sync::mpsc::channel::<TwoFactorCallbackResponse>();
                let tx1 = tx.clone();
                let h1 = window_clone.listen("2fa-submit", move |event| {
                    let code = event.payload().trim_matches('"').to_string();
                    let _ = tx1.send(TwoFactorCallbackResponse::SubmitCode(code));
                });
                let tx2 = tx.clone();
                let h2 = window_clone.listen("2fa-send-sms", move |event| {
                    let id: u32 = event.payload().trim_matches('"').parse().unwrap_or(0);
                    let _ = tx2.send(TwoFactorCallbackResponse::SendSms(id));
                });
                let tx3 = tx.clone();
                let h3 = window_clone.listen("2fa-send-devices", move |_| {
                    let _ = tx3.send(TwoFactorCallbackResponse::SendToDevices);
                });
                let tx4 = tx.clone();
                let h4 = window_clone.listen("2fa-resend", move |_| {
                    let _ = tx4.send(TwoFactorCallbackResponse::ResendCode);
                });
                let tx5 = tx.clone();
                let h5 = window_clone.listen("2fa-abort", move |_| {
                    let _ = tx5.send(TwoFactorCallbackResponse::Abort);
                });

                let result = rx.recv_timeout(Duration::from_secs(120))?;
                window_clone.unlisten(h1);
                window_clone.unlisten(h2);
                window_clone.unlisten(h3);
                window_clone.unlisten(h4);
                window_clone.unlisten(h5);

                Ok(result)
            }
            .boxed()
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(create_sideloading_storage(app)?)
                .set_url(&anisette_url),
        )
        .login(password, Box::new(tfa_closure))
        .await?;

    debug!("Logged in");

    let dev_session = DeveloperSession::from_account(&mut account).await?;

    debug!("Created developer session");

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                window_clone.emit("max-certs-reached", cert_infos)?;

                let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<String>>>();
                let handler_id = window_clone.listen("max-certs-response", move |event| {
                    let certs = event.payload();
                    let certs = serde_json::from_str::<Option<Vec<String>>>(certs).unwrap_or(None);
                    let _ = tx.send(certs);
                });

                let result = rx.recv_timeout(Duration::from_secs(300));
                window_clone.unlisten(handler_id);
                Ok(result?)
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("iloader".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::ReuseMain,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    debug!("Built sideloader");

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

#[tauri::command]
pub async fn export_signing_certificate(
    handle: AppHandle,
    sideloader_state: State<'_, SideloaderMutex>,
    password: String,
    path: String,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let email = sideloader.get_mut().get_email().to_string();
    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let storage = create_sideloading_storage(&handle)?;

    let noop = |_certs: Vec<isideload::dev::certificates::DevelopmentCertificate>| async {
        Ok(None)
    };
    let behavior = MaxCertsBehavior::Prompt(noop);

    let identity = CertificateIdentity::retrieve(
        "iloader",
        &email,
        dev_session,
        &team,
        &*storage,
        &behavior,
    )
    .await
    .map_err(|e| AppError::Misc(format!("Failed to retrieve signing certificate: {:?}", e)))?;

    let p12_password = if password.is_empty() {
        identity.machine_id.clone()
    } else {
        password
    };

    let bytes = identity
        .as_p12(&p12_password)
        .await
        .map_err(|e| AppError::Misc(format!("Failed to build p12: {:?}", e)))?;

    std::fs::write(&path, bytes)
        .map_err(|e| AppError::Misc(format!("Failed to write p12 file: {}", e)))?;

    Ok(())
}

#[tauri::command]
pub fn extract_provisioning_profile(ipa_path: String, output_path: String) -> Result<(), AppError> {
    let script = r#"
import zipfile, sys
ipa = sys.argv[1]
out = sys.argv[2]
with zipfile.ZipFile(ipa) as z:
    for n in z.namelist():
        if n.endswith('embedded.mobileprovision'):
            with open(out, 'wb') as f:
                f.write(z.read(n))
            print('ok')
            sys.exit(0)
print('embedded.mobileprovision not found in IPA')
sys.exit(1)
"#;
    let result = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&ipa_path)
        .arg(&output_path)
        .output()
        .map_err(|e| AppError::Misc(format!("Failed to run extractor: {}", e)))?;
    if !result.status.success() {
        return Err(AppError::Misc(
            String::from_utf8_lossy(&result.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn sign_ipa_and_save(
    sideloader_state: State<'_, SideloaderMutex>,
    ipa_path: String,
    output_path: String,
    bundle_id: Option<String>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;

    let ipa_to_sign = if let Some(bid) = bundle_id.filter(|s| !s.trim().is_empty()) {
        let tmp_ipa = format!("{}.reid.ipa", output_path);
        let script = r#"
import os, sys, zipfile, plistlib, shutil
src = sys.argv[1]; out = sys.argv[2]; new_id = sys.argv[3]
tmp = out + "_extracted"
if os.path.exists(tmp): shutil.rmtree(tmp)
os.makedirs(tmp)
with zipfile.ZipFile(src) as z:
    z.extractall(tmp)
payload = os.path.join(tmp, "Payload")
app_dirs = [d for d in os.listdir(payload) if d.endswith(".app")]
app_dir = os.path.join(payload, app_dirs[0])
main_plist_path = os.path.join(app_dir, "Info.plist")
with open(main_plist_path, "rb") as f:
    main_pl = plistlib.load(f)
old_id = main_pl.get("CFBundleIdentifier", "")
main_pl["CFBundleIdentifier"] = new_id
with open(main_plist_path, "wb") as f:
    plistlib.dump(main_pl, f)
# rewrite extension bundle ids by replacing old prefix
for root, dirs, files in os.walk(payload):
    for fn in files:
        if fn == "Info.plist":
            p = os.path.join(root, fn)
            with open(p, "rb") as f:
                pl = plistlib.load(f)
            bid = pl.get("CFBundleIdentifier")
            if isinstance(bid, str) and old_id and bid.startswith(old_id):
                pl["CFBundleIdentifier"] = new_id + bid[len(old_id):]
                with open(p, "wb") as f:
                    plistlib.dump(pl, f)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
    for root, _, files in os.walk(tmp):
        for fn in files:
            full = os.path.join(root, fn)
            arc = os.path.relpath(full, tmp)
            zout.write(full, arc)
print("ok")
"#;
        let res = std::process::Command::new("python3")
            .arg("-c").arg(script)
            .arg(&ipa_path).arg(&tmp_ipa).arg(&bid)
            .output()
            .map_err(|e| AppError::Misc(format!("Failed to rewrite bundle id: {}", e)))?;
        if !res.status.success() {
            return Err(AppError::Misc(String::from_utf8_lossy(&res.stderr).trim().to_string()));
        }
        tmp_ipa
    } else {
        ipa_path.clone()
    };

    let (signed_app_path, _) = sideloader
        .get_mut()
        .sign_app(
            std::path::PathBuf::from(&ipa_to_sign),
            Some(team),
            false,
            None::<fn(f32) -> std::future::Ready<()>>,
            None,
            None,
        )
        .await
        .map_err(|e| AppError::Misc(format!("Failed to sign IPA: {:?}", e)))?;

    let payload_dir = signed_app_path
        .parent()
        .ok_or_else(|| AppError::Misc("Invalid signed app path".into()))?
        .to_path_buf();

    let script = r#"
import os, sys, zipfile
payload_dir = sys.argv[1]
out = sys.argv[2]
base = os.path.dirname(payload_dir)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(payload_dir):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, base)
            z.write(full, arc)
print('ok')
"#;
    let result = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&payload_dir)
        .arg(&output_path)
        .output()
        .map_err(|e| AppError::Misc(format!("Failed to zip signed IPA: {}", e)))?;
    if !result.status.success() {
        return Err(AppError::Misc(
            String::from_utf8_lossy(&result.stderr).trim().to_string(),
        ));
    }

    Ok(())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}
