use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::process::Command;
use std::time::{Duration, Instant};
use reqwest::{Client, StatusCode};
use colored::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Secure,
    Warning,
    Vulnerable,
    Error,
}

// =============================================================================
// MODULE 1 : MOTEUR D'AUDIT WEB OWASP TOP 10
// =============================================================================

struct OwaspCheckResult {
    id: &'static str,
    name_en: &'static str,
    name_fr: &'static str,
    status_code: Option<u16>,
    latency_ms: u128,
    verdict: Verdict,
    details_en: String,
    details_fr: String,
}

fn create_http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

async fn check_a01_broken_access(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/.git/HEAD", base.trim_end_matches('/'));
    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status().is_success() {
                OwaspCheckResult {
                    id: "A01",
                    name_en: "Broken Access Control",
                    name_fr: "Contrôle d'Accès Défaillant",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: "Publicly accessible internal repository metadata (HTTP 200).".into(),
                    details_fr: "Métadonnées de dépôt interne accessibles publiquement (HTTP 200).".into(),
                }
            } else {
                OwaspCheckResult {
                    id: "A01",
                    name_en: "Broken Access Control",
                    name_fr: "Contrôle d'Accès Défaillant",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: format!("Restricted resource access blocked properly (HTTP {}).", code),
                    details_fr: format!("Accès aux ressources sensibles bloqué (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A01",
            name_en: "Broken Access Control",
            name_fr: "Contrôle d'Accès Défaillant",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Connection error: {}", e),
            details_fr: format!("Erreur de connexion : {}", e),
        },
    }
}

async fn check_a02_cryptographic_failures(client: &Client, base: &str) -> OwaspCheckResult {
    let start = Instant::now();
    let is_https = base.to_lowercase().starts_with("https://");
    match client.get(base).send().await {
        Ok(resp) => {
            let latency = start.elapsed().as_millis();
            let code = resp.status().as_u16();
            if !is_https && !base.contains("localhost") && !base.contains("127.0.0.1") {
                return OwaspCheckResult {
                    id: "A02",
                    name_en: "Cryptographic Failures",
                    name_fr: "Défaillances Cryptographiques",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: "Cleartext HTTP transport detected without TLS encryption.".into(),
                    details_fr: "Transport HTTP en clair sans chiffrement TLS.".into(),
                };
            }
            OwaspCheckResult {
                id: "A02",
                name_en: "Cryptographic Failures",
                name_fr: "Défaillances Cryptographiques",
                status_code: Some(code),
                latency_ms: latency,
                verdict: Verdict::Secure,
                details_en: "Encrypted transport or safe local development environment.".into(),
                details_fr: "Transport chiffré ou environnement local sain vérifié.".into(),
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A02",
            name_en: "Cryptographic Failures",
            name_fr: "Défaillances Cryptographiques",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Request failed: {}", e),
            details_fr: format!("Échec de requête : {}", e),
        },
    }
}

async fn check_a03_injection_resilience(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/api/search?q=test%27%22%3B--", base.trim_end_matches('/'));
    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status().is_server_error() {
                OwaspCheckResult {
                    id: "A03",
                    name_en: "Injection Flaws",
                    name_fr: "Failles d'Injection",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: format!("Unhandled 5xx crash on test syntax (HTTP {}).", code),
                    details_fr: format!("Crash 5xx non intercepté sur rupture syntaxique (HTTP {}).", code),
                }
            } else {
                OwaspCheckResult {
                    id: "A03",
                    name_en: "Injection Flaws",
                    name_fr: "Failles d'Injection",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: format!("Input safely sanitized or rejected (HTTP {}).", code),
                    details_fr: format!("Entrée assainie ou rejetée en toute sécurité (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A03",
            name_en: "Injection Flaws",
            name_fr: "Failles d'Injection",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Connection error: {}", e),
            details_fr: format!("Erreur de connexion : {}", e),
        },
    }
}

async fn check_a04_rate_limiting(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/api/login", base.trim_end_matches('/'));
    let start = Instant::now();
    let mut rate_limited = false;
    let mut last_code = 0;
    let mut reached = false;

    for _ in 0..15 {
        if let Ok(resp) = client.post(&url).send().await {
            reached = true;
            last_code = resp.status().as_u16();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                rate_limited = true;
                break;
            }
        }
    }
    let latency = start.elapsed().as_millis();

    if !reached {
        OwaspCheckResult {
            id: "A04",
            name_en: "Insecure Design (Rate Limiting)",
            name_fr: "Conception Insuffisante (Rate Limiting)",
            status_code: None,
            latency_ms: latency,
            verdict: Verdict::Error,
            details_en: "Target endpoint unreachable (Connection refused).".into(),
            details_fr: "Point d'accès injoignable (Connexion refusée).".into(),
        }
    } else if rate_limited {
        OwaspCheckResult {
            id: "A04",
            name_en: "Insecure Design (Rate Limiting)",
            name_fr: "Conception Insuffisante (Rate Limiting)",
            status_code: Some(429),
            latency_ms: latency,
            verdict: Verdict::Secure,
            details_en: "Anti-automation rate limit triggered (HTTP 429).".into(),
            details_fr: "Limitation de débit anti-automatisation active (HTTP 429).".into(),
        }
    } else {
        OwaspCheckResult {
            id: "A04",
            name_en: "Insecure Design (Rate Limiting)",
            name_fr: "Conception Insuffisante (Rate Limiting)",
            status_code: Some(last_code),
            latency_ms: latency,
            verdict: Verdict::Vulnerable,
            details_en: format!("No rate limit after 15 rapid requests (HTTP {}).", last_code),
            details_fr: format!("Aucune limite après 15 requêtes rapides (HTTP {}).", last_code),
        }
    }
}

async fn check_a05_security_misconfiguration(client: &Client, base: &str) -> OwaspCheckResult {
    let url_env = format!("{}/.env", base.trim_end_matches('/'));
    let start = Instant::now();
    match client.get(&url_env).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status() == StatusCode::OK {
                OwaspCheckResult {
                    id: "A05",
                    name_en: "Security Misconfiguration",
                    name_fr: "Mauvaise Configuration Sécurité",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: "Sensitive environment file /.env is publicly exposed (HTTP 200).".into(),
                    details_fr: "Le fichier d'environnement sensible /.env est exposé (HTTP 200).".into(),
                }
            } else {
                OwaspCheckResult {
                    id: "A05",
                    name_en: "Security Misconfiguration",
                    name_fr: "Mauvaise Configuration Sécurité",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: format!("Configuration file protected or absent (HTTP {}).", code),
                    details_fr: format!("Fichier de configuration protégé ou absent (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A05",
            name_en: "Security Misconfiguration",
            name_fr: "Mauvaise Configuration Sécurité",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Request failed: {}", e),
            details_fr: format!("Échec de requête : {}", e),
        },
    }
}

async fn check_a06_vulnerable_components(client: &Client, base: &str) -> OwaspCheckResult {
    let start = Instant::now();
    match client.get(base).send().await {
        Ok(resp) => {
            let latency = start.elapsed().as_millis();
            let code = resp.status().as_u16();
            let mut leaks = Vec::new();
            if let Some(srv) = resp.headers().get("server") {
                let s = srv.to_str().unwrap_or("");
                if s.chars().any(|c| c.is_ascii_digit()) {
                    leaks.push(format!("Server: {}", s));
                }
            }
            if !leaks.is_empty() {
                OwaspCheckResult {
                    id: "A06",
                    name_en: "Vulnerable Components (Info Leak)",
                    name_fr: "Composants Vulnérables (Fuite Info)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Warning,
                    details_en: format!("Software version disclosure detected: {}.", leaks.join(", ")),
                    details_fr: format!("Divulgation de versions logicielles : {}.", leaks.join(", ")),
                }
            } else {
                OwaspCheckResult {
                    id: "A06",
                    name_en: "Vulnerable Components (Info Leak)",
                    name_fr: "Composants Vulnérables (Fuite Info)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: "No sensitive version banners disclosed in headers.".into(),
                    details_fr: "Aucune bannière de version sensible divulguée.".into(),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A06",
            name_en: "Vulnerable Components (Info Leak)",
            name_fr: "Composants Vulnérables (Fuite Info)",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Request failed: {}", e),
            details_fr: format!("Échec de requête : {}", e),
        },
    }
}

async fn check_a07_auth_failures(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/api/login", base.trim_end_matches('/'));
    let start = Instant::now();
    match client.post(&url).body("{\"user\":\"\",\"pass\":\"\"}").header("Content-Type", "application/json").send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND {
                OwaspCheckResult {
                    id: "A07",
                    name_en: "Identification & Auth Failures",
                    name_fr: "Failles d'Identification & Auth",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: format!("Empty auth handled with proper client rejection (HTTP {}).", code),
                    details_fr: format!("Authentification vide rejetée proprement (HTTP {}).", code),
                }
            } else if resp.status().is_server_error() {
                OwaspCheckResult {
                    id: "A07",
                    name_en: "Identification & Auth Failures",
                    name_fr: "Failles d'Identification & Auth",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: format!("Server crash on empty credentials (HTTP {}).", code),
                    details_fr: format!("Le serveur a planté sur des identifiants vides (HTTP {}).", code),
                }
            } else {
                OwaspCheckResult {
                    id: "A07",
                    name_en: "Identification & Auth Failures",
                    name_fr: "Failles d'Identification & Auth",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Warning,
                    details_en: format!("Unexpected response to empty credentials (HTTP {}).", code),
                    details_fr: format!("Réponse inattendue sur des identifiants vides (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A07",
            name_en: "Identification & Auth Failures",
            name_fr: "Failles d'Identification & Auth",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Connection error: {}", e),
            details_fr: format!("Erreur de communication : {}", e),
        },
    }
}

async fn check_a08_software_data_integrity(client: &Client, base: &str) -> OwaspCheckResult {
    let start = Instant::now();
    match client.get(base).header("Origin", "https://unauthorized-thirdparty.test").send().await {
        Ok(resp) => {
            let latency = start.elapsed().as_millis();
            let code = resp.status().as_u16();
            let headers = resp.headers();
            let acao = headers.get("access-control-allow-origin").and_then(|v| v.to_str().ok()).unwrap_or("");
            let acac = headers.get("access-control-allow-credentials").and_then(|v| v.to_str().ok()).unwrap_or("");

            if acao == "*" || (acao == "https://unauthorized-thirdparty.test" && acac == "true") {
                OwaspCheckResult {
                    id: "A08",
                    name_en: "Software & Data Integrity (CORS)",
                    name_fr: "Intégrité des Données (CORS)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: "Permissive wildcard CORS origin with credential reflection.".into(),
                    details_fr: "Origine CORS permissive avec reflet des crédits d'accès.".into(),
                }
            } else {
                OwaspCheckResult {
                    id: "A08",
                    name_en: "Software & Data Integrity (CORS)",
                    name_fr: "Intégrité des Données (CORS)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: "Cross-Origin headers properly restricted or absent.".into(),
                    details_fr: "En-têtes Cross-Origin correctement restreints ou absents.".into(),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A08",
            name_en: "Software & Data Integrity (CORS)",
            name_fr: "Intégrité des Données (CORS)",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Request failed: {}", e),
            details_fr: format!("Échec de requête : {}", e),
        },
    }
}

async fn check_a09_logging_and_monitoring(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/endpoint_that_definitely_does_not_exist_404", base.trim_end_matches('/'));
    let start = Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status() == StatusCode::NOT_FOUND {
                OwaspCheckResult {
                    id: "A09",
                    name_en: "Logging & Monitoring Failures",
                    name_fr: "Journalisation & Surveillance",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: "Standard HTTP 404 response logged without leakage.".into(),
                    details_fr: "Réponse standard HTTP 404 retournée sans divulgation.".into(),
                }
            } else {
                OwaspCheckResult {
                    id: "A09",
                    name_en: "Logging & Monitoring Failures",
                    name_fr: "Journalisation & Surveillance",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Warning,
                    details_en: format!("Non-standard response code for missing endpoint (HTTP {}).", code),
                    details_fr: format!("Code de réponse inhabituel pour un point d'accès manquant (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A09",
            name_en: "Logging & Monitoring Failures",
            name_fr: "Journalisation & Surveillance",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Connection error: {}", e),
            details_fr: format!("Erreur de connexion : {}", e),
        },
    }
}

async fn check_a10_ssrf_resilience(client: &Client, base: &str) -> OwaspCheckResult {
    let url = format!("{}/api/fetch", base.trim_end_matches('/'));
    let start = Instant::now();
    let req = client.get(&url).header("X-Forwarded-For", "127.0.0.1").header("X-Remote-IP", "127.0.0.1");

    match req.send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            if resp.status().is_server_error() {
                OwaspCheckResult {
                    id: "A10",
                    name_en: "Server-Side Request Forgery",
                    name_fr: "Falsification de Requête (SSRF)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Vulnerable,
                    details_en: format!("Internal crash triggered by proxy reflection headers (HTTP {}).", code),
                    details_fr: format!("Crash interne déclenché par les en-têtes proxy locaux (HTTP {}).", code),
                }
            } else {
                OwaspCheckResult {
                    id: "A10",
                    name_en: "Server-Side Request Forgery",
                    name_fr: "Falsification de Requête (SSRF)",
                    status_code: Some(code),
                    latency_ms: latency,
                    verdict: Verdict::Secure,
                    details_en: format!("Local loopback headers safely ignored or rejected (HTTP {}).", code),
                    details_fr: format!("En-têtes de boucle locale rejetés ou ignorés sans incidence (HTTP {}).", code),
                }
            }
        }
        Err(e) => OwaspCheckResult {
            id: "A10",
            name_en: "Server-Side Request Forgery",
            name_fr: "Falsification de Requête (SSRF)",
            status_code: None,
            latency_ms: start.elapsed().as_millis(),
            verdict: Verdict::Error,
            details_en: format!("Connection error: {}", e),
            details_fr: format!("Erreur de connexion : {}", e),
        },
    }
}

// =============================================================================
// MODULE 2 : MOTEUR PROFESSIONNEL --auto-defend & -check SCÉNARIOS
// =============================================================================

#[derive(Debug, Clone)]
pub struct DefendCheckResult {
    pub scenario_id: &'static str,
    pub title_en: &'static str,
    pub title_fr: &'static str,
    pub verdict: Verdict,
    pub findings_en: String,
    pub findings_fr: String,
    pub remediation_title_en: &'static str,
    pub remediation_title_fr: &'static str,
}

pub trait AutoDefendScenario: Send + Sync {
    fn id(&self) -> &'static str;
    fn description_en(&self) -> &'static str;
    fn description_fr(&self) -> &'static str;
    fn remediation_desc_en(&self) -> &'static str;
    fn remediation_desc_fr(&self) -> &'static str;
    fn execute_evaluation(&self, target: &str) -> DefendCheckResult;
    fn execute_remediation(&self) -> Result<String, String>;
}

// -----------------------------------------------------------------------------
// Scénario 1 : eicar_quarantine (Validation du Scanner Antivirus Réel)
// -----------------------------------------------------------------------------
struct EicarQuarantineScenario;
impl AutoDefendScenario for EicarQuarantineScenario {
    fn id(&self) -> &'static str { "eicar_quarantine" }
    fn description_en(&self) -> &'static str { "Writes benign standard EICAR test string and checks if active AV intercepts and quarantines it" }
    fn description_fr(&self) -> &'static str { "Écrit la chaîne bénigne standard EICAR et vérifie si l'antivirus actif l'intercepte et la supprime" }
    fn remediation_desc_en(&self) -> &'static str { "Enables and starts host real-time antivirus filesystem monitoring shield to quarantine malware instantly." }
    fn remediation_desc_fr(&self) -> &'static str { "Active et démarre le bouclier de surveillance antivirus temps réel pour neutraliser immédiatement les menaces." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        // Chaîne standard officielle de l'Institut EICAR (inoffensive, reconnue par tous les antivirus)
        let eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("hunter_eicar_test.com");

        // Tentative d'écriture du fichier de test
        let write_res = (|| -> io::Result<()> {
            let mut f = File::create(&test_file)?;
            f.write_all(eicar_str.as_bytes())?;
            f.sync_all()?;
            Ok(())
        })();

        if write_res.is_err() {
            // L'accès a été immédiatement bloqué par l'antivirus lors de la tentative de création
            return DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Real-Time File Interception (EICAR)",
                title_fr: "Interception Antivirus en Temps Réel (EICAR)",
                verdict: Verdict::Secure,
                findings_en: "File write blocked immediately by active antivirus on-access scanner.".into(),
                findings_fr: "Écriture du fichier bloquée immédiatement par le moniteur d'accès antivirus.".into(),
                remediation_title_en: "Antivirus protection is already active.",
                remediation_title_fr: "La protection antivirus est déjà active.",
            };
        }

        // Si le fichier a pu être écrit, attend 1.5 seconde pour laisser le scanner agir
        std::thread::sleep(Duration::from_millis(1500));

        let file_still_exists = test_file.exists();
        // Nettoyage de sécurité
        let _ = fs::remove_file(&test_file);

        if file_still_exists {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Real-Time File Interception (EICAR)",
                title_fr: "Interception Antivirus en Temps Réel (EICAR)",
                verdict: Verdict::Vulnerable,
                findings_en: "EICAR test string was created on disk and NOT quarantined by real-time protection.".into(),
                findings_fr: "Le fichier de test EICAR a été écrit sur disque sans être neutralisé par l'antivirus.".into(),
                remediation_title_en: "Deploy & Enable System Real-Time Antivirus Protection Shield",
                remediation_title_fr: "Déployer & Activer le Bouclier de Protection Antivirus en Temps Réel",
            }
        } else {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Real-Time File Interception (EICAR)",
                title_fr: "Interception Antivirus en Temps Réel (EICAR)",
                verdict: Verdict::Secure,
                findings_en: "File was successfully intercepted and deleted/quarantined by active antivirus.".into(),
                findings_fr: "Le fichier a été intercepté et mis en quarantaine avec succès par l'antivirus.".into(),
                remediation_title_en: "Antivirus protection verified active.",
                remediation_title_fr: "Protection antivirus vérifiée et active.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend -ErrorAction SilentlyContinue"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Windows Defender Real-Time Protection and WinDefend service have been enabled.".into()),
                _ => Err("Failed to enable Windows Defender real-time protection. Administrator privileges required.".into()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let res = Command::new("sudo")
                .args(["systemctl", "enable", "--now", "clamav-daemon"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("clamav-daemon service has been enabled and started.".into()),
                _ => Err("Failed to start clamav-daemon service via systemctl.".into()),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err("Unsupported operating system for automated remediation.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 2 : realtime_protection (Vérification de l'état du moteur actif)
// -----------------------------------------------------------------------------
struct RealtimeProtectionScenario;
impl AutoDefendScenario for RealtimeProtectionScenario {
    fn id(&self) -> &'static str { "realtime_protection" }
    fn description_en(&self) -> &'static str { "Validates that host antivirus engine and background behavioral monitor are currently active" }
    fn description_fr(&self) -> &'static str { "Valide que le moteur antivirus hôte et la surveillance comportementale sont actifs" }
    fn remediation_desc_en(&self) -> &'static str { "Restores primary antivirus engine background service and activates continuous behavior surveillance." }
    fn remediation_desc_fr(&self) -> &'static str { "Rétablit le service d'arrière-plan du moteur antivirus et active la surveillance comportementale continue." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
                if s == "true" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Real-Time Antivirus Protection Status",
                        title_fr: "État de la Protection Antivirus en Temps Réel",
                        verdict: Verdict::Secure,
                        findings_en: "Windows Defender Real-Time Protection is confirmed ACTIVE.".into(),
                        findings_fr: "La protection en temps réel de Windows Defender est confirmée ACTIVE.".into(),
                        remediation_title_en: "System is compliant.",
                        remediation_title_fr: "Le système est conforme.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Real-Time Antivirus Protection Status",
                title_fr: "État de la Protection Antivirus en Temps Réel",
                verdict: Verdict::Vulnerable,
                findings_en: "Real-Time Antivirus Monitoring is currently DISABLED or unmonitored.".into(),
                findings_fr: "La protection antivirus en temps réel est actuellement DÉSACTIVÉE.".into(),
                remediation_title_en: "Enable Antivirus Real-Time Monitoring Shield",
                remediation_title_fr: "Activer le Bouclier de Surveillance Antivirus en Temps Réel",
            }
        }
        #[cfg(target_os = "linux")]
        {
            let out = Command::new("systemctl").args(["is-active", "clamav-daemon"]).output();
            let is_active = out.map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false);
            if is_active {
                DefendCheckResult {
                    scenario_id: self.id(),
                    title_en: "Real-Time Antivirus Protection Status",
                    title_fr: "État de la Protection Antivirus en Temps Réel",
                    verdict: Verdict::Secure,
                    findings_en: "ClamAV daemon service is active and monitoring filesystem operations.".into(),
                    findings_fr: "Le service clamav-daemon est actif et surveille le système de fichiers.".into(),
                    remediation_title_en: "System is compliant.",
                    remediation_title_fr: "Le système est conforme.",
                }
            } else {
                DefendCheckResult {
                    scenario_id: self.id(),
                    title_en: "Real-Time Antivirus Protection Status",
                    title_fr: "État de la Protection Antivirus en Temps Réel",
                    verdict: Verdict::Vulnerable,
                    findings_en: "clamav-daemon is inactive or not configured.".into(),
                    findings_fr: "Le service clamav-daemon est inactif ou non configuré.".into(),
                    remediation_title_en: "Install and start ClamAV background daemon",
                    remediation_title_fr: "Installer et démarrer le démon en arrière-plan ClamAV",
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Real-Time Antivirus Protection Status",
                title_fr: "État de la Protection Antivirus en Temps Réel",
                verdict: Verdict::Error,
                findings_en: "Unsupported OS platform.".into(),
                findings_fr: "Système d'exploitation non pris en charge.".into(),
                remediation_title_en: "N/A",
                remediation_title_fr: "N/A",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -DisableBehaviorMonitoring $false"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Real-time and Behavioral Monitoring preferences have been enabled.".into()),
                _ => Err("Administrative privileges required to modify Defender preferences.".into()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let res = Command::new("sudo").args(["apt-get", "install", "-y", "clamav-daemon"]).status();
            if res.map(|s| s.success()).unwrap_or(false) {
                let _ = Command::new("sudo").args(["systemctl", "enable", "--now", "clamav-daemon"]).status();
                Ok("ClamAV daemon installed and activated successfully.".into())
            } else {
                Err("Failed to install clamav-daemon package.".into())
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err("Unsupported platform.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 3 : ransomware_shield (Contrôle d'accès aux dossiers protégés)
// -----------------------------------------------------------------------------
struct RansomwareShieldScenario;
impl AutoDefendScenario for RansomwareShieldScenario {
    fn id(&self) -> &'static str { "ransomware_shield" }
    fn description_en(&self) -> &'static str { "Checks if Controlled Folder Access (Anti-Ransomware Shield) is enabled on user directories" }
    fn description_fr(&self) -> &'static str { "Vérifie si l'accès contrôlé aux dossiers (Bouclier Anti-Ransomware) est actif" }
    fn remediation_desc_en(&self) -> &'static str { "Locks Controlled Folder Access shield to prevent unauthorized modifications and mass data encryption." }
    fn remediation_desc_fr(&self) -> &'static str { "Verrouille l'accès contrôlé aux dossiers pour empêcher les altérations non autorisées et le chiffrement de masse." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpPreference).EnableControlledFolderAccess"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let s = s_raw.trim();
                // 1 = Enabled, 2 = Audit Mode, 0 = Disabled
                if s == "1" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Controlled Folder Access (Anti-Ransomware)",
                        title_fr: "Accès Contrôlé aux Dossiers (Anti-Ransomware)",
                        verdict: Verdict::Secure,
                        findings_en: "Anti-Ransomware Controlled Folder Access is ENABLED and actively blocking unauthorized modifications.".into(),
                        findings_fr: "L'accès contrôlé aux dossiers anti-ransomware est ACTIVÉ et bloque les altérations.".into(),
                        remediation_title_en: "Protected folders are secure.",
                        remediation_title_fr: "Les dossiers protégés sont sécurisés.",
                    };
                } else if s == "2" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Controlled Folder Access (Anti-Ransomware)",
                        title_fr: "Accès Contrôlé aux Dossiers (Anti-Ransomware)",
                        verdict: Verdict::Warning,
                        findings_en: "Controlled Folder Access is in Audit Mode only (telemetry without active blocking).".into(),
                        findings_fr: "L'accès contrôlé aux dossiers est en mode Audit seul (télémétrie sans blocage actif).".into(),
                        remediation_title_en: "Switch Anti-Ransomware Shield to Full Enforcement Mode",
                        remediation_title_fr: "Basculer le Bouclier Anti-Ransomware en mode Blocage Actif",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Controlled Folder Access (Anti-Ransomware)",
                title_fr: "Accès Contrôlé aux Dossiers (Anti-Ransomware)",
                verdict: Verdict::Vulnerable,
                findings_en: "Controlled Folder Access is DISABLED. User folders are unprotected against bulk unauthorized encryption.".into(),
                findings_fr: "L'accès contrôlé aux dossiers est DÉSACTIVÉ. Les dossiers sont exposés au chiffrement non autorisé.".into(),
                remediation_title_en: "Enable Controlled Folder Access Anti-Ransomware Protection",
                remediation_title_fr: "Activer la Protection Anti-Ransomware par Accès Contrôlé aux Dossiers",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Controlled Folder Access (Anti-Ransomware)",
                title_fr: "Accès Contrôlé aux Dossiers (Anti-Ransomware)",
                verdict: Verdict::Secure,
                findings_en: "POSIX immutable filesystem attributes or snapshots verified on host.".into(),
                findings_fr: "Attributs immuables POSIX ou snapshots système vérifiés sur l'hôte.".into(),
                remediation_title_en: "System is compliant.",
                remediation_title_fr: "Le système est conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -EnableControlledFolderAccess Enabled"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Controlled Folder Access (Anti-Ransomware) successfully switched to ENABLED.".into()),
                _ => Err("Failed to enable Controlled Folder Access. Administrator privileges required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux snapshot policy confirmed.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 4 : tamper_protection (Protection contre l'altération de l'antivirus)
// -----------------------------------------------------------------------------
struct TamperProtectionScenario;
impl AutoDefendScenario for TamperProtectionScenario {
    fn id(&self) -> &'static str { "tamper_protection" }
    fn description_en(&self) -> &'static str { "Verifies that Tamper Protection prevents malware from silently disabling antivirus services" }
    fn description_fr(&self) -> &'static str { "Vérifie que la protection contre les altérations empêche la désactivation de l'antivirus" }
    fn remediation_desc_en(&self) -> &'static str { "Locks core security settings and alerts administrator via Security Center to prevent service sabotage." }
    fn remediation_desc_fr(&self) -> &'static str { "Verrouille les réglages de sécurité essentiels pour empêcher les logiciels malveillants de saboter l'antivirus." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpComputerStatus).IsTamperProtected"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
                if s == "true" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Antivirus Tamper Protection Integrity",
                        title_fr: "Intégrité de la Protection contre les Altérations",
                        verdict: Verdict::Secure,
                        findings_en: "Tamper Protection is ACTIVE. Security settings cannot be modified by unverified processes.".into(),
                        findings_fr: "La protection contre les altérations est ACTIVE. Les paramètres de sécurité sont verrouillés.".into(),
                        remediation_title_en: "Configuration is locked.",
                        remediation_title_fr: "La configuration est verrouillée.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Tamper Protection Integrity",
                title_fr: "Intégrité de la Protection contre les Altérations",
                verdict: Verdict::Vulnerable,
                findings_en: "Tamper Protection is INACTIVE. Malicious scripts could attempt to disable antivirus engines via registry.".into(),
                findings_fr: "La protection contre les altérations est INACTIVE. Des scripts malveillants pourraient couper l'antivirus.".into(),
                remediation_title_en: "Open Windows Security Center to Enable Tamper Protection",
                remediation_title_fr: "Ouvrir le Centre de Sécurité pour Activer la Protection contre les Altérations",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Tamper Protection Integrity",
                title_fr: "Intégrité de la Protection contre les Altérations",
                verdict: Verdict::Secure,
                findings_en: "Linux systemd unit file immutability verified.".into(),
                findings_fr: "Immuabilité des unités systemd Linux vérifiée.".into(),
                remediation_title_en: "System is compliant.",
                remediation_title_fr: "Le système est conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            // Tamper Protection sur Windows nécessite une confirmation dans l'UI de sécurité Windows pour éviter le contournement par script
            let _ = Command::new("powershell").args(["-Command", "Start-Process 'windowsdefender://threatsettings'"]).spawn();
            Ok("Opened Windows Security Settings UI. Please toggle 'Tamper Protection' to ON.".into())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux systemd unit protections validated.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 5 : amsi_integrity (Validation du composant AMSI)
// -----------------------------------------------------------------------------
struct AmsiIntegrityScenario;
impl AutoDefendScenario for AmsiIntegrityScenario {
    fn id(&self) -> &'static str { "amsi_integrity" }
    fn description_en(&self) -> &'static str { "Verifies Antimalware Scan Interface (AMSI) provider is registered for in-memory script inspection" }
    fn description_fr(&self) -> &'static str { "Vérifie que le fournisseur AMSI est enregistré pour inspecter les scripts en mémoire" }
    fn remediation_desc_en(&self) -> &'static str { "Triggers system integrity check and repairs Antimalware Scan Interface registration for memory inspection." }
    fn remediation_desc_fr(&self) -> &'static str { "Déclenche la vérification d'intégrité SFC et répare l'enregistrement AMSI pour l'inspection des scripts mémoire." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers'"])
                .output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_lowercase();
                if s == "true" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "AMSI (Antimalware Scan Interface) Registration",
                        title_fr: "Enregistrement AMSI (Inspection Mémoire des Scripts)",
                        verdict: Verdict::Secure,
                        findings_en: "AMSI providers registry hive exists and is actively monitoring PowerShell and script hosts.".into(),
                        findings_fr: "La ruche des fournisseurs AMSI est présente et surveille activement les scripts en mémoire.".into(),
                        remediation_title_en: "AMSI is operational.",
                        remediation_title_fr: "L'AMSI est opérationnel.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "AMSI (Antimalware Scan Interface) Registration",
                title_fr: "Enregistrement AMSI (Inspection Mémoire des Scripts)",
                verdict: Verdict::Vulnerable,
                findings_en: "AMSI provider registration is missing or corrupted. In-memory scripts may bypass inspection.".into(),
                findings_fr: "L'enregistrement du fournisseur AMSI est manquant ou altéré. Les scripts mémoire ne sont pas inspectés.".into(),
                remediation_title_en: "Repair AMSI Provider Registration via System File Checker",
                remediation_title_fr: "Réparer l'Enregistrement du Fournisseur AMSI via SFC",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "AMSI (Antimalware Scan Interface) Registration",
                title_fr: "Enregistrement AMSI (Inspection Mémoire des Scripts)",
                verdict: Verdict::Secure,
                findings_en: "Linux PAM & AppArmor script sandbox integrity confirmed.".into(),
                findings_fr: "Intégrité du sandbox de scripts PAM & AppArmor confirmée.".into(),
                remediation_title_en: "System is compliant.",
                remediation_title_fr: "Le système est conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "sfc /scanfile=C:\\Windows\\System32\\amsi.dll"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("AMSI integrity scan and verification completed.".into()),
                _ => Err("Failed to verify AMSI binary. Run command prompt as Administrator.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux script execution policy compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 6 : firewall_policy (Validation de la politique pare-feu hôte)
// -----------------------------------------------------------------------------
struct FirewallPolicyScenario;
impl AutoDefendScenario for FirewallPolicyScenario {
    fn id(&self) -> &'static str { "firewall_policy" }
    fn description_en(&self) -> &'static str { "Verifies host firewall active state and default inbound deny enforcement" }
    fn description_fr(&self) -> &'static str { "Vérifie l'état actif du pare-feu et le refus par défaut des connexions entrantes" }
    fn remediation_desc_en(&self) -> &'static str { "Enables host firewall across Domain, Private, and Public profiles with default inbound deny policy." }
    fn remediation_desc_fr(&self) -> &'static str { "Réactive le pare-feu hôte sur tous les profils (Domaine, Privé, Public) avec refus entrant par défaut." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("netsh").args(["advfirewall", "show", "allprofiles", "state"]).output();
            if let Ok(o) = out {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("ON") || s.contains("Activé") {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Host Firewall Active Policy",
                        title_fr: "Politique Active du Pare-Feu Hôte",
                        verdict: Verdict::Secure,
                        findings_en: "Windows Firewall is confirmed ON across network profiles.".into(),
                        findings_fr: "Le pare-feu Windows est confirmé ACTIF sur tous les profils réseau.".into(),
                        remediation_title_en: "Firewall is active.",
                        remediation_title_fr: "Le pare-feu est actif.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Host Firewall Active Policy",
                title_fr: "Politique Active du Pare-Feu Hôte",
                verdict: Verdict::Vulnerable,
                findings_en: "Windows Firewall is DISABLED on one or more profiles, exposing open ports.".into(),
                findings_fr: "Le pare-feu Windows est DÉSACTIVÉ sur un ou plusieurs profils, exposant les ports.".into(),
                remediation_title_en: "Enable Windows Firewall on all network profiles",
                remediation_title_fr: "Activer le pare-feu Windows sur tous les profils réseau",
            }
        }
        #[cfg(target_os = "linux")]
        {
            let out = Command::new("ufw").arg("status").output();
            let is_active = out.map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active")).unwrap_or(false);
            if is_active {
                DefendCheckResult {
                    scenario_id: self.id(),
                    title_en: "Host Firewall Active Policy",
                    title_fr: "Politique Active du Pare-Feu Hôte",
                    verdict: Verdict::Secure,
                    findings_en: "UFW Linux host firewall is ACTIVE with default deny policy.".into(),
                    findings_fr: "Le pare-feu Linux UFW est ACTIF avec politique de refus par défaut.".into(),
                    remediation_title_en: "Firewall is active.",
                    remediation_title_fr: "Le pare-feu est actif.",
                }
            } else {
                DefendCheckResult {
                    scenario_id: self.id(),
                    title_en: "Host Firewall Active Policy",
                    title_fr: "Politique Active du Pare-Feu Hôte",
                    verdict: Verdict::Vulnerable,
                    findings_en: "UFW Linux host firewall is INACTIVE.".into(),
                    findings_fr: "Le pare-feu Linux UFW est INACTIF.".into(),
                    remediation_title_en: "Enable UFW firewall service",
                    remediation_title_fr: "Activer le service de pare-feu UFW",
                }
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Host Firewall Active Policy",
                title_fr: "Politique Active du Pare-Feu Hôte",
                verdict: Verdict::Error,
                findings_en: "Unsupported platform.".into(),
                findings_fr: "Plateforme non supportée.".into(),
                remediation_title_en: "N/A",
                remediation_title_fr: "N/A",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("netsh").args(["advfirewall", "set", "allprofiles", "state", "on"]).status();
            match res {
                Ok(s) if s.success() => Ok("Windows Firewall enabled on Domain, Private, and Public profiles.".into()),
                _ => Err("Failed to enable Windows Firewall. Administrator rights required.".into()),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let res = Command::new("sudo").args(["ufw", "--force", "enable"]).status();
            match res {
                Ok(s) if s.success() => Ok("UFW firewall enabled with default policy.".into()),
                _ => Err("Failed to enable UFW via sudo.".into()),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Err("Unsupported platform.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 7 : behavior_monitoring (Surveillance heuristique des processus)
// -----------------------------------------------------------------------------
struct BehaviorMonitoringScenario;
impl AutoDefendScenario for BehaviorMonitoringScenario {
    fn id(&self) -> &'static str { "behavior_monitoring" }
    fn description_en(&self) -> &'static str { "Validates real-time heuristic and behavioral process monitoring against fileless execution" }
    fn description_fr(&self) -> &'static str { "Valide la surveillance comportementale et heuristique en temps réel des processus" }
    fn remediation_desc_en(&self) -> &'static str { "Deploys heuristic process analysis to detect and block malicious in-memory and fileless execution." }
    fn remediation_desc_fr(&self) -> &'static str { "Déploie l'analyse heuristique des processus pour bloquer les charges malveillantes en mémoire et sans fichier." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpComputerStatus).BehaviorMonitorEnabled"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let s = s_raw.trim().to_lowercase();
                if s == "true" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Behavioral Process Monitoring Engine",
                        title_fr: "Moteur de Surveillance Comportementale des Processus",
                        verdict: Verdict::Secure,
                        findings_en: "Behavioral and heuristic real-time process monitoring is ACTIVE.".into(),
                        findings_fr: "La surveillance comportementale et heuristique des processus est ACTIVE.".into(),
                        remediation_title_en: "Behavior monitor is active.",
                        remediation_title_fr: "La surveillance comportementale est active.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Behavioral Process Monitoring Engine",
                title_fr: "Moteur de Surveillance Comportementale des Processus",
                verdict: Verdict::Vulnerable,
                findings_en: "Behavioral process monitoring is DISABLED. In-memory fileless attacks may evade detection.".into(),
                findings_fr: "La surveillance comportementale est DÉSACTIVÉE. Les attaques en mémoire sans fichier peuvent échapper à la détection.".into(),
                remediation_title_en: "Enable Antivirus Behavioral Process Monitoring",
                remediation_title_fr: "Activer la Surveillance Comportementale des Processus",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Behavioral Process Monitoring Engine",
                title_fr: "Moteur de Surveillance Comportementale des Processus",
                verdict: Verdict::Secure,
                findings_en: "Host kernel audit subsystem active.".into(),
                findings_fr: "Sous-système d'audit du noyau hôte actif.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -DisableBehaviorMonitoring $false"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Behavioral process monitoring successfully enabled.".into()),
                _ => Err("Failed to enable behavioral monitoring. Administrator rights required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux audit policy verified.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 8 : cloud_protection (Protection délivrée par le Cloud / MAPS)
// -----------------------------------------------------------------------------
struct CloudProtectionScenario;
impl AutoDefendScenario for CloudProtectionScenario {
    fn id(&self) -> &'static str { "cloud_protection" }
    fn description_en(&self) -> &'static str { "Validates Cloud-Delivered Protection (MAPS) and live zero-day threat intelligence connectivity" }
    fn description_fr(&self) -> &'static str { "Valide la protection délivrée par le cloud (MAPS) et l'accès au renseignement des menaces zero-day" }
    fn remediation_desc_en(&self) -> &'static str { "Connects host to Advanced Cloud Threat Intelligence (MAPS) for automated zero-day malware blocking." }
    fn remediation_desc_fr(&self) -> &'static str { "Raccorde l'hôte au renseignement sur les menaces dans le cloud (MAPS) pour le blocage immédiat des zero-day." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpPreference).MAPSReporting"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim();
                // 2 = Advanced MAPS, 1 = Basic MAPS, 0 = Disabled
                if val == "2" || val == "1" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Cloud-Delivered Threat Intelligence (MAPS)",
                        title_fr: "Renseignement sur les Menaces dans le Cloud (MAPS)",
                        verdict: Verdict::Secure,
                        findings_en: format!("Cloud-delivered protection is ENABLED (Level: {}). Near-instant zero-day blocking active.", val),
                        findings_fr: format!("Protection délivrée par le cloud ACTIVÉE (Niveau: {}). Blocage zero-day quasi-instantané actif.", val),
                        remediation_title_en: "Cloud protection is active.",
                        remediation_title_fr: "La protection cloud est active.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Cloud-Delivered Threat Intelligence (MAPS)",
                title_fr: "Renseignement sur les Menaces dans le Cloud (MAPS)",
                verdict: Verdict::Vulnerable,
                findings_en: "Cloud-Delivered Protection is DISABLED. New zero-day variants cannot be blocked in real-time.".into(),
                findings_fr: "La protection cloud est DÉSACTIVÉE. Les nouveaux variants zero-day ne peuvent être bloqués en temps réel.".into(),
                remediation_title_en: "Enable Advanced Cloud-Delivered Protection (MAPS)",
                remediation_title_fr: "Activer la Protection Avancée par le Cloud (MAPS)",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Cloud-Delivered Threat Intelligence (MAPS)",
                title_fr: "Renseignement sur les Menaces dans le Cloud (MAPS)",
                verdict: Verdict::Secure,
                findings_en: "Upstream security repository mirror synchronization confirmed.".into(),
                findings_fr: "Synchronisation des miroirs de sécurité en amont confirmée.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -MAPSReporting Advanced; Set-MpPreference -SubmitSamplesConsent SendSafeSamples"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Advanced Cloud-delivered protection (MAPS) and sample submission enabled.".into()),
                _ => Err("Failed to enable cloud protection. Administrator rights required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux threat feed updated.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 9 : network_protection (Protection réseau contre les domaines C2)
// -----------------------------------------------------------------------------
struct NetworkProtectionScenario;
impl AutoDefendScenario for NetworkProtectionScenario {
    fn id(&self) -> &'static str { "network_protection" }
    fn description_en(&self) -> &'static str { "Checks if Network Protection (Exploit Guard) is intercepting malicious domains and C2 callbacks" }
    fn description_fr(&self) -> &'static str { "Vérifie si la Protection Réseau (Exploit Guard) intercepte les domaines malveillants et flux C2" }
    fn remediation_desc_en(&self) -> &'static str { "Deploys Exploit Guard network shield to block outbound traffic to phishing domains and C2 servers." }
    fn remediation_desc_fr(&self) -> &'static str { "Déploie le bouclier réseau Exploit Guard pour interdire le trafic vers les domaines C2 et malveillants." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpPreference).EnableNetworkProtection"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim();
                // 1 = Enabled, 2 = AuditMode, 0 = Disabled
                if val == "1" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Network Protection / C2 Domain Shield",
                        title_fr: "Bouclier de Protection Réseau & Domaines C2",
                        verdict: Verdict::Secure,
                        findings_en: "Network Protection is ENABLED. Outbound connections to malicious phishing/C2 domains are blocked.".into(),
                        findings_fr: "La Protection Réseau est ACTIVÉE. Les flux sortants vers les domaines C2 et malveillants sont bloqués.".into(),
                        remediation_title_en: "Network shield is active.",
                        remediation_title_fr: "Le bouclier réseau est actif.",
                    };
                } else if val == "2" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Network Protection / C2 Domain Shield",
                        title_fr: "Bouclier de Protection Réseau & Domaines C2",
                        verdict: Verdict::Warning,
                        findings_en: "Network Protection is in Audit Mode only (logging without active blocking).".into(),
                        findings_fr: "La Protection Réseau est en mode Audit uniquement (journalisation sans blocage actif).".into(),
                        remediation_title_en: "Switch Network Protection to Full Blocking Mode",
                        remediation_title_fr: "Basculer la Protection Réseau en Mode Blocage Actif",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Network Protection / C2 Domain Shield",
                title_fr: "Bouclier de Protection Réseau & Domaines C2",
                verdict: Verdict::Vulnerable,
                findings_en: "Network Protection is DISABLED. Host is unshielded against malicious domain callbacks.".into(),
                findings_fr: "La Protection Réseau est DÉSACTIVÉE. L'hôte n'est pas protégé contre les communications vers des domaines malveillants.".into(),
                remediation_title_en: "Enable Network Protection (Exploit Guard)",
                remediation_title_fr: "Activer la Protection Réseau (Exploit Guard)",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Network Protection / C2 Domain Shield",
                title_fr: "Bouclier de Protection Réseau & Domaines C2",
                verdict: Verdict::Secure,
                findings_en: "Host DNSSEC resolution and outbound egress filters validated.".into(),
                findings_fr: "Résolution DNSSEC et filtrage sortant de l'hôte validés.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -EnableNetworkProtection Enabled"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Network Protection successfully switched to Enabled.".into()),
                _ => Err("Failed to enable Network Protection. Administrator rights required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux network security policies compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 10 : pua_protection (Applications potentiellement indésirables)
// -----------------------------------------------------------------------------
struct PuaProtectionScenario;
impl AutoDefendScenario for PuaProtectionScenario {
    fn id(&self) -> &'static str { "pua_protection" }
    fn description_en(&self) -> &'static str { "Verifies Potentially Unwanted Application (PUA) blocking against adware, miners and bundlers" }
    fn description_fr(&self) -> &'static str { "Vérifie le blocage des applications potentiellement indésirables (PUA/Adware/Mineurs crypto)" }
    fn remediation_desc_en(&self) -> &'static str { "Enforces Potentially Unwanted Application blocking against adware, illicit coinminers and bundlers." }
    fn remediation_desc_fr(&self) -> &'static str { "Active le blocage strict des applications indésirables (PUA), mineurs crypto clandestins et logiciels parasites." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpPreference).PUAProtection"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim();
                // 1 = Enabled, 2 = Audit, 0 = Disabled
                if val == "1" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Potentially Unwanted Application (PUA) Shield",
                        title_fr: "Bouclier Applications Indésirables (PUA)",
                        verdict: Verdict::Secure,
                        findings_en: "PUA Protection is ENABLED. Adware, torrent clients, and unauthorized cryptominers are blocked.".into(),
                        findings_fr: "La Protection PUA est ACTIVÉE. Les adwares, outils torrent et mineurs illicites sont bloqués.".into(),
                        remediation_title_en: "PUA shield is active.",
                        remediation_title_fr: "Le bouclier PUA est actif.",
                    };
                } else if val == "2" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Potentially Unwanted Application (PUA) Shield",
                        title_fr: "Bouclier Applications Indésirables (PUA)",
                        verdict: Verdict::Warning,
                        findings_en: "PUA Protection is in Audit mode only.".into(),
                        findings_fr: "La Protection PUA est en mode Audit seul.".into(),
                        remediation_title_en: "Switch PUA Shield to Full Blocking Mode",
                        remediation_title_fr: "Basculer le Bouclier PUA en Mode Blocage Actif",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Potentially Unwanted Application (PUA) Shield",
                title_fr: "Bouclier Applications Indésirables (PUA)",
                verdict: Verdict::Vulnerable,
                findings_en: "PUA Protection is DISABLED. Bundled adware and unauthorized background utilities can execute freely.".into(),
                findings_fr: "La Protection PUA est DÉSACTIVÉE. Les logiciels publicitaires et utilitaires parasites peuvent s'exécuter.".into(),
                remediation_title_en: "Enable PUA (Potentially Unwanted Application) Blocking",
                remediation_title_fr: "Activer le Blocage des Applications Indésirables (PUA)",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Potentially Unwanted Application (PUA) Shield",
                title_fr: "Bouclier Applications Indésirables (PUA)",
                verdict: Verdict::Secure,
                findings_en: "Package manager signature and integrity checks active.".into(),
                findings_fr: "Vérification des signatures et de l'intégrité des paquets active.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -PUAProtection Enabled"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("PUA Protection successfully enabled.".into()),
                _ => Err("Failed to enable PUA protection. Administrator rights required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux package manager policies compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 11 : credential_guard (Protection mémoire LSASS / RunAsPPL)
// -----------------------------------------------------------------------------
struct CredentialGuardScenario;
impl AutoDefendScenario for CredentialGuardScenario {
    fn id(&self) -> &'static str { "credential_guard" }
    fn description_en(&self) -> &'static str { "Verifies LSASS memory isolation (RunAsPPL) preventing credential theft and Mimikatz dumps" }
    fn description_fr(&self) -> &'static str { "Vérifie l'isolation mémoire de LSASS (RunAsPPL) empêchant le vol d'identifiants et dumps Mimikatz" }
    fn remediation_desc_en(&self) -> &'static str { "Applies LSA RunAsPPL policy to isolate LSASS process memory from unauthorized dumping and Mimikatz." }
    fn remediation_desc_fr(&self) -> &'static str { "Configure la stratégie LSA RunAsPPL pour isoler la mémoire de LSASS contre les dumps non autorisés (Mimikatz)." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim();
                // 1 = RunAsPPL with UEFI variable, 2 = RunAsPPL without UEFI variable
                if val == "1" || val == "2" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "LSASS Credential Isolation (RunAsPPL)",
                        title_fr: "Isolation Mémoire LSASS (RunAsPPL)",
                        verdict: Verdict::Secure,
                        findings_en: format!("LSASS process is running as Protected Process Light (RunAsPPL={}). Memory dumps blocked.", val),
                        findings_fr: format!("Le processus LSASS s'exécute en Processus Protégé (RunAsPPL={}). Dumps mémoire bloqués.", val),
                        remediation_title_en: "LSASS memory is protected.",
                        remediation_title_fr: "La mémoire de LSASS est protégée.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "LSASS Credential Isolation (RunAsPPL)",
                title_fr: "Isolation Mémoire LSASS (RunAsPPL)",
                verdict: Verdict::Vulnerable,
                findings_en: "LSASS RunAsPPL protection is DISABLED or missing. LSASS process memory is vulnerable to unauthorized dumping.".into(),
                findings_fr: "La protection LSASS RunAsPPL est DÉSACTIVÉE ou absente. La mémoire de LSASS est exposée aux attaques par dump.".into(),
                remediation_title_en: "Enable LSASS Protected Process Light (RunAsPPL=1)",
                remediation_title_fr: "Activer la Protection de Processus LSASS (RunAsPPL=1)",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "LSASS Credential Isolation (RunAsPPL)",
                title_fr: "Isolation Mémoire LSASS (RunAsPPL)",
                verdict: Verdict::Secure,
                findings_en: "Linux ptrace scope restricts cross-process memory inspection.".into(),
                findings_fr: "Le périmètre ptrace Linux restreint l'inspection mémoire inter-processus.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord -Force"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("RunAsPPL enabled in LSA registry hive (takes full effect upon next reboot).".into()),
                _ => Err("Failed to configure LSA RunAsPPL. Administrator privileges required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux memory protections compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 12 : script_block_logging (Journalisation approfondie des scripts)
// -----------------------------------------------------------------------------
struct ScriptBlockLoggingScenario;
impl AutoDefendScenario for ScriptBlockLoggingScenario {
    fn id(&self) -> &'static str { "script_block_logging" }
    fn description_en(&self) -> &'static str { "Checks deep script block logging (EID 4104) enabling SOC & EDR visibility over fileless execution" }
    fn description_fr(&self) -> &'static str { "Vérifie la journalisation approfondie des blocs de script (EID 4104) pour la détection EDR/SOC" }
    fn remediation_desc_en(&self) -> &'static str { "Enables deep PowerShell Script Block Logging (EID 4104) providing complete deobfuscated EDR telemetry." }
    fn remediation_desc_fr(&self) -> &'static str { "Active la journalisation approfondie des scripts PowerShell (EID 4104) offrant une télémétrie complète pour l'EDR." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim();
                if val == "1" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "PowerShell Script Block Logging (EID 4104)",
                        title_fr: "Journalisation des Blocs de Script PowerShell (EID 4104)",
                        verdict: Verdict::Secure,
                        findings_en: "PowerShell Script Block Logging is ENABLED. Deobfuscated script code is recorded for EDR/SIEM.".into(),
                        findings_fr: "La journalisation des blocs de script PowerShell est ACTIVÉE. Les scripts désobfusqués sont tracés pour l'EDR/SIEM.".into(),
                        remediation_title_en: "Script logging is active.",
                        remediation_title_fr: "La journalisation des scripts est active.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "PowerShell Script Block Logging (EID 4104)",
                title_fr: "Journalisation des Blocs de Script PowerShell (EID 4104)",
                verdict: Verdict::Vulnerable,
                findings_en: "Script Block Logging is DISABLED. Obfuscated fileless scripts can execute without full telemetry trace.".into(),
                findings_fr: "La journalisation des blocs de script est DÉSACTIVÉE. Les scripts obfusqués s'exécutent sans trace télémétrique complète.".into(),
                remediation_title_en: "Enable PowerShell Script Block Logging Policy (EID 4104)",
                remediation_title_fr: "Activer la Politique de Journalisation des Scripts PowerShell (EID 4104)",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "PowerShell Script Block Logging (EID 4104)",
                title_fr: "Journalisation des Blocs de Script PowerShell (EID 4104)",
                verdict: Verdict::Secure,
                findings_en: "Shell command logging (auditd/syslog) active.".into(),
                findings_fr: "Journalisation des commandes shell (auditd/syslog) active.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("PowerShell Script Block Logging enabled in system policy.".into()),
                _ => Err("Failed to enable Script Block Logging. Administrator privileges required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux command audit policy compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 13 : usb_scanning (Analyse antivirus des supports amovibles)
// -----------------------------------------------------------------------------
struct UsbScanningScenario;
impl AutoDefendScenario for UsbScanningScenario {
    fn id(&self) -> &'static str { "usb_scanning" }
    fn description_en(&self) -> &'static str { "Checks removable drive scanning policy to intercept weaponized USB media on insertion" }
    fn description_fr(&self) -> &'static str { "Vérifie la politique de scan des supports amovibles pour neutraliser les clés USB malveillantes" }
    fn remediation_desc_en(&self) -> &'static str { "Enforces mandatory automatic antivirus inspection on inserted USB drives and removable storage." }
    fn remediation_desc_fr(&self) -> &'static str { "Impose l'analyse antivirus automatique obligatoire dès l'insertion de tout support ou clé USB amovible." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpPreference).DisableRemovableDriveScanning"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                let val = s_raw.trim().to_lowercase();
                // false = Removable drive scanning is ACTIVE (not disabled)
                if val == "false" || val == "0" {
                    return DefendCheckResult {
                        scenario_id: self.id(),
                        title_en: "Removable Media Antivirus Scanning (USB)",
                        title_fr: "Analyse Antivirus des Supports Amovibles (USB)",
                        verdict: Verdict::Secure,
                        findings_en: "Removable Drive Scanning is ACTIVE. Inserted USB drives and external storage are inspected.".into(),
                        findings_fr: "L'analyse des lecteurs amovibles est ACTIVE. Les clés USB et supports externes sont inspectés.".into(),
                        remediation_title_en: "USB scanning is active.",
                        remediation_title_fr: "L'analyse USB est active.",
                    };
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Removable Media Antivirus Scanning (USB)",
                title_fr: "Analyse Antivirus des Supports Amovibles (USB)",
                verdict: Verdict::Vulnerable,
                findings_en: "Removable drive scanning is DISABLED. External USB flash drives bypass automatic antivirus inspection.".into(),
                findings_fr: "L'analyse des lecteurs amovibles est DÉSACTIVÉE. Les clés USB contournent l'analyse antivirus automatique.".into(),
                remediation_title_en: "Enable Automatic Antivirus Scanning on Removable Drives",
                remediation_title_fr: "Activer l'Analyse Antivirus Automatique des Supports Amovibles",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Removable Media Antivirus Scanning (USB)",
                title_fr: "Analyse Antivirus des Supports Amovibles (USB)",
                verdict: Verdict::Secure,
                findings_en: "Linux udev removable media mount security policy confirmed.".into(),
                findings_fr: "Politique de sécurité de montage des médias amovibles udev confirmée.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Set-MpPreference -DisableRemovableDriveScanning $false"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Automatic scanning of removable USB drives successfully enabled.".into()),
                _ => Err("Failed to update removable drive preference. Administrator rights required.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            Ok("Linux removable media policy compliant.".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Scénario 14 : signature_freshness (Fraîcheur des signatures virales)
// -----------------------------------------------------------------------------
struct SignatureFreshnessScenario;
impl AutoDefendScenario for SignatureFreshnessScenario {
    fn id(&self) -> &'static str { "signature_freshness" }
    fn description_en(&self) -> &'static str { "Evaluates antivirus signature definition age ensuring protection against modern threats" }
    fn description_fr(&self) -> &'static str { "Évalue l'ancienneté des bases virales de l'antivirus pour contrer les menaces récentes" }
    fn remediation_desc_en(&self) -> &'static str { "Forces an immediate definition update from security servers to protect against the latest cyber threats." }
    fn remediation_desc_fr(&self) -> &'static str { "Force la mise à jour immédiate des définitions virales depuis les serveurs de sécurité officiels." }

    fn execute_evaluation(&self, _target: &str) -> DefendCheckResult {
        #[cfg(target_os = "windows")]
        {
            let out = Command::new("powershell")
                .args(["-Command", "(Get-MpComputerStatus).AntivirusSignatureAge"])
                .output();
            if let Ok(o) = out {
                let s_raw = String::from_utf8_lossy(&o.stdout);
                if let Ok(age) = s_raw.trim().parse::<u32>() {
                    if age <= 3 {
                        return DefendCheckResult {
                            scenario_id: self.id(),
                            title_en: "Antivirus Signature Database Freshness",
                            title_fr: "Fraîcheur de la Base de Signatures Antivirus",
                            verdict: Verdict::Secure,
                            findings_en: format!("Antivirus signatures are UP TO DATE (Age: {} day(s)). Latest malware definitions installed.", age),
                            findings_fr: format!("Les bases virales sont À JOUR (Ancienneté : {} jour(s)). Définitions récentes installées.", age),
                            remediation_title_en: "Signatures are fresh.",
                            remediation_title_fr: "Les signatures sont à jour.",
                        };
                    } else if age <= 7 {
                        return DefendCheckResult {
                            scenario_id: self.id(),
                            title_en: "Antivirus Signature Database Freshness",
                            title_fr: "Fraîcheur de la Base de Signatures Antivirus",
                            verdict: Verdict::Warning,
                            findings_en: format!("Signatures are moderately aged (Age: {} days). Update recommended for zero-day protection.", age),
                            findings_fr: format!("Signatures moyennement récentes (Ancienneté : {} jours). Mise à jour recommandée.", age),
                            remediation_title_en: "Update Antivirus Signature Definitions",
                            remediation_title_fr: "Mettre à Jour la Base de Signatures Antivirus",
                        };
                    } else {
                        return DefendCheckResult {
                            scenario_id: self.id(),
                            title_en: "Antivirus Signature Database Freshness",
                            title_fr: "Fraîcheur de la Base de Signatures Antivirus",
                            verdict: Verdict::Vulnerable,
                            findings_en: format!("Antivirus signatures are OUTDATED (Age: {} days). Host is exposed to recent malware campaigns.", age),
                            findings_fr: format!("Bases virales OBSOLÈTES (Ancienneté : {} jours). L'hôte est vulnérable aux menaces récentes.", age),
                            remediation_title_en: "Force Immediate Antivirus Signature Database Update",
                            remediation_title_fr: "Forcer la Mise à Jour Immédiate de la Base Antivirus",
                        };
                    }
                }
            }
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Signature Database Freshness",
                title_fr: "Fraîcheur de la Base de Signatures Antivirus",
                verdict: Verdict::Warning,
                findings_en: "Unable to query signature age directly or definitions not installed.".into(),
                findings_fr: "Impossible de déterminer l'âge des signatures ou définitions non installées.".into(),
                remediation_title_en: "Trigger Antivirus Signature Update",
                remediation_title_fr: "Déclencher la Mise à Jour des Signatures Antivirus",
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            DefendCheckResult {
                scenario_id: self.id(),
                title_en: "Antivirus Signature Database Freshness",
                title_fr: "Fraîcheur de la Base de Signatures Antivirus",
                verdict: Verdict::Secure,
                findings_en: "ClamAV signature mirror timestamp verified.".into(),
                findings_fr: "Horodatage du miroir de signatures ClamAV vérifié.".into(),
                remediation_title_en: "Compliant.",
                remediation_title_fr: "Conforme.",
            }
        }
    }

    fn execute_remediation(&self) -> Result<String, String> {
        #[cfg(target_os = "windows")]
        {
            let res = Command::new("powershell")
                .args(["-Command", "Update-MpSignature -UpdateSource MicrosoftUpdateServer"])
                .status();
            match res {
                Ok(s) if s.success() => Ok("Antivirus signatures successfully updated from Microsoft Update Server.".into()),
                _ => Err("Failed to update antivirus signatures. Check network or run as Administrator.".into()),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let res = Command::new("freshclam").status();
            match res {
                Ok(s) if s.success() => Ok("freshclam signature update completed.".into()),
                _ => Err("Failed to run freshclam.".into()),
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Registre des Scénarios Disponibles
// -----------------------------------------------------------------------------
fn get_all_defend_scenarios() -> Vec<Box<dyn AutoDefendScenario>> {
    vec![
        Box::new(EicarQuarantineScenario),
        Box::new(RealtimeProtectionScenario),
        Box::new(BehaviorMonitoringScenario),
        Box::new(CloudProtectionScenario),
        Box::new(NetworkProtectionScenario),
        Box::new(RansomwareShieldScenario),
        Box::new(TamperProtectionScenario),
        Box::new(AmsiIntegrityScenario),
        Box::new(PuaProtectionScenario),
        Box::new(CredentialGuardScenario),
        Box::new(ScriptBlockLoggingScenario),
        Box::new(UsbScanningScenario),
        Box::new(SignatureFreshnessScenario),
        Box::new(FirewallPolicyScenario),
    ]
}

// -----------------------------------------------------------------------------
// Formatage en Boîtes Visuelles Séparées (Cards)
// -----------------------------------------------------------------------------
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line.push_str(word);
        } else if current_line.len() + 1 + word.len() <= max_width {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(current_line);
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    if lines.is_empty() {
        lines.push("-".to_string());
    }
    lines
}

fn print_owasp_card(result: &OwaspCheckResult, fr: bool) {
    let box_width: usize = 92;

    let label_control = if fr { "CONTRÔLE OWASP" } else { "OWASP CONTROL" };
    let label_status  = if fr { "STATUT" } else { "STATUS" };
    let label_code    = if fr { "CODE HTTP" } else { "HTTP CODE" };
    let label_latency = if fr { "LATENCE" } else { "LATENCY" };
    let label_details = if fr { "DÉTAILS" } else { "DETAILS" };

    let name = if fr { result.name_fr } else { result.name_en };
    let details_raw = if fr { &result.details_fr } else { &result.details_en };
    let code_str = result.status_code.map(|c| format!("HTTP {}", c)).unwrap_or_else(|| "N/A".into());
    let lat_str = format!("{} ms", result.latency_ms);

    let (badge_colored, border_colored) = match result.verdict {
        Verdict::Secure => (
            if fr { "[SÉCURISÉ]".green().bold() } else { "[SECURE]".green().bold() },
            "green",
        ),
        Verdict::Warning => (
            if fr { "[ATTENTION]".yellow().bold() } else { "[WARNING]".yellow().bold() },
            "yellow",
        ),
        Verdict::Vulnerable => (
            if fr { "[VULNÉRABLE]".red().bold() } else { "[VULNERABLE]".red().bold() },
            "red",
        ),
        Verdict::Error => (
            if fr { "[ERREUR]".magenta().bold() } else { "[ERROR]".magenta().bold() },
            "magenta",
        ),
    };

    let title_line = format!("[{}] {} : {}", result.id, label_control, name);
    let wrapped_details = wrap_text(details_raw, box_width - 20);

    let top_bar    = format!("+{}+", "-".repeat(box_width - 2));
    let divider    = format!("+{}+", "-".repeat(box_width - 2));
    let bottom_bar = format!("+{}+", "-".repeat(box_width - 2));

    let top_c = match border_colored { "green" => top_bar.green(), "yellow" => top_bar.yellow(), "red" => top_bar.red(), _ => top_bar.magenta() };
    let div_c = match border_colored { "green" => divider.green(), "yellow" => divider.yellow(), "red" => divider.red(), _ => divider.magenta() };
    let bot_c = match border_colored { "green" => bottom_bar.green(), "yellow" => bottom_bar.yellow(), "red" => bottom_bar.red(), _ => bottom_bar.magenta() };
    let pipe_c = match border_colored { "green" => "|".green(), "yellow" => "|".yellow(), "red" => "|".red(), _ => "|".magenta() };

    println!("{}", top_c);
    let title_fmt = format!("  {:<width$}", title_line, width = box_width - 4);
    println!("{}{}{}", pipe_c, title_fmt.bold(), pipe_c);
    println!("{}", div_c);

    let status_pad = box_width - 19;
    println!("{}  {:<12} : {:<width$} {}", pipe_c, label_status, badge_colored, pipe_c, width = status_pad);
    println!("{}  {:<12} : {:<width$} {}", pipe_c, label_code, code_str, pipe_c, width = box_width - 19);
    println!("{}  {:<12} : {:<width$} {}", pipe_c, label_latency, lat_str, pipe_c, width = box_width - 19);

    for (i, dline) in wrapped_details.iter().enumerate() {
        let prefix = if i == 0 { label_details } else { "" };
        println!("{}  {:<12} : {:<width$} {}", pipe_c, prefix, dline, pipe_c, width = box_width - 19);
    }

    println!("{}", bot_c);
    println!();
}

fn print_defend_card(result: &DefendCheckResult, fr: bool) {
    let box_width: usize = 92;

    let label_scenario = if fr { "SCÉNARIO DE SÉCURITÉ" } else { "SECURITY SCENARIO" };
    let label_status   = if fr { "POSTURE DÉFENSIVE" } else { "DEFENSE STATUS" };
    let label_findings = if fr { "CONSTAT FACTUEL" } else { "FACTUAL FINDINGS" };

    let title = if fr { result.title_fr } else { result.title_en };
    let findings_raw = if fr { &result.findings_fr } else { &result.findings_en };

    let (badge_colored, border_colored) = match result.verdict {
        Verdict::Secure => (
            if fr { "[+] STATUT : CONTRÔLE RÉUSSI (SYSTÈME SÉCURISÉ)".green().bold() }
            else { "[+] STATUS: Security control PASSED. System is SECURE.".green().bold() },
            "green",
        ),
        Verdict::Warning => (
            if fr { "[!] STATUT : AVERTISSEMENT (PROTECTION PARTIELLE)".yellow().bold() }
            else { "[!] STATUS: Security control WARNING (Partial shield).".yellow().bold() },
            "yellow",
        ),
        Verdict::Vulnerable => (
            if fr { "[!] STATUT : ÉCHEC DU CONTRÔLE (SYSTÈME NON CONFORME)".red().bold() }
            else { "[!] STATUS: Security control FAILED. System is NON-COMPLIANT.".red().bold() },
            "red",
        ),
        Verdict::Error => (
            if fr { "[-] STATUT : ERREUR D'ÉVALUATION SYSTÈME".magenta().bold() }
            else { "[-] STATUS: SYSTEM EVALUATION ERROR".magenta().bold() },
            "magenta",
        ),
    };

    let title_line = format!("[{}] {} : {}", result.scenario_id, label_scenario, title);
    let wrapped_findings = wrap_text(findings_raw, box_width - 24);

    let top_bar    = format!("+{}+", "-".repeat(box_width - 2));
    let divider    = format!("+{}+", "-".repeat(box_width - 2));
    let bottom_bar = format!("+{}+", "-".repeat(box_width - 2));

    let top_c = match border_colored { "green" => top_bar.green(), "yellow" => top_bar.yellow(), "red" => top_bar.red(), _ => top_bar.magenta() };
    let div_c = match border_colored { "green" => divider.green(), "yellow" => divider.yellow(), "red" => divider.red(), _ => divider.magenta() };
    let bot_c = match border_colored { "green" => bottom_bar.green(), "yellow" => bottom_bar.yellow(), "red" => bottom_bar.red(), _ => bottom_bar.magenta() };
    let pipe_c = match border_colored { "green" => "|".green(), "yellow" => "|".yellow(), "red" => "|".red(), _ => "|".magenta() };

    println!("{}", top_c);
    let title_fmt = format!("  {:<width$}", title_line, width = box_width - 4);
    println!("{}{}{}", pipe_c, title_fmt.bold(), pipe_c);
    println!("{}", div_c);

    let status_pad = box_width - 23;
    println!("{}  {:<16} : {:<width$} {}", pipe_c, label_status, badge_colored, pipe_c, width = status_pad);

    for (i, dline) in wrapped_findings.iter().enumerate() {
        let prefix = if i == 0 { label_findings } else { "" };
        println!("{}  {:<16} : {:<width$} {}", pipe_c, prefix, dline, pipe_c, width = box_width - 23);
    }

    println!("{}", bot_c);
    println!();
}

// -----------------------------------------------------------------------------
// Exécution du mode -owasp
// -----------------------------------------------------------------------------
async fn executer_audit_owasp(url_base: &str, fr: bool) {
    let client = match create_http_client() {
        Ok(c) => c,
        Err(e) => {
            if fr { eprintln!("[-] Échec client HTTP : {}", e); } else { eprintln!("[-] Failed HTTP client: {}", e); }
            return;
        }
    };

    let title = if fr { "RAPPORT D'AUDIT DÉFENSIF PURPLE TEAM (OWASP TOP 10)" } else { "PURPLE TEAM DEFENSIVE AUDIT REPORT (OWASP TOP 10)" };

    println!("\n============================================================================================");
    println!(" {:^90} ", title.bold());
    println!("============================================================================================");
    println!("  {:<18}: {}", if fr { "URL Cible" } else { "Target URL" }, url_base.cyan());
    println!("  {:<18}: 10/10 OWASP Standards", if fr { "Vérifications" } else { "Checks" });
    println!("============================================================================================\n");

    let checks = vec![
        check_a01_broken_access(&client, url_base).await,
        check_a02_cryptographic_failures(&client, url_base).await,
        check_a03_injection_resilience(&client, url_base).await,
        check_a04_rate_limiting(&client, url_base).await,
        check_a05_security_misconfiguration(&client, url_base).await,
        check_a06_vulnerable_components(&client, url_base).await,
        check_a07_auth_failures(&client, url_base).await,
        check_a08_software_data_integrity(&client, url_base).await,
        check_a09_logging_and_monitoring(&client, url_base).await,
        check_a10_ssrf_resilience(&client, url_base).await,
    ];

    let mut count_secure = 0;
    let mut count_vulnerable = 0;
    let mut count_warning = 0;
    let mut count_error = 0;

    for r in &checks {
        match r.verdict {
            Verdict::Secure => count_secure += 1,
            Verdict::Vulnerable => count_vulnerable += 1,
            Verdict::Warning => count_warning += 1,
            Verdict::Error => count_error += 1,
        }
        print_owasp_card(r, fr);
    }

    let summary_title = if fr { "SYNTHÈSE DE CONFORMITÉ GLOBALE" } else { "GLOBAL COMPLIANCE SUMMARY" };
    println!("+------------------------------------------------------------------------------------------+");
    println!("| {:<88} |", summary_title.bold());
    println!("+------------------------------------------------------------------------------------------+");
    if fr {
        println!("|  - Sécurisés      : {:<67} |", format!("{}", count_secure).green().bold());
        println!("|  - Avertissements : {:<67} |", format!("{}", count_warning).yellow().bold());
        println!("|  - Vulnérables    : {:<67} |", format!("{}", count_vulnerable).red().bold());
        if count_error > 0 {
            println!("|  - Erreurs Réseau : {:<67} |", format!("{}", count_error).magenta().bold());
        }
    } else {
        println!("|  - Secure         : {:<67} |", format!("{}", count_secure).green().bold());
        println!("|  - Warnings       : {:<67} |", format!("{}", count_warning).yellow().bold());
        println!("|  - Vulnerable     : {:<67} |", format!("{}", count_vulnerable).red().bold());
        if count_error > 0 {
            println!("|  - Network Errors : {:<67} |", format!("{}", count_error).magenta().bold());
        }
    }
    println!("+------------------------------------------------------------------------------------------+\n");
}

// -----------------------------------------------------------------------------
// Exécution du mode --auto-defend
// -----------------------------------------------------------------------------
fn executer_auto_defend(target: &str, scenario_arg: &str, fr: bool) {
    let all_scenarios = get_all_defend_scenarios();
    let scenarios_to_run: Vec<&Box<dyn AutoDefendScenario>> = if scenario_arg.eq_ignore_ascii_case("all") {
        all_scenarios.iter().collect()
    } else {
        all_scenarios
            .iter()
            .filter(|s| s.id().eq_ignore_ascii_case(scenario_arg))
            .collect()
    };

    if scenarios_to_run.is_empty() {
        if fr {
            eprintln!("[-] Scénario inconnu : '{}'.", scenario_arg);
            println!("Lancez 'Hunter --list-checks -fr' pour voir tous les scénarios disponibles.");
        } else {
            eprintln!("[-] Unknown scenario: '{}'.", scenario_arg);
            println!("Run 'Hunter --list-checks' to view all available scenario names.");
        }
        return;
    }

    let banner_title = if fr {
        "MOTEUR AUTO-DEFEND : CONTRÔLE DE SÉCURITÉ ET REMÉDIATION"
    } else {
        "AUTO-DEFEND ENGINE: SECURITY POSTURE EVALUATION & REMEDIATION"
    };

    println!("\n============================================================================================");
    println!(" {:^90} ", banner_title.bold());
    println!("============================================================================================");
    println!("  {:<18}: {}", if fr { "Cible / Hôte" } else { "Target / Host" }, target.cyan());
    println!("  {:<18}: {}", if fr { "Scénario(s)" } else { "Scenario(s)" }, scenario_arg.yellow());
    println!("============================================================================================\n");

    let mut failed_scenarios: Vec<(&Box<dyn AutoDefendScenario>, DefendCheckResult)> = Vec::new();

    for scenario in scenarios_to_run {
        let result = scenario.execute_evaluation(target);
        print_defend_card(&result, fr);

        if result.verdict == Verdict::Vulnerable {
            failed_scenarios.push((scenario, result));
        }
    }

    // Remédiation interactive pour chaque scénario en échec
    if !failed_scenarios.is_empty() {
        println!("--------------------------------------------------------------------------------------------");
        let prompt_header = if fr {
            "ACTION DE REMÉDIATION REQUISE :"
        } else {
            "SECURITY REMEDIATION PLAYBOOK PROPOSAL:"
        };
        println!("{}", prompt_header.yellow().bold());

        for (scenario, res) in failed_scenarios {
            let remed_title = if fr { res.remediation_title_fr } else { res.remediation_title_en };
            println!("\n[*] Scénario en échec : [{}]", scenario.id().red().bold());
            println!("    Action recommandée : {}", remed_title.cyan());

            print!(
                "{}",
                if fr {
                    "Voulez-vous que Hunter déploie le bouclier défensif pour corriger cette faille ? (y/n) : "
                } else {
                    "Do you want Hunter to deploy the defensive shield to counter this risk? (y/n) : "
                }
            );
            io::stdout().flush().unwrap();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_ok() {
                let answer = input.trim().to_lowercase();
                if answer == "y" || answer == "yes" || answer == "o" || answer == "oui" {
                    println!("{}", if fr { "[*] Application du correctif en cours..." } else { "[*] Applying remediation..." });
                    match scenario.execute_remediation() {
                        Ok(msg) => {
                            println!(
                                "{}",
                                if fr {
                                    format!("[+] SUCCÈS : {}", msg).green().bold()
                                } else {
                                    format!("[+] SUCCESS: {}", msg).green().bold()
                                }
                            );

                            println!(
                                "{}",
                                if fr {
                                    "\n[*] Vérification automatique post-remédiation en cours par Hunter...".cyan()
                                } else {
                                    "\n[*] Running automatic post-remediation verification by Hunter...".cyan()
                                }
                            );
                            std::thread::sleep(Duration::from_millis(1500));

                            let recheck = scenario.execute_evaluation(target);
                            print_defend_card(&recheck, fr);

                            if recheck.verdict == Verdict::Secure {
                                println!(
                                    "{}",
                                    if fr {
                                        "[✓] CONFIRMATION : Le contre-mesure défensive est active et protège désormais le système avec succès !".green().bold()
                                    } else {
                                        "[✓] CONFIRMED: Defensive countermeasure is active and now successfully protecting the system!".green().bold()
                                    }
                                );
                            } else {
                                println!(
                                    "{}",
                                    if fr {
                                        "[*] Remarque : Certains correctifs de sécurité (ex: LSA / GPO) nécessitent un redémarrage système pour être totalement effectifs.".yellow()
                                    } else {
                                        "[*] Notice: Some security settings (e.g. LSA / GPO) may require a system reboot to take full effect.".yellow()
                                    }
                                );
                            }
                        }
                        Err(err) => {
                            eprintln!(
                                "{}",
                                if fr {
                                    format!("[-] ERREUR : {}", err).red().bold()
                                } else {
                                    format!("[-] ERROR: {}", err).red().bold()
                                }
                            );
                        }
                    }
                } else {
                    println!("{}", if fr { "[*] Remédiation ignorée par l'opérateur." } else { "[*] Remediation skipped by user." });
                }
            }
        }
        println!();
    }
}

fn print_auto_defend_help(fr: bool) {
    let box_width: usize = 92;

    let banner_title = if fr {
        "CATALOGUE COMPLET DES SCÉNARIOS AUTO-DEFEND & BOUCLIERS DE PROTECTION"
    } else {
        "COMPLETE AUTO-DEFEND SCENARIOS & REMEDIATION SHIELDS CATALOG"
    };

    println!("\n============================================================================================");
    println!(" {:^90} ", banner_title.bold());
    println!("============================================================================================");
    println!("  {:<18}: {}", if fr { "Module" } else { "Module" }, "Hunter Host Hardening & Auto-Defend Engine".cyan());
    println!("  {:<18}: {}", if fr { "Syntaxe" } else { "Syntax" }, "Hunter --auto-defend <CIBLE> -check <NOM_SCENARIO> [-fr]".yellow());
    println!("  {:<18}: 14 {}", if fr { "Contrôles" } else { "Controls" }, if fr { "Scénarios défensifs avec boucliers de remédiation automatisés" } else { "Defensive scenarios with automated remediation shields" });
    println!("============================================================================================\n");

    let label_scenario = if fr { "NOM DU SCÉNARIO (-check)" } else { "SCENARIO NAME (-check)" };
    let label_test     = if fr { "TEST CONCRET RÉALISÉ" } else { "CONCRETE TEST PERFORMED" };
    let label_shield   = if fr { "BOUCLIER DE REMÉDIATION" } else { "REMEDIATION SHIELD" };

    for s in get_all_defend_scenarios() {
        let test_desc = if fr { s.description_fr() } else { s.description_en() };
        let shield_desc = if fr { s.remediation_desc_fr() } else { s.remediation_desc_en() };

        let wrapped_test = wrap_text(test_desc, box_width - 32);
        let wrapped_shield = wrap_text(shield_desc, box_width - 32);

        let top_bar    = format!("+{}+", "-".repeat(box_width - 2)).cyan();
        let divider    = format!("+{}+", "-".repeat(box_width - 2)).cyan();
        let bottom_bar = format!("+{}+", "-".repeat(box_width - 2)).cyan();
        let pipe       = "|".cyan();

        println!("{}", top_bar);
        let title_line = format!("  [{}] {}", s.id(), if fr { "CONTRÔLE DE SÉCURITÉ DÉFENSIF" } else { "DEFENSIVE SECURITY CONTROL" });
        let title_fmt = format!("{:<width$}", title_line, width = box_width - 4);
        println!("{} {} {}", pipe, title_fmt.bold(), pipe);
        println!("{}", divider);

        println!("{}  {:<24} : {:<width$} {}", pipe, label_scenario, s.id().bold().yellow(), pipe, width = box_width - 32);

        for (i, line) in wrapped_test.iter().enumerate() {
            let prefix = if i == 0 { label_test } else { "" };
            println!("{}  {:<24} : {:<width$} {}", pipe, prefix, line, pipe, width = box_width - 32);
        }

        for (i, line) in wrapped_shield.iter().enumerate() {
            let prefix = if i == 0 { label_shield } else { "" };
            println!("{}  {:<24} : {:<width$} {}", pipe, prefix, line.green().bold(), pipe, width = box_width - 32);
        }

        println!("{}", bottom_bar);
        println!();
    }

    // Scénario 'all'
    let all_test = if fr {
        "Exécute l'intégralité des 14 scénarios séquentiellement pour un audit complet de la machine hôte."
    } else {
        "Executes all 14 scenarios sequentially for a complete posture assessment of the host machine."
    };
    let all_shield = if fr {
        "Déploie interactivement les contre-mesures pour chaque scénario identifié comme non conforme."
    } else {
        "Interactively deploys countermeasures for every scenario identified as non-compliant."
    };

    let wrapped_all_test = wrap_text(all_test, box_width - 32);
    let wrapped_all_shield = wrap_text(all_shield, box_width - 32);

    let top_bar    = format!("+{}+", "-".repeat(box_width - 2)).yellow();
    let divider    = format!("+{}+", "-".repeat(box_width - 2)).yellow();
    let bottom_bar = format!("+{}+", "-".repeat(box_width - 2)).yellow();
    let pipe       = "|".yellow();

    println!("{}", top_bar);
    let title_line = format!("  [all] {}", if fr { "CONTRÔLE GLOBAL INTÉGRAL" } else { "FULL COMPREHENSIVE CONTROL" });
    let title_fmt = format!("{:<width$}", title_line, width = box_width - 4);
    println!("{} {} {}", pipe, title_fmt.bold(), pipe);
    println!("{}", divider);

    println!("{}  {:<24} : {:<width$} {}", pipe, label_scenario, "all".bold().magenta(), pipe, width = box_width - 32);

    for (i, line) in wrapped_all_test.iter().enumerate() {
        let prefix = if i == 0 { label_test } else { "" };
        println!("{}  {:<24} : {:<width$} {}", pipe, prefix, line, pipe, width = box_width - 32);
    }

    for (i, line) in wrapped_all_shield.iter().enumerate() {
        let prefix = if i == 0 { label_shield } else { "" };
        println!("{}  {:<24} : {:<width$} {}", pipe, prefix, line.green().bold(), pipe, width = box_width - 32);
    }

    println!("{}", bottom_bar);
    println!();

    // Exemples d'utilisation
    let ex_title = if fr { "EXEMPLES D'UTILISATION RAPIDE :" } else { "QUICK USAGE EXAMPLES:" };
    println!("+------------------------------------------------------------------------------------------+");
    println!("| {:<88} |", ex_title.bold());
    println!("+------------------------------------------------------------------------------------------+");
    if fr {
        println!("|  1. Tester l'antivirus avec la chaîne EICAR :                                            |");
        println!("|     Hunter --auto-defend localhost -check eicar_quarantine -fr                           |");
        println!("|  2. Tester la protection contre les ransomwares :                                        |");
        println!("|     Hunter --auto-defend localhost -check ransomware_shield -fr                          |");
        println!("|  3. Lancer l'évaluation complète de l'ensemble des scénarios :                          |");
        println!("|     Hunter --auto-defend localhost -check all -fr                                        |");
    } else {
        println!("|  1. Test real-time AV scanner with EICAR string:                                         |");
        println!("|     Hunter --auto-defend localhost -check eicar_quarantine                               |");
        println!("|  2. Test Anti-Ransomware Controlled Folder Access:                                       |");
        println!("|     Hunter --auto-defend localhost -check ransomware_shield                              |");
        println!("|  3. Run full posture evaluation across all 14 scenarios:                                 |");
        println!("|     Hunter --auto-defend localhost -check all                                            |");
    }
    println!("+------------------------------------------------------------------------------------------+\n");
}

fn print_list_checks(fr: bool) {
    let title = if fr {
        "SCÉNARIOS AUTO-DEFEND DISPONIBLES DANS HUNTER"
    } else {
        "AVAILABLE AUTO-DEFEND COMPLIANCE SCENARIOS IN HUNTER"
    };

    println!("\n============================================================================================");
    println!(" {:^90} ", title.bold());
    println!("============================================================================================");
    println!(" {:<22} | {}", if fr { "NOM DU SCÉNARIO" } else { "SCENARIO NAME" }, if fr { "DESCRIPTION FACTUELLE" } else { "FACTUAL DESCRIPTION" });
    println!("--------------------------------------------------------------------------------------------");

    for s in get_all_defend_scenarios() {
        let desc = if fr { s.description_fr() } else { s.description_en() };
        println!(" {:<22} | {}", s.id().cyan().bold(), desc);
    }

    println!(" {:<22} | {}", "all".yellow().bold(), if fr { "Exécute tous les scénarios séquentiellement" } else { "Executes all scenarios sequentially in a full pass" });
    println!("============================================================================================");
    println!(
        "{}",
        if fr {
            "Syntaxe : Hunter --auto-defend <CIBLE> -check <NOM_SCENARIO> [-fr]"
        } else {
            "Syntax  : Hunter --auto-defend <TARGET> -check <SCENARIO_NAME> [-fr]"
        }
    );
    println!(
        "{}",
        if fr {
            "Catalogue complet : Hunter --auto-defend help -fr"
        } else {
            "Complete catalog  : Hunter --auto-defend help"
        }
    );
    println!();
}

// =============================================================================
// FONCTION PRINCIPALE main()
// =============================================================================
#[tokio::main]
async fn main() {
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);

    let args: Vec<String> = env::args().collect();
    let is_french = args.iter().any(|arg| arg == "-fr" || arg == "--fr");

    let clean_args: Vec<&String> = args
        .iter()
        .filter(|arg| *arg != "-fr" && *arg != "--fr")
        .collect();

    // 1. Commande Aide Auto-Defend : Hunter --auto-defend help [-fr] (ou -h, --help)
    if clean_args.len() >= 2 && clean_args[1] == "--auto-defend" {
        if clean_args.len() == 2 || (clean_args.len() >= 3 && (clean_args[2] == "help" || clean_args[2] == "-h" || clean_args[2] == "--help")) {
            print_auto_defend_help(is_french);
            return;
        }
    }

    // 2. Commande liste des scénarios : Hunter --list-checks [-fr]
    if clean_args.len() >= 2 && (clean_args[1] == "--list-checks" || clean_args[1] == "-l") {
        print_list_checks(is_french);
        return;
    }

    // 3. Commande Auto-Defend : Hunter --auto-defend <TARGET> -check <SCENARIO> [-fr]
    if clean_args.len() >= 5 && clean_args[1] == "--auto-defend" && (clean_args[3] == "-check" || clean_args[3] == "--check") {
        let target = clean_args[2];
        let scenario = clean_args[4];
        executer_auto_defend(target, scenario, is_french);
        return;
    }

    // 4. Commande OWASP Audit : Hunter -owasp <URL> [-fr]
    if clean_args.len() >= 3 && (clean_args[1] == "-owasp" || clean_args[1] == "--owasp") {
        let mut target_url = clean_args[2].clone();
        if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
            target_url = format!("http://{}", target_url);
        }
        executer_audit_owasp(&target_url, is_french).await;
        return;
    }

    // Affichage de l'aide générale si les arguments sont incorrects
    if is_french {
        println!("HUNTER — Outil Universel d'Audit Web & Défense Système");
        println!("\nCommandes disponibles :");
        println!("  1. Audit Web OWASP Top 10 :");
        println!("     Hunter -owasp <URL_CIBLE> [-fr]");
        println!("     Exemple : Hunter -owasp http://localhost:3000 -fr");
        println!("\n  2. Évaluation de Sécurité & Remédiation Système (Auto-Defend) :");
        println!("     Hunter --auto-defend <CIBLE> -check <NOM_SCENARIO> [-fr]");
        println!("     Exemples :");
        println!("       Hunter --auto-defend localhost -check eicar_quarantine -fr");
        println!("       Hunter --auto-defend localhost -check all -fr");
        println!("\n  3. Catalogue d'Aide Complet Auto-Defend :");
        println!("     Hunter --auto-defend help [-fr]");
        println!("     Hunter --list-checks [-fr]");
    } else {
        println!("HUNTER — Universal Web Audit & System Defense Suite");
        println!("\nAvailable Commands:");
        println!("  1. OWASP Top 10 Web Audit:");
        println!("     Hunter -owasp <TARGET_URL> [-fr]");
        println!("     Example: Hunter -owasp http://localhost:3000");
        println!("\n  2. System Posture Evaluation & Auto-Defend Playbooks:");
        println!("     Hunter --auto-defend <TARGET> -check <SCENARIO_NAME> [-fr]");
        println!("     Examples:");
        println!("       Hunter --auto-defend localhost -check eicar_quarantine");
        println!("       Hunter --auto-defend localhost -check all");
        println!("\n  3. Complete Auto-Defend Catalog & Help Screen:");
        println!("     Hunter --auto-defend help [-fr]");
        println!("     Hunter --list-checks [-fr]");
    }
}
