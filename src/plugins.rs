use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginTestDefinition {
    pub id: String,
    pub test_name: String,
    #[serde(default)]
    pub description_en: Option<String>,
    #[serde(default)]
    pub description_fr: Option<String>,
    #[serde(default = "default_category")]
    pub category: String, // "io_file", "http_status", "system_io"
    #[serde(default)]
    pub test_path: Option<String>,
    #[serde(default)]
    pub test_payload: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub expected_status_code: Option<u16>,
    #[serde(default)]
    pub remediation_command: Option<String>,
}

fn default_category() -> String {
    "io_file".to_string()
}

#[derive(Debug, Clone)]
pub struct TestReportItem {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub latency_ms: u128,
    pub details: String,
    pub remediation: Option<String>,
}

/// 1. CHARGEMENT DYNAMIQUE : Scanne le dossier 'plugins/' et parse tous les fichiers JSON
pub fn load_plugins_from_directory<P: AsRef<Path>>(dir_path: P) -> (Vec<PluginTestDefinition>, Vec<String>) {
    let mut tests = Vec::new();
    let mut errors = Vec::new();
    let p = dir_path.as_ref();

    if !p.exists() {
        if let Err(e) = fs::create_dir_all(p) {
            errors.push(format!("Impossible de créer le dossier plugins/ : {}", e));
            return (tests, errors);
        }
    }

    let entries = match fs::read_dir(p) {
        Ok(e) => e,
        Err(e) => {
            errors.push(format!("Erreur lors de la lecture du dossier plugins/ : {}", e));
            return (tests, errors);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    if let Ok(single_test) = serde_json::from_str::<PluginTestDefinition>(&content) {
                        tests.push(single_test);
                    } else if let Ok(test_list) = serde_json::from_str::<Vec<PluginTestDefinition>>(&content) {
                        tests.extend(test_list);
                    } else {
                        errors.push(format!("Format JSON invalide dans {}", path.display()));
                    }
                }
                Err(e) => {
                    errors.push(format!("Lecture impossible de {} : {}", path.display(), e));
                }
            }
        }
    }

    tests.sort_by(|a, b| a.id.cmp(&b.id));
    (tests, errors)
}

/// 2. SÉCURITÉ COMPORTEMENTALE : Exécute le test d'E/S système réel (I/O, Path::exists, lecture)
pub fn execute_io_test(test: &PluginTestDefinition, is_fr: bool) -> TestReportItem {
    let start = Instant::now();
    let payload = test.test_payload.as_deref().unwrap_or("HUNTER_DIAGNOSTIC_PAYLOAD_TEST_OK");
    
    // Détermine le chemin cible (soit spécifié, soit dans le dossier temporaire)
    let default_temp = std::env::temp_dir().join(format!("hunter_io_test_{}.tmp", test.id.to_lowercase()));
    let target_path: PathBuf = match &test.test_path {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => default_temp,
    };

    // 1. Tenter l'écriture réelle sur le disque
    let write_result = (|| -> io::Result<()> {
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut file = File::create(&target_path)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let latency = start.elapsed().as_millis();
        let details = if is_fr {
            format!("Échec d'écriture disque / I/O intercepté : {}", e)
        } else {
            format!("Disk write failure / I/O intercepted: {}", e)
        };
        return TestReportItem {
            id: test.id.clone(),
            name: test.test_name.clone(),
            passed: false,
            latency_ms: latency,
            details,
            remediation: test.remediation_command.clone(),
        };
    }

    // 2. Vérifier explicitement std::path::Path::exists
    if !target_path.exists() {
        let latency = start.elapsed().as_millis();
        let details = if is_fr {
            "Fichier absent ou supprimé immédiatement après l'écriture (interception E/S active).".to_string()
        } else {
            "File missing or deleted immediately after write (active I/O interception).".to_string()
        };
        return TestReportItem {
            id: test.id.clone(),
            name: test.test_name.clone(),
            passed: false,
            latency_ms: latency,
            details,
            remediation: test.remediation_command.clone(),
        };
    }

    // 3. Vérifier les permissions de lecture et l'intégrité de la charge
    let read_result = fs::read_to_string(&target_path);
    
    // Nettoyage sécurisé du fichier de test
    let _ = fs::remove_file(&target_path);
    let latency = start.elapsed().as_millis();

    match read_result {
        Ok(read_content) if read_content == payload => {
            let details = if is_fr {
                format!("Écriture, Path::exists et lecture validés ({} octets)", payload.len())
            } else {
                format!("Write, Path::exists, and read verified ({} bytes)", payload.len())
            };
            TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed: true,
                latency_ms: latency,
                details,
                remediation: None,
            }
        }
        Ok(_) => {
            let details = if is_fr {
                "Intégrité compromise : le contenu lu diffère de la charge injectée.".to_string()
            } else {
                "Integrity compromised: read content differs from injected payload.".to_string()
            };
            TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed: false,
                latency_ms: latency,
                details,
                remediation: test.remediation_command.clone(),
            }
        }
        Err(e) => {
            let details = if is_fr {
                format!("Permission de lecture refusée / Accès verrouillé : {}", e)
            } else {
                format!("Read permission denied / Access locked: {}", e)
            };
            TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed: false,
                latency_ms: latency,
                details,
                remediation: test.remediation_command.clone(),
            }
        }
    }
}

/// Exécute un test HTTP si spécifié dans le plugin
pub async fn execute_http_test(client: &reqwest::Client, test: &PluginTestDefinition, is_fr: bool) -> TestReportItem {
    let start = Instant::now();
    let url = match &test.target_url {
        Some(u) => u,
        None => {
            return TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed: false,
                latency_ms: 0,
                details: if is_fr { "Aucune URL cible définie dans le plugin.".into() } else { "No target URL defined in plugin.".into() },
                remediation: None,
            };
        }
    };

    let expected = test.expected_status_code.unwrap_or(200);

    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let latency = start.elapsed().as_millis();
            let passed = status == expected;
            let details = if is_fr {
                format!("Code HTTP reçu : {} (Attendu : {})", status, expected)
            } else {
                format!("HTTP status received: {} (Expected: {})", status, expected)
            };
            TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed,
                latency_ms: latency,
                details,
                remediation: if passed { None } else { test.remediation_command.clone() },
            }
        }
        Err(e) => {
            let latency = start.elapsed().as_millis();
            let details = if is_fr {
                format!("Échec de requête HTTP : {}", e)
            } else {
                format!("HTTP request failed: {}", e)
            };
            TestReportItem {
                id: test.id.clone(),
                name: test.test_name.clone(),
                passed: false,
                latency_ms: latency,
                details,
                remediation: test.remediation_command.clone(),
            }
        }
    }
}

/// 3. RÉSULTATS : Affiche les résultats dans un tableau formaté bilingue
pub fn print_plugin_results_table(results: &[TestReportItem], errors: &[String], is_fr: bool) {
    let title = if is_fr {
        "RAPPORT D'EXÉCUTION DU MOTEUR DE PLUGINS & TESTS SYSTÈME"
    } else {
        "DYNAMIC PLUGIN & SYSTEM TESTING ENGINE EXECUTION REPORT"
    };

    println!("\n{}", "============================================================================================".cyan());
    println!(" {:^90} ", title.bold().white());
    println!("{}\n", "============================================================================================".cyan());

    if !errors.is_empty() {
        println!("{}", if is_fr { "[-] Avertissements de chargement :" } else { "[-] Loading warnings:" }.yellow());
        for err in errors {
            println!("  ⚠️  {}", err);
        }
        println!();
    }

    if results.is_empty() {
        println!("{}", if is_fr { "Aucun plugin trouvé dans le dossier 'plugins/'." } else { "No plugins found in 'plugins/' directory." }.yellow());
        println!("{}", if is_fr { "Déposez des fichiers .json dans plugins/ pour les exécuter automatiquement." } else { "Drop .json files into plugins/ to execute them automatically." });
        return;
    }

    // Affichage des cartes de résultats
    for res in results {
        let status_text = if res.passed {
            if is_fr { "[CONFORME / SUCCÈS]".green().bold() } else { "[PASS / SUCCESS]".green().bold() }
        } else {
            if is_fr { "[NON-CONFORME / ÉCHEC]".red().bold() } else { "[FAIL / ERROR]".red().bold() }
        };

        println!("+------------------------------------------------------------------------------------------+");
        println!("| {:<8} : {:<78} |", if is_fr { "TEST" } else { "TEST" }, res.id.bold());
        println!("| {:<8} : {:<78} |", if is_fr { "NOM" } else { "NAME" }, res.name);
        println!("+------------------------------------------------------------------------------------------+");
        println!("| {:<13} : {:<73} |", if is_fr { "STATUT" } else { "STATUS" }, status_text);
        println!("| {:<13} : {:<73} |", if is_fr { "LATENCE" } else { "LATENCY" }, format!("{} ms", res.latency_ms));
        println!("| {:<13} : {:<73} |", if is_fr { "DÉTAILS" } else { "DETAILS" }, res.details);
        
        if let Some(cmd) = &res.remediation {
            println!("| {:<13} : {:<73} |", if is_fr { "REMÉDIATION" } else { "REMEDIATION" }, cmd.yellow());
        }
        println!("+------------------------------------------------------------------------------------------+\n");
    }

    // Synthèse finale
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    println!("+------------------------------------------------------------------------------------------+");
    println!("| {:<88} |", if is_fr { "SYNTHÈSE GLOBALE DES TESTS" } else { "GLOBAL TEST SYNTHESIS" }.bold());
    println!("+------------------------------------------------------------------------------------------+");
    println!("|  - {} : {:<71} |", if is_fr { "Total des tests" } else { "Total tests" }, total);
    println!("|  - {} : {:<71} |", if is_fr { "Succès / Validés" } else { "Passed / Validated" }, passed.to_string().green());
    println!("|  - {} : {:<71} |", if is_fr { "Échecs" } else { "Failed" }, if failed > 0 { failed.to_string().red() } else { "0".normal() });
    println!("+------------------------------------------------------------------------------------------+\n");
}
