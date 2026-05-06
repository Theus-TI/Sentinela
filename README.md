# 🛡️ Sentinel EDR
> **Advanced Endpoint Detection & Response | Active Defense & Forensic System**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Linux-Kernel_Internals-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Status](https://img.shields.io/badge/Status-Enterprise_Ready-OKGREEN?style=for-the-badge&logo=shield)](https://github.com/)

```ascii
   ____  _____ _   _ _____ ___ _   _ _____ _     
  / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
  \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
   ___) | |___| |\  | | |  | || |\  | |___| |___ 
  |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
  v11.0.0 | High-Precision Defense Engine
```

## 📌 Visão Geral
O **Sentinel EDR** é uma plataforma de segurança de host (HIDS) desenvolvida para operações de **Blue Team** e **SOC**. Ele combina monitoramento de integridade em tempo real, análise heurística de arquivos, detecção de ameaças baseada em assinaturas APT e uma camada de interceptação de rede a nível de Kernel (IPS), tudo consolidado em um painel de comando e controle (C2) moderno.

---

### 🚀 Motores de Detecção Integrados

| Motor | Tecnologia | Capacidade de Defesa |
| :--- | :--- | :--- |
| **Watchdog FIM** | `inotify` + `SHA-256` | Monitoramento de integridade em milissegundos com persistência atômica. |
| **YARA Engine** | `yara-python` | Detecção de backdoors, miners e LOLBins via assinaturas de mercado. |
| **Entropy Analyzer** | `Shannon Entropy` | Identificação de Ransomware através de análise matemática de cifragem. |
| **Network HIDS** | `/proc/net/tcp` | Monitoramento de sockets em tempo real com congelamento de processos hostis. |
| **NFQueue IPS** | `netfilterqueue` | Interceptação de pacotes (DPI) para prevenção de exfiltração de dados. |
| **Suricata Connector** | `eve.json` tailing | Integração nativa com alertas IDS e bloqueio automatizado de IPs no Firewall. |
| **VirusTotal Cloud** | `API v3` | Inteligência global de ameaças com consultas assíncronas e rate-limiting. |

---

### 🛡️ Módulo de Imortalidade (Anti-Tampering)
O Sentinel v11 introduz o **Guardian Process**, um módulo de monitoramento redundante que garante que o motor principal não seja desativado por agentes externos. Caso o processo mestre seja encerrado abruptamente, o Guardião o revive instantaneamente, mantendo a proteção ativa 24/7.

---

### 🕹️ Centro de Comando (C2 Dashboard)
O Sentinel oferece um painel intuitivo e responsivo para gerenciamento de incidentes:

- **Dual-Control Response:** Tome decisões críticas diretamente pelo Terminal (CLI) ou pelo Painel Web.
- **Threat Extermination:** Destruição segura de arquivos (secure shred) e encerramento de processos via C2.
- **Health Monitoring:** Acompanhe a saúde de cada motor de defesa em tempo real.
- **Adaptive Radar:** Visualização dinâmica que reage à severidade das ameaças detectadas.

---

### ⚡ Instalação e Uso Rápido

#### Pré-requisitos
```bash
# Dependências Core
python3 -m pip install watchdog flask flask-cors

# Motores Avançados (Opcional)
python3 -m pip install yara-python netfilterqueue scapy
```

#### Execução
```bash
# 1. Gerar baseline de segurança
python3 sentinel.py -b /diretorio/alvo

# 2. Iniciar monitoramento total
sudo python3 sentinel.py -m /diretorio/alvo
```
O painel será aberto automaticamente em `http://127.0.0.1:1337`.

---

### ⚙️ Configuração (sentinel_config.json)
O Sentinel utiliza um arquivo de configuração centralizado (protegido por `.gitignore`) para gerenciar sua inteligência:

```json
{
    "vt_api_key": "YOUR_API_KEY",
    "entropy_threshold": 7.9,
    "trusted_ips": ["10.0.0.1", "127.0.0.1"],
    "trusted_domains": ["google.com", "microsoft.com"],
    "dashboard_port": 1337,
    "natural_entropy_extensions": ["png", "zip", "pdf"],
    "malicious_extensions": ["locked", "crypt", "ransom"]
}
```

---

### 🔒 Hardening & Segurança (v11.0.0)
- **Atomic Persistence:** Previne corrupção da baseline em crashes de sistema.
- **Anti-Tampering:** Sincronização de sinais para evitar desligamentos não autorizados.
- **Memory Optimization:** Coleta seletiva de metadados para evitar vazamentos de RAM.
- **Forensic Integrity:** Logs rotativos e banco de dados SQLite assíncrono para investigação pós-incidente.
- **Secure Communication:** Headers de segurança e proteção contra XSS/CORS no Dashboard.

---
<div align="center">
  <i>Desenvolvido para entusiastas de Blue Team e Analistas de SOC.</i>
</div>
