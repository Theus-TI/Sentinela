# Sentinel EDR
> **Advanced Endpoint Detection & Response | Active Defense & Forensic System**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Linux-Kernel_Internals-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![Status](https://img.shields.io/badge/Status-Enterprise_Ready-007ACC?style=for-the-badge)](https://github.com/)

```text
  _________  __________  __________  ____  __  _______  __ 
 / ___/ __ \/ ___/ __ \/ ___/ __ \/ __ \/ / / / ___/ / / /
/ /__/ /_/ / /__/ /_/ / /__/ /_/ / /_/ / /_/ / /__/ /_/ / 
\___/\____/\___/\____/\___/\____/\____/\____/\___/\____/  
                                                          
                    SECURITY ENGINE V11.0.0
```

## Visão Geral
O Sentinel EDR é uma plataforma de segurança de host (HIDS) desenvolvida para operações de Blue Team e SOC. Ele combina monitoramento de integridade em tempo real, análise heurística de arquivos, detecção de ameaças baseada em assinaturas APT e uma camada de interceptação de rede a nível de Kernel (IPS), consolidado em um painel de comando e controle (C2).

---

### Motores de Detecção Integrados

| Motor | Tecnologia | Capacidade de Defesa |
| :--- | :--- | :--- |
| **Watchdog FIM** | inotify + SHA-256 | Monitoramento de integridade com persistência atômica. |
| **YARA Engine** | yara-python | Detecção de backdoors e LOLBins via assinaturas APT. |
| **Entropy Analyzer** | Shannon Entropy | Identificação de Ransomware via análise matemática de cifragem. |
| **Network HIDS** | /proc/net/tcp | Monitoramento de sockets com congelamento de processos. |
| **NFQueue IPS** | netfilterqueue | Interceptação de pacotes para prevenção de exfiltração. |
| **Suricata Connector** | eve.json tailing | Integração nativa com alertas IDS e bloqueio de IPs. |
| **VirusTotal Cloud** | API v3 | Inteligência global de ameaças com consultas assíncronas. |

---

### Módulo de Imortalidade (Anti-Tampering)
O Sentinel utiliza o Guardian Process, um módulo de monitoramento redundante que garante a resiliência do motor principal. Caso o processo mestre seja encerrado de forma anômala, o Guardião o reinicia imediatamente, garantindo a continuidade da proteção.

---

### Centro de Comando (C2 Dashboard)
O sistema oferece uma interface centralizada para gerenciamento de incidentes:

- **Dual-Control Response:** Decisões críticas via Terminal (CLI) ou Painel Web.
- **Threat Extermination:** Destruição segura de arquivos e encerramento de processos.
- **Health Monitoring:** Monitoramento de integridade de cada motor de defesa.
- **Adaptive Radar:** Visualização dinâmica de telemetria de severidade.

---

### Instalação e Execução

#### Pré-requisitos
```bash
# Dependências Core
python3 -m pip install watchdog flask flask-cors

# Motores Avançados (Opcional)
python3 -m pip install yara-python netfilterqueue scapy
```

#### Operação
```bash
# 1. Geração de baseline de integridade
python3 sentinel.py -b /diretorio/alvo

# 2. Ativação do monitoramento completo
sudo python3 sentinel.py -m /diretorio/alvo
```
Acesso ao dashboard via http://127.0.0.1:1337.

---

### Configuração (sentinel_config.json)
Configuração centralizada para gestão de inteligência e limites:

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

### Hardening e Segurança
- **Atomic Persistence:** Proteção contra corrupção de dados em falhas de energia/sistema.
- **Signal Synchronization:** Sincronização de encerramento para evitar bypass de segurança.
- **Memory Optimization:** Gestão eficiente de cache para prevenção de vazamento de memória.
- **Forensic Records:** Registro assíncrono em SQLite para auditoria e investigação.
- **Network Isolation:** Proteção de headers e isolamento de origens via CORS.

---
<div align="center">
  Desenvolvido para operações de Blue Team e Análise de Segurança.
</div>
