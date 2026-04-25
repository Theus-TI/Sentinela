<div align="center">
  <img src="https://img.icons8.com/color/100/000000/cyber-security.png" width="100">
  <h1>🛡️ Sentinel EDR - Active Defense System </h1>
  <p><b>DevSecOps & Blue Team — Sistema de Detecção de Intrusão em Nuvem e Host (HIDS / FIM)</b></p>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
    <img src="https://img.shields.io/badge/Architecture-SOC_Defense-black?style=for-the-badge" />
    <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
  </p>
</div>

---

## 📌 Contexto Organizacional
Baseado nas exigências operacionais de um **Centro de Operações de Segurança (SOC)** moderno, proteger o perímetro não é suficiente. Invasões e Backdoors muitas vezes escapam ao firewall.

O projeto **Sentinel EDR** atua em duas frentes vitais (Air-gapped):
1. **[FIM] Monitor de Integridade de Arquivos:** Rastreador de Malware por Hashes de disco.
2. **[HIDS] Análise de Rede com Resposta Ativa:** Engenharia reversa no Kernel Linux (`/proc/net/tcp`) para derrubar portas e processos Bind executados por criminosos.

---

## 🚀 Capacidades Oficiais (Architecture)
A estrutura do projeto repousa **100% sobre a Python Standard Library** — Desenvolvido de forma autônoma para ambientes Dry-Containers e Servidores Críticos de Cloud que não possuem Luxo de pacotes `pip` na internet.

*   **🛡️ Active Defense PIDs (KILL-SWITCH):** Se um Backdoor é ativado (ex: Netcat Bind Shell na porta 4444), o sistema reverte sockets p/ Inodes do Kernel, rastreia os "File Descriptors" físicos e assassina (`SIGKILL -9`) a intrusão instantaneamente.
*   **🦠 Threat Intel (VirusTotal API v3):** Se um arquivo estranho surgir (ex: Zero-Day Drops), o Sentinel isola o Hash OOM-Safe e consome a REST API global do VirusTotal. Com a detecção positivada (e.g., Spyware, Ransomware), disparamos `chmod 000` confinando a ameaça em Área de Quarentena.
*   **🧩 Criptografia SHA-512 FIM:** Perfis estritos na memória base com chaves indecifráveis para evitar bypasses de Blue Team clássicos de malwares evasivos.

---

## 🕹️ Testes de Invasão Pessoal (Hands-On)

1. **Inicie sua Baseline limpa de Portas e Hashs**
```bash
./sentinel.py -m /seu/diretorio/importante/
```

2. **Simule a Invasão por Portas (Side B: Red Team)**
```bash
# Abra uma nova aba de terminal e ouça como um Cavalo de Troia
nc -lvnp 4444
```

3. **Reação do Sentinel em Tempo real:**
```bash
[⚠️ REDE ALERTA] Backdoor Escutando (4444)!
  └─> 🔬 Forense: Processo [nc] operando no PID (13238)
  └─> ⚠️ EDR ATIVO: Deseja MATAR o programa suspeito 'nc' (PID 13238)? [S/N]: s
  └─> 💥 ALVO DERRUBADO! Acesso do hacker extirpado do sistema.
```

---
`Engenharia e Defesa Arquitetada por` **[@Theus-TI]**
