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

## 🚀 Capacidades Oficiais (Architecture V9)
A estrutura principal do projeto foi projetada para ambientes Táticos, unindo a Portabilidade de Bibliotecas padrão Python à eficiência de APIs de Segurança.

*   **🌐 C2 Web Dashboard (Dual-Control):** Uma interface moderna administrativa operando sob arquitetura em tempo real. O Analista de SOC pode monitorar a máquina, ver PIDs maliciosos e apertar o botão de "Extermínio" sem tocar no terminal.
*   **🧬 Motor YARA Local:** Identificação ultrarrápida (Pattern Matching estático) mapeando assinaturas hexadecimais de Ameaças Famosas (APTs, Ransomwares).
*   **🛡️ Active Defense PIDs (KILL-SWITCH):** O clássico HIDS. O Sentinel reverte sockets suspeitos direto do Kernel (`/proc/net/tcp`), mapeia FD nodes e extirpa o atacante assincronamente (evitando sistema travado).
*   **🦠 Threat Intel (VirusTotal API v3):** Camada de defesa secundária na nuvem para varredura de Zero-Days com Sandboxing e Quarentena agressiva automática.
*   **🧩 FIM O(1) e Criptografia:** Monitor de Integridade de disco (SHA-512) reescrito utilizando Hashes em Sets (O(1)) para otimização radical de recursos da máquina monitorada.

---

## 🕹️ Usabilidade Em Tempo Real (Dual-Control)

1. **Inicialização Conjunta (Sentinel + Web Server)**
```bash
./sentinel.py -m /diretorio/protegido/
```
> *Nota: O Dashboard Web será iniciado simultaneamente. Abra (127.0.0.1:8000/dashboard/index.html) em seu navegador.* 📊

2. **Simulando um Ataque de Rede (Red Team)**
```bash
# Finja ser um atacante abrindo uma Shell reversa/Bind:
nc -lvnp 4444
```

3. **Resposta a Incidente Integrada:**
*   No **Dashboard**, um sinal de Card Crítico aparecerá identificando o netcat com Botões interativos para Abortar Processo.
*   No **Terminal Host**, o aviso reativo irá pipocar:
```bash
[⚠️ REDE ALERTA] Backdoor Escutando (4444)!
  └─> 🔬 Forense: Processo [nc] operando no PID (13238)
  └─> ⚠️ EDR Dual-Control (Via Web ou CLI). Deseja MATAR o processo suspeito? [S/N]: s
  └─> 💥 ALVO DERRUBADO! (Resolução instantânea)
```

---
`Engenharia e Defesa Arquitetada por` **[@Theus-TI]**
