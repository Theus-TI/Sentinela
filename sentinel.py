#!/usr/bin/env python3
"""
Sentinel EDR/HIDS - Host Intrusion Detection System
Motores: [Entropy Analyser, Yara-Lite Scanner, HIDS Network, VT Cloud]
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import shutil
import urllib.request
import urllib.error
import math
from collections import Counter
from datetime import datetime

VT_API_KEY = os.environ.get("VT_API_KEY", "ffc4f4553c804ffbefc1bd39344763acb0e60df6341dd767d97ef52d522c6b15") 

class Colors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

logging.basicConfig(filename='sentinel_audit.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==========================================
# EDR DE REDE: MONITORAMENTO & RESPOSTA
# ==========================================
def get_listening_sockets():
    sockets = {}
    try:
        for proto_file in ['/proc/net/tcp', '/proc/net/tcp6']:
            if os.path.exists(proto_file):
                with open(proto_file, 'r') as f:
                    lines = f.readlines()[1:] 
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 10 and parts[3] == '0A':
                            hex_port = parts[1].split(':')[1]
                            dec_port = int(hex_port, 16)
                            if dec_port < 32000:
                                sockets[str(dec_port)] = parts[9]
    except Exception:
        pass
    return sockets

def get_pid_by_inode(target_inode):
    try:
        for pid in os.listdir('/proc'):
            if pid.isdigit():
                fd_dir = os.path.join('/proc', pid, 'fd')
                if os.access(fd_dir, os.R_OK) and os.access(fd_dir, os.X_OK):
                    for fd in os.listdir(fd_dir):
                        try:
                            if f"socket:[{target_inode}]" in os.readlink(os.path.join(fd_dir, fd)): return pid
                        except Exception:
                            continue
    except Exception:
        pass
    return None

def get_process_name(pid):
    try:
        with open(f'/proc/{pid}/comm', 'r') as f: return f.read().strip()
    except Exception:
        return "Desconhecido"

# ==========================================
# NOVOS MOTORES CYBER: ENTROPIA E YARA
# ==========================================
def calculate_entropy(file_path):
    """Calcula a aleatoriedade dos bytes para detectar criptografia pesada (Ransomware)"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(256000) # Lê 250kb
            if not data: return 0.0
            counter = Counter(data)
            length = len(data)
            return sum(- (count / length) * math.log2(count / length) for count in counter.values())
    except Exception:
        return 0.0

def scan_yara_lite(file_path):
    """Buscador de Sintax Maliciosa em Memória"""
    # Regex brutal do Red Team para Backdoors e exploits comuns
    BANNED_SIGNATURES = [
        b'eval(base64_decode(', b'nc -e /bin/sh', b'nc -e /bin/bash', 
        b'import pty; pty.spawn', b'powershell -enc', b'exec(compile(',
        b'wget http', b'curl -s http', b'WannaCry'
    ]
    try:
         with open(file_path, 'rb') as f:
             data = f.read(1024 * 1024) # Impede OOM
             for sig in BANNED_SIGNATURES:
                 if sig in data:
                     return True, sig.decode('utf-8', errors='ignore')
             return False, ""
    except Exception:
         return False, ""

# ==========================================
# THREAT INTEL & FIM CORE
# ==========================================
def check_virustotal(file_path, api_key):
    if not api_key: return False, "Sem Chave API."
    hasher = hashlib.sha256()
    try:
         with open(file_path, 'rb') as f:
             while chunk := f.read(65536): hasher.update(chunk)
    except: return False, "Erro leitura hash."

    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{hasher.hexdigest()}", headers={'x-apikey': api_key})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read())
            mc = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            if mc > 0: return True, f"{mc} Antivírus Ativados. Arquivo Maligno!"
            return False, "Limpo nas nuvens (VT)."
    except urllib.error.HTTPError as e:
        if e.code == 404: return False, "Desconhecido pelo VT."
        return False, f"Erro VT API: {e.code}"
    except Exception as e: return False, f"Falha de Conexão: {str(e)}"

def quarantine_file(file_path, directory):
    q_dir = os.path.join(directory, ".quarentena")
    try:
        if not os.path.exists(q_dir):
            os.makedirs(q_dir)
            os.chmod(q_dir, 0o700) 
        safe_name = f"{os.path.basename(file_path)}.malware.{int(time.time())}"
        target_path = os.path.join(q_dir, safe_name)
        shutil.move(file_path, target_path)
        os.chmod(target_path, 0o000)
        return True, target_path
    except Exception as e: return False, str(e)

def calculate_file_hash(filepath):
    try:
        hasher = hashlib.new("sha512")
        with open(filepath, 'rb') as f:
            while chunk := f.read(65536): hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError): return None

def create_baseline(directory, baseline_file="baseline.json"):
    if not os.path.exists(directory): sys.exit(1)
    q_dir = os.path.join(directory, ".quarentena")
    baseline_data = {}
    print(f"{Colors.HEADER}{Colors.BOLD}\n[+] Iniciando criação da Baseline do Sistema de Arquivos...{Colors.ENDC}")
    for root, _, files in os.walk(directory):
        if root.startswith(q_dir): continue
        for filename in files:
            filepath = os.path.join(root, filename)
            if h := calculate_file_hash(filepath):
                baseline_data[filepath] = h
                print(f"Adicionado: {filepath} -> {h[:15]}...")
    with open(baseline_file, 'w') as f: json.dump(baseline_data, f, indent=4)
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n[+] Assinatura base criada! ({len(baseline_data)} files){Colors.ENDC}")

# ==========================================
# LOOP PRINCIPAL DO EDR MESTRE
# ==========================================
def monitor_directory(directory, baseline_file="baseline.json"):
    if not os.path.exists(baseline_file): sys.exit(1)
    with open(baseline_file, 'r') as f: baseline_data = json.load(f)

    print(f"\n{Colors.WARNING}{Colors.BOLD}🛡️ Sentinel EDR Ativado! Motores [FIM, Entropy, YARA, Network IDS, VT] online...{Colors.ENDC}\n")
    baseline_sockets = get_listening_sockets()
    if baseline_sockets: print(f"{Colors.HEADER}└─> 🌐 Escudo Ciber-Físico da Rede blindado.{Colors.ENDC}")

    q_dir_prevent = os.path.join(directory, ".quarentena")

    try:
        while True:
            # 1. SCAN DE REDE (HIDS)
            current_sockets = get_listening_sockets()
            novas_portas = set(current_sockets.keys()) - set(baseline_sockets.keys())
            
            for porta in novas_portas:
                inode = current_sockets[porta]
                pid = get_pid_by_inode(inode)
                pname = get_process_name(pid) if pid else "Não Mapeado"
                
                print(f"\n{Colors.FAIL}{Colors.BOLD}[⚠️ REDE ALERTA] Backdoor Escutando TCP ({porta})!{Colors.ENDC}")
                print(f"  {Colors.HEADER}└─> 🔬 Forense: Processo [{pname}] operando no PID ({pid}){Colors.ENDC}")
                baseline_sockets[porta] = inode
                
                if pid:
                    try:
                        if input(f"\n  {Colors.WARNING}└─> ⚠️ EDR ATIVO: Deseja MATAR o programa '{pname}'? [S/N]: {Colors.ENDC}").strip().upper() == 'S':
                            os.kill(int(pid), 9)
                            print(f"  {Colors.OKGREEN}{Colors.BOLD}└─> 💥 ALVO DERRUBADO! Hacker extirpado.{Colors.ENDC}")
                    except Exception as err:
                         print(f"  {Colors.FAIL}└─> ❌ Falha Falta Root: {err}{Colors.ENDC}")

            # 2. SCAN DE HD (FIM + ENTROPY + YARA)
            current_files_scanned = []
            for root, dirs, files in os.walk(directory):
                if root.startswith(q_dir_prevent): continue 
                for filename in files:
                    filepath = os.path.join(root, filename)
                    current_hash = calculate_file_hash(filepath)
                    current_files_scanned.append(filepath)
                    if not current_hash: continue 
                    
                    if filepath not in baseline_data:
                        print(f"\n{Colors.WARNING}[ALERTA] ARQUIVO NOVO DETECTADO: {filepath}{Colors.ENDC}")
                        
                        # Motor de Entropia (Ransomware)
                        entropia = calculate_entropy(filepath)
                        if entropia > 7.9:
                             print(f"  {Colors.FAIL}{Colors.BOLD}└─> ⚠️ ALTA ENTROPIA ({entropia:.2f}/8.0). Risco Crítico de Ransomware!{Colors.ENDC}")
                        else:
                             print(f"  {Colors.HEADER}└─> 🔍 Entropia Padrão ({entropia:.2f}/8.0).{Colors.ENDC}")
                             
                        # Motor YARA Local
                        is_yara, bad_string = scan_yara_lite(filepath)
                        if is_yara:
                             print(f"  {Colors.FAIL}{Colors.BOLD}└─> 💀 YARA ENGINE: Encontrado código perigoso [{bad_string}]!{Colors.ENDC}")

                        # Motor Nuvem
                        print(f"  {Colors.HEADER}└─> ☁️ Enviando ao VirusTotal...{Colors.ENDC}")
                        is_vt, vt_msg = check_virustotal(filepath, VT_API_KEY)
                        
                        # Julgamento da Matriz de Decisão
                        is_hacked = is_vt or is_yara or (entropia > 7.95)
                        
                        if is_vt: print(f"  {Colors.FAIL}└─> {vt_msg}{Colors.ENDC}")
                        else: print(f"  {Colors.OKGREEN}└─> 🟢 Status VirusTotal: {vt_msg}{Colors.ENDC}")

                        if is_hacked:
                            print(f"  {Colors.WARNING}└─> 🚨 INICIANDO QUARENTENA GLOBAL!{Colors.ENDC}")
                            success, q_msg = quarantine_file(filepath, directory)
                            if success:
                                try:
                                    if input(f"\n  {Colors.WARNING}└─> ⚠️ Deseja DELETAR '{filename}' pra sempre? [S/N]: {Colors.ENDC}").strip().upper() == 'S':
                                        os.chmod(q_msg, 0o600) ; os.remove(q_msg)
                                        print(f"  {Colors.OKGREEN}{Colors.BOLD}└─> 💥 EXTERMINADO DO DISCO!{Colors.ENDC}")
                                except Exception as err:
                                    print(f"  {Colors.FAIL}└─> ❌ Falha: {err}{Colors.ENDC}")
                            continue
                        baseline_data[filepath] = current_hash 

                    elif baseline_data[filepath] != current_hash:
                        print(f"\n{Colors.FAIL}{Colors.BOLD}[CRÍTICO] ARQUIVO MODIFICADO / QUEBRA DE INTEGRIDADE: {filepath}{Colors.ENDC}")
                        baseline_data[filepath] = current_hash

            # Remove chaves velhas
            remover = [p for p in baseline_data if p.startswith(directory) and p not in current_files_scanned]
            for c in remover:
                print(f"\n{Colors.FAIL}[FATAL] ARQUIVO FOI APAGADO SILENCIOSAMENTE: {c}{Colors.ENDC}")
                del baseline_data[c]
            time.sleep(3)

    except KeyboardInterrupt:
         print(f"\n{Colors.HEADER}[-] Sentinel desativado.{Colors.ENDC}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🛡️ Sentinel EDR - Active Defense System")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--baseline', help='Cria uma nova baseline a partir do diretório alvo')
    group.add_argument('-m', '--monitor', help='Ativa o monitoramento do diretório alvo')
    args = parser.parse_args()

    print(f"{Colors.BOLD}{Colors.HEADER}\nSentinel Advanced EDR (Entropia+YARA) v5.0{Colors.ENDC}")
    if args.baseline: create_baseline(args.baseline)
    elif args.monitor: monitor_directory(args.monitor)
