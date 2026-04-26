/*
Sentinel EDR - Advanced Threat Signatures
Desenvolvido por Theus-TI para rastreamento de Botnets
*/

rule Backdoor_Netcat_ReverseShell
{
    meta:
        author = "SOC Sentinel"
        description = "Detecta comandos perigosos usados para abrir backdoors em servidores Linux."
        threat_level = "Extremo"
        kill_chain = "C2 (Command and Control)"
        
    strings:
        $cmd_nc_sh = "nc -e /bin/sh" ascii
        $cmd_nc_bash = "nc -e /bin/bash" ascii
        $cmd_dev_tcp = "/dev/tcp/" ascii
        
    condition:
        any of them
}

rule Powershell_Encoded_Execution
{
    meta:
        author = "SOC Sentinel"
        description = "Identifica a tática clássica de esconder malware dentro de strings em base64 no Windows/Wsl."
        threat_level = "Alto"
        
    strings:
        $ps_enc = "powershell -enc" nocase ascii wide
        $ps_bypass = "powershell.exe -ExecutionPolicy Bypass" nocase ascii wide
        
    condition:
        any of them
}

rule Web_Malware_Droppers
{
    meta:
        author = "SOC Sentinel"
        description = "Scripts que baixam malwares do lado do servidor via CLI."
        
    strings:
        $curl_eval = "curl -s http" ascii
        $wget_eval = "wget http" ascii
        $eval_b64 = "eval(base64_decode" ascii
        
    condition:
        any of them
}
