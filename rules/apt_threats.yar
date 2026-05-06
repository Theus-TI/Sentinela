/*
Sentinel EDR - Advanced Threat Signatures v2.0
Desenvolvido por Theus-TI para rastreamento de Botnets e APTs
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
        $cmd_ncat = "ncat -e /bin" ascii
        $cmd_socat = "socat exec:" ascii nocase
        
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
        $ps_hidden = "powershell -w hidden" nocase ascii wide
        $ps_iex = "IEX(New-Object" nocase ascii wide
        
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
        $curl_pipe = "curl" ascii
        $wget_pipe = "| bash" ascii
        $wget_sh = "| sh" ascii
        
    condition:
        ($curl_pipe and ($wget_pipe or $wget_sh)) or $eval_b64 or $curl_eval or $wget_eval
}

rule Cryptominer_Detection
{
    meta:
        author = "SOC Sentinel"
        description = "Detecta mineradores de criptomoedas (XMRig, Stratum protocol)."
        threat_level = "Alto"
        kill_chain = "Resource Hijacking"

    strings:
        $xmrig = "xmrig" nocase ascii
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $pool = "pool.minexmr" ascii
        $monero = "randomx" nocase ascii
        $hashrate = "hashrate" ascii
        
    condition:
        2 of them
}

rule Privilege_Escalation_Linux
{
    meta:
        author = "SOC Sentinel"
        description = "Tentativas de escalação de privilégios em sistemas Linux."
        threat_level = "Crítico"

    strings:
        $suid_find = "find / -perm -4000" ascii
        $suid_find2 = "find / -perm -u=s" ascii
        $sudo_exploit = "sudo -u#-1" ascii
        $passwd_write = "/etc/passwd" ascii
        $shadow_read = "/etc/shadow" ascii
        $pkexec = "pkexec" ascii
        
    condition:
        2 of them
}

rule Data_Exfiltration_Patterns
{
    meta:
        author = "SOC Sentinel"
        description = "Padrões de exfiltração de dados via CLI."
        threat_level = "Extremo"
        kill_chain = "Exfiltration"

    strings:
        $tar_curl = "tar cz" ascii
        $base64_pipe = "base64 |" ascii
        $xxd_pipe = "xxd |" ascii
        $dns_exfil = "nslookup" ascii
        $nc_file = "nc -w" ascii
        
    condition:
        2 of them
}

rule LOLBins_Abuse
{
    meta:
        author = "SOC Sentinel"
        description = "Abuso de binários legítimos do sistema (Living off the Land)."
        threat_level = "Alto"

    strings:
        $python_pty = "python -c 'import pty" ascii
        $python3_pty = "python3 -c 'import pty" ascii
        $perl_socket = "perl -e 'use Socket" ascii
        $ruby_socket = "ruby -rsocket" ascii
        $php_exec = "php -r '$sock=fsockopen" ascii
        
    condition:
        any of them
}
