# Simple - HackMyVM (Easy)

![Simple.png](Simple.png)

## Übersicht

*   **VM:** Simple
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Simple)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-12-06
*   **Original-Writeup:** https://alientec1908.github.io/Simple_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, die User- und Root-Flags der Maschine "Simple" zu erlangen. Die initiale Reconnaissance offenbarte einen Windows-Host mit einem IIS-Webserver auf Port 80 und SMB-Diensten (Ports 139/445). Auf der Webseite wurden Benutzernamen (`ruy`, `marcos`, `lander`, `bogo`, `vaiper`) gefunden. SMB-Enumeration identifizierte den Benutzer `sysadmin` und eine schwache Passwortrichtlinie. Der Login-Versuch `bogo:bogo` via SMB schlug mit `STATUS_PASSWORD_EXPIRED` fehl. Der genaue Weg zum Initial Access und zur Privilegieneskalation wurde im bereitgestellten Log nicht dokumentiert. Die Flags deuten auf eine ASPX-Webshell für den User-Zugriff und einen Impersonation-Privilege-Exploit für Root hin.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nikto`
*   `gobuster`
*   `dirb`
*   Wappalyzer (implizit)
*   `ping`
*   `nmap`
*   `enum4linux`
*   `crackmapexec`
*   `smbclient` (versucht)
*   `msfconsole` (für SMB-Login-Versuch)
*   Standard Linux-Befehle (`echo`, `tr`, `cat`, `hydra` (impliziert für Web-Login))

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Simple" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/SMB Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.114) mit `arp-scan` identifiziert. Hostname `simple.hmv` in `/etc/hosts` eingetragen. Ping-Test bestätigte Windows (TTL=128).
    *   `nmap`-Scan offenbarte Port 80 (HTTP, Microsoft IIS 10.0, Titel "Simple") und Ports 139/445 (SMB, Samba 4.6.2 – *Hinweis: Nmap meldet Samba, aber OS ist Windows, hier liegt eine Inkonsistenz vor oder Nmap interpretiert falsch*). NetBIOS-Name "SIMPLE".
    *   `nikto` auf Port 80 bestätigte IIS/ASP.NET und meldete fehlende Sicherheitsheader.
    *   `gobuster` und `dirb` auf Port 80 fanden `index.html`, `/images/`, `/fonts/`.
    *   Auf der Webseite `http://simple.hmv/` wurden die Namen `ruy`, `marcos`, `lander`, `bogo`, `vaiper` gefunden und in `users.txt` gespeichert.
    *   `enum4linux` fand den Benutzer `sysadmin` und eine schwache Passwortrichtlinie (Länge 5, keine Komplexität). Null Session war nicht erlaubt.
    *   `crackmapexec smb` mit `bogo` und Passwörtern aus `users.txt` fand `bogo:bogo` mit `STATUS_PASSWORD_EXPIRED`. Anonyme SMB-Share-Enumeration scheiterte.
    *   Metasploit (`auxiliary/scanner/smb/smb_login`) bestätigte `bogo:bogo` als gültig, aber wahrscheinlich abgelaufen.

2.  **Initial Access (Undokumentiert im Log):**
    *   Der genaue Weg zum Erhalt des initialen Zugriffs wurde im bereitgestellten Log nicht dokumentiert.
    *   Basierend auf der User-Flag (`SIMPLE{ASPXT0SH311}`) ist zu vermuten, dass eine ASPX-Webshell hochgeladen oder eine RCE-Schwachstelle in der IIS/ASP.NET-Anwendung ausgenutzt wurde.

3.  **Privilege Escalation (Undokumentiert im Log):**
    *   Der genaue Weg zur Privilegieneskalation zu Root wurde im bereitgestellten Log nicht dokumentiert.
    *   Basierend auf der Root-Flag (`SIMPLE{S31MP3R50N4T3PR1V1L363}`) ist zu vermuten, dass eine Impersonation-Privileg-Schwachstelle (z.B. SeImpersonatePrivilege, Juicy Potato, PrintSpoofer etc.) auf dem Windows-System ausgenutzt wurde.

4.  **Flags (Quelle des Auslesens nicht dokumentiert):**
    *   User-Flag: `SIMPLE{ASPXT0SH311}`
    *   Root-Flag: `SIMPLE{S31MP3R50N4T3PR1V1L363}`

## Wichtige Schwachstellen und Konzepte (basierend auf Funden & Flags)

*   **Information Disclosure:** Benutzernamen wurden auf der Webseite preisgegeben.
*   **Schwache Passwortrichtlinie & abgelaufenes Passwort:** Der Benutzer `bogo` verwendete seinen eigenen Namen als Passwort, welches zudem abgelaufen war.
*   **(Vermutet) ASPX Webshell / RCE:** Die User-Flag deutet auf eine Kompromittierung über eine ASPX-basierte Webshell hin.
*   **(Vermutet) Windows Impersonation Privilege Escalation:** Die Root-Flag deutet auf die Ausnutzung einer bekannten Windows-Privilegieneskalationstechnik hin, die auf Impersonation basiert.
*   **Fehlende Sicherheitsheader:** Nikto meldete das Fehlen von `X-Frame-Options` und `X-Content-Type-Options`.
*   **Veraltete Samba-Version (Fehlinterpretation?):** Nmap meldete Samba 4.6.2, obwohl es sich um ein Windows-System handelt. Dies könnte ein Hinweis auf eine ungewöhnliche Konfiguration oder eine Fehlinterpretation durch Nmap sein.

## Flags

*   **User Flag:** `SIMPLE{ASPXT0SH311}`
*   **Root Flag:** `SIMPLE{S31MP3R50N4T3PR1V1L363}`

## Tags

`HackMyVM`, `Simple`, `Easy`, `Information Disclosure`, `IIS`, `ASP.NET`, `SMB`, `Windows Privilege Escalation`, `Impersonation`, `Webshell` (vermutet), `Windows`
