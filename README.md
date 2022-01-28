![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## Lazarus Group

## Aliases
* [Hidden Cobra]() 
* [The Guardians of Peace](https://techcrunch.com/2017/11/14/u-s-government-issues-alerts-about-malware-and-ip-addresses-linked-to-north-korean-cyber-attacks/)

## Overview

## Attack Pattern
* A type of Tactics, Techniques, and Procedures (TTP) that describes ways threat actors attempt to compromise targets.

## Campaign
* A grouping of adversarial behaviors that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.

## Course of Action 
* An action taken to either prevent an attack or respond to an attack.

## Identity
* Individuals, organizations, or groups, as well as classes of individuals, organizations, or groups.

## Indicator 
* Contains a pattern that can be used to detect suspicious or malicious cyber activity.

## Intrusion Set 
* A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor.

## Malware
* A type of TTP, also known as malicious code and malicious software, used to compromise the confidentiality, integrity, or availability of a victim’s data or system.

## Observed Data
* Conveys information observed on a system or network (e.g., an IP address).

## Report
* Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details.

## Threat Actor
* Individuals, groups, or organizations believed to be operating with malicious intent.

## Tool 
* Legitimate software that can be used by threat actors to perform attacks.

## Vulnerability
* A mistake in software that can be directly used by a hacker to gain access to a system or network.

## Raw Intelligence

https://piie.com/blogs/north-korea-witness-transformation/cyber-update-cashing-bitcoin-other-mischief-and-just-surfin
Previous reporting from cybersecurity firms Kaspersky Labs, Symantec, and Fireye used patterns and clues within Wannacry’s code to conclude that The Lazarus Group, a hacking group known to be connected to the North Korean government, was indeed responsible.
At the time, the malware exploit only made off with about $140,000 in Bitcoin from those willing to pay, 
Since then, the three bitcoin wallets reported to be the depositories saw no activity. But on August 2nd, after over 300 unique payments, the perpetrators finally began to reap their ill-gotten loot. In a rapid succession of seven withdrawals, the three wallets were quickly emptied. 
The second major finding is that the DPRK routes substantial traffic through internet nodes abroad. Of course, China is in this mix. But the surprise of the report is that Chinese networks only account for about 10% of traffic, with India being a more significant player and Indonesia, Mozambique, New Zealand, Kenya, and Nepal all playing a role as well. These patterns underscore the need for greater coordination on cyber issues as well as sanctions enforcement.

http://www.securityweek.com/taiwan-bank-heist-linked-north-korean-hackers
Hackers exploited the SWIFT global financial network to steal roughly $60 million from Taiwan’s Far Eastern International Bank. The money was transferred to several countries, but bank officials claimed they had managed to recover most of it. Two individuals were arrested earlier this month in Sri Lanka for their role in the operation.
Researchers at BAE Systems have identified some of the tools used in the attack and found connections to the North Korean threat actor known as Lazarus. This group is also believed to be behind the 2014 attack on Sony Pictures and campaigns targeting several banks, including Bangladesh’s central bank.
The attack on the Bangladesh bank, which resulted in the theft of $81 million, also involved the SWIFT system. Similar methods were also used to target several other banks, but SWIFT said some of the operations failed due to the new security measures implemented by the company.
While it’s still unclear how attackers gained access to the systems of Far Eastern International Bank, an analysis of various malware samples apparently involved in the attack suggests that the hackers may have used a piece of ransomware as a distraction.
The ransomware involved in the attack is known as Hermes. According to Bleeping Computer, the threat surfaced in February and its latest version has an encryption mechanism that makes it impossible to recover files without paying the ransom.
However, researchers at McAfee discovered that the Hermes variant used in the attack on the Taiwanese bank did not display a ransom note, which led them to believe it may have been only a distraction.
“Was the ransomware used to distract the real purpose of this attack? We strongly believe so,” McAfee researchers said. “Based on our sources, the ransomware attack started in the network when the unauthorized payments were being sent.”
Another malware sample linked by BAE Systems to this attack is a loader named Bitsran, which spreads a malicious payload on the targeted network. This threat contained what appeared to be hardcoded credentials for Far Eastern International’s network, which suggests the threat group may have conducted previous reconnaissance.
Some pieces of malware discovered by BAE Systems are known to have been used by the Lazarus group, including in attacks aimed at financial organizations in Poland and Mexico. The malware includes commands and other messages written in Russia, which experts believe is likely a false flag designed to throw off investigators.
It’s worth noting that the Hermes ransomware samples checked the infected machine’s language settings and stopped running if Russian, Ukrainian or Belarusian was detected. This is common for malware created by Russian and Ukrainian hackers who often avoid targeting their own country’s citizens. However, this could also be a false flag.
Another piece of evidence linking the Taiwan bank attacks to Lazarus is the fact that money was transferred to accounts in Sri Lanka and Cambodia, similar to other operations attributed to the group.

http://www.securityweek.com/north-korean-hackers-target-android-users-south
The malware sample analyzed by McAfee, delivered as an APK file, has been designed to mimic a Korean bible app made available on Google Play by a developer named GODpeople. However, the malicious application did not make it onto the official app store and it’s unclear what method of distribution has been used. - android app
“GodPeople is sympathetic to individuals from North Korea, helping to produce a movie about underground church groups in the North. Previous dealings with the Korean Information Security Agency on discoveries in the Korean peninsula have shown that religious groups are often the target of such activities in Korea,” explained McAfee’s Christiaan Beek and Raj Samani.
McAfee said the malware, which has been around since at least March, delivers a backdoor as an executable and linkable format (ELF) file. The backdoor allows hackers to collect information about the infected device, download and upload files, and execute commands. The list of command and control (C&C) servers used by the malware includes IP addresses previously linked to the Lazarus group.
Palo Alto Networks has not shared any information about the applications used to deliver the malware, but the company pointed out that the operation appears to be aimed at Samsung device users in South Korea.
The firm’s analysis started with a PE file uploaded to VirusTotal. This file is designed to deliver ELF ARM files and APK files from an HTTP server. The APK that represents the final payload provides backdoor capabilities and allows its operator to spy on the targeted user by recording audio via the microphone, capturing images via the camera, uploading and downloading files, harvesting GPS information, reading contacts, collecting SMS and MMS messages, recording browsing history, and capturing Wi-Fi information.
Palo Alto Networks has also found links between the malware and the Lazarus group, particularly to malware and infrastructure used in attacks on the SWIFT banking system and activities described in reports on Operation Blockbuster.
This is not the first time North Korea has reportedly targeted mobile users in the South. Back in 2014, South Korea’s National Intelligence Service said more than 20,000 smartphones had been infected that year with a piece of malware traced back to North Korea.

http://www.ibtimes.co.uk/what-hidden-cobra-us-warns-about-north-korean-hacker-groups-8-year-long-attack-spree-1626185
According to US authorities, North Korean hackers used a malware dubbed DeltaCharlie to control a DDoS botnet, which in turn the hackers leveraged to conduct widespread attacks. The cyberespionage group has been operating since 2009 and has been typically targeting "systems running older, unsupported versions of Microsoft operating systems".
"It is clear the purpose of building a DDoS botnet is to cripple a target," Mounir Hahad, senior director, Cyphort Labs told IBTimes UK. "Sometimes that's an end by itself, as when the electrical grid infrastructure or water treatment plants or air traffic control systems are targeted.
"But more often than not, DDoS attacks are used to hide more nefarious activity taking place under the radar while the IT staff is busy fighting the overt DDoS attack. That's is the kind of scenario to worry about when the target of the DDoS attack is a government installation for example and those are typically espionage by nature."
Experts believe that the cyberespionage group has also posed as hacktivists groups, one in particular called the Guardians of Peace.
North Korean hackers also made use of a DDoS malware tool called DeltaCharlie, which "is capable of downloading executables, changing its own configuration, updating its own binaries, terminating its own processes, and activating and terminating denial-of-service attacks".

https://techcrunch.com/2017/11/14/u-s-government-issues-alerts-about-malware-and-ip-addresses-linked-to-north-korean-cyber-attacks/
The technical alert from the FBI and Department of Homeland Security says a remote administration tool (RAT) called FALLCHILL has been deployed by Hidden Cobra since 2016 to target the aerospace, telecommunications and finance industries.
FALLCHILL allows Hidden Cobra to issue commands to a victim’s server by dual proxies, which means it can potentially perform actions like retrieving information about all installed disks, accessing files, modifying file or directory timestamps and deleting evidence that it’s been on the infected server.
The FBI says it “has high confidence” that those IP addresses are linked to attacks that infect computer systems with Volgmer, a Trojan malware variant used by Hidden Cobra to target the government, financial, auto and media industries.
The U.S. government says Volgmer has been used to gain access to computer systems since at least 2013. Once Volgmer establishes a presence in a systems, it can gather system information, update service registry keys, download and upload files, execute commands and terminate processes and list directories, says the FBI and Department of Homeland Security.

https://www.us-cert.gov/ncas/alerts/TA17-318B
This joint Technical Alert (TA) is the result of analytic efforts between the Department of Homeland Security (DHS) and the Federal Bureau of Investigation (FBI). Working with U.S. government partners, DHS and FBI identified Internet Protocol (IP) addresses and other indicators of compromise (IOCs) associated with a Trojan malware variant used by the North Korean government—commonly known as Volgmer. The U.S. Government refers to malicious cyber activity by the North Korean government as HIDDEN COBRA. 
FBI has high confidence that HIDDEN COBRA actors are using the IP addresses—listed in this report’s IOC files—to maintain a presence on victims’ networks and to further network exploitation. DHS and FBI are distributing these IP addresses to enable network defense and reduce exposure to North Korean government malicious cyber activity.

Description
Volgmer is a backdoor Trojan designed to provide covert access to a compromised system. Since at least 2013, HIDDEN COBRA actors have been observed using Volgmer malware in the wild to target the government, financial, automotive, and media industries.

It is suspected that spear phishing is the primary delivery mechanism for Volgmer infections; however, HIDDEN COBRA actors use a suite of custom tools, some of which could also be used to initially compromise a system. Therefore, it is possible that additional HIDDEN COBRA malware may be present on network infrastructure compromised with Volgmer

The U.S. Government has analyzed Volgmer’s infrastructure and have identified it on systems using both dynamic and static IP addresses. At least 94 static IP addresses were identified, as well as dynamic IP addresses registered across various countries. The greatest concentrations of dynamic IPs addresses are identified below by approximate percentage:

    India (772 IPs) 25.4 percent
    Iran (373 IPs) 12.3 percent
    Pakistan (343 IPs) 11.3 percent
    Saudi Arabia (182 IPs) 6 percent
    Taiwan (169 IPs) 5.6 percent
    Thailand (140 IPs) 4.6 percent
    Sri Lanka (121 IPs) 4 percent
    China (82 IPs, including Hong Kong (12)) 2.7 percent
    Vietnam (80 IPs) 2.6 percent
    Indonesia (68 IPs) 2.2 percent
    Russia (68 IPs) 2.2 percent

Technical Details

As a backdoor Trojan, Volgmer has several capabilities including: gathering system information, updating service registry keys, downloading and uploading files, executing commands, terminating processes, and listing directories. In one of the samples received for analysis, the US-CERT Code Analysis Team observed botnet controller functionality.

Volgmer payloads have been observed in 32-bit form as either executables or dynamic-link library (.dll) files. The malware uses a custom binary protocol to beacon back to the command and control (C2) server, often via TCP port 8080 or 8088, with some payloads implementing Secure Socket Layer (SSL) encryption to obfuscate communications.

Malicious actors commonly maintain persistence on a victim’s system by installing the malware-as-a-service. Volgmer queries the system and randomly selects a service in which to install a copy of itself. The malware then overwrites the ServiceDLL entry in the selected service's registry entry. In some cases, HIDDEN COBRA actors give the created service a pseudo-random name that may be composed of various hardcoded words.
Detection and Response

This alert’s IOC files provide HIDDEN COBRA indicators related to Volgmer. DHS and FBI recommend that network administrators review the information provided, identify whether any of the provided IP addresses fall within their organizations’ allocated IP address space, and—if found—take necessary measures to remove the malware.

When reviewing network perimeter logs for the IP addresses, organizations may find instances of these IP addresses attempting to connect to their systems. Upon reviewing the traffic from these IP addresses, system owners may find some traffic relates to malicious activity and some traffic relates to legitimate activity.
Network Signatures and Host-Based Rules

This section contains network signatures and host-based rules that can be used to detect malicious activity associated with HIDDEN COBRA actors. Although created using a comprehensive vetting process, the possibility of false positives always remains. These signatures and rules should be used to supplement analysis and should not be used as a sole source of attributing this activity to HIDDEN COBRA actors.
Network Signatures

alert tcp any any -> any any (msg:"Malformed_UA"; content:"User-Agent: Mozillar/"; depth:500; sid:99999999;)

___________________________________________________________________________________________________
YARA Rules

rule volgmer
{
meta:
    description = "Malformed User Agent"
strings:
    $s = "Mozillar/"
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $s
}
Impact

A successful network intrusion can have severe impacts, particularly if the compromise becomes public and sensitive information is exposed. Possible impacts include

    temporary or permanent loss of sensitive or proprietary information,
    disruption to regular operations,
    financial losses incurred to restore systems and files, and
    potential harm to an organization’s reputation.

Solution
Mitigation Strategies

DHS recommends that users and administrators use the following best practices as preventive measures to protect their computer networks:

    Use application whitelisting to help prevent malicious software and unapproved programs from running. Application whitelisting is one of the best security strategies as it allows only specified programs to run, while blocking all others, including malicious software.
    Keep operating systems and software up-to-date with the latest patches. Vulnerable applications and operating systems are the target of most attacks. Patching with the latest updates greatly reduces the number of exploitable entry points available to an attacker.
    Maintain up-to-date antivirus software, and scan all software downloaded from the Internet before executing.
    Restrict users’ abilities (permissions) to install and run unwanted software applications, and apply the principle of “least privilege” to all systems and services. Restricting these privileges may prevent malware from running or limit its capability to spread through the network.
    Avoid enabling macros from email attachments. If a user opens the attachment and enables macros, embedded code will execute the malware on the machine. For enterprises or organizations, it may be best to block email messages with attachments from suspicious sources. For information on safely handling email attachments, see Recognizing and Avoiding Email Scams. Follow safe practices when browsing the web. See Good Security Habits and Safeguarding Your Data for additional details.
    Do not follow unsolicited web links in emails. See Avoiding Social Engineering and Phishing Attacks for more information.

https://www.proofpoint.com/sites/default/files/pfpt-us-wp-north-korea-bitten-by-bitcoin-bug.pdf
was cited in https://www.securityweek.com/north-korean-hackers-targeting-individuals-report dated December 21, 2017 

he Lazarus Group has increasingly focused on financially motivated attacks and appears to be capitalizing on both the 
increasing interest and skyrocketing prices for cryptocurrencies.We also discovered what appears to be the first publicly documented instance of a nation-state targeting a point-of-sale related framework for the theft of credit card data in a related set of attacks. We hypothesize that many of these previously reported
operations targeting cryptocurrency organizations have actually been conducted by the espionage team of the Lazarus
Group based on evidence we provide in the Attribution section. Further, we assess that until today, many of Lazarus
Group’s traditional financially motivated team have remained largely in the shadows as they conduct these operations
adding to their already impressive stockpile of various cryptocurrencies.

![alt tag](https://user-images.githubusercontent.com/24201238/44615268-68159c00-a88a-11e8-89e7-fb56945ea804.png)
Flow of PowerRatankba activity from victims to the Lazarus Group operators

the different attack vectors and campaigns we have discovered that eventually lead to
the delivery of PowerRatankba. In total we have discovered six different attack vectors:
• A new Windows executable downloader dubbed PowerSpritz
• A malicious Windows Shortcut (LNK) file
• Several malicious Microsoft Compiled HTML Help (CHM) files using two different techniques
• Multiple JavaScript (JS) downloaders
• Two macro-based Microsoft Office documents
• Two campaigns utilizing backdoored popular cryptocurrency applications hosted on internationalized domain (IDN)
infrastructure to trick victims into thinking they were on a legitimate website

The campaigns discussed in this research began on or around June 30th, 2017. According to our data those campaigns
were highly targeted spearphishing attacks targeting at least one executive at a cryptocurrency organization to deliver a
PowerRatankba.A variant. All other campaigns utilized PowerRatankba.B variants. We currently have no visibility into how
the LNK, CHM, and JS campaigns were delivered to users, but given common Lazarus modus operandi, we can speculate
that they may have been delivered through attachments or links in emails. We gained visibility again during the massive
email campaigns utilizing BTG- and Electrum-themed applications to ultimately deliver PowerRatankba. The timeline below
illustrates the exact dates of campaigns where we are aware of them. Where exact dates are unknown, we based estimates
on first campaign observations and metadata (Fig. 2).

![alt_tag](https://user-images.githubusercontent.com/24201238/44615304-1faaae00-a88b-11e8-8e2d-4a4acfeaae72.png)
Timeline of campaigns ultimately related to PowerRatankba

PowerSpritz is a Windows executable that hides both its legitimate payload and malicious PowerShell command using
a non-standard implementation of the already rarely used Spritz encryption algorithm (see the Attribution section for
additional analysis of the Spritz implementation). This malicious downloader has been observed being delivered via
spearphishing attacks using the TinyCC link shortener service to redirect to likely attacker-controlled servers hosting the
malicious PowerSpritz payload. In early July 2017 an individual on Twitter shared an attack they observed targeting them
(Fig. 3) utilizing a fake Skype update lure to trick users into clicking on a link to hxxps://skype.2[.]vu/1. The TinyCC link
redirected to a server that, at the time, would have likely returned a PowerSpritz payload: hxxp://201.211.183[.]215:8080/
update.php?t=Skype&r=update

![alt_tag](https://user-images.githubusercontent.com/24201238/44615661-a19ed500-a893-11e8-9872-c94a4275a6a0.png)
https://twitter.com/LeoAW/status/881761293874610176

We have since discovered three additional TinyCC URLs utilized to spread PowerSpritz: one with a Telegram theme (hxxp://
telegramupdate.2[.]vu/5 -> hxxp://122.248.34[.]23/lndex.php?t=Telegram&r=1.1.9) and two more with Skype theme
(hxxp://skypeupdate.2[.]vu/1 -> hxxp://122.248.34[.]23/lndex.php?t=SkypeSetup&r=mail_new and hxxp://skype.2[.]vu/k
-> unknown). Some of the PowerSpritz payloads were previously hosted on Google Drive; however, we were unable to
determine if that service was actually used to spread the payloads in-the-wild (ITW).
PowerSpritz decrypts a legitimate Skype or Telegram installer using a custom Spritz implementation with the key “Znxkai@
if8qa9w9489”. PowerSpritz then writes the legitimate installer to disk in the directory returned by GetTempPathA either as
a hardcoded filename such as SkypeSetup.exe or, in some versions, as the filename returned by GetTempFileNameA.
The installer is then executed to trick the potential victim into thinking they downloaded a legitimate, working application
installer or update. Finally, Spritz uses the same key to decrypt a PowerShell command that downloads the first stage of
PowerRatankba (Fig. 4). All three PowerSpritz samples we discovered executed the identical PowerShell command.

![alt_tag](https://user-images.githubusercontent.com/24201238/44615704-d2333e80-a894-11e8-83e9-a333ce7ba5d0.png)
Script output showing PowerSpritz PowerShell encoded and decoded command

As shown in the above decoded script (Fig. 4), PowerSpritz attempts to retrieve a payload from hxxp://dogecoin.
deaftone[.]com:8080/mainls.cs that is expected to be a Base64-encoded PowerShell script. After decoding mainls.cs,
a PowerRatankba.A implant is revealed (Fig. 5) with hxxp://vietcasino.linkpc[.]net:8080/search.jsp as its command and
control (C&C).

![alt_tag](https://user-images.githubusercontent.com/24201238/44615721-3b1ab680-a895-11e8-8768-213c21366287.png)
PowerSpritz retrieving Base64-encoded PowerRatankba

A LNK masquerading as a PDF document was discovered on an antivirus
scanning service. The malicious “Scanned Document Part 1.pdf.lnk”
LNK file, along with a corrupted PDF named “Scanned Document Part
2.pdf,” were compressed in a ZIP file named “Scanned Documents.zip”
(Fig. 6). It is unclear if the PDF document was tampered with intentionally
to increase the chances a target would open the malicious LNK or if the
actor(s) unintentionally used a corrupted document. We currently are not
aware of how the LNK or compressed ZIP files were utilized ITW.
The malicious LNK uses a [known AppLocker bypass](https://www.theregister.co.uk/2016/04/22/applocker_bypass/) to retrieve its
payload from a TinyURL shortener link hxxp://tinyurl[.]com/y9jbk8cg (Fig.
7). This shortener previously redirected to hxxp://201.211.183[.]215:8080/
pdfviewer.php?o=0&t=report&m=0 . At the time of analysis the C&C
server was no longer returning payloads. However, the same IP was
used in the PowerSpritz campaigns. Based on the same C&C usage
and similar URI structure, we assess with low confidence that the LNK
campaign would have delivered PowerRatankba via PowerSpritz.

![alt_tag](https://user-images.githubusercontent.com/24201238/44615765-3d314500-a896-11e8-9c3f-c660328e4794.png)
Malicious LNK AppLocker bypass to retrieve payload

Several malicious CHM files were uploaded to a multi antivirus scanning service in October, November, and December. We
inspected the compressed ZIP metadata to better understand the likely chronological order in which the CHMs were used.
Unfortunately we have been unable to determine how these infection attempts were delivered to victims ITW. The themes of
the malicious CHMs include:
• A confusing, poorly written request for assistance with creating a website with possible romantic undertones (Fig. 8-1)
• Documentation on a blockchain technology called ALCHAIN from Orient Exchange Co. (Fig. 8-2)
• A request for assistance in developing an initial coin offering (ICO) platform (Fig. 8-3)
• White paper on the Falcon Coin ICO (Fig. 8-4)
• A request for applications to develop a cryptocurrency exchange platform (Fig. 8-5)
• A request for assistance in creating an email marketing tool (Fig. 8-6)

![alt_tag](https://user-images.githubusercontent.com/24201238/44615801-de200000-a896-11e8-9f6d-b92d6247b556.png)
CHM lures utilized in attempts to deliver PowerRatankba

All of the CHM files use a [well-known technique](https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1) to create a shortcut object capable of executing malicious code and then
causing that shortcut object to be automatically clicked via the “x.Click();” function. Two different methods were used
across the CHMs to retrieve the malicious payload.
The first method uses a VBScript Execute command and BITSAdmin tool to download a malicious VBScript file (Fig.
9). The payload is downloaded (Fig. 10) from hxxp://www.businesshop[.]net/hide.gif and saved to C:\windows\temp\
PowerOpt.vbs. Once the downloaded VBScript (Fig. 10) is executed, it will attempt to download PowerRatankba from
hxxp://158.69.57[.]135/theme.gif, saving the expected PowerShell script to C:\Users\Public\Pictures\opt.ps1.

![alt_tag](https://user-images.githubusercontent.com/24201238/44711227-f6478780-ab01-11e8-96ef-c7be877af46f.png)
Malicious code embedded in CHM to download a VBScript PowerRatankba downloader

![alt_tag](https://user-images.githubusercontent.com/24201238/44711422-72da6600-ab02-11e8-97e2-e118d8777a45.png)
BITSAdmin retrieving malicious payload over HTTP

![alt_tag](https://user-images.githubusercontent.com/24201238/44711865-7cb09900-ab03-11e8-9164-1945ebe63871.png)
PowerShell utilized in CHM to retrieve PowerRatankba downloader VBS

![alt_tag](https://user-images.githubusercontent.com/24201238/44712258-7e2e9100-ab04-11e8-9c7e-782d2fbbf845.png)
Leftover code in 5_6283065828631904327.chm

As a final note on the CHM campaigns, the following three samples contain an email address of either robert_mobile@
gmail[.]com or robert_mobile@mail[.]com, which we assess with some confidence are related to the threat actor:
• 772b9b873100375c9696d87724f8efa2c8c1484853d40b52c6dc6f7759f5db01
• 6cb1e9850dd853880bbaf68ea23243bac9c430df576fa1e679d7f26d56785984
• 9d10911a7bbf26f58b5e39342540761885422b878617f864bfdb16195b7cd0f5

Throughout November several compressed ZIP files containing a JavaScript (JS) downloader were observed being hosted
on likely attacker-controlled servers. We are not currently aware if or how these files were delivered to potential victims. The
naming of the files and the decoy PDF documents they retrieve provide some clues about the nature of the lures. Themes
include the cryptocurrency exchanges Coinbase and Bithumb, the Falcon Coin ICO, and a list of Bitcoin transactions.
Each JavaScript downloader is obfuscated (Fig. 13) using JavaScript Obfuscator (see Attribution section for additional
analysis) or a similar tool. After de-obfuscating (Fig. 14), the logic of the malicious downloader is very straightforward. First,
an obfuscated PowerRatankba.B PowerShell script is downloaded from a fake image URL such as: hxxp://51.255.219[.]82/
theme.gif. Next, the PowerShell script is saved to C:\Users\Public\Pictures\opt.ps1 and then executed.

![alt_tag](https://user-images.githubusercontent.com/24201238/44713708-d1561300-ab07-11e8-9ef2-8b80c0a28b2a.png)
Obfuscated falconcoin.js

![alt_tag](https://user-images.githubusercontent.com/24201238/44714006-65c07580-ab08-11e8-948a-8f688e4992cc.png)
Deobfuscated falconcoin.js revealing PowerRatankba and decoy PDF URLs

The last step in execution is to retrieve the decoy PDF from hxxp://51.255.219[.]82/files/download/falconcoin.pdf and open
it using rundll32.exe and shell32.dll,OpenAs_RunDLL (Fig. 15-1). Samples using Coinbase and Bithumb themes also
downloaded PDF decoys (Fig. 15-2,15-3). Additionally we discovered that the content from the Coinbase decoy has been
used in Lazarus group-attributed espionage campaigns (see Attribution for more details).

![image](https://user-images.githubusercontent.com/24201238/44714195-ccde2a00-ab08-11e8-9216-a88cc2a3f3ca.png)
Decoys downloaded or sent along with PowerRatankba JavaScript downloaders

VBScript Macro Microsoft Office Documents
Two VBScript macro-laden Microsoft Office documents have been observed associated with this activity: one Word
document and one Excel spreadsheet. The Word document (b3235a703026b2077ccfa20b3dabd82d65c6b5645f7f1
5e7bbad1ce8173c7960) uses an Internal Revenue Service (IRS) theme and was sent as an attachment named “report
phishing.doc”. The spearphishing email was sent from an @mail.com address with the subject of “Phishing Warnning”[sic].
Ironically, the sender email address was spoofed as phishing@irs.gov (Fig. 16) while the content of the lure (Fig. 17) was
likely copied from an official IRS webpage.

![alt_tag](https://user-images.githubusercontent.com/24201238/44715050-f1d39c80-ab0a-11e8-8e6a-43f7d9c0b538.png)
Spearphishing email spoofed sender and subject

![alt_tag](https://user-images.githubusercontent.com/24201238/44715064-f9934100-ab0a-11e8-83f3-f26c8c6fd9f6.png)
IRS themed Word document PowerRatankba downloader

The IRS-themed malicious document uses a macro
to download a PowerRatankba VBScript from
hxxp://198.100.157[.]239/hide.gif (Fig. 18), save it to C:\
Users\Public\Pictures\opt.vbs, and execute it with wscript.
exe. It in turn downloads the PowerRatankba.B from
hxxp://198.100.157[.]239/theme.gif, saving the downloaded
payload to C:\Users\Public\Pictures\opt.ps1, and finally
executing it with powershell.exe.

![alt_tag](https://user-images.githubusercontent.com/24201238/44715561-3a3f8a00-ab0c-11e8-8bb8-a973eb6a7c4e.png)
IRS-themed malicious document macro

The second malicious Office document we discovered is an Excel spreadsheet named bithumb.xls. It uses a Bithumb lure
(Fig. 19) and includes stolen branding. The spreadsheet was found compressed in a ZIP file named Bithumb.zip along with
a decoy PDF document named “About Bithumb.pdf” (Fig. 20).

![alt_tag](https://user-images.githubusercontent.com/24201238/44715643-69ee9200-ab0c-11e8-84b6-2a6f0194f12b.png)
Malicious Bithumb Excel spreadsheet with English option shown, with stolen branding

![alt_tag](https://user-images.githubusercontent.com/24201238/44715664-7541bd80-ab0c-11e8-9a16-380f0cecfb65.png)
“About Bithumb.pdf decoy” document inside Bithumb.zip archive, with stolen branding

The Excel spreadsheet contains a macro with an embedded Base64-encoded PowerRatankba VBScript downloader
(rather than retrieving it from a C&C using HTTP (Fig. 21)). The embedded VBScript is first dropped to disk at c:\Users\
Public\Documents\Proxy.vbs and then executed using wscript.exe. The dropped VBScript file is configured to download
PowerRatankba from hxxp://www.energydonate[.]com/images/character.gif while saving the downloaded payload to C:\
Users\Public\Documents\ProxyAutoUpdate.ps1.

![alt_tag](https://user-images.githubusercontent.com/24201238/44715747-a28e6b80-ab0c-11e8-8b74-c85716755f28.png)
Base64 encoded PowerRatankba downloader embedded in bithumb.xls

Most recently, several large email phishing campaigns attempted to trick unsuspecting victims into visiting fake webpages
to download or update cryptocurrency applications. The copycat websites were mirror images of legitimate websites with
software download links pointing to the correct installers hosted on the legitimate websites. The only exception was the
link to download the Windows version of the application, which was hosted on the copycat websites. These PyInstaller
executables were backdoored with a few lines of Python code added to download the PowerRatankba implant.
The first campaign that utilized this technique used a Bitcoin Gold (BTG) theme to trick the targets into visiting an
internationalized domain name (IDN) website (Fig. 22). An email was sent to targets offering a BTG wallet application
along with a link to the malicious website: hxxps://xn--bitcoingld-lcb[.]org/. However, web browsers and email clients would
display the link as follows: hxxps://bitcoingöld[.]org/. Emails in this BTG campaign were sent between approximately
November 10-16, 2017. Some of the known sender emails include but are not limited to: info@xn--bitcoingod-8yb[.]com,
info@xn--bitcoigold-o1b[.]com, and tech@xn--bitcoingld-lcb[.]org. Campaigns using IDN can be difficult to recognize as
malicious because they are typically very similar to the mimicked legitimate domains except for a single character (Fig. 23).
(see IOC section for more likely related IDNs)

![alt_tag](https://user-images.githubusercontent.com/24201238/44716060-71fb0180-ab0d-11e8-994e-44b026143172.png)
IDN email address is emphasized in a red box.

![alt_tag](https://user-images.githubusercontent.com/24201238/44716082-7e7f5a00-ab0d-11e8-8779-117d1cba7054.png)
Excerpt from phishing email showing the IDN link with red arrow pointing to internationalized character

![alt_tag](https://user-images.githubusercontent.com/24201238/44716107-89d28580-ab0d-11e8-8dad-8f4ea9df025e.png)
Figure 24: Malicious BTG website hosting PowerRatankba downloader. Credit: RiskIQ

![alt_tag](https://user-images.githubusercontent.com/24201238/44716131-93f48400-ab0d-11e8-881a-f58be04773bf.png)
Legitimate BTG website showing difference between legitimate and malicious websites (note: this screenshot was not taken on the same day as the screenshot of the malicious website)

Many thanks to Yonathan Klijnsma (@ydklijnsma) of RiskIQ,
whose assistance allowed us to analyze a historical scrape of
one of the web pages hosting the malware at xn--bitcoingldlcb[.]
org. In the scrape, an additional text and a button were
inserted in place of the BTG logo. The button used JavaScript to
download a payload from hxxps://bitcoingöld[.]org/bitcoingold.
exe (IDN: xn--bitcoingld-lcb[.]org) (Fig. 24). Additional
differences are likely the result of changes to the legitimate
website (Fig. 25) since the malicious campaign.

page 17

## Links:

http://www.securityweek.com/north-korean-hackers-targeting-individuals-report

http://www.securityweek.com/north-korean-hackers-prep-attacks-against-cryptocurrency-exchanges-report

http://www.securityweek.com/north-korea-linked-lazarus-hackers-update-arsenal-hacking-tools

https://www.us-cert.gov/ncas/alerts/TA17-164A

https://www.securityweek.com/new-north-korea-linked-cyberattacks-target-financial-institutions

http://www.systemtek.co.uk/2018/02/north-korean-trojan-activity-bankshot-hardrain-badcall/?utm_source=hs_email&utm_medium=email&utm_content=60917153&_hsenc=p2ANqtz-8FO3E6nBr1k76mScnM0kUc9w2JTIDfNSxNlwknVRBMtQir_ceNRAtPoAyAQObJoA2-LVBbendpZwS5UTKioRIh9oAPDA&_hsmi=60917153#sthash.Vw0YgjRx.dpbs

http://www.intezer.com/lazarus-group-targets-more-cryptocurrency-exchanges-and-fintech-companies/?utm_source=hs_email&utm_medium=email&utm_content=61724703&_hsenc=p2ANqtz-9SnDQN4G7q7NKq_rjc_wP1MNgOwbbDtTrMhlr5D81d4MFuSkQu8oQx3Xrtq5AWZZrR9BkOITfbpycS-hG24U-Cqiwo-A&_hsmi=61724703

https://www.securityweek.com/north-korean-hackers-behind-online-casino-attack-report

https://www.darkreading.com/threat-intelligence/north-korea-ramps-up-operation-ghostsecret-cyber-espionage-campaign/d/d-id/1331667

https://www.darkreading.com/vulnerabilities---threats/lazarus-group-attacks-banks-bitcoin-users-in-new-campaign/d/d-id/1331053?elq_mid=83241&elq_cid=25141692&_mc=NL_DR_EDT_DR_daily_20180214&cid=NL_DR_EDT_DR_daily_20180214&elqTrackId=c4203a7125944a4e89ce551a1d229d66&elq=1e094049bd9347578d81791e0c86afad&elqaid=83241&elqat=1&elqCampaignId=29731
https://threatpost.com/thaicert-seizes-hidden-cobra-server-linked-to-ghostsecret-sony-attacks/131498/

https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/?utm_source=hs_email&utm_medium=email&utm_content=62366014&_hsenc=p2ANqtz-_l35C77JG20NOlda-4DsLFLv93mvAONPMRJm6XGN5OMWsQUFMjUMEzDmAV328XkBB0Gk1XNWXZHh6NL_xvi2ewFm52xQ&_hsmi=62366014

https://www.securityweek.com/north-korean-hackers-behind-online-casino-attack-report

https://www.securityweek.com/north-korea-linked-group-stops-targeting-us

https://www.securityweek.com/us-attributes-two-more-malware-families-north-korea

https://www.washingtonpost.com/world/national-security/the-nsa-has-linked-the-wannacry-computer-worm-to-north-korea/2017/06/14/101395a2-508e-11e7-be25-3a519335381c_story.html?noredirect=on&utm_term=.221143e6b664

https://www.cyberscoop.com/north-koreas-cyber-connections-to-china-and-india-come-under-scrutiny/

https://www.recordedfuture.com/north-korea-internet-activity/

https://www.securityweek.com/sri-lanka-arrests-two-men-over-taiwan-bank-hacking attributed to NK

https://baesystemsai.blogspot.com/2017/10/taiwan-heist-lazarus-tools.html

https://www.bleepingcomputer.com/news/security/hermes-ransomware-decrypted-in-live-video-by-emsisofts-fabian-wosar/ used by NK in the Swift attack of Far Eastern International Bank

https://securingtomorrow.mcafee.com/mcafee-labs/taiwan-bank-heist-role-pseudo-ransomware/

https://www.securityweek.com/russian-words-used-decoy-lazarus-linked-bank-attacks

https://www.securityweek.com/wannacry-highly-likely-work-north-korean-linked-hackers-symantec-says

https://www.securityweek.com/us-warns-north-koreas-hidden-cobra-attacks

https://www.securityweek.com/sony-hack-serious-national-security-matter-white-house

https://www.securityweek.com/north-korea-possibly-behind-wannacry-ransomware-attacks

https://www.securityweek.com/sony-hackers-linked-many-espionage-destruction-campaigns

https://www.securityweek.com/south-korea-cyber-attack-tied-darkseoul-crew-symantec

https://www.securityweek.com/data-wiping-attacks-south-korea-were-culmination-multi-year-espionage-campaign

https://securingtomorrow.mcafee.com/mcafee-labs/android-malware-appears-linked-to-lazarus-cybercrime-group

https://researchcenter.paloaltonetworks.com/2017/11/unit42-operation-blockbuster-goes-mobile/

https://www.securityweek.com/us-suspects-north-korea-81-million-bangladesh-theft-report

https://www.securityweek.com/south-korea-spy-agency-says-north-hacking-smartphones

https://www.securityweek.com/us-government-shares-details-north-korea-cyber-attacks

https://www.securityweek.com/north-korean-hackers-targeted-us-electric-firms-report

https://www.securityweek.com/north-korea-accused-stealing-bitcoin-bolster-finances

https://www.securityweek.com/north-koreas-elite-more-connected-previously-thought

https://www.ibtimes.co.uk/operation-blockbuster-lazarus-group-involved-sony-hack-hunted-by-intelligence-coalition-1545752

https://www.ibtimes.co.uk/lazarus-north-korea-linked-sony-hackers-suspected-be-behind-cyberattacks-against-global-banks-1606194

https://www.ibtimes.co.uk/north-korean-worldwide-hacking-rampage-steals-millions-casinos-banks-1615271

https://www.ibtimes.co.uk/ibm-advises-users-destroy-storwize-usb-sticks-shipped-north-korea-liked-malware-1619511

https://www.ibtimes.co.uk/un-hack-experts-monitoring-violations-sanctions-north-korea-hit-by-sustained-cyberattack-1622882

https://www.ibtimes.co.uk/what-eternalrocks-wannacry-successor-new-doomsday-smb-worm-that-uses-7-nsa-hacking-tools-1622675

https://www.ibtimes.co.uk/kim-jong-uns-hacker-army-may-step-cybercrime-offset-losses-incurred-chinas-coal-ban-1607711

https://www.ibtimes.co.uk/north-korea-linked-global-wannacry-cyberattacks-by-shared-malware-code-1621731

https://www.us-cert.gov/ncas/alerts/TA17-318A

https://www.us-cert.gov/ncas/alerts/TA17-318B

https://www.us-cert.gov/ncas/alerts/TA17-164A

https://www.wired.com/story/north-korea-cyberattacks/

https://www.nytimes.com/2017/10/15/world/asia/north-korea-hacking-cyber-sony.html

https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity

https://www.securityweek.com/north-korean-hackers-abuse-activex-recent-attacks

https://www.securityweek.com/dhs-fbi-share-details-north-koreas-typeframe-malware

https://www.securityweek.com/north-korean-hackers-exploit-hwp-docs-recent-cyber-heists

https://www.securityweek.com/north-korean-hackers-launch-new-activex-attacks

https://www.securityweek.com/researchers-say-code-reuse-links-north-koreas-malware

https://www.securityweek.com/organizations-hit-north-korean-linked-ryuk-ransomware

https://www.securityweek.com/sony-hack-serious-national-security-matter-white-house
https://www.securityweek.com/us-suspects-north-korea-81-million-bangladesh-theft-report
https://www.securityweek.com/australia-canada-others-blame-north-korea-wannacry-attack
https://www.securityweek.com/malware-attacks-polish-banks-linked-lazarus-group
https://www.securityweek.com/north-korea-linked-hacker-group-poses-serious-threat-banks-kaspersky
https://www.securityweek.com/north-korean-hackers-targeting-crypto-currency-exchanges-fireeye
https://www.securityweek.com/search/google/Gh0st?query=Gh0st&cx=016540353864684098383%3A6mcx-eenlzi&cof=FORID%3A11&sitesearch=&safe=off
https://www.securityweek.com/north-koreas-new-front-cyberheists

https://www.fireeye.com/blog/threat-research/2017/09/north-korea-interested-in-bitcoin.html

https://www.bbc.com/news/world-asia-42378638

https://www.symantec.com/connect/blogs/attackers-target-dozens-global-banks-new-malware-0 - ratankba attributed

https://www.symantec.com/security-center/writeup/2017-020908-1134-99

https://blog.trendmicro.com/trendlabs-security-intelligence/ratankba-watering-holes-against-enterprises/

https://www.securityweek.com/north-korean-hackers-hit-cryptocurrency-exchange-macos-malware

https://www.securityweek.com/north-korea-linked-hackers-stole-135-million-cosmos-bank-report

https://www.securityweek.com/us-charges-north-korean-over-lazarus-group-hacks

https://www.justice.gov/opa/pr/north-korean-regime-backed-programmer-charged-conspiracy-conduct-multiple-cyber-attacks-and

https://www.securityweek.com/opsec-mistakes-allowed-us-link-north-korean-man-hacks

https://www.securityweek.com/us-links-north-korean-government-atm-hacks

https://www.securityweek.com/nkorea-said-have-stolen-fortune-online-bank-heists

https://www.securityweek.com/north-korean-attacks-banks-attributed-apt38-group

https://www.securityweek.com/north-korean-hackers-hit-latin-american-banks

https://www.securityweek.com/researchers-link-chilean-interbank-attack-north-korea

https://www.securityweek.com/north-koreas-lazarus-hackers-found-targeting-russian-entities

https://www.bleepingcomputer.com/news/security/op-sharpshooter-connected-to-north-koreas-lazarus-group/

https://securelist.com/cryptocurrency-businesses-still-being-targeted-by-lazarus/90019/

https://www.securityweek.com/north-korea-linked-hackers-target-macos-users

https://www.securityweek.com/us-attributes-new-trojan-north-korean-hackers

https://www.securityweek.com/us-government-details-electricfish-malware-used-north-korea

https://www.cyberscoop.com/lazarus-group-hacking-malware-cyber-command/

https://www.itsecuritynews.info/u-s-cyber-command-adds-north-korean-malware-samples-to-virustotal/

https://www.reuters.com/article/us-northkorea-usa-sanctions/u-s-imposes-sanctions-on-north-korean-hacking-groups-blamed-for-global-attacks-idUSKCN1VY1RB

https://brica.de/alerts/alert/public/1278013/dtrack-rat-is-behind-virulent-atm-espionage-campaign/

https://www.databreachtoday.com/kaspersky-dual-use-dtrack-malware-linked-to-atm-thefts-a-13144

https://securelist.com/my-name-is-dtrack/93338/?utm_source=newsletter&utm_medium=Email&utm_campaign=sl%20weekly%20digest

https://www.patreon.com/posts/30715524

https://thenextweb.com/hardfork/2019/10/14/north-korea-hacking-group-lazarus-old-cryptocurrency-scam-control-mac/

https://www.itsecuritynews.info/experts-attribute-nukesped-rat-to-north-korea-linked-hackers

https://www.scmagazine.com/home/security-news/fake-company-pushes-phony-cryptocurrency-app-to-spread-mac-malware/

https://www.digitalmunition.me/confirmed-north-korean-malware-found-on-indian-nuclear-plants-network/

https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity

https://www.us-cert.gov/ncas/analysis-reports/ar19-304a

https://hotforsecurity.bitdefender.com/blog/lazarus-group-may-have-hacked-indian-nuclear-power-plant-21716.html

https://www.cyberscoop.com/north-korea-malware-cyber-command-virus-total-apt38/

https://blog.trendmicro.com/trendlabs-security-intelligence/mac-backdoor-linked-to-lazarus-targets-korean-users/

https://www.hindustantimes.com/analysis/decoding-motives-behind-the-kudankulam-intrusion/story-c3odQAUqOT1nDgjOMFQRPK.html

https://thenextweb.com/hardfork/2019/12/04/cryptocurrency-trading-platform-macos-malware-lazarus-north-korea/

https://www.digitalmunition.me/lazarus-hacking-group-strikes-again-with-fileless-malware/

https://www.bleepingcomputer.com/news/security/lazarus-hackers-use-trickbot-to-infect-high-end-victims/

https://cyware.com/news/lazarus-apt-group-linked-to-new-dacls-malware-that-targets-linux-systems-6abd448d

https://www.globalsecuritymag.com/Lazarus-enhances-capabilities-in,20200108,94395.html

https://www.securityweek.com/uscybercom-shares-more-north-korean-malware-samples

https://www.us-cert.gov/ncas/current-activity/2020/02/14/north-korean-malicious-cyber-activity

https://arstechnica.com/tech-policy/2020/02/us-government-exposes-malware-used-in-north-korean-sponsored-hacking-ops/

https://securelist.com/operation-applejeus-sequel/95596/?utm_source=newsletter&utm_medium=Email&utm_campaign=sl%20weekly%20digest

https://www.securityweek.com/north-korean-hackers-continue-target-cryptocurrency-exchanges

https://www.wired.com/story/malware-reuse-north-korea-lazarus-group/

https://metaswan.github.io/posts/Malware-Lazarus-group's-Brambul-worm-of-the-former-Wannacry-2

https://arstechnica.com/information-technology/2020/02/why-write-your-own-mac-malware-when-you-can-rip-off-a-competitors-a-how-to/

https://labs.sentinelone.com/dprk-hidden-cobra-update-north-korean-malicious-cyber-activity/

https://www.cyberscoop.com/north-korea-sanctions-lazarus-group-treasury-department/

https://blog.lexfo.fr/ressources/Lexfo-WhitePaper-The_Lazarus_Constellation.pdf

https://labs.sentinelone.com/dprk-hidden-cobra-update-north-korean-malicious-cyber-activity/

https://marcoramilli.com/2019/11/04/is-lazarus-apt38-targeting-critical-infrastructures/

https://global.ahnlab.com/global/upload/download/asecreport/ASEC%20REPORT_vol.98_ENG.pdf

https://www.us-cert.gov/sites/default/files/2020-04/DPRK_Cyber_Threat_Advisory_04152020_S508C.pdf

https://blog.telsy.com/lazarus-gate/

https://securelist.com/apt-trends-report-q1-2020/96826/

https://www.securityweek.com/north-korean-threat-actors-acted-hackers-hire-says-us-government

https://www.us-cert.gov/ncas/alerts/aa20-106a

https://www.cisomag.com/lazarus-hacking-group-strikes-again-with-fileless-malware/

https://threatpost.com/lazarus-collaborates-trickbots-anchor-project/151000/

https://securityaffairs.co/wordpress/95008/apt/trickbot-group-lazarus-link.html

https://objective-see.com/blog/blog_0x49.html

https://portswigger.net/daily-swig/crypto-exchange-admins-targeted-with-malware-ridden-trading-app

https://www.securityweek.com/researchers-analyze-north-korea-linked-nukesped-rat

https://arstechnica.com/information-technology/2019/10/indian-nuke-plants-network-reportedly-hit-by-malware-tied-to-n-korea/

https://blog.malwarebytes.com/threat-analysis/2020/05/new-mac-variant-of-lazarus-dacls-rat-distributed-via-trojanized-2fa-app/

https://www.securityweek.com/us-cyber-command-shares-more-north-korean-malware-variants

https://medium.com/@dinu135dk/lazarus-group-leverages-covid-themed-hwp-document-dde6b80d51eb - application shimming??

https://twitter.com/RedDrip7/status/1245557988401623040

https://www.cyberscoop.com/north-korea-hacking-hidden-cobra-dhs-fbi/

https://www.us-cert.gov/ncas/current-activity/2020/05/12/north-korean-malicious-cyber-activity

https://blog.malwarelab.pl/posts/lazarus_validator/

https://www.securityweek.com/aerospace-military-hit-ongoing-espionage-campaign-linked-north-korea

https://www.welivesecurity.com/2020/06/17/operation-interception-aerospace-military-companies-cyberspies/ ??

https://blog.reversinglabs.com/blog/hidden-cobra

https://www.securityweek.com/magecart-attacks-claires-and-other-us-stores-linked-north-korea

https://www.scmagazine.com/home/security-news/hidden-cobra-built-global-exfiltration-network-for-magecart-skimming-scheme/

https://sansec.io/research/north-korea-magecart

https://www.infosecurity-magazine.com/news/north-korean-hackers-sniffing-us/

https://www.technadu.com/operation-north-star-targeting-american-aerospace-defense-industry/162553/

https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32020D1127&from=EN

https://www.consilium.europa.eu/en/press/press-releases/2020/07/30/eu-imposes-the-first-ever-sanctions-against-cyber-attacks/

https://threatpost.com/lazarus-group-advanced-malware-framework/157636/ 

https://www.sentinelone.com/blog/four-distinct-families-of-lazarus-malware-target-apples-macos-platform/

https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/

https://www.scmagazine.com/home/security-news/government-and-defense/operation-north-star-attackers-appear-to-be-hidden-cobra/

https://www.zdnet.com/article/us-defense-and-aerospace-sectors-targeted-in-new-wave-of-north-korean-attacks/

https://www.mcafee.com/blogs/other-blogs/mcafee-labs/operation-north-star-a-job-offer-thats-too-good-to-be-true/#%20Techniques,%20Tactics%20&%20Procedures%20(TTPs)

https://news.yahoo.com/israel-says-thwarted-foreign-cyber-160853524.html

https://www.cyberscoop.com/north-korea-hackers-lazarus-group-israel-defense/

https://www.clearskysec.com/operation-dream-job/

https://www.kaspersky.com/blog/lazarus-vhd-ransomware/36559/

https://labs.f-secure.com/assets/BlogFiles/f-secureLABS-tlp-white-lazarus-threat-intel-report2.pdf

https://cyware.com/news/north-korean-hackers-using-blindingcan-malware-strain-dhs-sounds-alert-83986e9d

https://blog.chainalysis.com/reports/lazarus-group-north-korea-doj-complaint-august-2020

https://www.sentinelone.com/blog/the-blindingcan-rat-and-malicious-north-korean-activity/

https://blogs.jpcert.or.jp/en/2020/08/Lazarus-malware.html

https://www.zdnet.com/article/lazarus-group-strikes-cryptocurrency-firm-through-linkedin-job-adverts/

https://www.bankinfosecurity.com/lazarus-group-uses-spear-phishing-to-steal-cryptocurrency-a-14898

https://www.scmagazine.com/home/security-news/new-report-details-how-north-korean-and-russian-cybercriminals-are-cooperating/

https://securelist.com/an-overview-of-targeted-attacks-and-apts-on-linux/98440/

https://www.welivesecurity.com/2020/11/16/lazarus-supply-chain-attack-south-korea/

https://threatpost.com/russia-north-korea-attacking-covid-19-vaccine-makers/161205/

https://securityaffairs.co/wordpress/112621/apt/lazarus-apt-targets-covid-19.html

https://blogs.jpcert.or.jp/en/2020/09/BLINDINGCAN.html

https://labs.f-secure.com/blog/catching-lazarus-threat-intelligence-to-real-detection-logic

https://www.cyberscoop.com/north-korean-hacking-lazarus-job-applicants/ - something in unattributed as well

https://www.securityweek.com/lazarus-group-targets-south-korea-supply-chain-attack

https://www.securityweek.com/us-details-north-korean-malware-used-attacks-defense-organizations

https://medium.com/walmartglobaltech/anchor-and-lazarus-together-again-24744e516607

https://www.cyberscoop.com/google-north-korea-fake-security-blog/

https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/ - tentatively attributed by others

https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/

https://enki.co.kr/blog/2021/02/04/ie_0day.html

https://www.securityweek.com/us-charges-north-korean-hackers-over-13-billion-bank-heists

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048g

https://www.infosecurity-magazine.com/news/lazarus-group-indicted-north/

https://securityaffairs.co/wordpress/115013/apt/lazarus-apt-threatneedle.html

https://securelist.com/lazarus-threatneedle/100803/

https://www.bankinfosecurity.com/lazarus-group-tied-to-tflower-ransomware-a-16100

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048d

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048e

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048c

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048b

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048a

https://us-cert.cisa.gov/ncas/alerts/aa21-048a

https://us-cert.cisa.gov/ncas/analysis-reports/ar21-048f

https://www.cyberscoop.com/north-korean-hackers-fake-company-security-researchers-social-media/

https://www.welivesecurity.com/2021/04/08/are-you-afreight-dark-watch-out-vyveva-new-lazarus-backdoor/

https://blog.malwarebytes.com/malwarebytes-news/2021/04/lazarus-apt-conceals-malicious-code-within-bmp-file-to-drop-its-rat/

https://www.group-ib.com/blog/btc_changer

https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/lazarus-recruitment/

https://thehackernews.com/2021/05/researchers-link-cryptocore-attacks-on.html

https://threatpost.com/lazarus-engineers-malicious-docs/167647/

https://www.netskope.com/blog/not-laughing-malicious-office-documents-using-lolbins

https://cybersecurity.att.com/blogs/labs-research/lazarus-campaign-ttps-and-evolution

https://blog.bushidotoken.net/2021/08/the-lazarus-heist-where-are-they-now.html

https://lifars.com/2021/08/lifars-alert-flashback-and-update-north-korean-trojan-keymarble/

https://www.bleepingcomputer.com/news/security/north-korean-state-hackers-start-targeting-the-it-supply-chain/

https://www.bleepingcomputer.com/news/security/lazarus-hackers-target-researchers-with-trojanized-ida-pro/

https://bzx.network/blog/prelminary-post-mortem - part of SnatchCrypto

https://lifars.com/2021/11/lazarus-hacking-group-set-it-supply-chain-attacks-in-motion/

https://therecord.media/north-korean-hackers-posed-as-samsung-recruiters-to-target-security-researchers/

https://threatpost.com/pseudomanuscrypt-mass-spyware-campaign/177097/

https://www.zdnet.com/article/fingers-point-to-lazarus-cobalt-fin7-as-key-hacking-groups-focused-on-finance-industry/

https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/
