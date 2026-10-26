
Data exfiltration is the unauthorized transfer of sensitive data from a computer or other device. It's a primary objective for attackers who have breached a network.Adeversaries have different motivation for data exfilteration which include:

-  Ransomeware
- Distruption and Sabotage
- Persistence  and Reicconainsance
- Espionage.

There are different techniques in Data exfilteraion :

1. **APT29(Cozy bear**)- HTTPs over legitimate domain i. e encrypting traffic over http to exfilterate govt data
2. **FIN7-**HTTP post to C2 i .e hide stolen data inside the HTTP Post  request to evoke detection
3. **Lunar Spider(Zloader):**ENcrypted C2 tunnel i.e Maintain 2month intrusion usig encrypted channel& staged exfilteration
4**. Darkside Ransomware:** Dual Extortion i. e exfiterate before encryption and threath public realease.
5. APT 10 : cloud to cloud ie  exfilterion throigh the cloud serviuce providers;

Type of Exfilteration are:

**Networkbased exfiletarion:**( http,https,dns tunnelling,ICMO covert,) to analise this look into the FIREWALL,PROXY, WEBGATEWAY,DNS LOG.
**Hostbased Exfilteration**  : (powershell,ADS,) analize this look into the sysmon/EDR, window security,linux,removable media.
**Cloud based Exfilteration**: (S3 PutObject / multipart upload, Azure Blob uploads, Google Cloud Storage objects. Insert, Drive/SharePoint external sharing.)(Cloud trail,Azure activities)
**Covert &encoding:** (DNS tunnelling, base64 or chunked encoding, steganography into images/audio, splitting files into many small requests (low-and-slow) .Toanalize this look into the DNS logs, proxy logs with many small POSTs, correlation of intermittent uploads + suspicious process activity
**Insider & collaboration tools:** (Slack/Teams/Dropbox/Google Drive/Box uploads) To analize this look into theAudit logs (share events, file downloads), and mail logs.
General IoAs & triage signals:(large outbound volume to external IPs/domains, unknown destination domains, suspicious processes/command lines, many file read events followed by an outbound connection, and multipart/streamed uploads.)To analyse this look into the Proxy/Firewall/Netflow, DNS, Sysmon/EDR (EventID 1/3/11), mail server logs.
I will using Tryhackme lab for this project:

**TASK 1: What is the suspicious domain receiving the DNS traffic?**

In this task i will be making use of Splunk installed on the system , The first query i did was to look for all DNS logs make use pf the command : _**index=data_exfil sourcetype=DNS_logs**_  which resulted in the output below

<img width="476" height="365" alt="Image" src="https://github.com/user-attachments/assets/6d14e3ae-4e31-4e3f-aaf5-a6007cda90b1" />
In the screenshot above  we can see the uspicious looking domains with a huge query count from multiple hosts or from one host (suspicious if the domain is untrusted). 
 After which i deplay the stats of DNS queries generated accordding to the source IP with the query
_**index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip**_  s shown below:

<img width="488" height="329" alt="Image" src="https://github.com/user-attachments/assets/55791edc-d0fa-4ac4-94e5-8121de1a3aa5" />

 I then filter the siuspicious using the  query : _**index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count**_ 

<img width="485" height="332" alt="Image" src="https://github.com/user-attachments/assets/f1457248-8049-4327-9d7b-093d2a983061" />/

 As shown above the suspicios domain is  _**tunnelcorp.net**_

**TASK 2: How many suspicious traffic/logs related to dns tunneling were observed?**

I analyse the output  using the query _index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30_ looking for traffic which len is greater thsn 30. This give an outputv of 315.

<img width="482" height="364" alt="Image" src="https://github.com/user-attachments/assets/e857b331-882b-49aa-82c2-7a27560fab28" />


TASK 3: Which local IP sent the maximum number of suspicious requests?

<img width="478" height="362" alt="Image" src="https://github.com/user-attachments/assets/0619f800-6c18-40e1-98f5-37f58e5b8d63" />

**DATA EXFILTERATION WITH FTP**

**TASK 1: How many connections were observed from the guest account?**

In this task i make use of aquery that filter all ftp package that contains guest as follow _**ftp contains "guest"**_
 as shown below the total number is 5

<img width="506" height="400" alt="Image" src="https://github.com/user-attachments/assets/3f75e0c6-e0b7-4919-a7bd-751cb6f519ed" />

_**TASK 2: Apply the filter; what is the name of the customer-related file exfiltrated from the root account?**_

In this task, i make use of te same query but filter ftp that contains root instead  _**ftp contains "root"**_ as shown below

<img width="480" height="324" alt="Image" src="https://github.com/user-attachments/assets/511beec7-a068-485f-bfba-208f0575b2e6" />

i right-clicked and and follow then TCP stream  as shown below the file related to this exfilteration  is  _customer_data.xlsx_ as shown below:

<img width="493" height="391" alt="Image" src="https://github.com/user-attachments/assets/6e64de30-7323-4972-a51a-08af8951a441" />

<img width="310" height="196" alt="Image" src="https://github.com/user-attachments/assets/2e325569-7125-4867-8c23-f103e4c3d6ab" />

**TASK 3: Which internal IP was found to be sending the largest payload to an external IP?**
In this task i use a query to filter the ftp where the frame lenght is greater which indicate suspicious Data exfilteration
**_ftp && frame.len >90_**
This display all packet and the ip addrress highest nu,ber of payload is _**192.168.1.105**_  s it send total of 127 packet  shown below:

<img width="475" height="248" alt="Image" src="https://github.com/user-attachments/assets/8651163e-93fd-4a2c-b45f-23f0784da0ae" />

TASK 4: What is the flag hidden inside the ftp stream transferring the CSV file to the suspicious IP?
In this task i make use of the query to filter packet that contain csv file, follow and check the tcp strame to find the flag as display below:

<img width="473" height="344" alt="Image" src="https://github.com/user-attachments/assets/1c9e1107-e814-4dc8-a339-39c86d10baf4" />

<img width="398" height="292" alt="Image" src="https://github.com/user-attachments/assets/32c05001-1045-48c9-8e9a-c8099dc33595" />

DATA EXFILTERATIONNISING HTTP:
Http cand be use for data exfileration using the following methods:
POST uploads to external servers: Bulk data is sent to attacker-controlled hosts or cloud storage in POST request bodies.
**GET requests with encoded data:** Attacker squeezes small chunks into query strings or path segments (useful for low-and-slow exfiltration).
**Use of common services / CDN:** Exfiltration disguised as uploads to popular services or attacker-controlled subdomains under reputable domains.
**Custom headers:** Data placed in headers (e.g., X-Data: <base64>) may bypass some string-based DLP.
**Chunked transfer / multipart:** Large payloads split into multiple requests to avoid size thresholds.
**HTTPS/TLS tunneling:** The encrypted channel hides the payload; detection requires TLS inspection, SNI analysis, or metadata-based detection.
**Staging via cloud services:** The attacker uploads to Dropbox/GitHub/Gist and then fetches externally.

 TASK 1: Which internal compromised host was used to exfiltrate this sensitive data?
 
In this task sine i know data exfilteration can happen through http POST i will make use of a query to filter the pavker with more frame lenght that indivcate suspicious data exfilteration  with _**http.request.method =="POST and frame.len >500**_

<img width="482" height="413" alt="Image" src="https://github.com/user-attachments/assets/b16acefa-77e8-4896-86c4-6a72535501de" />

This show many filter and i adjust the packet to 75o to reduce the amont of packet to investigate   _**http.request.method =="POST and frame.len >750**_

<img width="479" height="385" alt="Image" src="https://github.com/user-attachments/assets/6b863dd0-c14e-4ab4-b82c-a55e4d1e5298" />

As shown above the sourec IP ADDRESS IS 192.168.1.103.

TASK 2: What's the flag hidden inside the exfiltrated data?
 In this task, i click on the packet, follow and check on the Http stream to have a look at the detaiol as shown below

<img width="474" height="389" alt="Image" src="https://github.com/user-attachments/assets/6bbaca3e-becb-40b2-9da4-7220e73ec856" />

<img width="462" height="356" alt="Image" src="https://github.com/user-attachments/assets/8bb81a5d-6974-404b-a06e-b3c16b163fc6" />
