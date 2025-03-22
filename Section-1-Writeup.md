# Question 1

* Question - Type "Trust no one, question everything!" to start your investigation.

Here we're off to an easy start, I just type the statement in the input box and that's the right answer. 

![Question 1-1](https://github.com/user-attachments/assets/ad9ed280-90db-470b-b833-7ed5a5c7276f)


# Question 2

* Question - How many emails did your colleagues receive?
* Answer - 1

For this question I'm given some context into threat hunting. The question scenario explains "Threat hunting isn’t about waiting for alerts to tell you something is wrong. It’s about proactively searching for signs of compromise before they trigger alarms."

After that, I'm given some context about this scenario and what I'm looking for. I'm informed that that malware can be delivered through a perfectly legit file-sharing site to evade detection at the inbox level. Security tools won't catch these types of attacks, and they can't block these useful file sharing services out of fear. It's up to me to look out for potential issues.

The article discussing the malware delivery through file-sharing sites mentions DocuSign, Microsoft SharePoint, and Dropbox. I'm given a query to run to find the answer to this question by finding out which of these services sent emails to Halaxy Neura.

```kql
Email
| where sender has_any ('docusign.net', 'sharepoint.com', 'dropbox.com')
```

After running the query on the right hand side of the page, I see the results below. Only one email is shown, so that's the answer.

![Question 2-1](https://github.com/user-attachments/assets/91d2e91c-f19c-4896-b88d-3bb2af5783ce)


# Question 3

* Question - What is the job role of the recipient of the Dropbox email?
* Answer - Senior Neuroscientist

From Question 2, there's only 1 hit. I need more context and details about the email before I "sound the alarm bell". Here, I'm given another query to run. 

```kql
Employees
| where email_addr == 'rick_kingsley@galaxyneura.tech'
```

After running this query, I look at the results and find the value for the ```role``` column. 

![Question 3-1](https://github.com/user-attachments/assets/3df600af-eb60-414b-8534-883197e9d528)


# Question 4

* Question - What is the name of the person who shared the file?
* Answer - Olivia Octopus

Our recipient of the Dropbox email is someone would receive research papers, considering he's a scientist. The next step is to see if Rick expected that email or if he knew the person sharing the paper. 

I run the same query from Question 2 above, since it shows the email and various details of the email. In the ```subject``` column, I see the name of the person who shared the file.

```kql
Email
| where sender has_any ('docusign.net', 'sharepoint.com', 'dropbox.com')
```

![Question 4-1](https://github.com/user-attachments/assets/a4b5cc86-2315-4b04-9ade-709772b790c4)


# Question 5 

* Question - How many emails did the two of them exchange?
* Answer - 8

Now it's time to see if Rick had any prior contact with Olivia. I'm given the query below.

```kql
Email
| where sender == 'rick_kingsley@galaxyneura.tech' or sender contains 'octopus'
| where recipient == 'rick_kingsley@galaxyneura.tech' or recipient contains 'octopus'
```

![Question 5-1](https://github.com/user-attachments/assets/d8cabc95-2b3e-4b0e-88c6-6669a85df51b)


# Question 6

* Question - When did Rick first connect with Olivia? (paste the full timestamp)
* Answer - 2025-03-05T14:37:02Z

Rick and Olivia had an email conversation spanning multiple days, and he was expecting a file from Olivia. Do they really know each other? I'm told to take a look at the very first email Olivia sent, and to do that I use the provided query below. 

```kql
Email
| where recipient == 'rick_kingsley@galaxyneura.tech'
| where sender endswith "linkedin.com"
```

After running this query, the answer to this question is in the ```timestamp``` column.

![Question 6-1](https://github.com/user-attachments/assets/82535b55-c305-4154-b216-01e50b63efbe)


# Question 7

* Question - What is the domain used by Olivia in her email address?
* Answer - harvards.edu

The communication is recent, they likely never met in real life. Let's go back to the emails they exchanged to gather other clues. There is a mention of a renowed university there. I run the Query from Question 5 below and find the domain used by Olivia in her email address is “harvards.edu” from the ```sender``` column.

```kql
Email
| where sender == 'rick_kingsley@galaxyneura.tech' or sender contains 'octopus'
| where recipient == 'rick_kingsley@galaxyneura.tech' or recipient contains 'octopus'
```

![Question 7-1](https://github.com/user-attachments/assets/1d07eb25-e362-47c5-96cd-bc435a08702c)


# Question 8

* Question - What is the name of the last paper he shared with her? (include the extension)
* Answer - Secret_unethical_research_putting_the_apes_on_mute.pdf

So Rick fell victim to typosquatting/URL hijacking, as harvards is not the domain used by Harvard University. Rick sent documents to Olivia before she did the same. Again, I use the query from Question 5 to look at the details of the eight emails shared between them.

```kql
Email
| where sender == 'rick_kingsley@galaxyneura.tech' or sender contains 'octopus'
| where recipient == 'rick_kingsley@galaxyneura.tech' or recipient contains 'octopus'
```

I look at the ```attachments``` column in the query results. There’s an entry for March 8th that has an attachment named “Secret_unethical_research_putting_the_apes_on_mute.pdf”. That’s the answer.

![Question 8-1](https://github.com/user-attachments/assets/c4f655f5-e0ee-4df5-8593-407387bec122)


# Question 9

* Question - Rick downloaded the file Olivia shared. What is the sha256 of that pdf?
* Answer - 8ced3a034e25ae9669aae44af738ce16510122a0c0e23a4f5fcc32720f493fe8

Rick violated the NDA that everyone who works at Galaxy Neura signed, by sharing files he shouldn't have. By doing this, Rick is now considered an insider threat, leaking proprietary data of his own will. I'm given the query below to look for the answer.

```kql
FileCreationEvents
| where filename == 'Using_BCI_for_language_acquisition_in_children.pdf'
```

After running the query and viewing the results, I see the answer in the ```sha256``` column. 

![Question 9-1](https://github.com/user-attachments/assets/c2c66ba2-f8ce-4ab3-8e20-f4bba6cbf61b)


# Question 10

* Question - What was the extra extension in the email?
* Answer - .svg;svg

Since this question is talking about the email. I run the query from Question 2 below. 

```kql
Email
| where sender has_any ('docusign.net', 'sharepoint.com', 'dropbox.com')
```

I look for the subject line of the Dropbox email. In the ```subject``` column, I find the “Using_BCI_for_language_acquisition_in_children.pdf.svg” file mentioned. The extra extension is shown.

![Question 10-1](https://github.com/user-attachments/assets/2857c31d-11b3-43bb-a180-a236f2e669a3)


# Question 11

* Question - How many files, including the pdf, appeared on Rick's machine around that time?
* Answer - 4

Files with double extensions are suspicious. Let's look to see what else was downloaded around that timeframe when he received that email from Olivia. I'm given the query below.

```kql
FileCreationEvents
| where hostname == 'GWCY-MACHINE'
| where timestamp between (datetime(2025-03-08T07:26:00Z) .. datetime(2025-03-09T00:00:00Z))
```

After running the query, I see four results. That's the answer. 

![Question 11-1](https://github.com/user-attachments/assets/d349f130-0987-4399-8203-71de5823a1ab)


# Question 12 

* Question - What is the full command that was used to open the archive?
* Answer - Expand-Archive -Path C:\Users\rikingsley\Downloads\olivia_bci_research.zip -Force -DestinationPath C:\Users\rikingsley\AppData\Roaming

From the previous question, we see that four other files are downloaded. It seems that the Dropbox link downloaded a .zip archive that when opened spawned extra files, including the pdf file. So, the pdf file acted as a decoy, so that Rick wouldn't suspect anything was suspicious. To find the full command, I'm given the query below.

```kql
ProcessEvents
| where process_commandline has 'olivia_bci_research.zip'
```

I run the query above. The value in the ```process_commandline``` column for the one result has the value for the answer. 

![Question 12-1](https://github.com/user-attachments/assets/1d6a2dde-3099-484b-9848-37a7787024a9)


# Question 13

* Question - Going back to the files contained in the zip archive, what automation tool was used as a loader?
* Answer - autoit;AutoIt

I re-run the query provided in Question 11 above to see the different files again. 

```kql
FileCreationEvents
| where hostname == 'GWCY-MACHINE'
| where timestamp between (datetime(2025-03-08T07:26:00Z) .. datetime(2025-03-09T00:00:00Z))
```

Two of four files contain "auto" in the value for the ```filename``` field. 

![Question 13-1](https://github.com/user-attachments/assets/dd9ba1f9-7daf-4010-b7a5-3ca33afc1551)


# Question 14

* Question - What is the name of the executable for that malware?
* Answer - nymeria.exe;nymeria

So the automation tool used as a load, AutoIt was used to download extra malware. I'm given the query below to find the answer to this question.

```kql
ProcessEvents
| where hostname == 'GWCY-MACHINE'
| where process_name contains 'autoit'
```

The ```process_commandline``` field has the .exe file name, the answer to this question. 

![Question 14-1](https://github.com/user-attachments/assets/ba30fa5f-315c-4be5-a389-b7bbbfd6b66e)


# Question 15

* Question - Which domain was it downloaded from?
* Answer - bigbrainssmallbrains.net

Using the same query as question 14, I see the domain name in the ```process_commandline``` field.

![Question 15-1](https://github.com/user-attachments/assets/a14bc8d2-701a-49cb-ae7e-172abbad9106)


# Question 16

* Question - How many IP addresses did it resolve to?
* Answer - 4

Before looking at what happened once the malware was downloaded, I"m told to take a closer look at the domain. This will tell us more about the threat actor's infrastructure. 

I run the query provided below.

```kql
PassiveDns
| where domain == 'bigbrainssmallbrains.net'
| distinct ip
```

After running the query, there are four distinct IP addresses. That's the answer. 

![Question 16-1](https://github.com/user-attachments/assets/5158be16-28c8-4b5c-9ac4-504e1678935f)


# Question 17

* Question - How many times did the threat actor browse to Galaxy Neura's network?
* Answer - 12

We can use these IP addresses to see if the threat actor browsed to the company's network before the attack, and if they did, what they searched for. Leveraging publicly available information is typical during the reconnaissance phase in an attack. Looking into recon gave give insight into threat actor methods - like how they chose their victims or their end goal. 

I run the query provided below.

```kql
let bad_ips=
PassiveDns
| where domain == 'bigbrainssmallbrains.net' or domain == 'harvards.edu'
| distinct ip;
InboundNetworkEvents
| where src_ip in (bad_ips)
```

After viewing the query results, there are 12 results. 

![Question 17-1](https://github.com/user-attachments/assets/085e36fc-bd19-4ff0-82e6-ef14cc6b9329)


# Question 18

* Question - What type of researcher were they looking for? (only enter the search terms, replace the + by spaces)
* Answer - most gullible researcher at Galaxy Neura

I use the same query provided to me for Question 17. I look at the different values for the ```url``` column. Many of the results have the term “researcher” in the value for the URL field. The briefing says they ran a search for a specific kind of researcher. 

![Question 18-1](https://github.com/user-attachments/assets/91bb9d8c-3b1a-4c4e-a317-ee39fbe1e093)

I see the URL of “https://galaxyneura.tech/search=most+gullible+researcher+at+Galaxy+Neura” so the answer is “most gullible researcher at Galaxy Neura”.


# Question 19

* Question - What legitimate Windows tool did they use to do this?
* Answer - regedit;regedit.exe

Now we know that the threat actor used OSINT to search for a gulliable employee, Rick. Now it's time to go back to the Nymeria malware. The threat actor made sure that they would not lose access to Rick's machine, this is persistence. I run the query provided below.

```kql
ProcessEvents
| where process_commandline contains "nymeria"
```

This returns two results. I look at the values for the ```process_name``` column, and I see regedit.exe. This is the Registry Editor, it allows you to modify the registry settings via a GUI. Modifying the registry is a common persistence mechanism for Windows systems. 

![Question 19](https://github.com/user-attachments/assets/748153d9-3be2-47ed-9dcf-e930f104c0fc)


# Question 20 

* Question - How many discovery commands did "Olivia" run?
* Answer - 6

I need to keep looking into what happened next on Rick's machine. Once a threat actor gains access, they usualyl do some discovery on the machine and/or network that they compromised. I run the provided query below. 

```kql
ProcessEvents
| where hostname == 'GWCY-MACHINE'
| where timestamp >= datetime(2025-03-08T15:48:01Z)
| where process_name == "cmd.exe"
```
I see that there are six results for the query, so that's the answer.

![Question 20](https://github.com/user-attachments/assets/bd3f344c-fec7-4b84-9b75-955e02c80c4e)


# Question 21

* Question - What is "Olivia" trying to steal in the first Powershell command?
* Answer - creds;credentials

Threat actors often encode malicious commands so that they will be harder to detect by automated tools. Using a tool like [CyberChef](https://cyberchef.org/), we can decode encoded commands to discover what the threat actor is doing. First, I run the provided query below.

```kql
ProcessEvents
| where hostname == 'GWCY-MACHINE'
| where timestamp >= datetime(2025-03-09T09:57:31Z)
| where process_commandline has "-enc"
```

![Question 21-1](https://github.com/user-attachments/assets/52851da8-b6b1-4dea-9394-e05f65f33d79)

I take a look at the values for the ```process_commandline``` column for all four results. All of the commands are encoded, I suspect it's Base64 since that is a common encoding mechanism. I go to CyberChef, and select the “From Base64” recipe and paste the encoded PowerShell command from the first result. From the output, "Olivia" is trying to steal credentials, or “creds”.

![Question 21-2](https://github.com/user-attachments/assets/86903aed-24c4-4469-9b42-bcb1969acdbb)


# Question 22 

* Question - What type of malware usually behaves like that?
* Answer - keylogger

I look at the script contained in the second PowerShell command by looking at the value for the ```process_commandline``` field for the second result of the query used in Question 21. 

![Question 22-1](https://github.com/user-attachments/assets/1d0d3e79-ff3d-4618-b018-bee794d0e608)

It’s another Base64 encoded message, so I use CyberChef like how I did for Question 21 with the "From Base64" recipe. Considering the script captures keystokes, the answer is "keylogger”.

![Question 22-2](https://github.com/user-attachments/assets/5497bcc6-f8eb-4c3a-bd8f-2a34b070b02b)


# Question 23 

* Question - In which folder of the threat actor server is the data dumped?
* Answer - brain_dump

The briefing tells me that the third command also steals the content of the clipboard. So I view the value of the third result in the ```process_commandline``` column using the same query used for the previous two questions. I copy the Base64 encoded command to my clipboard.

![Question 23-1](https://github.com/user-attachments/assets/6f52cec5-b323-424b-adf7-8405dac49df1)

Using CyberChef again, I use the same "From Base64" recipe that I used in the previous two questions. Looking at the end of the URL in the ```$url``` variable, the folder is "brain_dump".

![Question 23-2](https://github.com/user-attachments/assets/7d5cd762-02f4-46cd-8f6b-6ce933b3ceb0)


# Question 24

* Question -
* Answer -
