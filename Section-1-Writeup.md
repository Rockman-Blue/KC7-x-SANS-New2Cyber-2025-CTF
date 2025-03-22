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

I run the query above. The process_commandline field for the 1 result has the value
