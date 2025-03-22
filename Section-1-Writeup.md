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

I run the same query from Question 2 above, since it shows the email and various details of the email. In the ```subject``` field, I see the name of the person who shared the file.

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

