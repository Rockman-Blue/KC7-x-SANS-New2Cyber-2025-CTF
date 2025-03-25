# Question 1 

* Question - What is the subject of the email all three of them received?
* Answer - Woopsie, the code for your secret chip is gone. Pay up if you want it back 😘

First, I get a link to check out KC7's [KQL 101 Module](https://kc7cyber.com/go/take10) to learn more about KQL basics. Compared to Section 1, this scenario is much more challenging - as I had to write the KQL queries on my own, without the help of the provided queries present in Section 1. 

The context of this scenario is as follows. You go to a cybersecurity conference and attend a talk that warns about the rise of double-extortion. Cybercriminals compromise a network, steal the most sensitive data they can find, and threaten high level exectutives with the release of the stolen data unless the company paid them. Refusal to comply results in the deployment of ransomware on the network. The criminals would then demand at least double the money they asked for in the first place. 

The researcher who presented the talk pointed out that this threat actor was skilled and hard to detect, and still very active. I have to look for traces of this threat actor as soon as I get back to the office. I have to find the email addresses for the CEO, CFO, and CTO. 

KQL queries start with the table name. In this case, the "Employees" table since we're looking for the email addresses of the executive. I run the below query to get the names of the CEO, CFO, and CTO.

```kql
Employees | where role contains "CEO" or role contains "CFO" or role contains "CTO"
```

![Question 1-1](https://github.com/user-attachments/assets/d5c6497e-63c3-411d-9a68-d0c37f425c87)

I now have their names and email adresses -  “otto_hoctavius@galaxyneura.tech”, “melon_husk@galaxyneura.tech”, and “normie_ozborn@galaxyneura.tech”. Now, I must write another query to see the subject of the email that they received. After some experimenting, I write and run the below query

```kql
Email
| where recipient in ("otto_hoctavius@galaxyneura.tech", "melon_husk@galaxyneura.tech", "normie_ozborn@galaxyneura.tech")
| summarize CountRecipients = dcount(recipient) by sender
| where CountRecipients == 3
```

![Question 1-2](https://github.com/user-attachments/assets/27f459ac-6246-4a1e-bd49-5c9e0c27479c)

When I run this, I see the sender is "jean_song@galaxyneura.tech". So I write another query to get emails sent to all of those emails, but from Jean. 

```kql
Email
| where recipient in ("otto_hoctavius@galaxyneura.tech", "melon_husk@galaxyneura.tech", "normie_ozborn@galaxyneura.tech") | where sender == "jean_song@galaxyneura.tech"
```

![Question 1-3](https://github.com/user-attachments/assets/ff3d8c03-7c05-4493-be44-d64c7a63f3da)

Finally, I look at the value for the ```subject``` column, and see the answer for this question. 


# Question 2 

* Question - Who sent the email?
* Answer - jean_song@galaxyneura.tech

This could be the threat actor the researcher at the conference was describing in his talk. From the last query I ran in Question 1 above, I find the answer in the ```sender``` column. 

![Question 2-1](https://github.com/user-attachments/assets/944a570e-c94a-49bc-8aba-cca1c261e561)


# Question 3

* Question - What is their role?
* Answer - Freelance Software Engineer

The domain is coming from inside the company. This behavior was not mentioned by the researcher, let's learn more about Jean Song. So I know the email sender's name, Jean Song. I’ll have to query the ```Employees``` database for his email and look for the role. I use the queue below.

```kql
Employees
| where email_addr == "jean_song@galaxyneura.tech"
```

After running the query, I find the role for Jean in the ```role``` column.

![Question 3-1](https://github.com/user-attachments/assets/626ac290-cc34-48b4-a30b-d37e0f93ed9d)


# Question 4 

* Question - When did Jean Song start working for Galaxy Neura? (format: yyyy-mm-dd)
* Answer - 2025-02-10

I use the same query from Question 3, and I see the value for the ```hire_date``` column is “2025-02-10T00:00:00Z”, but the answer asks for a specific format - so the answer is “2025-02-10”.

![Question 4-1](https://github.com/user-attachments/assets/0ebf0deb-217d-4d40-beb5-b7e9c72ccf25)


# Question 5

* Question - How many IP addresses are used to authenticate as Jean?
* Answer - 2

So Jean Song is a recently hired remote worker... suspicious. There's two options - either Jean has been compromised and the threat actor is using their account, or Jean is the threat actor. To get on the path to see which option is correct, let's see if anything suspicious happened with their login. 

From the keywork authenticate, I think of querying a different table. There is a table called ```AuthenticationEvents```. I write the query below.

```kql
AuthenticationEvents
| where username == "jesong"
```

There are 50 results, but two repeated values for the ```src_ip column``` “10.10.19.1” and “204.188.232.195”. 

![Question 5-1](https://github.com/user-attachments/assets/d9b4061e-446a-41d0-84a5-81a51bfc616f)


# Question 6

* Question - Which github repository did Jean delete?
* Answer - super-secret-chip-project

The amount of IPs - two, is not suspicious. A lot of folks will connect from at least two IPs depending on their setup. That might mean mean Jean is a threat actor. I should look back at their machine to see if anything is suspicious there. 

The email Jean sent mentions some code being deleted, code they had access to thanks to their job role. The briefing mentions looking at their machine. I rerun the query from Question 3 to get the hostname field value for Jean, ```UIWO-LAPTOP```.

![Question 6-1](https://github.com/user-attachments/assets/88a99c5f-d536-4c0d-b664-485053507986)

I use that hostname in a new query to filter on the ```ProcessEvents``` table. I arrive at the query below.

```kql
ProcessEvents
| where hostname == "UIWO-LAPTOP" | where username == "jesong" | where process_commandline contains "Git"
```

Looking at the results, there’s a ```process_commandline``` column that shows the GitHub repo link for two of the results - and the name is “super-secret-chip-project”.

![Question 6-2](https://github.com/user-attachments/assets/d4ad4741-ca38-4df8-a954-22c9a466199c)


# Question 7

* Question - What's the name of the github account they cloned the repository to?
* Answer - song-of-war

Jean picked a very important repo to clone, push, and delete. They picked one that they were sure they'd be able to ask a big ransom for, and since there was a "git clone" command - I know Jean must have a copy of the repository. 

![Question 7-1](https://github.com/user-attachments/assets/c3136533-743c-4d1e-a011-a0527e8f8bc8)

Looking at the results from the query used in Question 6 above, I find a command that's a "git push" command in the ```process_commandline``` column. The username is “song-of-war”.


# Question 8

* Question - Which search query shows Jean was getting frustrated? (only enter the search terms, replace the + by spaces)
* Answer - top secret projects come on you gotta gimme something interesting

Jean could not have found that secret repository by chance, he must have used some research/reconnaissance techniques beforehand. Galaxy Neura uses the subdomain "devteam" to host all their code development documentation. Jean would have been directed to that subdomain as a freelance software dev hire. 

A few searched have been done on that domain. The briefing tells me about the subdomain “devteam”. I need to look for searches that have been done on that subdomain. I search in a new table, ```InBoundNetworkEvents``` and arrive at the below query.

```kql
InboundNetworkEvents
| where url contains "devteam.galaxyneura.tech"
```

Now I can look at the values in the ```url``` column to look for the search terms. Looking at the URLs, I come across the answer - a suspicious looking search term “top secret projects come on you gotta gimme something interesting”. 

![Question 8-1](https://github.com/user-attachments/assets/f012dd3d-b9e3-40af-b64f-e25b3a97e65f)


# Question 9

* Question - Which domain that does not start with an "f" is linked to those IP addresses?
* Answer - hireadev.today

I know that Jean is the source of this browsing, because the ```user_agent``` is theirs - and one of the IP addresses matches the second discovered in the authentication records discovered in Question 5.

It's time to take a closer look at those IP addresses. We have the two discoverd in Question 5, plus the newly discovered IP address in the results of the query I used to solve Question 8. In total, Jean's IPs that we must investigate are:
* 199.115.99.34
* 174.128.251.99
* 204.188.232.195

 I query the ```PassiveDns``` table with the below queries for each IP in separate tabs in the KQL editor pane on the right hand side of the screen.

```kql
PassiveDns
| where ip == "199.115.99.34"
```

```kql
PassiveDns
| where ip == "174.128.251.99"
```

```kql
PassiveDns
| where ip == "204.188.232.195"
```

I look at the results of all three queries. Query 2 for shows a domain that does not start with an f, the domain “hireadev.today”.

![Question 9-1](https://github.com/user-attachments/assets/7254e427-2866-4d69-8bca-3af499da38ca)


# Question 10

* Question - There is one more IP address linked to those domains, what is it?
* Answer - 70.39.103.3

The domains I have from the three queries used in Question 9 are - “freelanceworkersunited.org”, “fundwmd.lol”, and “hireadev.today”. Now it’s just about crafting a different query against the  ```PassiveDns``` table. I create the three queries below and run them. 

```kql
PassiveDns
| where domain contains "freelanceworkersunited.org"
```

```kql
PassiveDns
| where domain contains "fundwmd.lol"
```

```kql
PassiveDns
| where domain contains "hireadev.today"
```

I look at the IP addresses in the results for each query and compare them to the known IPs from Question 9 - 199.115.99.34, 174.128.251.99, and 204.188.232.195. Query 1 that I used above shows the IP 70.39.103.3 for one of the five results, that new IP is the answer - since all of the other IPs present in the three queries line up with my known IP list from Question 9.

![Question 10-1](https://github.com/user-attachments/assets/9842c0c9-c259-49b2-b8e0-95ccdbea1dfe)


# Question 11

* Question - On what day did the previous browsing happen? (format: yyyy-mm-dd)
* Answer - 2025-02-05

Let's investigate any prior browsing on the company's network done by the four IP addresses I found. I put the four previously discovered IPs in a list and search for them using the ```InboundNetworkEvents``` table.

```kql
let ipList = dynamic(["199.115.99.34", "174.128.251.99", "204.188.232.195", "70.39.103.3"]);
InboundNetworkEvents
| where src_ip in (ipList)
```

Looking at the results of the query, two dates are shown - “2025-02-05” and “2025-02-13”. The first date is the answer, since it’s more recent.

![Question 11-1](https://github.com/user-attachments/assets/3293fedd-8f7f-49bb-b52c-a3807b3b9bd2)


# Question 12

* Question - Which url did Jean probably use to apply at Galaxy Neura?
* Answer - https://galaxyneura.tech/career/current-openings/freelance-opportunities-all-hands-on-deck

The date discovered in Question 11 is before Jean Song was hired. By the look of it, they were looking at employment opportunities. I look at the same query results from the query I used in Question 11. 

I look at the values for the ```url``` column for all of the events that matched the query on 2025-02-05. I find the URL “https://galaxyneura.tech/career/current-openings/freelance-opportunities-all-hands-on-deck”, and that’s the answer.

![Question 12-1](https://github.com/user-attachments/assets/31b02bb2-cbdd-43a6-8c9e-bc8184507281)


# Question 13

* Question - What email address did Jean use during the recruitment process?
* Answer - jeansong4@proton.me

So Jean applied, and was obviously hired as a freelance software dev. Since the question is asking about Jean's email address, I must look in the ```Email``` table. I write the below query.

```kql
Email
| where sender contains "song" 
```

Looking at the results of the query, I see the “jeansong4@proton.me” email multiple times in the ```reply_to``` column.

![Question 13-1](https://github.com/user-attachments/assets/17e3ea3a-1204-4791-b71e-a86433abe7fc)


# Question 14

* Question - When did Jean say they received their work laptop? (paste the full timestamp)
* Answer - 2025-02-11T10:14:57Z

So far, I know that Jean was hired on 2025-02-05 and that the email he used during the recruitment process is “jeansong4@proton.me”. I run the query below.

```kql
Email
| where sender contains "jeansong4@proton.me"
```

The second value in the ```subject``` column shows that Jean got the package. The answer is the full timestamp “2025-02-11T10:14:57Z”.

![Question 14-1](https://github.com/user-attachments/assets/a831e1c4-fd15-47da-bee2-0521551499d4)


# Question 15

* Question - What command did they use to download it?
* Answer - curl -L "https://github.com/rustdesk/rustdesk/releases/download/1.3.8/rustdesk-1.3.8-x86_64.exe" -o rustdesk.exe

Let's investigate to see what Jean did once they got their hands on the company-issued computer. It looks like Jean downloaded and installed a remote access tool. From a previous question, I got the hostname of Jean’s laptop. I run the query below.

```kql
ProcessEvents
| where hostname == "UIWO-LAPTOP" | where username == "jesong"
```

I look through the different values for the ```process_commandline``` column for the date Jean received their laptop, 02/11. I find the command “curl -L "https://github.com/rustdesk/rustdesk/releases/download/1.3.8/rustdesk-1.3.8-x86_64.exe" -o rustdesk.exe” in the query results. 

![Question 15-1](https://github.com/user-attachments/assets/9f9b6455-565f-418f-adf8-6d446d3d0732)


# Question 16

* Question - What is the name of the remote access tool?
* Answer - RustDesk;rustdesk.exe

In the screenshot results from the query used in Question 15 above, the name of the tool is shown at the end of the command. It is “rustdesk.exe”.


# Question 17

* Question - According to their browsing history, what option did they want to add to that second tool?
* Answer - mouse jiggler

It seems Jean had some trouble setting up another tool the next day, 02/12. Let's see what it is. For this question, I need to use the ```OutboundNetworkEvents``` table since browsing is an outbound event. 

From the query in Question 5, I know Jean’s IPs are 10.10.19.1 and 204.188.232.195. These are the IPs used by Jean to access the company network. I must account for this in my query below. I tried using the below query with both of the IPs, but only 10.10.19.1 returned results.

```kql
OutboundNetworkEvents
| where src_ip == "10.10.19.1" | where url_1 contains "search"
```

I look at the values for the ```url``` column in the two results of the query and find the answer at the end of the second url search “mouse jiggler”.

![Question 17-1](https://github.com/user-attachments/assets/f80f4717-893e-4f4e-b9f3-33da72a8bbb7)


# Question 18

* Question - 
* Answer - 
