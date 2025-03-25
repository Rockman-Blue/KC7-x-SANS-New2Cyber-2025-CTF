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

* Question -
* Answer - 
