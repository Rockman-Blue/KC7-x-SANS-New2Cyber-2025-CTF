# KC7-x-SANS-New2Cyber-2025-CTF
* Write-up for KC7’s “A Day in the Life of a Threat Hunter” CTF from the 2025 SANS New2Cyber Summit.
* This CTF was a look into threat hunting concepts using KQL (Kusto Query Language). In this CTF, I performed threat hunting activities in two scenarios for a fictional company.

## Goal of CTF:
* Investigate a cyber attack on GalaxyNeura, a cutting-edge company developing Brain-Computer Interface (BCI) technology.
* Adversaries rarely force their way in. Instead, they recon, manipulate, and persist, carefully chaining together tactics to achieve their goal.
* Threat actors may have infiltrated their systems, and it’s up to you to track their movements, uncover their TTPs, and piece together the attack before it’s too late!

## CTF Structure
* This KC7 CTF is comprised of two scenarios, an easier one (Section 1) and a harder one (Section 2).
* My write-up will show the question, KQL queries used, and the answer.

## KQL Quick Overview
* KQL (Kusto Query Language) is a Microsoft developed query language and tool used for exploring data to discover patterns, identify anomalies in data, and much more.
* KQL queries start with a data source (usually a table) and cosnists of one or more operators connected by the pipe  ```|``` characters.
* An example of the syntax is below. Please read more at the [KQL Documentation](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric) on the Microsoft Learn site
```
TableName
| where ColumnName == "Value"
```

## Skills Gained and Lessons Learned
* Investigated a cyber attack on the fictitious company GalaxyNeura in an effort to better understand threat actor movements, TTPs, and map intrusions.
* Learned and engaged with threat hunting concepts to put them into practice to solve 44 challenges, mostly focused on using KQL (Kusto Query Language).
* Used KQL along with analytical skills to solve multiple real-world cybersecurity challenges, uncovering information about insider and external threats in two full scope investigation scenarios.

![KC7 Completion Badge](https://github.com/user-attachments/assets/4cdbede0-0e32-4964-85da-5d48aef6e371)
