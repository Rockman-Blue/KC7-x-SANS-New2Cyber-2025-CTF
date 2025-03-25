# Project Overview
* This is my writeup for KC7’s “A Day in the Life of a Threat Hunter” CTF from the 2025 SANS New2Cyber Summit.
* In this CTF, I performed threat hunting activities in two scenarios for a fictional company using KQL to gain experience and hands-on practice with threat hunting.

# Goal of CTF
* Investigate a cyber attack on GalaxyNeura, a cutting-edge company developing Brain-Computer Interface (BCI) technology.
* Adversaries rarely force their way in. Instead, they recon, manipulate, and persist, carefully chaining together tactics to achieve their goal.
* Threat actors may have infiltrated their systems, and it’s up to you to track their movements, uncover their TTPs, and piece together the attack before it’s too late!

# CTF Structure
* This KC7 CTF is comprised of two scenarios, an easier one (Section 1) and a harder one (Section 2).
* Section 1 mostly provided me with the queries to use, sometimes I had to slightly modify them. This section covers threat hunting to uncover an external adversary.
* Section 2 is harder, where I had to write the KQL queries using the knowledge gained from the provided queries in Section 1. This section covers threat hunting to uncover an internal adversary. 
* My write-up will show the question, answer, KQL queries used, and supporting screenshots.

# KQL Quick Overview
* KQL (Kusto Query Language) is a Microsoft developed query language and tool used for exploring data to discover patterns, identify anomalies in data, and much more.
* KQL queries start with a data source (usually a table) and cosnists of one or more operators connected by the pipe  ```|``` characters.
* An example of the syntax is below. Please read more at the [KQL Documentation](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric) on the Microsoft Learn site.
* If you want to learn more about KQL, check out KC7's [KQL 101 Module](https://kc7cyber.com/go/take10).
```kql
TableName
| where ColumnName == "Value"
```

# Skills Gained and Lessons Learned
* Investigated a cyber attack on the fictitious company GalaxyNeura in an effort to better understand threat actor movements, TTPs, and map intrusions.
* Learned and engaged with threat hunting concepts to put them into practice to solve 44 challenges, mostly focused on using KQL (Kusto Query Language).
* Used KQL along with analytical skills to solve multiple real-world cybersecurity challenges, uncovering information about insider and external threats in two full scope investigation scenarios.

![KC7 Completion Badge](https://github.com/user-attachments/assets/4cdbede0-0e32-4964-85da-5d48aef6e371)
