# SQL Log Analysis: Finding Security Problems in Login Records

## Project description

Imagine you're a security detective looking through your company's login records. Your job is to find unusual activity that might mean someone's password got stolen, or someone is trying to break in. This project walks you through real examples of how to search through login records using SQL (a tool for asking questions about databases) to spot these problems.

By learning these searches, you'll understand how companies actually hunt for security issues—not by reading dry textbooks, but by looking at real data and finding what doesn't belong.

---

## Retrieve after hours failed login attempts

**What we're looking for:** Someone trying to log in after 6 PM and getting rejected. This is suspicious because it often means either a hacker trying random passwords, or an employee's account that was stolen.

```sql
SELECT 
    employee_id,
    login_time,
    login_attempt_date,
    failure_reason
FROM login_audit_logs
WHERE login_time > '18:00:00' 
  AND success = FALSE
ORDER BY login_attempt_date DESC, login_time DESC;
```

**How it works:** Think of this like setting up two filters. First, we say "show me any login that happened after 6 PM." Then we add another filter: "and it has to be a failed login." By combining these two filters, we catch people (or hackers) trying to get in when the office is closed and their attempts are failing. We sort the results by date so we can see the most recent attempts first.

---

## Retrieve login attempts on specific dates

**What we're looking for:** If someone's account gets hacked, they'll often try logging in many times over a few days, especially when they're running automated tools to crack passwords. We want to find days where one person tried logging in way too many times.

```sql
SELECT 
    employee_id,
    login_attempt_date,
    COUNT(login_attempt_date) AS attempt_count,
    login_time,
    source_ip
FROM login_audit_logs
WHERE login_attempt_date = '2024-07-15' 
   OR login_attempt_date = '2024-07-16'
   OR login_attempt_date = '2024-07-17'
GROUP BY employee_id, login_attempt_date
HAVING COUNT(login_attempt_date) > 5
ORDER BY attempt_count DESC;
```

**How it works:** Here we're looking at three specific days in a row (July 15, 16, and 17). We use "OR" to say "I want all logins from any of these three days." Then we count how many times each person tried to log in on each day. Finally, we only show the results if someone tried more than 5 times—that's our alert level for "this looks suspicious." We sort by the highest count first so the worst offenders appear at the top.

---

## Retrieve login attempts outside of Mexico

**What we're looking for:** If all your employees work in Mexico, but someone's logging in from Russia, that's a red flag. This query helps us spot logins coming from unexpected countries.

```sql
SELECT 
    employee_id,
    login_time,
    source_ip,
    country_origin,
    login_status
FROM login_audit_logs
WHERE NOT country_origin LIKE 'MEX%'
  AND NOT country_origin LIKE 'CA%'
ORDER BY login_time DESC;
```

**How it works:** We want to exclude logins from Mexico and Canada (our trusted regions), and show everything else. So we set up a filter that says "show me any login where the country does NOT start with 'MEX' and does NOT start with 'CA'." The "NOT" flips our logic around—instead of looking for Mexico, we're looking for everyone *except* Mexico. Any logins that show up in these results are from outside our safe zone and need investigation.

---

## Retrieve employees in Marketing

**What we're looking for:** If a security issue happens, we might need to focus on specific departments first. Maybe Marketing workstations need an urgent security update. This query pulls all the devices in that department so we know what to fix.

```sql
SELECT 
    device_id,
    asset_hostname,
    department,
    building_location,
    os_version,
    last_patch_date
FROM corporate_assets
WHERE department = 'Engineering' 
  AND building_location LIKE 'East-%'
ORDER BY last_patch_date ASC;
```

**How it works:** We're looking for computers in the Engineering department *and* computers in the east wing of the building (anything that starts with "East-"). By combining these two conditions with "AND," we narrow down to just the devices in that specific area. We sort by when they were last updated, so we can see which ones need patching first.

---

## Retrieve employees in Finance or Sales

**What we're looking for:** Sometimes we need to look at multiple departments at once. Maybe Finance and Sales both use the same network printer or server, and we need to know all the devices in those departments for a security check.

```sql
SELECT 
    device_id,
    asset_hostname,
    department,
    owner_employee_id,
    access_control_level
FROM corporate_assets
WHERE department = 'Finance'
   OR department = 'Engineering'
   OR department = 'Operations'
ORDER BY department, asset_hostname;
```

**How it works:** We use "OR" to ask for devices from three departments: Finance, Engineering, or Operations. Think of it like saying "give me Finance computers, OR Engineering computers, OR Operations computers." We get a combined list of everything from all three departments, then sort it by department name so it's easy to read.

---

## Retrieve all employees not in IT

**What we're looking for:** If IT just finished patching all their systems, we want to focus on everyone else next. This query gets a list of all active employees *except* those in the IT department.

```sql
SELECT 
    employee_id,
    department,
    account_status,
    last_access_time,
    security_clearance_level
FROM corporate_accounts
WHERE account_status = 'ACTIVE'
  AND NOT department = 'InfoSec'
ORDER BY last_access_time DESC;
```

**How it works:** We start by asking for all active employee accounts. Then we add a "NOT" to exclude the IT/InfoSec department. The "NOT" inverts our filter—instead of looking for IT, we're looking for everyone except IT. This is really useful when you're rolling out updates in stages and you've already handled one group.

---

## Summary

These queries show how security teams really hunt for problems. We're not guessing—we're asking specific questions:

- **Is someone trying to log in at weird hours?** (After-hours logins)
- **Is one account being attacked over and over?** (Spike in attempts)
- **Are logins coming from the wrong countries?** (Geographic anomalies)
- **Which devices need updates in this group?** (Department-based targeting)
- **What do multiple departments have in common?** (Cross-department queries)
- **What's everyone doing except this one group?** (Exclusion patterns)

By writing these searches and looking at the results, you learn to think like a security analyst. You stop just reading reports and start asking the database the questions that actually matter.

---

*Case Study Completed: 2026-07-11*
