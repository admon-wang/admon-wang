# SQL Log Analysis: Security Incident Response & Asset Patching Audit

## Project Summary

**Objective:** Conduct a comprehensive database security audit to identify anomalous login patterns, suspicious access windows, unauthorized geographic origins, and vulnerable asset distributions across the corporate infrastructure.

**Context:** As a SecOps analyst, this case study demonstrates proficiency in SQL-based threat hunting, leveraging structured query logic to isolate security incidents from enterprise telemetry, prioritize patch deployment, and enforce access control policies.

---

## SQL Queries: Security Audit Functions

### 1. After-Hours Failed Login Detection

**Objective:** Isolate failed authentication attempts occurring outside standard business hours (after 18:00) to identify potential brute-force or unauthorized access attempts.

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

**Query Logic:** This query filters the `login_audit_logs` table using two conditional predicates: `login_time > '18:00:00'` selects all entries after 6 PM, and `success = FALSE` isolates only failed authentication attempts. The combination identifies after-hours failed login incidents, a common indicator of credential compromise or unauthorized access attempts. Results are ordered chronologically for incident timeline reconstruction.

---

### 2. Suspicious Login Attempt Windows (Adjacent Date Analysis)


**Objective:** Identify concentrated login attempts across specific adjacent dates to detect potential credential brute-force campaigns or compromised account access patterns.

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

**Query Logic:** The OR operator chains multiple date predicates, capturing login activity across three adjacent dates. The `GROUP BY` and `HAVING COUNT(...) > 5` clause identifies employees with abnormally high login attempt frequency—a signature of brute-force attacks or account compromise. This temporal windowing technique reveals attack campaigns that span multiple calendar days.

---

### 3. Malicious Traffic Filtering by Geographic Origin

**Objective:** Exclude login attempts originating from outside authorized geographic regions, identifying and isolating traffic from suspicious international sources.

```sql
SELECT 
    employee_id,
    login_time,
    source_ip,
    country_origin,
    login_status
FROM login_audit_logs
WHERE NOT country_origin LIKE 'US%'
  AND NOT country_origin LIKE 'CA%'
ORDER BY login_time DESC;
```

**Query Logic:** The NOT operator combined with LIKE wildcards (`LIKE 'US%'` and `LIKE 'CA%'`) inverts the matching logic to exclude authorized geographic regions (US and Canada). Any login attempt not matching these patterns is flagged as originating from outside the trusted geographic boundary, indicating potential threat actor infrastructure or compromised credentials accessed from unauthorized locations.

---

### 4. Department-Based Asset Segmentation for Patch Deployment

**Objective:** Segment corporate workstations by department and building sector to coordinate targeted security patch deployment across infrastructure zones.

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

**Query Logic:** The AND operator enforces dual filtering: `department = 'Engineering'` selects only the target department, while `building_location LIKE 'East-%'` uses a wildcard to match all eastern building sectors (East-1, East-2, etc.). This combination isolates a specific infrastructure zone, enabling security teams to prioritize patch deployment schedules by geographic and organizational boundaries.

---

### 5. Multi-Department Asset Identification

**Objective:** Query assets spanning multiple distinct departments to identify shared infrastructure, cross-functional systems, or misconfigured asset assignments requiring security review.

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

**Query Logic:** Multiple OR operators create a logical union across three distinct departments, returning all assets belonging to Finance, Engineering, or Operations. This query pattern is essential for identifying cross-functional shared resources and ensuring access controls are appropriately configured for multi-department asset sharing scenarios.

---

### 6. Global Accounts Excluding Pre-Patched Departments

**Objective:** Query all active corporate accounts while excluding a pre-patched department from the result set, ensuring patch deployment validation across the remaining infrastructure.

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

**Query Logic:** The NOT operator inverts the department equality check, excluding the InfoSec department (assumed pre-patched) from the result set. By combining `account_status = 'ACTIVE'` with the negation, this query returns all active accounts outside the pre-patched zone, enabling targeted deployment workflows and post-patch validation audits for the remaining infrastructure cohorts.

---

## Security Implications & Incident Response Workflow

1. **After-Hours Detection** identifies potential insider threats or compromised credentials used during non-standard operational windows.
2. **Temporal Analysis** reveals attack campaigns with concentrated attempt density, enabling rapid threat actor attribution.
3. **Geographic Filtering** enforces Zero Trust network controls, flagging unauthorized origin vectors.
4. **Asset Segmentation** enables risk-based patching prioritization tied to infrastructure criticality and department sensitivity.
5. **Multi-Department Queries** support compliance audits and cross-functional access review cycles.
6. **Global Exclusion Patterns** validate patch deployment efficacy and enable staged rollout strategies.

---

*Case Study Completed: 2026-07-11*
