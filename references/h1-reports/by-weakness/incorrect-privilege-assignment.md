# Incorrect Privilege Assignment

_1 reports — High/Critical, disclosed_

### [A potential risk in the experimental-programmatic-access-ccft which can be used to privilege escalation.](https://hackerone.com/reports/2808412)

- **Report ID:** `2808412`
- **Severity:** High
- **Weakness:** Incorrect Privilege Assignment
- **Program:** AWS VDP
- **Reporter:** @zolaer9527
- **Bounty:** - usd
- **Disclosed:** 2024-11-06T20:27:10.025Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**  I found a potential risk in the experimental-programmatic-access-ccft when I deployed it in the AWS Serverless Application Repository. A malicious can leverage the "sts:AssumeRole" permissions for "*" resources to escalate permission.

**Description:**  The experimental-programmatic-access-ccft application creates a function named ExtractCarbonEmissionsFunction, and the associated role is assigned policies with permissions such as "sts:AssumeRole " for  "*"  resources. A malicious user can leverage the "sts:AssumeRole" permissions to assume into any AWS Account in the AWS Organization, resulting in privilege escalation. This poses a significant security risk to the account used to deploy the application.



## Remediation Instructions
1. Use finer-grained authorization policies to replace the AWS-managed policies. And use the specific resource names to replace the "*".
2. The permissions for STS resources should be removed if they do not affect normal functionality.
3. Add a permissions boundary to restrict the permission.

## Supporting Material/References:

* Indicate the Amazon service or product that this vulnerability occurs on: (AWS S3, Amazon Lambda, etc): Amazon Lambda

## Impact

## Summary:
A malicious user could leverage these permissions to escalate his/her privilege.

---
