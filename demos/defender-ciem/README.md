# CIEM in Microsoft Defender for Cloud — Capability Guide & Customer Demo

**Audience:** Customer-facing security architect / pre-sales / SE walkthrough
**Product:** Microsoft Defender for Cloud — Defender CSPM plan
**Last verified against Microsoft Learn:** May 2026 (CIEM logic update of Feb 2, 2026 incorporated)
**Author:** Venicia Solomons

> All capability statements in this document have been cross-checked against the official Microsoft Learn documentation. Source URLs are inlined throughout for customer follow-up.

---

## Table of contents

1. [What CIEM is and why it matters](#1-what-ciem-is-and-why-it-matters)
2. [Where CIEM lives in Defender for Cloud](#2-where-ciem-lives-in-defender-for-cloud)
3. [Architecture and dependencies](#3-architecture-and-dependencies)
4. [Licensing, prerequisites, and onboarding](#4-licensing-prerequisites-and-onboarding)
5. [What changed recently (Dec 2025 / Feb 2026)](#5-what-changed-recently-dec-2025--feb-2026)
6. [The four CIEM surfaces — what each shows](#6-the-four-ciem-surfaces--what-each-shows)
7. [Lab/demo environment requirements](#7-labdemo-environment-requirements)
8. [Demo walkthrough — full timed script](#8-demo-walkthrough--full-timed-script)
9. [Cloud Security Explorer query catalog](#9-cloud-security-explorer-query-catalog)
10. [Recommendation catalog (the ones that prove CIEM)](#10-recommendation-catalog-the-ones-that-prove-ciem)
11. [Attack Path scenarios that highlight identity](#11-attack-path-scenarios-that-highlight-identity)
12. [CIEM Workbook setup](#12-ciem-workbook-setup)
13. [Common customer questions and accurate answers](#13-common-customer-questions-and-accurate-answers)
14. [Things to NOT promise](#14-things-to-not-promise)
15. [Reference links](#15-reference-links)

---

## 1. What CIEM is and why it matters

**Cloud Infrastructure Entitlement Management (CIEM)** is the discipline of discovering, analyzing, and right-sizing the **permissions** held by every identity (human and non-human) across your cloud estate, and using that data to enforce **least privilege**.

### The problem CIEM solves

Modern cloud estates accumulate **permission debt** faster than any other class of misconfiguration:

- **Identities multiply** — every workload spawns managed identities, service principals, IAM roles, service accounts.
- **Permissions are granted broadly and never revoked** — Owner/Contributor/`*:*` is the path of least resistance.
- **Permissions are rarely used** — research consistently shows < 5–10% of granted permissions are actually exercised.
- **Identity is the new perimeter** — almost every published cloud breach in the last 3 years pivots through an over-permissioned identity (Capital One, Uber, MGM, Microsoft Storm-0558, Snowflake/UNC5537, etc.).
- **Static analysis can't tell you what an identity *can actually reach*** — you need to combine the permission graph with the resource graph.

### What CIEM in Defender for Cloud delivers

Per the official capability page ([learn.microsoft.com/azure/defender-for-cloud/permissions-management](https://learn.microsoft.com/azure/defender-for-cloud/permissions-management)):

| Capability | What it does |
|---|---|
| **Multicloud identity discovery** | Inventory of every identity across **Microsoft Entra ID, AWS IAM, and Google Cloud IAM** in a single pane — users, groups, service principals, IAM roles, managed identities, service accounts. |
| **Effective permission analysis** | Computes what each identity *can actually do*, including via group/role chaining. Surfaces who can reach sensitive or business-critical resources. |
| **Identity risk insights (recommendations)** | Inactive accounts, guest/blocked accounts, over-permissioned identities, MFA gaps, weak password policy, privileged service principals. |
| **Lateral movement detection** | Correlates identity risk with the cloud security graph to surface **identity-driven attack paths** — e.g. compromised SP → over-broad role → sensitive datastore. |

### CIEM's role in CNAPP

CIEM is one of the four pillars of a **Cloud Native Application Protection Platform (CNAPP)**:

```
CNAPP = CSPM + CWPP + CIEM + (Data + AI + Network) Security Posture
```

In Microsoft's stack, **all four pillars live inside Defender for Cloud** — CIEM is *not* a separate product, it's a feature of the Defender CSPM plan.

---

## 2. Where CIEM lives in Defender for Cloud

CIEM is delivered as a **component of the Defender CSPM plan**, alongside agentless scanning, sensitive data discovery, agentless container posture, and serverless protection.

You enable it under:

```
Defender for Cloud → Environment settings → <subscription/account/project>
  → Defender plans → Defender CSPM → Settings
  → toggle "Permissions Management (CIEM)" = On
```

Reference: [Enable cloud infrastructure entitlement management (CIEM)](https://learn.microsoft.com/azure/defender-for-cloud/enable-permissions-management) and [Protect your resources with Defender CSPM](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-cspm-plan#enable-the-components-of-the-defender-cspm-plan).

> ⚠️ **Foundational CSPM (the free tier) does NOT include CIEM, attack paths, or Cloud Security Explorer.** This is the #1 reason CIEM looks "empty" in a customer tenant — they're on the free plan.

---

## 3. Architecture and dependencies

CIEM in Defender for Cloud is built on top of the **Cloud Security Graph** — the same graph engine that powers Attack Path Analysis and Cloud Security Explorer.

```
                ┌────────────────────────────────────────┐
                │          Cloud Security Graph          │
                │    (snapshot-published, ~daily refresh)│
                └─────────────────┬──────────────────────┘
                                  │
        ┌─────────────────────────┼──────────────────────────────┐
        │                         │                              │
   ┌────▼─────┐             ┌─────▼──────┐               ┌───────▼───────┐
   │ Entra ID │             │  AWS IAM   │               │   GCP IAM     │
   │ users,   │             │  users,    │               │   users,      │
   │ SPs,     │             │  roles,    │               │   groups,     │
   │ groups,  │             │  groups    │               │   service     │
   │ MIs      │             │            │               │   accounts    │
   └──────────┘             └────────────┘               └───────────────┘
        │                         │                              │
        │                         │ (SAML/SSO needs              │ (requires
        │                         │  CloudTrail Logs - Preview)  │  Cloud Logging
        │                         │                              │  ingestion - Preview)
        │                         │                              │
   ┌────▼─────────────────────────▼──────────────────────────────▼───────┐
   │              CIEM activity-based evaluation engine                  │
   │   (90-day lookback, evaluates unused role assignments)              │
   └─────────────────────────────────────┬───────────────────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
       ┌──────▼──────┐         ┌─────────▼─────────┐      ┌─────────▼────────┐
       │Recommendations│       │ Attack Path       │      │ Cloud Security   │
       │(Identity &   │        │ Analysis          │      │ Explorer         │
       │ Access)     │         │ (graph-based)     │      │ (graph queries)  │
       └─────────────┘         └───────────────────┘      └──────────────────┘
                                         │
                                ┌────────▼────────┐
                                │  CIEM Workbook  │
                                │ (Azure Workbook)│
                                └─────────────────┘
```

### What CIEM relies on

| Dependency | Why |
|---|---|
| **Defender CSPM plan = On** | CIEM is a component of this plan. Without it, no graph, no recommendations. |
| **Multicloud connectors (AWS/GCP)** for non-Azure | CIEM is unified, but each cloud must be onboarded separately. |
| **AWS CloudTrail integration (Preview)** | Required to evaluate SAML/SSO identities in AWS. |
| **GCP Cloud Logging ingestion (Preview)** | Required for CIEM evaluation of GCP identities. |
| **Sensitive data discovery (optional, recommended)** | Unlocks the "identities → sensitive data" attack paths. The most powerful demo asset. |
| **Agentless scanning for VMs (recommended)** | Required for end-to-end attack paths that involve VM workloads. |
| **Agentless discovery for Kubernetes (optional)** | Required for container-related identity paths. |
| **24–48 hour wait** | Setup and data collection take up to 24 hours per the docs. **Do not enable the day of the demo.** |

---

## 4. Licensing, prerequisites, and onboarding

### Licensing

- **Defender CSPM** must be enabled at subscription / AWS account / GCP project scope.
- CIEM itself does **not** carry a separate license. It's included in the Defender CSPM SKU.
- Pricing is per billable resource (servers, DBs, storage, etc.) under the Defender CSPM meter — CIEM does not add a per-identity cost.

### Roles required

| Action | Role |
|---|---|
| Enable Defender CSPM + CIEM on Azure subscription | **Security Admin** at subscription scope |
| Enable CIEM on AWS account | **Security Admin** at the AWS account/org scope (in Azure RBAC; the connector handles AWS side) |
| Enable CIEM on GCP project | **Security Admin** at project scope |
| View CIEM data (Cloud Security Explorer, Attack Paths, Recommendations) | **Security Reader, Security Admin, Reader, Contributor, or Owner** |

> 🆕 As of **Feb 2026**, CIEM onboarding **no longer requires elevated high-risk permissions** on AWS/GCP — least-privilege connector permissions are sufficient.

Reference: [Enable cloud infrastructure entitlement management (CIEM)](https://learn.microsoft.com/azure/defender-for-cloud/enable-permissions-management).

### Onboarding steps (high level)

1. Onboard the cloud (Azure subscription is automatic; [AWS](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-aws) / [GCP](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-gcp) need a connector).
2. Enable Defender CSPM on the subscription/account/project.
3. In **Settings** for Defender CSPM, toggle **Permissions Management (CIEM) = On**.
4. (AWS) If the customer uses SAML/SSO identities (most enterprises) — enable **AWS CloudTrail Logs (Preview)** under the Defender CSPM plan settings: [integrate-cloud-trail](https://learn.microsoft.com/azure/defender-for-cloud/integrate-cloud-trail).
5. (GCP) Enable **Cloud Logging ingestion (Preview)** under the Defender CSPM plan settings: [logging-ingestion](https://learn.microsoft.com/azure/defender-for-cloud/logging-ingestion).
6. Re-run the connector deployment script (CloudShell or Terraform) to apply the updated permissions.
7. Wait up to 24 hours for the graph to populate with identity data.

---

## 5. What changed recently (Dec 2025 / Feb 2026)

This is critical to know — the public CIEM behavior changed materially in early 2026 and most internet content is now **stale**.

Source: [Defender for Cloud release notes — Feb 2026](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#february-2026) and [Dec 2025](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#december-2025).

| Change | Old behavior | New behavior (Feb 2, 2026) |
|---|---|---|
| **Inactivity detection signal** | Sign-in activity | **Unused role assignments** (more accurate — catches identities that never *did* anything, not just identities that didn't *log in*) |
| **Inactivity lookback window** | 45 days | **90 days** |
| **New identities** | Evaluated immediately | Identities **< 90 days old are excluded** from inactivity evaluation |
| **Permissions Creep Index (PCI)** | Headline metric | **Deprecated.** No longer appears in recommendations. Replaced by activity-based logic. |
| **CIEM onboarding permissions** | Required elevated/high-risk perms on AWS/GCP | Standard least-privilege connector perms suffice |
| **Azure inactivity evaluation** | Write-level only | **Now also evaluates read-level permissions** for higher fidelity |
| **AWS SAML/SSO identities** | Always evaluated | Require **CloudTrail Logs (Preview)** to be enabled |
| **AWS serverless/compute identities** | Included | **Excluded from CIEM inactivity logic** |
| **GCP identities** | Always evaluated | Require **Cloud Logging ingestion (Preview)** |

> 🚨 **Demo gotcha:** If you walk in expecting to show "PCI score = 87% → after remediation 22%" — that demo is **dead**. The new story is *activity-based recommendations* and *attack paths*, not PCI.

Forward-looking reference: [The future of CIEM in Microsoft Defender for Cloud](https://aka.ms/mdc-ciem). Note that **Microsoft Entra Permissions Management (the standalone product) is being deprecated** — but CIEM in Defender for Cloud is unaffected and is the strategic destination.

---

## 6. The four CIEM surfaces — what each shows

Per [How to view identity and permission risks](https://learn.microsoft.com/azure/defender-for-cloud/permissions-management#how-to-view-identity-and-permission-risks):

### 6.1 Cloud Security Explorer
**Path:** Defender for Cloud → Cloud Security Explorer
**What it does:** Run graph-based queries against the cloud security graph. Filter on identity, resource, exposure, sensitivity, vulnerability, permission level. The most flexible CIEM surface — and the most "wow" in a live demo.

### 6.2 Attack Path Analysis
**Path:** Defender for Cloud → Attack path analysis
**What it does:** Pre-computed attack paths from internet-exposed entry points to high-impact targets, including identity-driven paths (e.g. *VM with managed identity that has Owner on subscription*). Risk-scored.

### 6.3 Recommendations
**Path:** Defender for Cloud → Recommendations → filter by **Identity and access** control
**What it does:** Actionable recommendations per identity — overprovisioned, inactive, guest, blocked, MFA missing, privileged SP, etc. Each opens a remediation flow.

### 6.4 CIEM Workbook
**Path:** Defender for Cloud → Workbooks → "CIEM" (deploy from gallery)
**What it does:** Customizable Azure Workbook that aggregates identity counts, unhealthy CIEM recommendations, and identity-related attack paths into an executive view.

Reference: [Custom dashboards with Azure Workbooks](https://learn.microsoft.com/azure/defender-for-cloud/custom-dashboards-azure-workbooks).

---

## 7. Lab/demo environment requirements

### Minimum (Azure-only demo)

- 1 Azure subscription with **Defender CSPM = On**
- Permissions Management (CIEM) toggled **On**
- Sensitive data discovery toggled **On**
- Agentless scanning for VMs toggled **On**
- 24–48 hours of bake time
- Test workloads:
  - 1× internet-exposed VM with a system-assigned managed identity that has **Contributor** on the subscription (intentional misconfiguration)
  - 1× storage account with sensitive data (sample CSVs containing fake PII / credit card numbers — sensitive data discovery will tag it)
  - 1× Key Vault with a secret used by the VM
  - 1× user account that has not signed in for 90+ days (or no role-assignment activity)
  - 1× guest user with **Reader** on the subscription
  - 1× service principal with **Owner** on a resource group (to trigger the "SPs should not be assigned admin roles" recommendation)

### Recommended (multicloud demo)

Add:
- 1 AWS account onboarded to Defender for Cloud, with Defender CSPM + CIEM + CloudTrail integration enabled. Include 1 IAM user with `AdministratorAccess` that hasn't been used.
- 1 GCP project onboarded with Defender CSPM + CIEM + Cloud Logging ingestion. Include 1 service account with `roles/owner` that hasn't been used.

### Optional — for the strongest "wow"

- 1 AKS / EKS cluster with a workload pod whose service account has cluster-admin (agentless container posture must be on).
- 1 sensitive S3 bucket / Azure storage container that is publicly accessible.

---

## 8. Demo walkthrough — full timed script

**Total runtime: ~25 minutes**, with buffer for Q&A. This is the canonical flow.

### [0:00 – 2:00] Frame the problem

> "Before we go to the portal — the question CIEM answers is *not* 'who has Owner on this subscription?' Your IAM team can answer that. The question is: *if any one identity in my cloud is compromised right now, what could the attacker actually reach, and how bad would it be?* That's the question CIEM answers, by combining the permission graph with the resource graph."

Show on-screen: 1 slide with the CNAPP pillars, CIEM highlighted.

### [2:00 – 4:00] Inventory — identities are first-class assets

1. **Defender for Cloud → Inventory**
2. Filter **Resource type → Identity** (or use the Identity facet).
3. Show: identities listed alongside VMs, storage, databases.

> "Notice that identities — users, service principals, IAM roles — are inventoried like any other asset. Each one has a security posture, recommendations, and a position in the graph."

### [4:00 – 8:00] Recommendations — the activity-based story

1. **Recommendations** → filter by **Identity and access** control category.
2. Open: **"Azure overprovisioned identities should have only the necessary permissions"**.
3. Click into one identity. Show:
   - The identity's granted permissions vs. its actual usage over the last 90 days.
   - Defender's recommended right-sized role.
4. Open: **"Permissions of inactive identities in your Azure subscription should be revoked"**.
5. Show how the new logic (Feb 2026) is based on **unused role assignments over 90 days**, not just sign-in activity.
6. Open: **"Service Principals should not be assigned with administrative roles..."** — show the SP with Owner on the resource group.

> "This is what *activity-based CIEM* looks like. We're not just flagging 'has admin' — we're flagging 'has admin and never used it in 90 days'. That's the difference between a noise generator and an actionable least-privilege tool."

### [8:00 – 14:00] Attack Path Analysis — identity in context

1. **Attack path analysis**
2. Filter by **Risk Factors → Sensitive data** (or **Internet exposure**).
3. Pick an identity-driven attack path. Good ones to look for:
   - *"Internet-exposed VM with high-severity vulnerabilities and read permission to a data store with sensitive data"*
   - *"Internet-exposed Azure Storage container with sensitive data is publicly accessible"*
   - *"VM has high-severity vulnerabilities and read permission to a data store with sensitive data"*
4. **Walk the path** node by node — narrate the chokepoints:
   - **Entry:** Internet-exposed VM with CVE.
   - **Pivot:** VM's managed identity.
   - **Permission:** Contributor / read on storage.
   - **Target:** Storage account containing PII.
5. Open the **Insights** panel for the identity node — show the effective permissions list.
6. Open the **Active Recommendations** for the path — show that fixing *one* recommendation breaks the path.

> "This is the cloud security graph at work. The vulnerability isn't dangerous on its own. The identity isn't dangerous on its own. The data isn't dangerous on its own. The *combination* is what makes this a critical attack path. CIEM is the layer that proves the identity hop is real."

### [14:00 – 22:00] Cloud Security Explorer — live graph queries

This is the centerpiece. Run **3 queries live**, don't screenshot.

#### Query 1 — "Internet-exposed VMs whose identity can reach sensitive data"
- Resource type: **Virtual Machine**
- Condition: **Exposed to the internet**
- Linked: **Has permissions to → Data stores → Contains sensitive data**

#### Query 2 — "Identities with permissions to Key Vaults containing secrets used by internet-exposed workloads"
- Resource type: **Identity**
- Condition: **Has permissions to → Key Vault**
- Filter: Key Vault **Contains secrets used by → Internet-exposed compute**

#### Query 3 — "User accounts without MFA that have permissions to subscriptions" (Azure)
- Resource type: **Identity (User)**
- Condition: **MFA not enforced**
- Linked: **Has role assignment at subscription scope**

After each:
- Click **View details** on a result.
- Show the **Insights** panel (effective permissions, exposure paths).
- Optional: **Download CSV report** — show the customer they can hand this to GRC.

> "Every query you can imagine about *who can reach what* is one click away. This is the same engine the attack paths use — you can build your own."

### [22:00 – 24:00] CIEM Workbook — the executive view

1. **Workbooks → CIEM** workbook (deploy from gallery if not present).
2. Show: identity counts by cloud, unhealthy CIEM recommendations trend, top identity-related attack paths.

> "When the CISO asks 'are we improving?' — this is the dashboard. It trends over time, exports to PDF, and pins to your existing operations dashboards."

### [24:00 – 25:00] Close — remediation and integration

- Mention: recommendations integrate with **Azure Policy**, **ServiceNow**, **DevOps governance rules**, and **Microsoft Sentinel** (CIEM findings can drive analytics rules).
- Remind: the recommendation generates a **proposed least-privilege role** you can apply.

---

## 9. Cloud Security Explorer query catalog

These are the CIEM-relevant queries that work today. Build them in the query builder under **Defender for Cloud → Cloud Security Explorer**.

### A. Identity → sensitive data exposure

| # | Query | What it proves |
|---|---|---|
| 1 | Identity **has permissions to** Storage account that **contains sensitive data** | Who can read your PII/PHI |
| 2 | VM **exposed to internet** + **has managed identity** that **has permissions to** data store **with sensitive data** | The full sensitive-data attack chain |
| 3 | User **with role assignment** at subscription scope **without MFA enforced** | High-blast-radius accounts missing MFA |

### B. Privileged identity hygiene

| # | Query | What it proves |
|---|---|---|
| 4 | Service Principal **with Owner or Contributor** at subscription scope | Privileged non-human identities |
| 5 | Identity **inactive 90+ days** with **any role assignment** | Permission debt |
| 6 | Guest user **with any role assignment** at subscription/RG scope | External access surface |

### C. Cross-resource permission chains

| # | Query | What it proves |
|---|---|---|
| 7 | Identity **has permissions to** Key Vault that **contains secrets used by** internet-exposed compute | Secret-driven lateral movement |
| 8 | Compute **exposed to internet** with **plain-text keys** for storage | Credential leakage path |
| 9 | Container/pod **with service account** that **has permissions to** AWS S3 / Azure Storage with sensitive data | Container-to-data identity path |

### D. Multicloud parity

| # | Query | What it proves |
|---|---|---|
| 10 | AWS IAM role **with AdministratorAccess** **inactive 90+ days** | AWS permission debt |
| 11 | GCP service account with `roles/owner` **inactive 90+ days** | GCP permission debt |
| 12 | Identity (any cloud) **can reach** AWS S3 bucket / GCS bucket / Azure container with sensitive data | Unified multicloud blast radius |

> 💡 Use **Query templates** (bottom of the Cloud Security Explorer page) as starting points. Several of the above ship as templates today — you only need to tweak the resource selector.

Reference: [Build queries with cloud security explorer](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-cloud-security-explorer).

---

## 10. Recommendation catalog (the ones that prove CIEM)

All sourced from [Identity and access security recommendations](https://learn.microsoft.com/azure/defender-for-cloud/recommendations-reference-identity-access).

### Core CIEM recommendations (the ones to demo)

| Recommendation | Cloud | Severity |
|---|---|---|
| Azure overprovisioned identities should have only the necessary permissions | Azure | Medium |
| Permissions of inactive identities in your Azure subscription should be revoked | Azure | Medium |
| Service Principals should not be assigned with administrative roles at the subscription and resource group level | Azure | High |
| Privileged roles should not have permanent access at the subscription and resource group level | Azure | High |
| AWS overprovisioned identities should have only the necessary permissions | AWS | Medium |
| Permissions of inactive identities in your AWS account should be revoked | AWS | Medium |
| GCP overprovisioned identities should have only necessary permissions | GCP | Medium |
| Permissions of inactive identities in your GCP project should be revoked | GCP | Medium |

### Adjacent identity hygiene recommendations (also surfaced under Identity & Access)

| Recommendation | Cloud | Severity |
|---|---|---|
| A maximum of 3 owners should be designated for subscriptions | Azure | High |
| There should be more than one owner assigned to subscriptions | Azure | High |
| Deprecated accounts should be removed from subscriptions | Azure | High |
| Deprecated accounts with owner permissions should be removed from subscriptions | Azure | High |
| External accounts with owner / read / write permissions should be removed from subscriptions | Azure | High |
| Guest accounts with owner / read / write permissions on Azure resources should be removed | Azure | High |
| Blocked accounts with owner / read+write permissions on Azure resources should be removed | Azure | High |
| Avoid the use of the "root" account | AWS | High |
| Ensure access keys are rotated every 90 days or less | AWS | Medium |
| Do not set up access keys during initial user setup for IAM users with a console password | AWS | Medium |

> Use **Recommendations → Group by → Identity and access** to surface all of these in one shot during the demo.

---

## 11. Attack Path scenarios that highlight identity

These are pre-defined attack paths Defender for Cloud generates. Filter the **Attack path analysis** page by **Risk factor: Sensitive data** or **Internet exposure** to find them.

Confirmed examples from [Explore risks to sensitive data](https://learn.microsoft.com/azure/defender-for-cloud/data-security-review-risks):

- *"Internet-exposed Azure Storage container with sensitive data is publicly accessible"*
- *"Managed database with excessive internet exposure and sensitive data allows basic (local user/password) authentication"*
- *"VM has high-severity vulnerabilities and read permission to a data store with sensitive data"*
- *"Internet-exposed AWS S3 Bucket with sensitive data is publicly accessible"*
- *"Private AWS S3 bucket that replicates data to the internet is exposed and publicly accessible"*
- *"RDS snapshot is publicly available to all AWS accounts"*

### New as of Nov 2025 — OAuth application compromise paths

Per [release notes — Nov 2025](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#november-2025):

- Attack Path now shows how compromised **Microsoft Entra OAuth applications** can be used to move laterally to critical resources. Look for paths starting from over-privileged or vulnerable OAuth apps. Strong CIEM demo material because it focuses entirely on the identity vector.

### New as of Nov 2025 — plain-text key lateral movement

Attack paths involving lateral movement with plain-text keys are now generated **only when both source and target are protected by Defender CSPM**. If your demo is missing these, confirm Defender CSPM is on at *both* ends.

---

## 12. CIEM Workbook setup

1. **Defender for Cloud → Workbooks**
2. Search the gallery for **"CIEM"**.
3. Save it to your Log Analytics workspace (the workbook is parameterized by subscription + workspace).
4. Pin tiles to your Defender for Cloud overview page or to an Azure dashboard for executive consumption.

What it shows out of the box:
- Identity counts by type (user, SP, MI, IAM role) per cloud.
- Unhealthy CIEM recommendation counts and trends.
- Identity-related attack path counts.
- Top over-permissioned identities.

Reference: [Custom dashboards with Azure Workbooks](https://learn.microsoft.com/azure/defender-for-cloud/custom-dashboards-azure-workbooks).

---

## 13. Common customer questions and accurate answers

**Q: Is CIEM in Defender for Cloud the same as Microsoft Entra Permissions Management?**
A: No. **Entra Permissions Management is being deprecated.** CIEM in Defender for Cloud is the strategic successor for posture/visibility scenarios. Existing CIEM capabilities in Defender for Cloud are unaffected by the Entra PM deprecation. See [aka.ms/mdc-ciem](https://aka.ms/mdc-ciem).

**Q: Does CIEM revoke permissions automatically?**
A: No. Defender for Cloud generates **recommendations** with a proposed least-privilege role. Remediation is initiated by the customer (manually, via Azure Policy, via ServiceNow integration, or via your IaC pipelines).

**Q: How fresh is the data?**
A: The cloud security graph publishes **snapshots roughly daily**. Initial data collection after enabling CIEM can take **up to 24 hours**.

**Q: Does CIEM see role assignments at management group, subscription, RG, and resource scope?**
A: Yes for Azure. Effective permissions are computed across the full RBAC inheritance chain.

**Q: Does CIEM evaluate Conditional Access policies?**
A: No — CA is an Entra ID concern. CIEM is a **permissions/entitlements** layer, not an authentication-policy layer. Use **Identity Secure Score / Defender XDR Identity** for CA posture.

**Q: What's the licensing impact?**
A: Defender CSPM is per billable resource. CIEM is included — there is **no per-identity CIEM charge**.

**Q: Can I export findings?**
A: Yes — **Download CSV report** from Cloud Security Explorer; recommendations stream to **Continuous Export** (Event Hub / Log Analytics / Storage), which is how customers feed Sentinel.

**Q: Why is my Attack Path page empty?**
A: Per the docs: attack paths now focus on **real, externally-driven, exploitable threats**, not broad scenarios. An empty page can mean (a) you have no internet-exposed entry points (good!), (b) Defender CSPM isn't on at both ends of the would-be path, or (c) data hasn't populated yet.

**Q: Does this work for non-human identities?**
A: Yes — managed identities, service principals, IAM roles, and GCP service accounts are all in scope.

**Q: AWS SAML/SSO identities — why aren't they showing recommendations?**
A: As of Dec 2025 / Feb 2026, SAML and SSO identities require [**AWS CloudTrail Logs (Preview)**](https://learn.microsoft.com/azure/defender-for-cloud/integrate-cloud-trail) to be enabled in the Defender CSPM plan. Without it, CIEM cannot evaluate their activity.

**Q: Where is the Permissions Creep Index (PCI)?**
A: **Deprecated in Feb 2026.** It has been replaced by activity-based logic that produces clearer, more actionable recommendations. Don't expect to see a PCI score anymore.

---

## 14. Things to NOT promise

- ❌ **Automated permission revocation.** Defender CIEM is detect-and-recommend, not enforce.
- ❌ **Just-in-time access workflows** (the customer wants Entra PIM for that, not Defender CIEM).
- ❌ **A single PCI score number.** PCI is deprecated.
- ❌ **SaaS application entitlement coverage** (M365, Salesforce, etc.). CIEM in Defender for Cloud is **infrastructure** entitlement management — Azure/AWS/GCP cloud resources only.
- ❌ **On-prem AD entitlement coverage.** Use Defender for Identity for that.
- ❌ **Real-time evaluation.** Snapshot publishing is roughly daily.
- ❌ **Full attack path coverage without Defender CSPM at both ends** (per Nov 2025 change for plain-text-key paths).

---

## 15. Reference links

### Primary CIEM docs
- [Cloud infrastructure entitlement management (CIEM)](https://learn.microsoft.com/azure/defender-for-cloud/permissions-management) — capability overview
- [Enable CIEM](https://learn.microsoft.com/azure/defender-for-cloud/enable-permissions-management) — onboarding steps
- [The future of CIEM in Defender for Cloud](https://aka.ms/mdc-ciem)

### Defender CSPM
- [Defender CSPM overview](https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management)
- [Enable Defender CSPM and its components](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-cspm-plan)

### Cloud Security Graph / Explorer / Attack Paths
- [Security explorer and attack paths](https://learn.microsoft.com/azure/defender-for-cloud/concept-attack-path)
- [Build queries with Cloud Security Explorer](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-cloud-security-explorer)
- [Identify and remediate attack paths](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-attack-path)
- [Attack path reference (graph components)](https://learn.microsoft.com/azure/defender-for-cloud/attack-path-reference)
- [Test attack paths with vulnerable container image](https://learn.microsoft.com/azure/defender-for-cloud/how-to-test-attack-path-and-security-explorer-with-vulnerable-container-image)

### Recommendations & remediation
- [Identity and access security recommendations reference](https://learn.microsoft.com/azure/defender-for-cloud/recommendations-reference-identity-access)
- [Risk prioritization](https://learn.microsoft.com/azure/defender-for-cloud/risk-prioritization)

### Multicloud
- [Connect AWS account](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-aws)
- [Connect GCP project](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-gcp)
- [AWS CloudTrail logs integration (Preview)](https://learn.microsoft.com/azure/defender-for-cloud/integrate-cloud-trail)
- [GCP Cloud Logging ingestion (Preview)](https://learn.microsoft.com/azure/defender-for-cloud/logging-ingestion)

### Sensitive data discovery (essential for the strongest demo)
- [Data security posture management](https://learn.microsoft.com/azure/defender-for-cloud/concept-data-security-posture)
- [Explore risks to sensitive data](https://learn.microsoft.com/azure/defender-for-cloud/data-security-review-risks)

### Workbooks
- [Custom dashboards with Azure Workbooks](https://learn.microsoft.com/azure/defender-for-cloud/custom-dashboards-azure-workbooks)

### Release notes (the ones that matter for CIEM)
- [Feb 2026 — CIEM logic update](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#february-2026)
- [Dec 2025 — PCI deprecation, CloudTrail/Logging ingestion requirements](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#december-2025)
- [Nov 2025 — OAuth app compromise paths, attack path logic update](https://learn.microsoft.com/azure/defender-for-cloud/release-notes#november-2025)

---

## Appendix A — Pre-demo checklist (print this)

- [ ] Defender CSPM = **On** at subscription/account/project (NOT free tier)
- [ ] Permissions Management (CIEM) toggled **On**
- [ ] Sensitive data discovery toggled **On**
- [ ] Agentless scanning for VMs toggled **On**
- [ ] (AWS) CloudTrail logs integration enabled
- [ ] (GCP) Cloud Logging ingestion enabled
- [ ] At least 24h since enablement
- [ ] Demo workloads deployed (see [section 7](#7-labdemo-environment-requirements))
- [ ] CIEM workbook saved and verified
- [ ] Identity-driven attack path confirmed visible in Attack Path Analysis
- [ ] 3 Cloud Security Explorer queries pre-tested and saved as shareable links
- [ ] Browser tabs pre-loaded: Inventory, Recommendations (filtered to Identity & Access), Attack Path, Cloud Security Explorer, Workbook
- [ ] Backup screenshots of every step in case of portal latency
