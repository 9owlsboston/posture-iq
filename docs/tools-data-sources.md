# SecPostureIQ — Tools & Data Sources Reference

This document describes the 8 tools the SecPostureIQ agent provides, what data they retrieve, and where that data comes from.

---

## 1. `query_secure_score`

**Purpose:** Retrieves the tenant's overall Microsoft Secure Score with category breakdowns, 30-day trend, and industry comparison.

| Attribute | Detail |
|---|---|
| **Data Source** | Microsoft Graph Security API |
| **API Endpoints** | `GET /security/secureScores` (scores) + `GET /security/secureScoreControlProfiles` (per-control max scores) |
| **Portal Equivalent** | [Microsoft Defender portal](https://security.microsoft.com) → Secure Score |
| **Required Permission** | `SecurityEvents.Read.All` |
| **Authentication** | User-delegated token (OAuth2 from SPA login flow) |

**What it returns:**
- Current score and max score (e.g., 127.2 / 271.0)
- Percentage (score ÷ max)
- Category breakdown: **Identity, Data, Device, Apps, Infrastructure** — each with earned vs. max points and percentage
- 30-day trend (score delta)
- Industry comparison (vs. similar-size tenants or same-industry tenants)

### Category Breakdown — How It Works

The category breakdown percentages are computed by cross-referencing two Graph API endpoints:

1. **`GET /security/secureScores`** — Returns `controlScores`, a list of per-control entries. Each entry has:
   - `controlName` — the control identifier (e.g., `"MFARegistrationV2"`)
   - `controlCategory` — the category (e.g., `"Identity"`)
   - `score` — the **achieved** score for that control

2. **`GET /security/secureScoreControlProfiles`** — Returns the control definitions. Each profile has:
   - `id` — matches `controlName` from step 1
   - `maxScore` — the **maximum possible** score for that control

The tool joins these two datasets by control name, groups by `controlCategory`, and computes:

```
category_percentage = (sum of achieved scores in category) / (sum of max scores in category) × 100
```

**Why both endpoints are needed:** The `secureScores` endpoint provides what you've earned per control, but does **not** include the max score per control — only a single `maxScore` for the entire tenant. Each control can have a different weight (e.g., MFA might be worth 10 points while another control is worth 2), so the per-control max must come from `secureScoreControlProfiles`.

| Example | Achieved | Max | Percentage |
|---|---|---|---|
| Identity (portal: 85.23%) | 56.2 | ~65.9 | 85.2% |
| Data (portal: 0%) | 0.0 | ~40.0 | 0% |
| Apps (portal: 36.22%) | 71.0 | ~196.0 | 36.2% |

> **Previous bug (fixed):** The tool originally assumed every control had a max score of 10.0 and computed `max = count × 10`. This produced incorrect category percentages (e.g., Apps showed 13.9% instead of 36.22%). The fix cross-references `secureScoreControlProfiles` for real per-control max scores.

**Important distinction:** The _percentage_ returned here is the **Microsoft Secure Score** percentage, which spans the entire M365 environment (identity + devices + apps + data + infrastructure). This is **not** the same as the **Identity Secure Score** shown in the Entra portal, which only measures identity-related controls.

---

## 2. `assess_defender_coverage`

**Purpose:** Evaluates Microsoft 365 Defender deployment status across all four Defender workloads.

| Attribute | Detail |
|---|---|
| **Data Source** | Microsoft Graph Security API |
| **API Endpoint** | `GET /security/secureScoreControlProfiles` |
| **Portal Equivalent** | [Microsoft Defender portal](https://security.microsoft.com) → Secure Score → Improvement actions (filtered by Defender services) |
| **Required Permission** | `SecurityEvents.Read.All` |
| **Authentication** | User-delegated token |

**Workloads assessed:**

| Workload | Service field values matched |
|---|---|
| Defender for Endpoint | `MDE`, `Microsoft Defender for Endpoint` |
| Defender for Office 365 | `MDO`, `Microsoft Defender for Office 365` |
| Defender for Identity | `MDI`, `Microsoft Defender for Identity` |
| Defender for Cloud Apps | `MDA`, `Microsoft Defender for Cloud Apps`, `Microsoft Cloud App Security` |

**How it works:**
- Groups `SecureScoreControlProfile` records by their `service` field
- Computes per-workload coverage: (achieved score ÷ max score) × 100
- Identifies gaps — controls whose latest `control_state_updates` is neither `Resolved` nor `ThirdParty`
- Critical gaps flagged when tier is `Tier1`/`MandatoryTier` or `max_score ≥ 5`
- Status: 🟢 ≥ 70% · 🟡 ≥ 40% · 🔴 < 40%

---

## 3. `check_purview_policies`

**Purpose:** Assesses Microsoft Purview Information Protection & Compliance policy coverage.

| Attribute | Detail |
|---|---|
| **Primary Data Source** | Microsoft Graph Security API — `SecureScoreControlProfiles` filtered for data/information protection controls |
| **Secondary Data Source** | Microsoft Graph (beta) — `GET /informationProtection/sensitivityLabels` |
| **Portal Equivalent** | [Microsoft Purview compliance portal](https://compliance.microsoft.com) |
| **Required Permissions** | `SecurityEvents.Read.All`, `InformationProtectionPolicy.Read` |
| **Authentication** | User-delegated token |

**Components assessed:**

| Component | How it's identified |
|---|---|
| DLP Policies | Controls with keywords: `dlp`, `data loss prevention` |
| Sensitivity Labels | Controls with keywords: `sensitivity label`, `information protection label`, `labeling` |
| Retention Policies | Controls with keywords: `retention` |
| Insider Risk Management | Controls with keywords: `insider risk`, `insider threat` |

**How it works:**
- Filters `SecureScoreControlProfiles` where `service`, `control_category`, or `title` match Purview-related keywords (`information protection`, `purview`, `compliance`, `dlp`, `insider risk`, `retention`, `sensitivity`)
- Classifies each matching profile to a canonical component
- Computes per-component and overall coverage percentage
- Falls back to `SecureScoreControlProfiles` analysis when direct Purview endpoints return 403

### Known Limitations & Improvement Plan

**Validated against a real E5 tenant (March 2026):** The agent's Purview output was compared against the Purview portal (`purview.microsoft.com` → Posture Management) on a tenant with 0% posture score. The findings and improvement plan are documented below.

#### Issue 1: "Red" status on components with no data

When no `SecureScoreControlProfiles` match a component's keywords, `_build_component_result` returns `status: "not_assessed"` with 0 gaps, distinguishing "no data" from "assessed and failing."

| Component | Status when no controls found | Meaning |
|---|---|---|
| Any component | ⚪ `not_assessed` | No matching controls in `secureScoreControlProfiles` — component was not evaluated |
| Any component with controls | 🟢🟡🔴 green/yellow/red | Controls found and assessed based on coverage percentage |

> **Fixed:** Previously returned `status: "red"` for empty components, which was misleading. Now returns `"not_assessed"`.

#### Issue 2: Category names don't match the portal ✅ Fixed

The Purview portal uses its own posture categories — **"Data Protection Baseline"** and **"Microsoft 365"** — which do not map 1:1 to the agent's components. Each component result now includes a `portal_category` metadata field for cross-reference:

| Agent component | `portal_category` field |
|---|---|
| DLP Policies | `Data Protection Baseline` |
| Sensitivity Labels | `Data Protection Baseline` |
| Retention Policies | `Microsoft 365` |
| Insider Risk Management | `Microsoft 365` |
| General Data Protection | `Data Protection Baseline` |

> **Fixed:** Added `PORTAL_CATEGORY_MAP` constant and `portal_category` field to every component in the response.

#### Issue 3: Narrow keyword matching limits coverage ✅ Fixed

Previously only 1 control profile matched because:
- `control_category: "Data"` was not caught (the keyword `"data loss prevention"` is not a substring of `"data"`)
- Service keywords were too narrow for the values Graph actually returns

**Changes made:**
- Added exact-match check for `control_category` values (`"data"`) via new `PURVIEW_CONTROL_CATEGORIES` set
- Expanded `PURVIEW_SERVICE_KEYWORDS` with: `encryption`, `rights management`, `audit`, `eDiscovery`, `records management`, `communication compliance`
- Expanded `_COMPONENT_KEYWORDS` with: `auto-label`, `classify`, `classification` (→ Sensitivity Labels), `records management` (→ Retention), `communication compliance` (→ Insider Risk)
- Added **"General Data Protection"** as a 5th component for data-related controls that don't match a specific component (prevents silent drops into wrong bucket)
- Changed the default classification bucket from "DLP Policies" to "General Data Protection"

### Getting the Purview Score to Green (0% → 70%+)

For tenants at 0%, the following prioritized actions close the gap:

#### P0 — Quick Wins (1-2 days, ~40-50% impact)

| Action | Portal Path | Impact | Effort |
|---|---|---|---|
| Enable default DLP policies (Exchange + SPO + OneDrive + Teams) | Purview → Data loss prevention → Policies → Create policy | +25-30% | 1 day |
| Create and publish sensitivity labels (Public, Internal, Confidential, Highly Confidential) | Purview → Information protection → Labels → Create a label | +15-20% | 1 day |
| Enable retention policy for Exchange + SharePoint | Purview → Data lifecycle management → Retention policies | +10-15% | half day |

#### P1 — Important (3-5 days, ~20-30% additional)

| Action | Portal Path | Impact | Effort |
|---|---|---|---|
| Configure auto-labeling policies (run in simulation first) | Purview → Information protection → Auto-labeling | +10-15% | 2-3 days |
| Enable mandatory labeling in Office apps | Purview → Information protection → Label policies → Edit policy | +5-10% | 1 day |
| Turn on Insider Risk Management with "Data leaks" template | Purview → Insider Risk Management → Policies → Create | +5-10% | 2 days |

#### P2 — Comprehensive (1-2 weeks, remaining %)

| Action | Impact | Effort |
|---|---|---|
| Expand DLP to healthcare/PII/custom sensitive info types | +5-10% | 3-5 days |
| Configure records management with retention labels | +3-5% | 2-3 days |
| Enable Communication Compliance (if licensed) | +2-5% | 2 days |
| Enable Endpoint DLP for managed devices | +3-5% | 2-3 days |

**Recommended sequence:**
```
Day 1:  DLP policies (biggest single impact) + retention policy
Day 2:  Sensitivity labels (create, publish, set default)
Day 3:  Auto-labeling in simulation mode
Day 5:  Mandatory labeling enforcement + Insider Risk enable
Day 7+: Auto-labeling enforce, expand DLP, records management
```

DLP + labels + retention alone should reach 50-65%. Adding auto-labeling and Insider Risk should push past the 70% green threshold.

---

## 4. `get_entra_config`

**Purpose:** Reviews Entra ID P2 security configuration across identity governance features.

| Attribute | Detail |
|---|---|
| **Data Source** | Microsoft Graph API — multiple identity endpoints |
| **Fallback Source** | `SecureScoreControlProfiles` (when direct endpoints return 403) |
| **Portal Equivalent** | [Microsoft Entra admin center](https://entra.microsoft.com) |
| **Required Permissions** | `Policy.Read.All`, `RoleManagement.Read.Directory`, `IdentityRiskyUser.Read.All`, `AccessReview.Read.All` |
| **Authentication** | User-delegated token |

**API endpoints queried:**

| Component | Endpoint |
|---|---|
| Conditional Access | `GET /identity/conditionalAccess/policies` |
| Privileged Identity Management (PIM) | `GET /roleManagement/directory/roleAssignments` |
| Identity Protection | `GET /identityProtection/riskyUsers` |
| Access Reviews | `GET /identityGovernance/accessReviews/definitions` |

**What it evaluates:**
- **Conditional Access:** Number of active vs. report-only policies, whether MFA is enforced for all users, whether legacy authentication is blocked
- **PIM:** Total role assignments, number of permanent Global Admin assignments (flags if > 2)
- **Identity Protection:** Presence and count of risky users
- **Access Reviews:** Whether periodic access reviews are configured
- **SSO & App Registrations:** General app registration hygiene

**Note:** This tool evaluates the same identity controls that feed the **Identity Secure Score** in the Entra portal, but reports them in the context of SecPostureIQ's own scoring model (green ≥ 70% / yellow ≥ 40% / red < 40%).

---

## 5. `generate_remediation_plan`

**Purpose:** Generates a prioritized remediation plan with PowerShell/CLI scripts based on identified gaps.

| Attribute | Detail |
|---|---|
| **Data Source** | Assessment output from tools 1–4 (passed as `assessment_context` JSON) |
| **AI Model** | Azure OpenAI (GPT-4o) |
| **Safety Layer** | Azure AI Content Safety (validates LLM output before return) |
| **PII Handling** | Assessment context is redacted via `pii_redaction` middleware before being sent to the model |
| **Authentication** | Azure OpenAI API key or Managed Identity (`DefaultAzureCredential`) |

**How it works:**
1. Receives aggregated assessment findings as a JSON string
2. Redacts PII (tenant GUIDs, emails, IPs) from the context
3. Sends a structured prompt to Azure OpenAI requesting prioritized remediation steps
4. Parses the LLM response into structured JSON
5. Validates output through Azure AI Content Safety
6. Enriches each step with matching **Get to Green** offers from Foundry IQ playbooks
7. Computes estimated days-to-green and total score improvement

**Each remediation step includes:**
- Priority: P0 (critical/quick-win) → P1 (important) → P2 (housekeeping)
- Title, description, impact on Secure Score
- Effort estimate
- Confidence level (high/medium/low)
- PowerShell or CLI remediation script

**Fallback:** When Azure OpenAI is not configured, returns built-in mock remediation steps.

---

## 6. `create_adoption_scorecard`

**Purpose:** Produces a structured ME5 adoption scorecard with green/yellow/red ratings per workload.

| Attribute | Detail |
|---|---|
| **Data Source** | Aggregated output from tools 1–4 (passed as `assessment_context` JSON) |
| **Portal Equivalent** | No direct equivalent — this is a synthesized view |
| **External API Calls** | None — pure aggregation/computation |

**How it works:**
- Parses the combined assessment JSON from the other tools
- Extracts per-workload data for **Defender XDR**, **Microsoft Purview**, and **Entra ID P2**
- Computes sub-workload coverage percentages and status (🟢 ≥ 70% · 🟡 ≥ 40% · 🔴 < 40%)
- Collects critical gaps across all workloads
- Produces a markdown-formatted scorecard report with gap priorities and time-to-green estimates

This is a **pure computation tool** — it does not call any external APIs. It depends on assessments already gathered by tools 1–4.

---

## 7. `get_green_playbook`

**Purpose:** Retrieves Get to Green playbook sections from Foundry IQ based on identified security gaps.

| Attribute | Detail |
|---|---|
| **Primary Data Source** | Foundry IQ API (when configured) |
| **Fallback Data Source** | Built-in playbook content embedded in the tool (mirrors real Foundry IQ structure) |
| **External API** | Foundry IQ endpoint (optional — configured via `settings`) |

**Coverage areas (12 workload playbooks):**

| Area | Playbook |
|---|---|
| `defender_endpoint` | Defender for Endpoint — onboarding, ASR rules, AIR, EDR |
| `defender_office365` | Defender for Office 365 — Safe Attachments/Links, anti-phishing, ZAP |
| `defender_identity` | Defender for Identity — sensor deployment, gMSA, lateral movement |
| `defender_cloud_apps` | Defender for Cloud Apps — API connectors, Cloud Discovery, session policies |
| `purview_dlp` | DLP policies |
| `purview_labels` | Sensitivity labels |
| `purview_retention` | Retention policies |
| `purview_insider_risk` | Insider Risk Management |
| `entra_conditional_access` | Conditional Access policies |
| `entra_pim` | Privileged Identity Management |
| `entra_identity_protection` | Identity Protection |
| `entra_access_reviews` | Access Reviews |

**Each playbook entry includes:**
- Step-by-step remediation playbook
- Recommended **Get to Green** offer (workshop/engagement with ID, duration, delivery mode)
- Customer onboarding checklist
- Estimated effort and impact on Secure Score

---

## 8. `push_posture_snapshot`

**Purpose:** Pushes a security posture assessment snapshot to a Microsoft Fabric lakehouse for longitudinal dashboarding.

| Attribute | Detail |
|---|---|
| **Data Destination** | Microsoft Fabric lakehouse (when configured) |
| **Fallback** | In-memory buffer (for testing and local dev) |
| **Portal Equivalent** | Power BI dashboards connected to the Fabric lakehouse |
| **PII Handling** | Tenant ID is SHA-256 hashed; gap descriptions are scrubbed of GUIDs, emails, and IPs |

**Snapshot schema (v1.0):**

| Field | Description |
|---|---|
| `snapshot_id` | UUID for each snapshot |
| `tenant_id_hash` | SHA-256 hash of the tenant GUID (anonymized) |
| `timestamp` | UTC timestamp of the assessment |
| `secure_score_current` / `secure_score_max` | Raw Secure Score values |
| `workload_scores` | Per-workload coverage percentages (Defender, Purview, Entra) |
| `gap_count` | Total number of identified gaps |
| `estimated_days_to_green` | Computed from remediation effort estimates |
| `top_gaps` | Top 5 anonymized gap descriptions |
| `assessment_summary` | Free-text summary |

**When to call:** After a full assessment cycle (tools 1–6) is complete, this tool persists the results for trend tracking.

---

## Data Flow Summary

```
┌─────────────────────────┐
│   User's M365 Tenant    │
│   (via delegated token) │
└──────────┬──────────────┘
           │ OAuth2 user-delegated token
           ▼
┌──────────────────────────────────────────────────┐
│           Microsoft Graph Security API           │
│  /security/secureScores                          │
│  /security/secureScoreControlProfiles            │
│  /identity/conditionalAccess/policies            │
│  /roleManagement/directory/roleAssignments       │
│  /identityProtection/riskyUsers                  │
│  /identityGovernance/accessReviews/definitions   │
│  /informationProtection/sensitivityLabels (beta) │
└──────────────────┬───────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────┐
│            SecPostureIQ Agent (Tools 1-4)        │
│  query_secure_score · assess_defender_coverage   │
│  check_purview_policies · get_entra_config       │
└──────────────────┬───────────────────────────────┘
                   │ assessment_context JSON
                   ▼
┌──────────────────────────────────────────────────┐
│         Analysis & Planning (Tools 5-7)          │
│  generate_remediation_plan (→ Azure OpenAI)      │
│  create_adoption_scorecard (pure computation)    │
│  get_green_playbook (→ Foundry IQ / built-in)    │
└──────────────────┬───────────────────────────────┘
                   │ snapshot data
                   ▼
┌──────────────────────────────────────────────────┐
│         Persistence (Tool 8)                     │
│  push_posture_snapshot (→ Microsoft Fabric)       │
└──────────────────────────────────────────────────┘
```

## Key Distinction: Microsoft Secure Score vs. Identity Secure Score

| | Microsoft Secure Score | Identity Secure Score |
|---|---|---|
| **Source** | Defender portal (`security.microsoft.com`) | Entra portal (`entra.microsoft.com`) |
| **Scope** | Entire M365 environment (identity + devices + apps + data + infrastructure) | Identity-related controls only (Entra ID) |
| **What this agent reports** | `query_secure_score` (tool 1) returns this metric | `get_entra_config` (tool 4) assesses the same identity controls but uses its own scoring model |
| **Typical relationship** | Lower overall percentage | Higher percentage (identity is usually better-hardened than other areas) |

Both metrics ultimately derive from the same underlying `SecureScoreControlProfile` data in the Graph Security API — the difference is in **scope** (all categories vs. identity-only).

---

## Other Microsoft Security Metrics — Extension Opportunities

Beyond the metrics SecPostureIQ currently collects, Microsoft exposes several additional security scores and dashboards that could be integrated as future tools.

### Currently Not Covered

| Metric | Portal | API / Data Source | What It Measures | Extension Notes |
|---|---|---|---|---|
| **Identity Secure Score** | [Entra admin center](https://entra.microsoft.com) → Protection → Identity Secure Score | Graph API: `GET /security/secureScores` (identity category subset) or screen-scrape; no dedicated REST endpoint yet | Identity-only controls: MFA adoption, CA policies, PIM usage, risky sign-ins, password policies | Could be derived by filtering the existing `secureScores` category breakdown to the **Identity** category, or by computing a weighted score from `get_entra_config` output |
| **Microsoft Defender Exposure Score** | [Defender portal](https://security.microsoft.com) → Endpoints → Dashboard | Defender for Endpoint API: `GET /api/exposureScore` | Device vulnerability exposure across the endpoint fleet — based on unpatched CVEs, misconfigurations, and attack surface | Requires `Score.Read.All` scope; complements Secure Score by showing real-time vulnerability risk |
| **Device Compliance Rate** | [Intune admin center](https://intune.microsoft.com) → Devices → Compliance | Graph API: `GET /deviceManagement/managedDevices` with compliance state filter | Percentage of Intune-enrolled devices meeting compliance policies (encryption, OS version, PIN, etc.) | Requires `DeviceManagementManagedDevices.Read.All` |
| **Defender for Cloud Secure Score** | [Azure portal](https://portal.azure.com) → Microsoft Defender for Cloud → Secure Score | Azure Resource Manager: `GET /providers/Microsoft.Security/secureScores` | Security posture of Azure/hybrid/multi-cloud resources (separate from M365 Secure Score) | Relevant for customers with Azure workloads; requires Azure RBAC `Security Reader` role |
| **Attack Simulation Training Completion** | [Defender portal](https://security.microsoft.com) → Email & collaboration → Attack simulation training | Graph API (beta): `GET /security/attackSimulation/simulations` | Phishing simulation results — click rates, compromise rates, training completion | Requires `AttackSimulation.Read.All`; useful for measuring security awareness |
| **Threat Analytics Coverage** | [Defender portal](https://security.microsoft.com) → Threat analytics | Defender XDR API: threat analytics reports | Exposure to active threat campaigns and whether mitigations are deployed | Gives real-time context on whether current gaps are being actively exploited |
| **Data Classification Overview** | [Purview compliance portal](https://compliance.microsoft.com) → Data classification → Overview | Graph API (beta): `GET /security/informationProtection/sensitivityLabels` + activity explorer APIs | Volume of labeled content, auto-labeling coverage, sensitive info type detections | Extends `check_purview_policies` with quantitative adoption data |
| **Insider Risk Severity Distribution** | [Purview compliance portal](https://compliance.microsoft.com) → Insider Risk Management → Dashboard | No public API yet (portal-only) | Active insider risk alerts by severity, policy matches, user risk levels | Would require Purview Insider Risk API (currently limited availability) |
| **Conditional Access Gap Analyzer** | [Entra admin center](https://entra.microsoft.com) → Protection → Conditional Access → Overview → Insights and reporting | Graph API: `GET /identity/conditionalAccess/policies` + sign-in logs correlation | Sign-ins not covered by any CA policy, legacy auth usage trends | Could augment `get_entra_config` with sign-in log analysis to show real coverage gaps vs. policy-only analysis |
| **Authentication Methods Registration** | [Entra admin center](https://entra.microsoft.com) → Protection → Authentication methods → Activity | Graph API: `GET /reports/authenticationMethods/userRegistrationDetails` | Per-user MFA method registration (Authenticator app, FIDO2, phone, etc.) | Requires `AuditLog.Read.All`; shows MFA adoption depth, not just policy presence |

### Priority Recommendations for Extension

1. **Identity Secure Score** — Highest value; users already expect this metric. Can be approximated today by filtering the Identity category from `query_secure_score` output.
2. **Defender Exposure Score** — Complements the control-based Secure Score with real vulnerability data from endpoints.
3. **Device Compliance Rate** — Critical for organizations using Intune; directly impacts the Device category of Secure Score.
4. **Authentication Methods Registration** — Adds depth to the Entra assessment — knowing MFA is _enforced_ vs. knowing users have actually _registered_ strong methods are different things.

---

## Portal Navigation — Viewing Metrics in the UI

Step-by-step instructions for viewing the same data each tool retrieves, directly in Microsoft portals.

### Tool 1: `query_secure_score` → Microsoft Defender Portal

1. Go to [https://security.microsoft.com](https://security.microsoft.com)
2. Sign in with an account that has **Security Reader** or **Global Reader** role
3. In the left navigation, expand **Exposure management** → click **Secure Score**
4. The **Overview** tab shows:
   - Current score and max score (e.g., 127.2 / 271.0)
   - Percentage bar
   - Score trend chart (30-day, 90-day)
   - Comparison to similar organizations
5. Click the **Breakdown** tab to see scores by category: Identity, Device, Apps, Data, Infrastructure
6. Click **Improvement actions** to see individual controls with their status and point values

### Tool 2: `assess_defender_coverage` → Microsoft Defender Portal

1. Go to [https://security.microsoft.com](https://security.microsoft.com)
2. Navigate to **Exposure management** → **Secure Score** → **Improvement actions**
3. Use the **Service** filter dropdown to filter by:
   - *Microsoft Defender for Endpoint*
   - *Microsoft Defender for Office 365*
   - *Microsoft Defender for Identity*
   - *Microsoft Defender for Cloud Apps*
4. For each service, note:
   - Total improvement actions and their status (Completed / To address / Resolved through third party)
   - Points achieved vs. points available
5. Alternatively, each Defender workload has its own dashboard:
   - **Defender for Endpoint:** Settings → Endpoints → Onboarding (device count)
   - **Defender for Office 365:** Email & collaboration → Policies & rules → Threat policies
   - **Defender for Identity:** Settings → Identities → Sensors (sensor health)
   - **Defender for Cloud Apps:** Cloud apps → Cloud Discovery dashboard

### Tool 3: `check_purview_policies` → Microsoft Purview Portal

1. Go to [https://compliance.microsoft.com](https://compliance.microsoft.com) (or [https://purview.microsoft.com](https://purview.microsoft.com))
2. **DLP Policies:**
   - Navigate to **Data loss prevention** → **Policies**
   - View active policies, their scope, and match counts
3. **Sensitivity Labels:**
   - Navigate to **Information protection** → **Labels**
   - See published labels and their usage in **Data classification** → **Overview**
4. **Retention Policies:**
   - Navigate to **Data lifecycle management** → **Retention policies**
   - View policies, covered locations (Exchange, SharePoint, OneDrive, Teams)
5. **Insider Risk Management:**
   - Navigate to **Insider Risk Management** → **Dashboard**
   - View active alerts, policy matches, and risk levels
6. For the Secure Score perspective on Purview controls:
   - Go to [https://security.microsoft.com](https://security.microsoft.com) → **Secure Score** → **Improvement actions**
   - Filter by **Category: Data** to see data protection recommendations

### Tool 4: `get_entra_config` → Microsoft Entra Admin Center

1. Go to [https://entra.microsoft.com](https://entra.microsoft.com)
2. **Conditional Access:**
   - Navigate to **Protection** → **Conditional Access** → **Policies**
   - Review each policy's state (On / Report-only / Off), assignments, and grant controls
   - Click **Overview** → **Insights and reporting** for sign-in coverage analysis
3. **Privileged Identity Management (PIM):**
   - Navigate to **Identity governance** → **Privileged Identity Management** → **Microsoft Entra roles**
   - Click **Roles** to see which roles have active vs. eligible assignments
   - Check **Global Administrator** for permanent assignment count
4. **Identity Protection:**
   - Navigate to **Protection** → **Identity Protection**
   - View **Risky users**, **Risky sign-ins**, and **Risk detections** tabs
   - Check **Policies** for sign-in risk and user risk policy configuration
5. **Access Reviews:**
   - Navigate to **Identity governance** → **Access Reviews**
   - View active and scheduled reviews
6. **Identity Secure Score (for comparison):**
   - Navigate to **Protection** → **Identity Secure Score**
   - This shows the identity-only percentage (e.g., 77.04%) with its own improvement actions

### Tool 5: `generate_remediation_plan` → No Direct Portal Equivalent

This tool uses Azure OpenAI to generate remediation plans. There is no single portal view, but the underlying recommendations can be found in:

1. **Secure Score improvement actions** at [https://security.microsoft.com](https://security.microsoft.com) → **Secure Score** → **Improvement actions** — each action includes Microsoft's recommended remediation steps
2. **Defender for Cloud recommendations** at [https://portal.azure.com](https://portal.azure.com) → **Microsoft Defender for Cloud** → **Recommendations** (for Azure resource remediations)

### Tool 6: `create_adoption_scorecard` → No Direct Portal Equivalent

This is a synthesized view unique to SecPostureIQ. The closest portal equivalents are:

1. **Secure Score category breakdown** at [https://security.microsoft.com](https://security.microsoft.com) → **Secure Score** → **Breakdown** tab — shows per-category percentages
2. **Microsoft 365 admin center** at [https://admin.microsoft.com](https://admin.microsoft.com) → **Health** → **Product usage** — shows license activation and feature adoption rates
3. **Adoption Score** at [https://admin.microsoft.com](https://admin.microsoft.com) → **Reports** → **Adoption Score** — measures organizational adoption of M365 features (distinct from security)

### Tool 7: `get_green_playbook` → Foundry IQ / Internal Tooling

1. If your organization has access to **Foundry IQ**, the playbooks are available through the Foundry IQ portal
2. Microsoft's public equivalent for remediation guidance:
   - [https://security.microsoft.com](https://security.microsoft.com) → **Secure Score** → click any **Improvement action** → the detail pane shows implementation steps, user impact, and related documentation links
   - [Microsoft 365 security deployment guides](https://learn.microsoft.com/en-us/microsoft-365/security/) — official step-by-step deployment documentation per workload

### Tool 8: `push_posture_snapshot` → Microsoft Fabric / Power BI

1. Go to [https://app.fabric.microsoft.com](https://app.fabric.microsoft.com)
2. Navigate to your **Workspace** containing the SecPostureIQ lakehouse
3. Open the **Lakehouse** → browse the posture snapshot table
4. For dashboarding, open the connected **Power BI report** to see:
   - Secure Score trend over time
   - Per-workload coverage trends
   - Gap closure velocity
5. If Fabric is not configured, snapshots are only stored in-memory (local dev mode) and are not persisted

---

## Live Tenant Validation (March 2026)

The following results were obtained by running all 4 assessment tools against a live E5 test tenant using client credentials flow. This section documents the findings alongside portal values and identifies remaining action items.

### Secure Score — Agent vs. Portal

| Category | Agent (old, count×10) | Agent (fixed, real maxScore) | Portal (security.microsoft.com) | Match? |
|---|---|---|---|---|
| **Overall** | 127.2/271.0 = 47% | 127.2/271.0 = **47%** | 47% | ✅ Exact |
| **Identity** | 56.2/120.0 = 46.8% | 56.2/63.8 = **88.2%** | 85.23% | ✅ Close (~3% delta from profile pagination) |
| **Data** | 0.0/40.0 = 0% | 0.0/8.0 = **0%** | 0% | ✅ Exact |
| **Apps** | 71.0/510.0 = 13.9% | 71.0/117.0 = **60.7%** | 36.22% | ⚠️ Off — see pagination issue below |

> The category fix (using real `maxScore` from `secureScoreControlProfiles`) significantly improved accuracy. Identity went from 46.8% → 88.2%, matching the portal's 85.23%.

### Defender Coverage

All 4 workloads returned `not_assessed` — no Defender-specific control profiles matched the `service` field filter. This is expected when the app registration doesn't have Defender workload controls in `SecureScoreControlProfiles`, or when the tenant hasn't onboarded Defender services.

### Purview — Agent vs. Portal

| Source | Score | Category System |
|---|---|---|
| **Agent** (`check_purview_policies`) | 0% (3 controls found, all gaps) | DLP, Sensitivity Labels, Retention, Insider Risk, General Data Protection |
| **Purview Portal** (Compliance Posture) | **56%** | AI Baseline (63%), Microsoft 365 (56%), Data Protection Baseline (57%) |
| **Secure Score** (Data category) | 0% | Data category within Microsoft Secure Score |

The Purview portal's "Compliance Posture" uses **Microsoft Purview Posture Management** — a completely different scoring engine from `SecureScoreControlProfiles`. It auto-detects built-in tenant configurations and credits them, while `SecureScoreControlProfiles` only shows a narrow set of improvement actions.

### Entra Config — Permission Gaps

| Component | Result | Issue |
|---|---|---|
| Conditional Access | ✅ yellow (working) | Returned policy data successfully |
| PIM | ❌ 403 Forbidden | Missing `RoleManagement.Read.Directory` |
| Identity Protection | ❌ 403 Forbidden | Missing `IdentityRiskyUser.Read.All` |
| Access Reviews | ❌ 403 Forbidden | Missing `AccessReview.Read.All` |
| Overall | 55% (partial) | Only Conditional Access + SSO data available |

---

## Action Items

### AI-1: Increase `$top` to 999 for `secureScoreControlProfiles` ✅ Fixed

**Problem:** The `_fetch_profile_max_scores()` function in `secure_score.py` uses `$top=200`, but the tenant has **440 control profiles**. This truncates the profile list, causing incorrect `max_score` totals for categories with many controls (especially Apps: agent shows 60.7% vs. portal's 36.22%).

**Root cause:** The same issue exists in `defender_coverage.py` and `purview_policies.py` — all use `$top=200`.

**Validated finding:** A live API call with `$top=999` returned all 440 profiles in a single response with no `@odata.nextLink` — pagination is not needed, just a higher `$top` value.

**Fix:** Change `$top=200` → `$top=999` in all three tools. The Graph API accepts up to 999 per page, and typical tenants have 300–500 profiles.

**Files to change:**
- `src/tools/secure_score.py` — `_fetch_profile_max_scores()` and `_ControlProfilesQueryParameters`
- `src/tools/defender_coverage.py` — `assess_defender_coverage()` query params
- `src/tools/purview_policies.py` — `check_purview_policies()` query params

**Impact:** Will fix the Apps category percentage discrepancy and ensure all Defender/Purview controls are captured.

### AI-2: Grant missing Entra ID permissions ✅ Done

**Problem:** The app registration is missing 3 API permissions, causing PIM, Identity Protection, and Access Reviews to return 403.

**Fix:**
```bash
APP_ID="<your-app-registration-client-id>"

# Add missing permissions
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    49981c42-fd7b-4530-be03-e77b21aed25e=Role \  # RoleManagement.Read.Directory
    dc5007c0-2d7d-4c42-879c-2dab87571379=Role \  # IdentityRiskyUser.Read.All
    ebfcd32b-babb-40f4-a14b-42706e83bd28=Role     # AccessReview.Read.All

# Grant admin consent
az ad app permission admin-consent --id $APP_ID
```

**Impact:** Will enable full Entra ID assessment (currently only getting Conditional Access data).

### AI-3: Investigate Purview Posture Management API ✅ Mitigated

**Problem:** The Purview portal's "Compliance Posture" (56%) uses a different scoring engine than the Graph Security API's `SecureScoreControlProfiles` (0%). The agent's Purview assessment fundamentally undercounts because it relies on the wrong data source.

**Validated finding:** Probing the Graph API confirmed:
- Compliance Manager API (`/beta/compliance/ediscovery/cases`) → 401 (missing `eDiscovery.Read.All` scope)
- Sensitivity labels endpoints (`/informationProtection/policy/labels`, `/beta/security/informationProtection/sensitivityLabels`) → 400/404 (endpoints moved or deprecated)
- No public Graph API currently exposes the Purview Posture Management data

**What was addressed:**
- Added a `disclaimer` field to the Purview tool's JSON output explaining that the portal uses a separate scoring engine (Purview Posture Management) not available via Graph API
- Expanded keyword matching to capture more data controls: `MIP` service, `control_category: "Data"`, encryption, audit, records management, eDiscovery, communication compliance
- Added `General Data Protection` as a 5th component so data controls not matching specific keywords are still captured

**Outstanding gap — three Purview scoring systems exist:**

| Scoring System | Agent Access | Example Score | API |
|---|---|---|---|
| Secure Score "Data" category | ✅ Accessed | 0% | `GET /security/secureScoreControlProfiles` |
| Compliance Manager | ❌ Not accessed | Unknown | `GET /beta/compliance/...` — needs `ComplianceManager.Read.All` |
| Purview Posture Management | ❌ No API exists | 56% | Portal-only (purview.microsoft.com) |

**To fully close this gap (future work):**
1. **Grant `ComplianceManager.Read.All`** scope and integrate the Compliance Manager API — would add improvement actions and assessment coverage data
2. **Wait for Microsoft** to expose the Purview Posture Management REST API — this is the 56% score and currently has no public Graph surface
3. **Alternative: PowerShell data source** — `Connect-IPPSSession` can enumerate DLP policies, sensitivity labels, and retention policies directly, but requires an architectural change to invoke PowerShell from the Python agent

**Current mitigation impact:** The disclaimer sets accurate user expectations. Expanded keywords improved control matching. Full parity with the portal requires API availability from Microsoft.

### AI-4: Fix Defender `WORKLOAD_SERVICE_MAP` with real service values ✅ Fixed

**Problem:** All 4 Defender workloads returned `not_assessed` from live data because the `service` field values in the tenant's control profiles don't match our `WORKLOAD_SERVICE_MAP`.

**Validated finding:** The live API returned 26 unique service values. The actual values vs. what the agent expects:

| Defender Workload | Agent expects | Actual service value(s) | Matched? |
|---|---|---|---|
| Defender for Endpoint | `MDE`, `Microsoft Defender for Endpoint` | **`MDATP`** | ❌ |
| Defender for Office 365 | `MDO`, `Microsoft Defender for Office 365` | **`MDO`** | ✅ |
| Defender for Identity | `MDI`, `Microsoft Defender for Identity` | **`Azure ATP`** | ❌ |
| Defender for Cloud Apps | `MDA`, `Microsoft Defender for Cloud Apps` | **`MCAS`**, `MDA_Atlassian`, `MDA_CitrixSF`, `MDA_DocuSign`, `MDA_Dropbox`, `MDA_GitHub`, `MDA_Google`, `MDA_NetDocuments`, `MDA_Okta`, `MDA_SF`, `MDA_SNOW`, `MDA_Workplace`, `MDA_Zendesk`, `MDA_Zoom` | ❌ |

**Fix:** Update `WORKLOAD_SERVICE_MAP` in `defender_coverage.py` to include the real service values:
- Add `MDATP` → Defender for Endpoint
- Add `Azure ATP` → Defender for Identity
- Add `MCAS` → Defender for Cloud Apps
- Add `MDA_*` prefix matching → Defender for Cloud Apps (app connectors)

**Impact:** Will enable Defender workload assessment from live data — currently shows 0% for all workloads.

### AI-5: Add `MIP` to Purview service keywords ✅ Fixed

**Problem:** Microsoft Information Protection controls use service value `MIP`, which is not in `PURVIEW_SERVICE_KEYWORDS`. These controls are silently skipped by the Purview tool.

**Validated finding:** The live API returned `MIP` as a service value for information protection controls. Our current keyword set checks for substrings like `"information protection"` but the short abbreviation `"mip"` would false-match other words. Needs to be added as an exact service match.

**Fix:** Add `"mip"` to `PURVIEW_SERVICE_KEYWORDS` in `purview_policies.py`.

**Impact:** Will capture additional Purview-related controls that are currently missed.

### AI-6: Add remaining service values for full coverage ✅ Partial (AppG added)

**Problem:** Several service values from the live API are not mapped to any tool: `Admincenter`, `AppG`, `EXO`, `SPO`, `MS Teams`, `FORMS`, `SWAY`. These controls fall through all tool filters and are only visible in the overall Secure Score.

**What was addressed:**
- Added `AppG` (App Governance) → Defender for Cloud Apps in `WORKLOAD_SERVICE_MAP`

**Outstanding gap — 7 unmapped service values:**

| Service | What it is | Category | Why not mapped | Impact |
|---|---|---|---|---|
| `EXO` | Exchange Online security controls | Apps | No dedicated Exchange tool — M365-wide controls | Low — covered by overall Secure Score |
| `SPO` | SharePoint Online controls | Apps | Same — M365-wide | Low |
| `MS Teams` | Teams security controls | Apps | Same | Low |
| `AzureAD` | Entra ID controls (from Secure Score) | Identity | `get_entra_config` uses direct Graph APIs instead | Would duplicate data |
| `Admincenter` | M365 admin center controls | Apps | General admin hygiene settings | Low |
| `FORMS` | Microsoft Forms (~1-2 controls) | Apps | Very few controls | Negligible |
| `SWAY` | Microsoft Sway (~1-2 controls) | Apps | Very few controls | Negligible |

**Key insight:** These 7 services already contribute to the **overall Secure Score** percentage correctly (47%). They are only missing from the **per-workload** breakdowns in `assess_defender_coverage` and `check_purview_policies`. The overall score is accurate; the gap is in granularity, not accuracy.

**To fully close (future work):**
- Create an "M365 Services" tool that reports on `EXO`, `SPO`, `MS Teams`, `Admincenter` controls
- Or add them to existing tools: `EXO`/`SPO`/`MS Teams` → Purview (data protection context) or a new general M365 component
- `AzureAD` could be cross-referenced with `get_entra_config` for validation, but would likely duplicate findings

**Full service value inventory (440 profiles, 26 unique services):**
```
Admincenter, AppG, Azure ATP, AzureAD, EXO, FORMS, MCAS, MDATP,
MDA_Atlassian, MDA_CitrixSF, MDA_DocuSign, MDA_Dropbox, MDA_GitHub,
MDA_Google, MDA_NetDocuments, MDA_Okta, MDA_SF, MDA_SNOW, MDA_Workplace,
MDA_Zendesk, MDA_Zoom, MDO, MIP, MS Teams, SPO, SWAY
```

**4 categories:** Apps, Data, Device, Identity
