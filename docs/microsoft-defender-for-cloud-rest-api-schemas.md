# Microsoft Defender for Cloud REST API Schemas and Plan Enablement

Microsoft Defender for Cloud does not use one schema for every piece of data, but it also does not define a completely separate schema for every Defender plan.

The most accurate model is:

1. **Plan configuration has one common schema.** Defender plans are represented by `Microsoft.Security/pricings`.
2. **Security data has a schema per data family.** Alerts, assessments, sub-assessments, software inventory, SQL vulnerability results, secure scores, and compliance data use different REST resources.
3. **Workload-specific details can appear inside a common schema.** For example, VM and SQL vulnerability findings share the sub-assessment envelope, but their `additionalData` differs.

## Short answer

| Question | Answer |
| --- | --- |
| Is there one schema shared by every Defender plan? | Yes, for plan enablement and configuration. |
| Is there one schema shared by all Defender security data? | No. |
| Is there one independent schema per plan? | Generally no. Schemas are organized by REST resource and data type, not by billing plan. |
| How do we find which plans are enabled? | Query `Microsoft.Security/pricings` and inspect `pricingTier`, `subPlan`, `extensions`, and `resourcesCoverageStatus`. |

## 1. Common schema for Defender plan enablement

All Defender plans use the `Microsoft.Security/pricings` resource. The plan is identified by its `name`, while its configuration is stored in `properties`.

At subscription scope, retrieve all plan configurations with:

```http
GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2024-01-01
Authorization: Bearer {access-token}
```

A response can look like this:

```json
{
  "value": [
    {
      "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings/VirtualMachines",
      "name": "VirtualMachines",
      "type": "Microsoft.Security/pricings",
      "properties": {
        "enablementTime": "2026-01-15T10:30:00Z",
        "enforce": "False",
        "freeTrialRemainingTime": "PT0S",
        "pricingTier": "Standard",
        "resourcesCoverageStatus": "FullyCovered",
        "subPlan": "P2",
        "extensions": [
          {
            "name": "AgentlessVmScanning",
            "isEnabled": "True"
          },
          {
            "name": "FileIntegrityMonitoring",
            "isEnabled": "True"
          }
        ]
      }
    },
    {
      "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings/SqlServers",
      "name": "SqlServers",
      "type": "Microsoft.Security/pricings",
      "properties": {
        "enablementTime": "2026-01-15T10:30:00Z",
        "enforce": "False",
        "freeTrialRemainingTime": "PT0S",
        "pricingTier": "Standard",
        "resourcesCoverageStatus": "FullyCovered"
      }
    },
    {
      "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings/AppServices",
      "name": "AppServices",
      "type": "Microsoft.Security/pricings",
      "properties": {
        "pricingTier": "Free",
        "resourcesCoverageStatus": "NotCovered"
      }
    }
  ]
}
```

### Plan configuration fields

| Field | Meaning |
| --- | --- |
| `name` | Defender plan identifier, such as `VirtualMachines`, `SqlServers`, or `SqlServerVirtualMachines`. |
| `pricingTier` | `Standard` means the paid Defender plan is enabled at the queried scope. `Free` means the paid plan is not enabled at that scope. |
| `subPlan` | Selected plan level when the plan offers multiple levels. Defender for Servers uses `P1` or `P2`. |
| `extensions` | Optional capabilities within a plan, such as agentless VM scanning. |
| `enablementTime` | Last available timestamp at which `pricingTier` was set to `Standard`. |
| `freeTrialRemainingTime` | Remaining trial duration in ISO 8601 duration format. |
| `resourcesCoverageStatus` | Whether all, some, or none of the applicable resources are covered. |
| `enforce` | Whether descendant resources can override the subscription-level plan configuration. |
| `deprecated` | Indicates that a pricing plan has been deprecated. |
| `replacedBy` | Lists the plans that replace a deprecated plan. |

### Plan names relevant to servers and SQL

At minimum, inspect:

| Plan name | Protection represented |
| --- | --- |
| `VirtualMachines` | Defender for Servers |
| `SqlServers` | Defender for Azure SQL databases |
| `SqlServerVirtualMachines` | Defender for SQL Server on machines |

Depending on the environment, `OpenSourceRelationalDatabases` and other database plan names might also be relevant.

## 2. Enabled does not always mean fully covered

Do not rely on `pricingTier` alone.

```json
{
  "pricingTier": "Standard",
  "resourcesCoverageStatus": "PartiallyCovered"
}
```

This means the plan is enabled at subscription scope, but the effective configuration is not uniform across all applicable resources.

| `pricingTier` | `resourcesCoverageStatus` | Interpretation |
| --- | --- | --- |
| `Standard` | `FullyCovered` | The plan is enabled and all applicable resources are covered. |
| `Standard` | `PartiallyCovered` | The plan is enabled, but some resources have different effective coverage. |
| `Free` | `NotCovered` | The paid plan is disabled and applicable resources are not covered. |
| `Free` | `PartiallyCovered` | The subscription plan is disabled, but some resources can have resource-level enablement. |

`resourcesCoverageStatus` is available at subscription scope. Its possible values are `FullyCovered`, `PartiallyCovered`, and `NotCovered`.

## 3. Resource-level configuration and inheritance

The 2024-01-01 Pricings API supports resource-level queries for virtual machines, virtual machine scale sets, and Azure Arc-enabled servers.

For an Azure VM:

```http
GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2024-01-01
```

Example:

```json
{
  "name": "VirtualMachines",
  "type": "Microsoft.Security/pricings",
  "properties": {
    "pricingTier": "Standard",
    "subPlan": "P2",
    "inherited": "True",
    "inheritedFrom": "/subscriptions/{subscriptionId}"
  }
}
```

At resource scope:

- `inherited: "True"` means the resource inherits its configuration from its parent.
- `inherited: "False"` means the resource has an explicitly configured resource-level setting.
- `inheritedFrom` identifies the parent scope. It is `null` when the configuration is not inherited.

Resource-level pricing support is not a universal mechanism for every resource and Defender plan. The API documentation specifically identifies VMs, VM scale sets, and Arc machines as supported resource types.

## 4. Retrieve plan enablement with Azure CLI

### List every plan

```powershell
$subscriptionId = az account show --query id --output tsv

$response = az rest `
    --method get `
    --url "https://management.azure.com/subscriptions/$subscriptionId/providers/Microsoft.Security/pricings?api-version=2024-01-01" |
    ConvertFrom-Json

$response.value |
    Select-Object `
        name,
        @{Name = 'Enabled'; Expression = { $_.properties.pricingTier -eq 'Standard' } },
        @{Name = 'Tier'; Expression = { $_.properties.pricingTier } },
        @{Name = 'SubPlan'; Expression = { $_.properties.subPlan } },
        @{Name = 'Coverage'; Expression = { $_.properties.resourcesCoverageStatus } },
        @{Name = 'EnabledAt'; Expression = { $_.properties.enablementTime } },
        @{Name = 'Enforced'; Expression = { $_.properties.enforce } } |
    Format-Table -AutoSize
```

### List the primary VM and SQL plans

```powershell
$relevantPlans = @(
    'VirtualMachines',
    'SqlServers',
    'SqlServerVirtualMachines'
)

$response.value |
    Where-Object name -In $relevantPlans |
    Select-Object `
        name,
        @{Name = 'Enabled'; Expression = { $_.properties.pricingTier -eq 'Standard' } },
        @{Name = 'Tier'; Expression = { $_.properties.pricingTier } },
        @{Name = 'SubPlan'; Expression = { $_.properties.subPlan } },
        @{Name = 'Coverage'; Expression = { $_.properties.resourcesCoverageStatus } },
        @{Name = 'Extensions'; Expression = {
            ($_.properties.extensions | ForEach-Object {
                "$($_.name)=$($_.isEnabled)"
            }) -join '; '
        }} |
    Format-Table -AutoSize
```

### Request selected plans through the REST filter

The list operation supports a plan-name filter:

```http
GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?$filter=name%20in%20(VirtualMachines,SqlServers,SqlServerVirtualMachines)&api-version=2024-01-01
```

## 5. There is no universal schema for Defender security data

The enabled plan determines which protections and findings Defender for Cloud can produce. It does not determine one plan-specific response format for all of that data.

Instead, the REST API is divided into data families:

| Data | REST resource or operation group | Schema behavior |
| --- | --- | --- |
| Plan configuration | `Microsoft.Security/pricings` | One common pricing schema for all plans |
| Threat alerts | Alerts | One alert schema with extensible entities, properties, and evidence |
| Recommendations and resource assessments | Assessments | One assessment schema across resource types |
| Detailed vulnerability findings | Sub-assessments | Common envelope with workload-specific `additionalData` |
| VM software inventory | Software Inventories | Dedicated software inventory schema |
| SQL vulnerability scans and results | SQL Vulnerability Assessment operations | Dedicated SQL scan, result, baseline, and settings schemas |
| Secure score | Secure Scores and Secure Score Controls | Dedicated secure-score schemas |
| Regulatory compliance | Regulatory Compliance operations | Dedicated compliance schemas |

### Common Azure Resource Manager envelope

Many list operations share an outer Azure Resource Manager structure:

```json
{
  "value": [
    {
      "id": "...",
      "name": "...",
      "type": "Microsoft.Security/...",
      "properties": {
        "...": "The schema depends on the REST resource"
      }
    }
  ],
  "nextLink": "..."
}
```

This envelope is common, but the contents of `properties` are not universal.

## 6. Alerts share an alert schema

VM, SQL, container, storage, and other Defender alerts use the Alerts API model:

```json
{
  "id": ".../providers/Microsoft.Security/locations/westeurope/alerts/{alertId}",
  "name": "{alertId}",
  "type": "Microsoft.Security/locations/alerts",
  "properties": {
    "alertType": "VM_SuspiciousProcess",
    "alertDisplayName": "Suspicious process executed",
    "severity": "High",
    "status": "Active",
    "compromisedEntity": "vm01",
    "resourceIdentifiers": [],
    "entities": [],
    "extendedProperties": {},
    "supportingEvidence": {}
  }
}
```

Fields such as `alertType`, `severity`, `status`, and `resourceIdentifiers` form a stable alert model. The following fields are intentionally extensible and can vary by workload and detection:

- `entities`
- `extendedProperties`
- `supportingEvidence`
- `resourceIdentifiers`

## 7. Recommendations share the assessment schema

Defender for Cloud recommendations and resource health results are exposed as assessments:

```json
{
  "id": ".../providers/Microsoft.Security/assessments/{assessmentKey}",
  "name": "{assessmentKey}",
  "type": "Microsoft.Security/assessments",
  "properties": {
    "displayName": "Recommendation name",
    "resourceDetails": {
      "source": "Azure",
      "id": "{affectedResourceId}"
    },
    "status": {
      "code": "Unhealthy",
      "statusChangeDate": "2026-10-01T12:00:00Z",
      "firstEvaluationDate": "2026-09-01T12:00:00Z"
    },
    "additionalData": {}
  }
}
```

VM and SQL assessments share this envelope. Optional fields and nested details can differ.

## 8. Detailed findings use polymorphic sub-assessments

Detailed vulnerability or recommendation findings use a common sub-assessment envelope:

```json
{
  "id": ".../providers/Microsoft.Security/assessments/{assessmentKey}/subAssessments/{findingId}",
  "name": "{findingId}",
  "type": "Microsoft.Security/assessments/subAssessments",
  "properties": {
    "displayName": "Vulnerability finding",
    "description": "Description of the finding",
    "resourceDetails": {
      "source": "Azure",
      "id": "{affectedResourceId}"
    },
    "status": {
      "code": "Unhealthy",
      "severity": "High"
    },
    "additionalData": {
      "assessedResourceType": "SqlServerVulnerability"
    },
    "timeGenerated": "2026-10-01T12:00:00Z"
  }
}
```

`additionalData.assessedResourceType` is a discriminator. Documented values include:

- `SqlServerVulnerability`
- `ServerVulnerabilityAssessment`
- `ContainerRegistryVulnerability`

This is a shared envelope with typed workload-specific details, not a completely separate top-level schema for each Defender plan.

## 9. Export destination also affects the schema

The REST schema should not be confused with schemas used by other delivery mechanisms:

| Destination | Alert representation |
| --- | --- |
| Direct Defender for Cloud REST API | Alerts API schema |
| Continuous export to Event Hubs | Same schema as the Alerts API |
| Continuous export to Log Analytics | Azure Monitor `SecurityAlert` table schema |
| Azure Activity Log | Activity Log event schema |
| Microsoft Sentinel | Sentinel/Log Analytics representation |
| Microsoft Graph Security | Microsoft Graph alert schema |

Before implementing a parser, confirm both the **data family** and the **transport**.

## 10. Recommended ingestion design

Select and version schemas using:

```text
REST operation or resource type + api-version + optional discriminator
```

Do not select a parser using only:

```text
Defender plan name
```

A robust collector should:

1. Preserve the raw JSON response.
2. Record the source endpoint and `api-version`.
3. Normalize common fields such as `id`, `name`, `type`, and `properties`.
4. Maintain a typed model for each REST data family.
5. Use discriminators such as `assessedResourceType`, entity `type`, and resource-detail `source`.
6. Preserve unknown fields to tolerate additive API changes.
7. Follow `nextLink` for paginated results.
8. Pin API versions and regression-test before upgrading them.
9. Evaluate both `pricingTier` and `resourcesCoverageStatus` when reporting plan enablement.
10. Query supported resource-level pricing when subscription coverage is `PartiallyCovered`.

## Conclusion

You do not need 30 to 40 unrelated schemas corresponding one-to-one with Defender plans.

You need:

- One common `Microsoft.Security/pricings` schema for plan enablement.
- One schema for each Defender REST data family and API version.
- Workload-specific handling for extensible or polymorphic nested properties.
- Separate handling when the same data is delivered through Log Analytics, Activity Log, Microsoft Sentinel, or Microsoft Graph instead of the Defender for Cloud REST API.

## Official Microsoft references

- [Defender for Cloud REST API operation groups](https://learn.microsoft.com/rest/api/defenderforcloud-composite/operation-groups?view=rest-defenderforcloud-composite-latest)
- [Pricings - List](https://learn.microsoft.com/rest/api/defenderforcloud-composite/pricings/list?view=rest-defenderforcloud-composite-latest)
- [Pricings - Get](https://learn.microsoft.com/rest/api/defenderforcloud-composite/pricings/get?view=rest-defenderforcloud-composite-latest)
- [Microsoft.Security/pricings 2024-01-01 schema](https://learn.microsoft.com/azure/templates/microsoft.security/2024-01-01/pricings)
- [Alerts - List](https://learn.microsoft.com/rest/api/defenderforcloud-composite/alerts/list?view=rest-defenderforcloud-composite-latest)
- [Assessments - List](https://learn.microsoft.com/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-latest)
- [Sub-assessments - List](https://learn.microsoft.com/rest/api/defenderforcloud-composite/sub-assessments/list?view=rest-defenderforcloud-composite-latest)
- [Defender for Cloud alert schemas](https://learn.microsoft.com/azure/defender-for-cloud/alerts-schemas)
- [Export alerts and recommendations with continuous export](https://learn.microsoft.com/azure/defender-for-cloud/benefits-of-continuous-export)
- [Software inventories - List by extended resource](https://learn.microsoft.com/rest/api/defenderforcloud-composite/software-inventories/list-by-extended-resource?view=rest-defenderforcloud-composite-latest)

