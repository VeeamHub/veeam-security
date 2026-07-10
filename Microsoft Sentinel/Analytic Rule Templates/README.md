## KQL Queries for Microsoft Sentinel Analytics Rules

The queries below are built to work with data ingested via the **Veeam App for Microsoft Sentinel**. For background on how Analytics Rules are structured and used in this context, see the official reference:

📖 [Veeam App for Microsoft Sentinel – Analytics Rule Reference](https://helpcenter.veeam.com/docs/security_plugins_microsoft_sentinel/guide/sentinel_analytics_rule_reference.html?ver=1)

---

### 1. Analytics Rule Template – High Risk Recon Scanner Findings

This query can be used directly as a **Scheduled Analytics Rule** in Microsoft Sentinel. It triggers whenever a Recon Scanner finding with a `High` risk level is detected.

> **Note:** The `RiskLevel` field can take one of four values: `critical`, `high`, `medium`, or `low`. Adjust the filter below depending on the severity you want to alert on.

```kql
VeeamCovewareFindings_CL
| where RiskLevel == "High"
```

**Suggested rule settings:**
- **Severity:** set to match the filtered RiskLevel (e.g. High for the example above)
- **Run frequency / lookup period:** Configure this to match how often new data is ingested into VeeamCovewareFindings_CL in your environment.
- **Alert threshold:** Trigger on any result (> 0 events)
- **Entity mapping:** `Hostname`, `MachineId`, `TenantId`

---

### 2. Follow-up Analysis Query – 7-Day Findings Summary

This query is **not intended as a standalone detection rule**, but as a follow-up investigation query once an alert has fired or an incident has been created from the rule above. It provides a broader picture of Recon Scanner activity over the past 7 days, helping analysts assess scope and severity before triaging the incident.

```kql
VeeamCovewareFindings_CL
| where TimeGenerated >= ago(7d)
| summarize
    Events=count(),
    High=countif(RiskLevel == "high"),
    Medium=countif(RiskLevel == "medium"),
    Low=countif(RiskLevel == "low"),
    DistinctHosts=dcount(Hostname),
    DistinctMachines=dcount(MachineId),
    TenantsAffected=dcount(TenantId),
    TechniquesCount=dcount(TechniqueId),
    EventTypesCount=dcount(EventType),
    TopTechniques=make_set(TechniqueId, 12),
    TopEventTypes=make_set(EventType, 10),
    TopEventActivities=make_set(EventActivity, 10),
    TopCountries=make_set(Country, 8),
    SampleArtifacts=make_set(Artifact, 8),
    SampleHashesSha256=make_set(Sha256Hash, 10),
    EarliestEvent=min(EventTime),
    LatestEvent=max(EventTime)
| project Events, High, Medium, Low, DistinctHosts, DistinctMachines, TenantsAffected, TechniquesCount, EventTypesCount, TopTechniques, TopEventTypes, TopEventActivities, TopCountries, SampleArtifacts, SampleHashesSha256, EarliestEvent, LatestEvent
```

**When to use it:**
- After an incident is created from the High Risk Rule Template above
- During manual threat hunting or weekly reporting
