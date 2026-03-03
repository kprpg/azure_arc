# Azure Arc Hybrid Governance Workbook

Companion guide for `arc-hybrid-governance-workbook.json`.

This workbook provides a MAP-like, continuous view of hybrid/on-prem estate visibility using Azure Arc + Azure Monitor, with focus on:

- Inventory and machine status
- Patch compliance and missing updates
- SQL Server discovery
- Shadow IT style software detection
- Security recommendations and coverage posture

## File

- Template: `arc-hybrid-governance-workbook.json`
- Companion guide: `arc-hybrid-governance-workbook.md`
- Portal editor JSON: `arc-hybrid-governance-workbook.portal.json`

Important:
`arc-hybrid-governance-workbook.json` is an ARM deployment template. If you paste it directly into Workbook Advanced Editor, the editor can reset/blank because it expects a `Notebook/1.0` workbook document, not an ARM wrapper.

## Prerequisites

- Azure Arc onboarding for target hybrid servers.
- One or more Log Analytics workspaces receiving telemetry.
- Data collection enabled for the signals you want to visualize.

Recommended capabilities:

- `Heartbeat` data (Azure Monitor agent/Arc-connected monitoring)
- Update assessment/compliance data (`Update`, `UpdateSummary`)
- Guest inventory/change tracking data (`ConfigurationData`)
- Defender for Cloud export/signals (`SecurityRecommendation`)

## Deploy

### Option 1: ARM deployment

```powershell
az deployment group create \
  --resource-group <resource-group-name> \
  --template-file "azure_jumpstart_arcbox/artifacts/monitoring/arc-hybrid-governance-workbook.json"
```

### Option 2: Portal

1. Go to Azure Portal.
2. Open `Monitor` -> `Workbooks`.
3. Import/deploy the ARM template, or open Advanced Editor and use the workbook content from the template.
4. Save as shared workbook.

## Parameters

Global filters are in the top parameter bar.

- `Subscription`: Multi-select subscription picker.
- `Log Analytics Workspace` (`Workspace`): Multi-select dropdown populated dynamically from Resource Graph.
- `Resource group` (`ResourceGroup`): Dynamic filter for hybrid machine resource groups.
- `Machine scope` (`MachineScope`): `Arc` or `AzureVM`.
- `OS type` (`OSType`): `All`, `Windows`, or `Linux`.
- `Shadow DB keywords` (`DbKeywords`): Comma-separated software patterns used in shadow IT detection.
- `Time Range` (`timeRange`): Workbook-wide time context.

## Tabs and What They Show

- `Executive`
- Hybrid KPI snapshot (machine count, reporting footprint, update gap, SQL and shadow DB signals).
- Online/offline distribution.
- Average patch compliance.

- `Inventory`
- Unified machine inventory from Resource Graph.
- OS and status breakdown from heartbeat telemetry.

- `Patch`
- Missing updates by machine/classification.
- Compliance by machine.
- Critical/security missing update trend.

- `SQL`
- SQL service detection from guest inventory (`MSSQL` service signals).
- SQL software version breakdown.
- Arc-enabled SQL resource inventory (Resource Graph).

- `ShadowIT`
- Potential non-standard DB software footprints using `DbKeywords`.
- Recent software drift highlights.

- `Security`
- Defender recommendation summary (`SecurityRecommendation`).
- Arc coverage ratio.
- Machines not reporting heartbeat for more than 24 hours.

## Data Sources Used

The workbook queries these common tables/resources:

- Azure Resource Graph: `Resources`
- Log Analytics: `Heartbeat`, `Update`, `UpdateSummary`, `ConfigurationData`, `SecurityRecommendation`

If any source is not configured in your environment, the corresponding visuals will return empty results.

## Tuning Guidance

- Keep `MachineScope` at `Arc` for strict on-prem/hybrid focus.
- Include `AzureVM` when you want a single cloud + hybrid operations view.
- Update `DbKeywords` to match organizational risk patterns, for example:
  - `MySQL,Postgre,Oracle,Mongo,Redis,Cassandra`
- Adjust `timeRange` to 24h or 7d for daily operations, 30d for executive trend reviews.

## Troubleshooting

- Empty workbook visuals:
  - Verify at least one workspace is selected in `Log Analytics Workspace`.
  - Check selected subscriptions/resource groups have onboarded resources.
  - Confirm required data tables are populated in the selected workspace(s).

- Patch tab has no data:
  - Confirm Update Manager/assessment data is flowing to Log Analytics (`Update`/`UpdateSummary`).

- SQL tab has no detections:
  - Ensure guest inventory/change tracking is enabled and `ConfigurationData` exists.
  - Arc SQL resource list only populates if Arc-enabled SQL resources are onboarded.

- Security tab is empty:
  - Ensure Defender for Cloud recommendations are available in Log Analytics (`SecurityRecommendation`).

## Known Notes

- The workbook is designed to degrade gracefully when optional tables are missing, but some visuals still require specific telemetry streams.
- This workbook complements MAP-like discovery but is intended for continuous operations visibility rather than one-time assessment snapshots.
