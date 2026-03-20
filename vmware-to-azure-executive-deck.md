# VMware to Azure Migration - Executive Deck

## Slide 1 - Title

**VMware to Azure Migration**

Decision path, cost posture, and migration recommendation

Speaker notes:
- This version is optimized for executive sponsors, steering committees, and finance partners.
- It answers three questions: what are the options, what are the tradeoffs, and what should we do.

---

## Slide 2 - Executive Takeaway

- No single path fits the full estate
- Azure VMs should be the default target
- AVS should be used selectively
- IP retention is a design issue, not a reason to default the whole program
- Best outcome is a mixed migration portfolio

Speaker notes:
- Microsoft guidance favors Azure Migrate for new migration programs.
- AVS is valuable when the business needs speed and low application change.

---

## Slide 3 - Decision in One Line

**Choose the operating model first. Then choose the migration tool.**

| Desired end state           | Preferred path                |
| --------------------------- | ----------------------------- |
| Keep VMware operations      | AVS                           |
| Adopt Azure-native IaaS     | Azure Migrate to Azure VMs    |
| Preserve existing DR motion | ASR only where already in use |
| Improve strategic apps      | Selective modernization       |

Speaker notes:
- The main mistake in VMware migrations is optimizing only for VM relocation speed and not for the future operating model.

---

## Slide 4 - Option Summary Scorecard

Scoring: 5 = best fit

| Option                     | Speed | Change risk | Long-term cost | Azure alignment | Overall use         |
| -------------------------- | ----- | ----------- | -------------- | --------------- | ------------------- |
| Azure Migrate to Azure VMs | 4     | 4           | 4              | 5               | Default path        |
| AVS                        | 5     | 5           | 2              | 2               | Exception path      |
| AVS then modernize         | 4     | 4           | 3              | 4               | Transitional path   |
| ASR-led migration          | 3     | 3           | 3              | 3               | Existing DR only    |
| Selective modernization    | 2     | 2           | 5              | 5               | Strategic apps only |

Speaker notes:
- AVS leads on speed and low disruption.
- Azure VMs lead on steady-state efficiency and platform alignment.

---

## Slide 5 - What to Analyze First

- Actual utilization, not allocated size
- Application dependencies and cutover windows
- Network overlap and IP retention constraints
- License position and Azure Hybrid Benefit eligibility
- Team readiness for Azure operations

Speaker notes:
- A weak assessment drives poor cost estimates and weak wave planning.
- Performance-based sizing materially improves the business case.

---

## Slide 6 - Cost Lens

**Do not compare only VM compute.**

- Platform cost
- Connectivity cost
- Backup, monitoring, security cost
- Migration tooling and temporary replication cost
- Operations labor and support cost
- Future optimization opportunity

Speaker notes:
- AVS can reduce immediate migration effort but may cost more in steady state.
- Azure VMs often win on right-sizing and reservation-based savings.

---

## Slide 7 - IP Address Behavior

| Topic                    | AVS                                         | Azure native                                         |
| ------------------------ | ------------------------------------------- | ---------------------------------------------------- |
| Private IP retention     | Often feasible with HCX L2 extension        | Usually changes unless subnet failover is engineered |
| Public IP retention      | New Azure public IPs usually required       | New Azure public IPs required                        |
| Routing impact           | High if stretched networks create asymmetry | High if same subnet is moved to Azure                |
| Coexistence with on-prem | Harder with stretched or overlapping ranges | Hard if same IP range remains active on-prem         |
| Cutover style            | Network-aware HCX migration                 | DNS and routing-led cutover is more typical          |

Speaker notes:
- If preserving private IPs is a top requirement, AVS is usually easier.
- In Azure native, preserving private IPs is possible only in narrower failover-style designs and adds routing complexity.

---

## Slide 8 - Customer Scenario

**Assumed scenario for recommendation**

- 700 VMware VMs across two datacenters
- Datacenter exit required in 12 months
- 20 tier-1 applications
- 15% of apps have hard-coded IP or legacy network dependencies
- Operations team is strong in VMware, early in Azure
- Board priority: lower risk first, optimize cost over 24 months

Speaker notes:
- This scenario is specific enough for a recommendation and common enough to be reusable.

---

## Slide 9 - Board-Ready Recommendation

**Recommended portfolio**

- 60% to Azure VMs via Azure Migrate
- 25% to AVS for low-change critical apps
- 10% to selective modernization
- 5% remain under transition or retirement planning

Why this mix:
- Meets datacenter deadline
- Avoids overusing AVS as a permanent platform
- Contains application risk for the hardest workloads
- Preserves a credible 24-month cost optimization path

Speaker notes:
- The recommendation is intentionally mixed. Forcing every workload into AVS or Azure native creates avoidable cost or risk.

---

## Slide 10 - Wave Plan

```mermaid
flowchart LR
    A[Wave 0: Assess] --> B[Wave 1: Easy rehost to Azure VMs]
    B --> C[Wave 2: AVS for fragile apps]
    C --> D[Wave 3: Modernize strategic apps]
    D --> E[Wave 4: Optimize and exit exceptions]
```

Speaker notes:
- Start with estate discovery and dependency mapping.
- Use early Azure VM waves to build execution muscle before handling the hardest apps.

---

## Slide 11 - Key Risks and Controls

| Risk                          | Control                                           |
| ----------------------------- | ------------------------------------------------- |
| AVS becomes permanent         | Quarterly economic review and exit criteria       |
| Azure VM costs are overstated | Performance-based sizing and reservation planning |
| App cutover issues            | Dependency mapping and pilot waves                |
| IP-related outages            | Network overlap review, DNS plan, route testing   |
| Landing zone immaturity       | Governance gates before wave expansion            |

Speaker notes:
- Most migration failure modes are governance and dependency failures, not tooling failures.

---

## Slide 12 - Decision Required

**Approve this direction**

- Azure VMs as default target
- AVS as controlled exception path
- 90-day assessment and pilot phase
- Board review after pilot with refined TCO and wave plan

Speaker notes:
- The next decision is not the full migration budget. It is approval to baseline the estate, validate pilot assumptions, and refine the portfolio mix.