# VMware to Azure Migration

## Slide 1 - Title

**VMware to Azure Migration**

Analyzing the current VMware estate and selecting the right Azure migration path

Subtitle:
- Decision framework for infrastructure, platform, application, finance, and operations stakeholders
- Focus areas: assessment methods, migration options, cost, risk, speed, and operating model impact

Presenter notes:
- This deck is designed for architecture reviews, steering committees, and migration planning workshops.
- It compares the main ways to move VMware-hosted workloads to Azure rather than assuming one universal answer.

---

## Slide 2 - Executive Summary

**Key message:** There is no single best VMware-to-Azure migration path. The correct choice depends on workload criticality, appetite for change, licensing position, operational maturity, and target timeline.

Headline findings:
- **Azure Migrate to Azure VMs** is usually the default path for net-new migrations when the goal is to move off VMware and run on native Azure IaaS.
- **Azure VMware Solution (AVS)** is usually the fastest path when the priority is minimal application change and preserving VMware tools, skills, and processes.
- **Azure Site Recovery (ASR)** is primarily a disaster recovery service and should usually be treated as a migration path only when it is already in place or when DR and migration are tightly linked.
- **Selective modernization** often delivers the best long-term cost and agility, but it requires more design effort and more application change.

Executive recommendation:
- Use **Azure Migrate** to assess the estate first.
- Segment applications into migration waves.
- Use a **mixed strategy** rather than forcing all workloads into one target pattern.

---

## Slide 3 - The Core Decision

**The real decision is not only "How do we move VMs?" It is "What operating model do we want after migration?"**

Decision branches:
- **Move and keep VMware constructs**: AVS
- **Move and adopt Azure-native IaaS**: Azure Migrate to Azure VMs
- **Move under DR-led replication**: ASR-led transition in limited scenarios
- **Move and improve the application platform**: replatform or refactor selected workloads

Key tradeoff:
- The less change you make to the application and operations model, the faster the initial migration usually is.
- The more Azure-native the target becomes, the more long-term optimization opportunity you usually unlock.

---

## Slide 4 - How to Analyze the Existing VMware Estate

**Assessment should combine discovery, technical fit, dependency insight, and business value.**

Recommended analysis methods:
- **Azure Migrate appliance discovery** for agentless discovery of VMware machines, configuration, and performance history
- **RVTools import** when rapid inventory baselining is needed or appliance rollout is delayed
- **CSV or CMDB import** for incomplete or pre-staged estates, with lower automation and confidence
- **Dependency mapping** to understand application tiers, east-west traffic, shared services, and wave design
- **Business case review** to compare native Azure VM costs, AVS node-based economics, and modernization economics

What should be measured:
- VM count, cluster count, datastore usage, snapshots, templates, and overcommit patterns
- CPU and memory utilization over time, not just allocated values
- Network dependencies, latency sensitivity, and IP retention constraints
- OS versions, support status, backup tooling, monitoring tooling, and security controls
- Application owner readiness, maintenance windows, and tolerance for downtime

Presenter notes:
- A static inventory is not enough. Migration sizing based only on allocated resources often overstates Azure cost.
- Performance history improves confidence and can materially alter target sizing.

---

## Slide 5 - Current-State Data Required for a Credible Decision

**Minimum data set for each workload:**

Technical:
- vCPU, memory, storage footprint, IOPS, throughput, peak utilization, and uptime profile
- Guest OS, middleware, database, clustering, load balancer, and storage dependencies
- Recovery objectives: RPO, RTO, backup retention, and resiliency requirements

Business:
- Application criticality and outage tolerance
- Compliance and data residency constraints
- Planned retirement or replacement horizon
- Growth forecast for 12 to 36 months

Financial:
- Current VMware platform costs: licensing, hosts, storage, network, support, facilities, and operations
- Azure cost assumptions: region, reservation or savings plan potential, Azure Hybrid Benefit, network egress, storage tier, backup, and monitoring

Organizational:
- Team skills in VMware, Azure IaaS, automation, and platform engineering
- Governance maturity for landing zones, identity, patching, backup, policy, and FinOps

---

## Slide 6 - Azure Migration Target Patterns

**Five practical target patterns**

| Option | Target model                     | Best for                                           | Main upside                                | Main downside                                    |
| ------ | -------------------------------- | -------------------------------------------------- | ------------------------------------------ | ------------------------------------------------ |
| A      | Azure Migrate to Azure VMs       | Standard rehost of VMware guests                   | Native Azure landing, broad default choice | More operating model change than AVS             |
| B      | ASR-led migration                | Existing DR users or DR-to-migration transition    | Reuses existing replication approach       | Not the preferred default for net-new migrations |
| C      | Azure VMware Solution            | Fastest path with least VMware change              | Preserves vSphere, NSX, vSAN, HCX workflow | Can be expensive at scale if kept long term      |
| D      | AVS as transitional landing zone | Fast exit from datacenter with later modernization | Reduces immediate change pressure          | Risks becoming a permanent expensive bridge      |
| E      | Selective modernization          | Strategic apps needing platform improvement        | Best long-term agility and optimization    | Highest design and change effort                 |

---

## Slide 7 - Option A: Azure Migrate to Native Azure VMs

**What it is**
- Azure Migrate is Microsoft's recommended default service for discovery, assessment, business case analysis, and migration of on-premises servers to Azure.
- For VMware, Azure Migrate supports agentless migration scenarios and assessment workflows.

How it works:
- Deploy Azure Migrate appliance
- Discover VMware estate
- Build performance-based assessments
- Group machines by application dependency
- Replicate and test migrate into Azure VMs
- Cut over in waves

Strengths:
- Best fit when the end-state is **Azure-native IaaS**, not hosted VMware
- Strong assessment and business case workflow in one service
- Supports right-sizing, region-based cost estimates, reservations, savings plans, and Azure Hybrid Benefit considerations
- Positions the estate for later modernization to managed services

Limitations:
- Requires more change in operations than AVS because teams move from vCenter-based management to Azure-native constructs
- Networking, identity, backup, monitoring, and governance must be redesigned in the Azure landing zone
- Legacy applications with unusual network or appliance dependencies may require exceptions

Best fit workloads:
- General Windows and Linux line-of-business VMs
- Multi-tier applications that can tolerate moderate platform change
- Workloads that benefit from right-sizing and native Azure cost controls

---

## Slide 8 - Option B: Azure Site Recovery as a Migration Path

**What it is**
- Azure Site Recovery is primarily a disaster recovery service.
- Microsoft guidance is to use Azure Migrate for new migrations, but ASR can still be relevant where DR is already deployed or where migration and DR strategy overlap.

When it makes sense:
- The organization already uses ASR replication and wants to convert DR motion into relocation motion
- DR protection must remain active while architecture decisions are still being finalized
- The business needs a short-term bridge before moving fully into Azure Migrate-led operations

Strengths:
- Familiar replication-led workflow for teams already invested in ASR
- Strong DR story during transition
- Can help reduce duplication of tooling in specific in-flight programs

Weaknesses:
- Not Microsoft's preferred default for new server migration programs
- Weaker as a centralized discovery and assessment hub than Azure Migrate
- Less aligned with newer migration feature investment

Use this option when:
- Existing ASR deployment is already protecting target workloads
- The migration program wants to preserve DR continuity while planning the steady-state architecture

---

## Slide 9 - Option C: Azure VMware Solution

**What it is**
- AVS is a first-party Azure service delivering a VMware-based private cloud in Azure, including vSphere, NSX, vSAN, and HCX.
- It is designed for organizations that want to move VMware estates to Azure with minimal change to guest workloads and admin tooling.

Strengths:
- Lowest disruption for VMware-centric operations teams
- Fast path to datacenter exit when applications cannot be changed quickly
- Supports HCX-based migration patterns for bulk VM movement
- Lets the organization adopt Azure services incrementally instead of forcing immediate replatforming

Weaknesses:
- Economics are cluster and node based, which can be less efficient than right-sized Azure VMs for many steady-state workloads
- Long-term value depends on whether AVS is a destination or a transition state
- Teams may delay modernization because the platform feels familiar

Best fit workloads:
- Business-critical applications with low tolerance for change
- Estates with heavy VMware operational dependency
- Applications with strict latency or compatibility concerns that make direct rehost difficult

Presenter notes:
- AVS is often the speed and risk answer, not always the lowest cost answer.

---

## Slide 10 - Option D: AVS as a Transitional Landing Zone

**Concept:** Use AVS to exit the datacenter quickly, then progressively move selected workloads from AVS to native Azure services.

Why organizations choose this pattern:
- Datacenter lease exit is urgent
- Hardware refresh costs must be avoided immediately
- Application teams are not ready for large-scale replatforming in the first wave
- Leadership wants fast risk reduction now and optimization later

Benefits:
- Faster evacuation from on-premises constraints
- Lower immediate application change
- Buys time to redesign networking, identity, and platform standards for later waves

Risks:
- Transitional platforms often become permanent without clear governance
- Cost can remain elevated if no deadline exists to move suitable workloads off AVS
- Dual operating models can persist longer than expected

Control measures:
- Define exit criteria for each workload placed into AVS
- Review AVS placement every quarter
- Treat AVS as a strategic exception unless a long-term business case proves otherwise

---

## Slide 11 - Option E: Selective Modernization

**This is not a pure VMware migration path. It is a business-value path.**

Typical modernization destinations:
- Azure App Service for web applications
- Azure Kubernetes Service or Azure Container Apps for containerizable services
- Azure SQL, Azure Database for PostgreSQL, or managed data services for database workloads
- Azure Files, Blob Storage, or managed integration services where appropriate

When it is justified:
- The application already needs remediation, scaling changes, or platform improvements
- License or infrastructure costs are high enough that simple rehost is unattractive
- The workload is strategic and will remain important for years

Benefits:
- Best long-term elasticity, resilience, and automation potential
- Often strongest long-term TCO position if the application is actively used and improved
- Reduces future dependence on hypervisor-level constructs

Drawbacks:
- Requires architecture, testing, and change management effort
- Harder to standardize as a first wave across a broad estate
- Can slow down portfolio migration if applied indiscriminately

Recommended use:
- Reserve for high-value apps, not as the default for every VM in the estate

---

## Slide 12 - Decision Matrix

Scoring scale:
- 5 = most favorable
- 1 = least favorable

| Criterion                             | Azure Migrate to Azure VMs | ASR-led migration | AVS | AVS as transition | Selective modernization |
| ------------------------------------- | -------------------------- | ----------------- | --- | ----------------- | ----------------------- |
| Speed to first migration wave         | 4                          | 3                 | 5   | 4                 | 2                       |
| Ease for VMware operations teams      | 3                          | 3                 | 5   | 5                 | 2                       |
| Minimal application change            | 4                          | 4                 | 5   | 5                 | 1                       |
| Long-term Azure optimization          | 5                          | 4                 | 2   | 4                 | 5                       |
| Cost efficiency in steady state       | 4                          | 3                 | 2   | 3                 | 5                       |
| Platform familiarity                  | 3                          | 3                 | 5   | 5                 | 2                       |
| Future modernization flexibility      | 5                          | 4                 | 3   | 4                 | 5                       |
| Governance simplicity after migration | 4                          | 3                 | 3   | 2                 | 4                       |

Interpretation:
- **AVS wins on speed and familiarity**.
- **Azure Migrate to Azure VMs wins on default destination quality and optimization potential**.
- **Modernization wins on strategic value but loses on speed and simplicity**.

---

## Slide 13 - Cost Considerations

**Migration decisions fail when only VM compute price is compared.**

Cost lenses to compare:
- **Migration tooling and temporary replication**
- **Target infrastructure**
- **Networking and connectivity**
- **Backup, monitoring, and security tooling**
- **Licensing**
- **Operations labor and platform support**

How the options behave:
- **Azure Migrate to Azure VMs**
  - Typically benefits from right-sizing and native cost controls
  - Savings improve further with reservations, savings plans, and Azure Hybrid Benefit
  - Landing zone services must be included in TCO
- **AVS**
  - Node-based pricing can be attractive for dense, difficult-to-change estates but less efficient for lightly utilized estates
  - Good for avoiding immediate refactoring costs and maintaining continuity
  - Long-term cost can drift upward if AVS becomes the permanent home for workloads better suited to Azure VMs or PaaS
- **ASR-led migration**
  - Transitional economics depend heavily on whether it avoids duplicate tooling or duplicated DR architecture
- **Selective modernization**
  - Highest upfront engineering effort
  - Often lowest long-term infrastructure and operations cost for strategic apps

Presenter notes:
- Ask finance to compare a 3-year view, not just first-year migration budget.

---

## Slide 14 - Ease of Migration and Change Impact

| Factor                               | Azure Migrate to Azure VMs | AVS      | Modernization  |
| ------------------------------------ | -------------------------- | -------- | -------------- |
| Infrastructure change                | Medium                     | Low      | High           |
| Application change                   | Low to medium              | Very low | Medium to high |
| Operations model change              | Medium to high             | Low      | High           |
| Required Azure landing zone maturity | High                       | Medium   | High           |
| Training burden                      | Medium                     | Low      | High           |
| Testing intensity                    | Medium                     | Medium   | High           |

Practical takeaway:
- If the constraint is **time and application risk**, AVS often wins.
- If the constraint is **long-term platform efficiency**, Azure VMs or modernization usually win.

---

## Slide 15 - Recommended Target by Workload Archetype

| Workload archetype                                          | Recommended default                         | Why                                                   |
| ----------------------------------------------------------- | ------------------------------------------- | ----------------------------------------------------- |
| Standard Windows or Linux business app                      | Azure VMs via Azure Migrate                 | Good balance of speed, cost, and Azure-native landing |
| Legacy app with brittle VMware dependencies                 | AVS                                         | Lowest disruption and fastest path out of on-premises |
| App already protected with ASR and under migration pressure | ASR-led transition, then reassess           | Avoids breaking current DR model midstream            |
| Strategic customer-facing app                               | Selective modernization                     | Better long-term resilience and product velocity      |
| Datacenter exit with aggressive deadline                    | AVS first, then rationalize                 | Reduces immediate relocation risk                     |
| Underutilized VM sprawl                                     | Azure Migrate with performance-based sizing | Best chance to eliminate overprovisioning             |

---

## Slide 16 - Suggested Migration Program Structure

**Phase 1: Discover and assess**
- Deploy Azure Migrate appliance
- Import RVTools where useful for cross-checking
- Build performance-based assessments
- Classify workloads by criticality, fit, and target pattern

**Phase 2: Decide target pattern by wave**
- Wave A: straightforward rehost to Azure VMs
- Wave B: AVS for low-change critical apps
- Wave C: strategic apps for modernization

**Phase 3: Pilot and validate**
- Select 5 to 20 representative workloads
- Validate network, identity, backup, monitoring, and security controls
- Run test migrations and rollback drills

**Phase 4: Scale execution**
- Use factory approach with runbooks, templates, and cutover standards
- Track wave velocity, failed migrations, outage minutes, and realized cost variance

**Phase 5: Optimize after migration**
- Right-size native Azure VMs
- Move eligible AVS workloads to Azure-native platforms
- Apply FinOps, reservations, and platform modernization backlog

---

## Slide 17 - Governance and Risk Controls

**Top migration risks:**
- Underestimating application dependencies
- Using allocated VMware size instead of actual utilization for target sizing
- Treating AVS as a permanent default without economic review
- Migrating infrastructure without ready Azure governance controls
- Ignoring backup, patching, monitoring, identity, and security redesign

Risk controls:
- Require dependency mapping for business-critical tiers
- Use performance-based assessments where possible
- Establish architecture review gates for AVS placement
- Align migration waves with landing zone readiness
- Include application owners, security, network, and operations teams early

---

## Slide 18 - Sample Recommendation Framework

**If the goal is fastest safe exit from VMware with low application disruption:**
- Prioritize AVS for the most fragile or critical workloads
- Use Azure Migrate for the broader rehostable estate
- Set an explicit 12- to 24-month rationalization plan for AVS-hosted applications

**If the goal is long-term Azure cost and platform optimization:**
- Make Azure Migrate to Azure VMs the default path
- Reserve AVS for justified exceptions only
- Modernize strategic applications in parallel where business value is clear

**If the goal is continuity for already protected workloads:**
- Keep ASR where it is already materially embedded
- Use Azure Migrate for assessment, business case work, and future-state planning

---

## Slide 19 - Key Questions for Stakeholders

Executive and finance:
- Is the priority speed of datacenter exit, cost reduction, risk reduction, or modernization?
- What is the acceptable payback period for migration and optimization?

Infrastructure and operations:
- Does the team want to keep a VMware operating model in Azure, or adopt Azure-native operations quickly?
- Are landing zone controls ready for large-scale Azure VM onboarding?

Application owners:
- Which applications cannot tolerate infrastructure or network change?
- Which applications are already due for platform refresh or retirement?

Security and governance:
- Are policy, identity, backup, logging, and compliance controls in place for the target state?

---

## Slide 20 - Final Recommendation

**Recommended decision rule:**
- Start with **Azure Migrate assessment for the full estate**.
- Use **Azure VMs as the default target** for general-purpose rehostable workloads.
- Use **AVS selectively** for workloads where minimizing change is more valuable than immediate cost optimization.
- Use **ASR primarily where DR already exists or must remain central during transition**.
- Use **modernization selectively** for applications that justify the engineering investment.

**Bottom line:**
- Most enterprises should expect a **portfolio strategy**, not a single migration pattern.
- The highest-quality migration program is the one that separates fast relocation decisions from long-term platform decisions without confusing the two.

---

## Appendix - Source Anchors Used for This Deck

Key Microsoft guidance reflected in this deck:
- Microsoft recommends **Azure Migrate** over **Azure Site Recovery** for new server migration programs.
- Azure Migrate supports discovery, assessment, business case development, and migration workflows for VMware estates.
- AVS provides a VMware-based private cloud on Azure and is designed to reduce migration complexity and business disruption.
- AVS assessments can estimate node-based monthly costs and recommend HCX-oriented migration guidance for VMware workloads.
- Azure Migrate assessments can incorporate pricing settings such as region, VM uptime, reservations, savings plans, and Azure Hybrid Benefit assumptions.

Suggested visual inserts when converting to slides:
- Portfolio segmentation heat map
- Option comparison radar chart
- 3-year TCO comparison table
- Wave plan timeline
- Current-state to target-state operating model diagram