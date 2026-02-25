# Set your target subscription
az account set --subscription "5f3972d8-b1e2-4a27-bf67-0db461308c53"

# Enable automatic upgrades on a single Arc-enabled server
az rest 
--method PATCH 
--url "https://management.azure.com/subscriptions/5f3972d8-b1e2-4a27-bf67-0db461308c53/resourceGroups/RGAZLOCAL/providers/Microsoft.HybridCompute/machines/AZLHOST1?api-version=2024-05-20-preview" 
--headers "Content-Type=application/json" 
--body '{"properties":{"agentUpgrade":{"enableAutomaticUpgrade":true}}}'

az rest 
--method PATCH 
--url "https://management.azure.com/subscriptions/5f3972d8-b1e2-4a27-bf67-0db461308c53/resourceGroups/RGAZLOCAL/providers/Microsoft.HybridCompute/machines/AZLHOST2?api-version=2024-05-20-preview" 
--headers "Content-Type=application/json" 
--body '{"properties":{"agentUpgrade":{"enableAutomaticUpgrade":true}}}'