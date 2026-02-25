Set-AzContext -Subscription "5f3972d8-b1e2-4a27-bf67-0db461308c53"

$params = @{
  ResourceGroupName = "RGAZLOCAL"
  ResourceProviderName = "Microsoft.HybridCompute"
  ResourceType = "Machines"
  ApiVersion = "2024-05-20-preview"
  Name = "AZLHOST1"
  Method = "PATCH"
  Payload = '{"properties":{"agentUpgrade":{ "enableAutomaticUpgrade":true}}}'
}
Invoke-AzRestMethod @params