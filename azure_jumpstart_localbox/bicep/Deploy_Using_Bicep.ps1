az group create --name "rgAzureLocal"  --location "West Europe"
az deployment group create -g "rgAzureLocal" -f "main.bicep" -p "main.bicepparam"