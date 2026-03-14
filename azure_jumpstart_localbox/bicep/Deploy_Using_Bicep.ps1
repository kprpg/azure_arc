az group create --name "rgAzLocal"  --location "West Europe"
az deployment group create -g "rgAzLocal" -f "main.bicep" -p "main.bicepparam"