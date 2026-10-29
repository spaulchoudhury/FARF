# build_and_deploy.ps1
# Dot-source once, then call ONE function at a time:
#     . .\build_and_deploy.ps1
#     Get-AwsLogin ; Build-PartitionImage -Tag v5-partition
# Written without being executed (no PowerShell in the authoring environment).
# Run from the repo root (farf_prototype_v7_9_7) with Docker Desktop running.

$Project   = "<GCP_PROJECT_ID>"
$Region    = "asia-south1"
$Service   = "<farf-prototype>-bus"
$GcpRepo   = "asia-south1-docker.pkg.dev/$Project/<GCP_REPO_ID>"
$AwsAcct   = "<AWS_ACCOUNT_ID>"
$AwsRegion = "ap-south-1"
$EcrHost   = "$AwsAcct.dkr.ecr.$AwsRegion.amazonaws.com"
$EcrRepo   = "$EcrHost/<farf-prototype>-org-b"

# ---- 0. one-off: make sure the env file and .dockerignore exist in the repo root
#         (copy bus-env.yaml and .dockerignore from the delivered files; check with Test-Path)

# ---- 1. sanity: what is inside an image? (also proves no AWS key got baked in)
function Test-ImageContents([string]$Image) {
  docker run --rm --entrypoint sh $Image -c "ls /app/aws_pilot; echo ---; grep -rIl 'AKIA' /app || echo 'no AWS key pattern found in /app'"
}

# ---- 2. GCP: rebuild + push the bus image. Only needed if bus_service.py or the
#         federation code changed. The fixes in v3 runbook did NOT change the bus, so the
#         image already deployed (see precheck G2) can normally be reused as-is.
function Build-BusImage([string]$Tag) {
  Copy-Item .\pentest_cloud\bus_service.py .\docker\bus_service.py -Force
  $img = "$GcpRepo/federation-bus:$Tag"
  docker build -f .\docker\Dockerfile.cloudrun -t $img .
  docker push $img
  "Pushed $img"
}

# ---- 3. GCP: deploy an image with the FULL env set from bus-env.yaml
#         --env-vars-file REPLACES every env var with exactly the file's contents,
#         so the file is the single source of truth (no more --set-env-vars surprises).
function Deploy-Bus([string]$Tag, [int]$MinInstances = 1) {
  $img = "$GcpRepo/federation-bus:$Tag"
  gcloud run deploy $Service --project $Project --region $Region --image $img `
    --min-instances $MinInstances --max-instances 1 --port 8080 `
    --allow-unauthenticated --env-vars-file .\bus-env.yaml
}

# ---- 4. GCP: warm / cold without changing image or env (each creates a NEW revision = clean state)
function Set-BusWarm { gcloud run services update $Service --project $Project --region $Region --min-instances 1 }
function Set-BusCold { gcloud run services update $Service --project $Project --region $Region --min-instances 0 }

# ---- 5. GCP: what is actually running right now
function Show-BusConfig {
  gcloud run services describe $Service --project $Project --region $Region `
    --format="yaml(status.url,status.latestReadyRevisionName,spec.template.spec.containers[0].image,spec.template.spec.containers[0].env,spec.template.metadata.annotations)"
}

# ---- 6. AWS: log in to ECR (token lasts 12 h)
function Get-AwsLogin {
  aws ecr get-login-password --region $AwsRegion | docker login --username AWS --password-stdin $EcrHost
}

# ---- 7. AWS: build + push the partition-test image (contains adr004_partition_client_v5.py)
function Build-PartitionImage([string]$Tag = "v5-partition") {
  if (-not (Test-Path .\aws_pilot\adr004_partition_client_v5.py)) { throw "Copy adr004_partition_client_v5.py into aws_pilot\ first." }
  $img = "${EcrRepo}:$Tag"
  docker build -f .\docker\Dockerfile.awsecs -t $img .
  docker push $img
  "Pushed $img"
}

# ---- 8. AWS: register the partition task definition
function Register-PartitionTaskDef {
  aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def-partition-v5.json --region $AwsRegion
}
