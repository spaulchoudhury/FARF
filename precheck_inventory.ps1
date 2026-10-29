# precheck_inventory.ps1
# READ-ONLY inventory of what exists on this laptop, in GCP and in AWS.
# Nothing here creates, changes or deletes anything.
# Run from the repo root (farf_prototype_v7_9_7) in the VS Code PowerShell terminal:
#     .\precheck_inventory.ps1
# Output: one text file per section in .\precheck_<timestamp>\ (also echoed on screen).
# NOTE: written without being executed (no PowerShell in the authoring environment).
# If a section errors, the script carries on; read the error in that section's file.

param(
  [string]$GcpProject = "<GCP_PROJECT_ID>",
  [string]$GcpRegion  = "asia-south1",
  [string]$Service    = "<farf-prototype>-bus",
  [string]$GcpRepo    = "<GCP_REPO_ID>",
  [string]$KeyRing    = "<GCP_REPO_ID>-keyring",
  [string]$AwsRegion  = "ap-south-1",
  [string]$Cluster    = "<farf-prototype>-cluster",
  [string]$Vpc        = "vpc-0f3d9dbfcbdf90e57"
)

$ts  = Get-Date -Format "yyyyMMdd_HHmmss"
$out = Join-Path $PWD "precheck_$ts"
New-Item -ItemType Directory -Path $out | Out-Null

function Section([string]$name, [scriptblock]$cmd) {
  Write-Host ""
  Write-Host "=== $name" -ForegroundColor Cyan
  $file = Join-Path $out (($name -replace '[^A-Za-z0-9]+', '_') + ".txt")
  try   { $text = (& $cmd 2>&1 | Out-String) }
  catch { $text = "ERROR: $_" }
  $text | Set-Content -Path $file -Encoding utf8
  Write-Host $text
}

# ---------------------------------------------------------------- LAPTOP
Section "L1 tools and location" {
  "PWD: $PWD"
  "PowerShell: $($PSVersionTable.PSVersion)"
  python --version
  docker --version
  aws --version
  gcloud --version | Select-Object -First 1
  git --version
}

Section "L2 git state" {
  git status --short
  git log -1 --oneline
}

Section "L3 docker images and containers on this laptop" {
  docker images --format "table {{.Repository}}`t{{.Tag}}`t{{.ID}}`t{{.CreatedSince}}`t{{.Size}}"
  "--- containers (all)"
  docker ps -a --format "table {{.Names}}`t{{.Image}}`t{{.Status}}"
}

Section "L4 which script versions are in this folder" {
  $files = @(
    "aws_pilot\adr004_partition_client.py",
    "aws_pilot\adr004_partition_client_v3.py",
    "aws_pilot\adr004_partition_client_v4.py",
    "aws_pilot\adr004_partition_client_v5.py",
    "aws_pilot\analyze_partition_log.py",
    "aws_pilot\adr010_boundary_probe.py",
    "aws_pilot\adr010_boundary_probe_v2.py",
    "gcp_pilot\cloud_run_final_checks.py",
    "gcp_pilot\cloud_run_final_checks_FIXED.py",
    "pentest_cloud\pt08_session_hijack_cloud.py",
    "pentest_cloud\bus_service.py",
    "docker\bus_service.py",
    "docker\Dockerfile.cloudrun",
    "docker\Dockerfile.awsecs"
  )
  foreach ($f in $files) {
    if (Test-Path $f) {
      $h = (Get-FileHash $f -Algorithm SHA256).Hash.Substring(0, 12)
      $i = Get-Item $f
      "{0,-52} {1}  {2}  {3} bytes" -f $f, $h, $i.LastWriteTime.ToString("yyyy-MM-dd HH:mm"), $i.Length
    } else {
      "{0,-52} MISSING" -f $f
    }
  }
  ""
  "--- version markers (which file is the FIXED one)"
  "adr010 files containing 'toctou_resource_mismatch' (v2 has it, v1 does not):"
  Select-String -Path "aws_pilot\adr010_boundary_probe*.py" -Pattern "toctou_resource_mismatch" -List | ForEach-Object { "  " + $_.Path }
  "cloud_run_final_checks files containing '--from-agent' (FIXED has it):"
  Select-String -Path "gcp_pilot\cloud_run_final_checks*.py" -Pattern "--from-agent" -List | ForEach-Object { "  " + $_.Path }
  "pt08 files containing 'run_id' (ADR-018 fix):"
  Select-String -Path "pentest_cloud\pt08*.py" -Pattern "run_id" -List | ForEach-Object { "  " + $_.Path }
  ""
  "--- are the two bus_service.py copies identical? (docker\ is what gets built)"
  if ((Test-Path "docker\bus_service.py") -and (Test-Path "pentest_cloud\bus_service.py")) {
    $a = (Get-FileHash "docker\bus_service.py").Hash
    $b = (Get-FileHash "pentest_cloud\bus_service.py").Hash
    if ($a -eq $b) { "IDENTICAL" } else { "DIFFERENT - copy pentest_cloud\bus_service.py over docker\bus_service.py before building" }
  }
}

Section "L5 secrets scan (AWS key pattern; paths only, never prints the value)" {
  Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\\.venv\\|\\\.git\\|\\node_modules\\|\\precheck_' -and
                   $_.Extension -in '.txt', '.md', '.json', '.py', '.ps1', '.yaml', '.yml', '.jsonl', '.log', '.env' } |
    Select-String -Pattern 'AKIA[0-9A-Z]{16}' -ErrorAction SilentlyContinue |
    ForEach-Object { "{0}:{1}" -f $_.Path, $_.LineNumber }
  "(if nothing is listed above, no AKIA-pattern key was found in the repo folder)"
  ""
  ".dockerignore present? " + (Test-Path ".dockerignore")
}

# ---------------------------------------------------------------- GCP
Section "G1 identity and project" {
  gcloud config list
  gcloud auth list
  gcloud billing projects describe $GcpProject
}

Section "G2 Cloud Run service (image, env vars, scaling, resources)" {
  $svc = gcloud run services describe $Service --project $GcpProject --region $GcpRegion --format=json | ConvertFrom-Json
  "URL:                   $($svc.status.url)"
  "Latest ready revision: $($svc.status.latestReadyRevisionName)"
  "Image:                 $($svc.spec.template.spec.containers[0].image)"
  ""
  "Environment variables (expect FARF_PENTEST_MODE=1 AND FARF_LOG_FORMAT=json):"
  $env_ = $svc.spec.template.spec.containers[0].env
  if ($env_) { $env_ | ForEach-Object { "  {0}={1}" -f $_.name, $_.value } } else { "  (none set)" }
  ""
  "Scaling annotations (minScale / maxScale; missing minScale = 0):"
  $svc.spec.template.metadata.annotations | Format-List | Out-String
  "Resources (empty = defaults 1 CPU / 512Mi):"
  $svc.spec.template.spec.containers[0].resources | ConvertTo-Json -Depth 4
  "containerConcurrency: $($svc.spec.template.spec.containerConcurrency)"
}

Section "G3 who can call the service (allUsers = public)" {
  gcloud run services get-iam-policy $Service --project $GcpProject --region $GcpRegion
}

Section "G4 recent revisions" {
  gcloud run revisions list --service $Service --project $GcpProject --region $GcpRegion --limit 8
}

Section "G5 Artifact Registry images" {
  gcloud artifacts docker images list "$GcpRegion-docker.pkg.dev/$GcpProject/$GcpRepo" --include-tags --project $GcpProject
}

Section "G6 Cloud KMS" {
  gcloud kms keyrings list --location $GcpRegion --project $GcpProject
  gcloud kms keys list --keyring $KeyRing --location $GcpRegion --project $GcpProject
}

Section "G7 anything else billable in the project" {
  "--- Cloud Run services"
  gcloud run services list --project $GcpProject
  "--- Compute Engine VMs (API was enabled once)"
  gcloud compute instances list --project $GcpProject
  "--- enabled APIs"
  gcloud services list --enabled --project $GcpProject --format="value(config.name)"
}

# ---------------------------------------------------------------- AWS
Section "A1 identity" {
  aws sts get-caller-identity
  aws configure list
}

Section "A2 ECR images" {
  aws ecr describe-repositories --region $AwsRegion --query "repositories[].repositoryName" --output table
  aws ecr describe-images --repository-name <farf-prototype>-org-b --region $AwsRegion --query "imageDetails[].{Tags:imageTags,Pushed:imagePushedAt,SizeBytes:imageSizeInBytes}" --output table
}

Section "A3 ECS clusters, tasks and task definitions" {
  aws ecs list-clusters --region $AwsRegion
  "--- RUNNING tasks (should be empty, each costs money while running)"
  aws ecs list-tasks --cluster $Cluster --desired-status RUNNING --region $AwsRegion
  "--- services"
  aws ecs list-services --cluster $Cluster --region $AwsRegion
  "--- active task definitions"
  aws ecs list-task-definitions --family-prefix farf --status ACTIVE --region $AwsRegion
}

Section "A4 VPC, security groups, ENIs, and cost-relevant network objects" {
  "--- security groups in the VPC (egress rules shown)"
  aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$Vpc" --region $AwsRegion --query "SecurityGroups[].{Name:GroupName,Id:GroupId,Egress:IpPermissionsEgress}" --output json
  "--- network interfaces (which SG is attached to what; public IPs)"
  aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=$Vpc" --region $AwsRegion --query "NetworkInterfaces[].{Eni:NetworkInterfaceId,Desc:Description,Status:Status,Groups:Groups[].GroupId,PublicIp:Association.PublicIp}" --output json
  "--- Elastic IPs (billed when allocated)"
  aws ec2 describe-addresses --region $AwsRegion --query "Addresses[].{Ip:PublicIp,Assoc:AssociationId}" --output json
  "--- NAT gateways (billed hourly)"
  aws ec2 describe-nat-gateways --region $AwsRegion --filter "Name=state,Values=available,pending" --query "NatGateways[].NatGatewayId" --output json
  "--- VPC endpoints (interface endpoints are billed hourly)"
  aws ec2 describe-vpc-endpoints --region $AwsRegion --query "VpcEndpoints[].{Id:VpcEndpointId,Svc:ServiceName,Type:VpcEndpointType}" --output json
  "--- EC2 instances that are running"
  aws ec2 describe-instances --region $AwsRegion --filters "Name=instance-state-name,Values=running" --query "Reservations[].Instances[].InstanceId" --output json
}

Section "A5 CloudWatch log groups" {
  aws logs describe-log-groups --region $AwsRegion --query "logGroups[].{Name:logGroupName,RetentionDays:retentionInDays,StoredBytes:storedBytes}" --output table
}

Section "A6 KMS keys and Lambda" {
  aws kms list-aliases --region $AwsRegion --query "Aliases[?starts_with(AliasName, 'alias/farf')]" --output json
  "--- Lambda functions"
  aws lambda list-functions --region $AwsRegion --query "Functions[].{Name:FunctionName,Runtime:Runtime,Modified:LastModified}" --output table
}

Section "A7 IAM objects created for the pilot, and access-key age" {
  aws iam list-roles --query "Roles[?starts_with(RoleName, 'farf')].RoleName" --output json
  aws iam list-policies --scope Local --query "Policies[].PolicyName" --output json
  "--- users and their access keys (status/age; rotate or delete any key that appeared in a shared file)"
  aws iam list-users --query "Users[].UserName" --output text
  foreach ($u in (aws iam list-users --query "Users[].UserName" --output text).Split()) {
    if ($u) { "user: $u"; aws iam list-access-keys --user-name $u --query "AccessKeyMetadata[].{Id:AccessKeyId,Status:Status,Created:CreateDate}" --output table }
  }
}

Write-Host ""
Write-Host "Done. Files are in: $out" -ForegroundColor Green
Write-Host "Share those .txt files (after checking for secrets) if you want me to interpret them." -ForegroundColor Green
