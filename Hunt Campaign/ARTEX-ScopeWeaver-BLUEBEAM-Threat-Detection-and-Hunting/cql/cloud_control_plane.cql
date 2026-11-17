// Purpose : for AWS CloudTrail / Azure logs ingested into NG-SIEM.
// Why no exact equivalent: control-plane logs are not Falcon sensor data; field names depend on the
// connector/parser, so this matches @rawstring. Rewrite to parsed fields once validated.
// Limitations: No per-principal baselining as in KQL; treat non-literal hits as Hunting.
#repo!=base_sensor
| case {
@rawstring=/ami-0661cce2d6259c605|ami-0b2c9d1f3edcfd709/ | Signal:="Reported AMI" | Priority:="High";
@rawstring=/CreateDeployment/ @rawstring=/(deploy|recon2?)_probe_[0-9a-f]{8,10}\.zip/i | Signal:="CodeDeploy probe archive" | Priority:="High";
@rawstring=/DROP DATABASE SCOPED CREDENTIAL/i | Signal:="SQL scoped credential dropped" | Priority:="High";
@rawstring=/RunInstances/ @rawstring=/DryRunOperation/ | Signal:="EC2 DryRun" | Priority:="Hunting";
@rawstring=/DescribeRepositories|DescribeVpcPeeringConnections/ @rawstring=/Boto3/i | Signal:="AWS enum via Boto3" | Priority:="Hunting";
@rawstring=/STORAGEACCOUNTS\/LISTKEYS\/ACTION/i | Signal:="Azure storage ListKeys" | Priority:="Hunting";
@rawstring=/DatasourcesAsAdmin/i | Signal:="Power BI admin datasource enum" | Priority:="Hunting";
}
| groupBy([#repo, Signal, Priority],
function=[count(as=Hits), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([@rawstring], limit=10)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
