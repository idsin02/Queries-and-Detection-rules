// Purpose : Scripted egress to webhook.site / ntfy.sh.
// Fidelity: Hunting by default; Critical/High with an artex topic or server-process parent.
// Note : DnsRequest has no CommandLine. On DNS-only hits, pivot ContextProcessId -> TargetProcessId.
// Tuning : Exclude dev workstations and CI runners.
#event_simpleName=ProcessRollup2
| CommandLine=/webhook\.site|ntfy\.sh/i
| ImageFileName=/curl(\.exe?|powershell\.exe|pwsh(\.exe)?|python3?(\.exe)?|wget)$/i
| case {
CommandLine=/artex/i | Priority:="Critical";
ParentBaseFileName=/^(sqlservr\.exe|w3wp\.exe|java(\.exe)?|lsphp|cmd\.exe)$/i | Priority:="High";
CommandLine=/\s-d\s|-X\s+POST|--data|\s-F\s|Invoke-RestMethod/i | Priority:="Medium";
* | Priority:="Hunting";
}
| groupBy([ComputerName, UserName, ParentBaseFileName, ImageFileName, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([CommandLine], limit=20)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
