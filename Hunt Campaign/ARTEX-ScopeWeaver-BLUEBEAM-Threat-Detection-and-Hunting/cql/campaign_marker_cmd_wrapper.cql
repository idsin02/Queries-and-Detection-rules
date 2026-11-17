// Purpose : BLUEBEAM hex-boundary command wrapper (Windows + Linux).
// Fidelity: High.
#event_simpleName=ProcessRollup2
| case {
CommandLine=/cd\s+\/d\s+"?[^&]+"?\s*&.+&\s*echo\s+[0-9a-f]{4,16}\s*&\s*cd\s*&\s*echo\s+[0-9a-f]{4,16}/i | Platform:="Windows";
CommandLine=/cd\s+"[^"]+";.+;\s*echo\s+[0-9a-f]{4,16};\s*pwd;\s*echo\s+[0-9a-f]{4,16}/i | Platform:="Linux";
}
| regex("(?:\"\\s*&|\";)\\s*(?<InnerCmd>.+?)\\s*[;&]\\s*echo\\s+[0-9a-f]{4,16}", field=CommandLine, strict=false)
| case {
CommandLine=/\/dev\/tcp\/|copy_fail|urlcache|potato|whoami|net user/i | Priority:="Critical";
* | Priority:="High";
}
| groupBy([ComputerName, UserName, ParentBaseFileName, Platform, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([InnerCmd], limit=50)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
