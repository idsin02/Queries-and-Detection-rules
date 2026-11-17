// Purpose : Potato artifacts, CVE-2026-31431 PoC piped to python, web/DB parent -> SYSTEM shell.
// Limitation: ProcessRollup2 lacks the parent's user, so the SYSTEM branch keys on parent image + child
// SID S-1-5-18 (weaker than KQL). Built from described technique, not a sample.
// Tuning : Exclude red-team hosts; allow-list known installer URLs for pipe-to-python.
#event_simpleName=ProcessRollup2
| case {
CommandLine=/\s-t\s+\*\s+-p\s+\S+.*\s-l\s+\d+/i
| Signal:="JayPotato-style cmdline" | Priority:="High";
CommandLine=/McpManagementPotato|msp\.out|GodPotato|PrintSpoofer/i
| Signal:="Potato tool name" | Priority:="High";
ImageFileName=/\\ProgramData\\(by|start|McpManagementPotato)\.exe$/i
| Signal:="Potato staging path" | Priority:="High";
CommandLine=/copy_fail/i
| Signal:="CVE-2026-31431 PoC" | Priority:="Critical";
CommandLine=/(curl|wget)[^|]+\|\s*python3?\b/i ParentBaseFileName=/^(sh|bash|lsphp|php-fpm.*)$/i
| Signal:="Remote script piped to python" | Priority:="Medium";
UserSid="S-1-5-18" ParentBaseFileName=/^(w3wp\.exe|sqlservr\.exe|msp\.out|start\.exe|by\.exe)$/i ImageFileName=/\\(cmd|powershell|whoami|net1?)\.exe$/i
| Signal:="Web/DB parent -> SYSTEM shell" | Priority:="Medium";
}
| groupBy([ComputerName, UserName, ParentBaseFileName, ImageFileName, Signal, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([CommandLine], limit=25)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
