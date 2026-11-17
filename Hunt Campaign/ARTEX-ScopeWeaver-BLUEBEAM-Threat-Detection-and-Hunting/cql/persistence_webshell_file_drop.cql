// Purpose : Script files written by DB engines (log poisoning), reported webshell names,
// and scripts written into media/upload paths.
// Caveat : Falcon file-write telemetry is class-based (e.g. NewScriptWritten, WebScriptFileWritten);
// .jsp/.aspx coverage varies by sensor/policy. Treat absence as "not visible", not "clean".
// Tuning : Exclude CMS update processes for the path-based branch.
#event_simpleName=/Written$/
| TargetFileName=/\.(jspx?|aspx|ashx|asmx|php|phtml)$/i
| case {
ContextImageFileName=/(mysqld|mariadbd|sqlservr)(\.exe)?$/i
| Signal:="DB engine wrote script (log poisoning)" | Priority:="High";
TargetFileName=/0b[12]?\.(php|aspx|jb\.php|cangma\.(php|aspx)|cmds\.php|log\.php|zhaosaa?\.aspx|z\.aspx|rgmsr\.aspx|cmdss\.aspx|gallery_26[12]_Pic\.aspx|f1169f\.jsp|h1278\.jsp|q601084\.jsp|k1278y2\.jsp|i1279_808615\.jsp|noticed814\.jspx)$/i
| Signal:="Reported webshell name" | Priority:="High";
TargetFileName=/(media.gallery|images.gallery|wp-content.ngg|wp-content.uploads|wp-admin.images|SIMCardFiles|\/app\/weaver\/ecology)/i
| Signal:="Script in media/upload path" | Priority:="Medium";
}
| groupBy([ComputerName, ContextImageFileName, Signal, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([TargetFileName], limit=50)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
