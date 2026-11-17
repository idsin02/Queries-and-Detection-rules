// Purpose : Shells/LOLBins with web/DB parents (sqlservr, w3wp, lsphp, java, mysqld).
// Data : ProcessRollup2 (Windows + Linux). Uses ParentBaseFileName.
// Fidelity: High for sqlservr/w3wp/Critical markers; Medium otherwise.
// Tuning : Baseline java/tomcat children per host; exclude known maintenance scripts.
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^(w3wp\.exe|sqlservr\.exe|lsphp|php-fpm.*|php-cgi|httpd|apache2|nginx|java(\.exe)?|tomcat.*|mysqld(\.exe)?)$/i
| ImageFileName=/cmd\.exe|powershell\.exe|pwsh(\.exe?|curl(\.exe)?|certutil\.exe|whoami(\.exe)?|nltest\.exe|dsquery\.exe|dsget\.exe|net1?\.exe|systeminfo\.exe|sh|bash|dash|python3?|wget|id)$/i
| case {
CommandLine=/ntfy\.sh|webhook\.site|\/dev\/tcp\/|urlcache|copy_fail/i | Priority:="Critical";
ParentBaseFileName=/^(sqlservr\.exe|w3wp\.exe|mysqld(\.exe)?)$/i | Priority:="High";
* | Priority:="Medium";
}
| groupBy([ComputerName, UserName, ParentBaseFileName, ImageFileName, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([CommandLine], limit=25)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
| sort(Priority)
