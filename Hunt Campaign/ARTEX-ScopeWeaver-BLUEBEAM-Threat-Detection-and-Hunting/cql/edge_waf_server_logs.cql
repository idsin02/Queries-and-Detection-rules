// Purpose : third-party web/WAF/proxy data in NG-SIEM.
// Why no exact equivalent: Falcon EDR has no HTTP request telemetry. This needs IIS/WAF/proxy logs
// ingested into NG-SIEM. Parser field names vary, so it matches @rawstring (slower, parser-agnostic).
// Limitations: No per-field normalisation; Cookie/Accept-Language only if the source logs them.
// Tuning : The Accept-Language branch alone is weak (real zh-CN browsers). Pair with webshell paths or IPs.
#repo!=base_sensor
| case {
@rawstring=/[?&]t=[^&\s]+&m=(sql|ping|res|https)(&|\s|$)/i | Signal:="JSP webshell t/m params" | Priority:="Critical";
@rawstring=/[?&]k=[^&\s]+&c=/i | Signal:="Probe webshell k/c params" | Priority:="Critical";
@rawstring=/usr=[^&]*&pwd=[^&]*&sch=NTLM/i | Signal:="Webshell NTLM relay" | Priority:="Critical";
@rawstring=/\bact=[^;]+;\s*f=/i | Signal:="Cookie-command webshell" | Priority:="Critical";
@rawstring=/\b(103\.140\.154\.152|116\.206\.125\.116|139\.84\.132\.91|139\.84\.134\.148|154\.197\.141\.246|188\.253\.121\.53|188\.253\.121\.93)\b/
| Signal:="Staging/C2 IP" | Priority:="Critical";
@rawstring=/artex|nuclei\.svg|%00\.(pdf|jpg|png)/i | Signal:="ARTEX probe marker" | Priority:="High";
@rawstring=/\/api\/cube\/form\/checkVsql|weaver\.file\.FileDownload/ | Signal:="Weaver endpoint" | Priority:="High";
@rawstring=/\.scm\.azurewebsites\.net/i @rawstring=/\/api\/(command|vfs\/site\/wwwroot\/)/i
| Signal:="Kudu API exec/VFS" | Priority:="Medium";
@rawstring=/zh-CN,zh;q=0\.8,zh-TW;q=0\.7,zh-HK;q=0\.5,en-US;q=0\.3,en;q=0\.2/ | Signal:="Operator Accept-Language" | Priority:="Medium";
@rawstring=/\/\.git\/HEAD/ | Signal:="Git exposure probe" | Priority:="Medium";
}
| groupBy([#repo, #type, Signal, Priority],
function=[count(as=Hits), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([@rawstring], limit=10)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
