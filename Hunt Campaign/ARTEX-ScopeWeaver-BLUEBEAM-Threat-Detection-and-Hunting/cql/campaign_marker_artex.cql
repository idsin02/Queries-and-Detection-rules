// Purpose : ARTEX literal markers and intent-ID file naming.
// Data : ProcessRollup2, *Written file events, DnsRequest.
// Caveat : Falcon only records writes for certain file classes; .sql/.out/.csv writes may be absent.
// Tuning : Exclude detection-engineering / intel-notes hosts.
(#event_simpleName=ProcessRollup2 OR #event_simpleName=/Written$/ OR #event_simpleName=DnsRequest)
| Artifact:=concat([CommandLine, TargetFileName, DomainName])
| case {
Artifact=/ntfy\.sh\/artex-|artex[_-]probe|HELLO_FROM_|HELLO1298_TEST_041923|SQLPWN WROTE|Artex-Four-/i
| Priority:="Critical";
Artifact=/(prod_shell\.ps1|tmpq794ba1\.ps1|ebx_chunk1\.csv|q_tabs\.sql|(deploy|recon2?)_probe_[0-9a-f]{8,10}\.zip)/i
| Priority:="Critical";
Artifact=/(^|[\\\/\s])i\d{3,5}_([0-9a-f]{6,10}|pth|probe)\.(ps1|sql|out|jsp|jspx|txt)\b/i
| Priority:="High";
}
| groupBy([ComputerName, #event_simpleName, Priority],
function=[count(as=Count), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([Artifact], limit=25)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
