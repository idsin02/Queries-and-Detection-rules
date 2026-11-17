// Purpose : Closest CQL alternative to kql/00 (MDVM CVE mapping) for CVE-2026-31431 (Linux kernel).
// Why no honest equivalent: Falcon Spotlight CVE data is not in the LogScale event stream by default.
// This is a kernel-version INVENTORY only. It can't separate patched from vulnerable (distro backports),
// and no affected/fixed versions were published. CVE-2022-31814 has no product detail, so no query.
// Use : Feed the output into Spotlight or a distro advisory review.
#event_simpleName=OsVersionInfo event_platform=Lin
| groupBy([aid, ComputerName], function=selectLast([OSVersionString, @timestamp]))
| groupBy([OSVersionString], function=[count(aid, distinct=true, as=Hosts), collect([ComputerName], limit=200)])
| sort(Hosts, order=desc)
