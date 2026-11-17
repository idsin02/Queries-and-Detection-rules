// Purpose : IP + hash sweep. VPN-tagged ranges and low-tier IPs are hunt only.
// Data : NetworkConnectIP4, NetworkReceiveAcceptIP4, ProcessRollup2, *Written.
// Note : SHA1-only indicators (z.aspx, jb.php, cangma.php, cmds.php) are rarely populated by Falcon;
// use yara/a on disk for those.
(#event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkReceiveAcceptIP4 OR #event_simpleName=ProcessRollup2 OR #event_simpleName=/Written$/)
| case {
in(field=RemoteAddressIP4, values=["103.140.154.152","116.206.125.116","139.84.132.91","139.84.134.148","154.197.141.246","188.253.121.53","188.253.121.93"])
| Tier:="StagingC2-High" | Indicator:=RemoteAddressIP4;
in(field=RemoteAddressIP4, values=["123.58.198.236","124.222.109.22","124.223.193.202","134.122.200.96","150.158.102.111","167.160.190.182","167.17.47.213","45.127.35.186","45.152.64.65","45.87.53.6","64.94.85.173","91.224.92.16","91.92.242.3"])
| Tier:="Artex-Medium" | Indicator:=RemoteAddressIP4;
RemoteAddressIP4=/^(141\.98\.253\.\d{1,3}|141\.98\.255\.243|31\.169\.53\.\d{1,3}|194\.127\.199\.96)$/
| Tier:="SharedVPN-HuntOnly" | Indicator:=RemoteAddressIP4;
in(field=RemoteAddressIP4, values=["101.126.23.9","103.30.78.179","103.42.183.18","107.150.34.18","117.50.196.50","117.72.170.153","122.51.128.105","122.51.155.167","122.51.183.32","122.51.248.170","122.51.44.181","122.51.46.17","124.221.80.161","144.172.85.164","149.104.24.79","149.104.24.91","149.104.29.151","156.238.224.161","162.251.92.25","162.251.94.166","173.249.205.139","192.144.217.101","223.113.41.56","38.147.170.214","47.105.69.187","47.99.67.157","47.99.67.249","49.234.189.73","61.155.145.182","91.229.78.35"])
| Tier:="Artex-HuntOnly" | Indicator:=RemoteAddressIP4;
in(field=SHA256HashString, values=["001eb437c20805fb94e8e7014c019318f0f3186bc0cd2ea3508245aafbf0c248","052b2461d06b3d3b37f52c3ef308a7c204e01c0b293cce08f6694152f859aa9e","54eee4274db92b85e7148d9581224b47f4badd283103661ae173034ae4eb07fd","57a19c552b14da85f478ab0bc09c9613aaa2425395407b6879c111806c801e9f","68218101d6c83cd34c23c9afc7ca2c7fa13a1bc8138481232a9410c5da4a9386","7bf0cb8dfd5073d3b02668991203f6fdc3ef55c8c730e5edd3274be3d32967bd","89ba544dda435fe58382efe215779e9449e101f7f86a7a978d4820c7e39d5818","cc6e2711d9adbcf54db0edb2e35bd58abe3b1cd7b0aeede4e918736b2c71be80","dd47129298e3f478db2f7a8e7a7b54b448cb3095a91c318554f3eacc42496134","e653a824be01baa02de28fed768d25698ecdaed250ca57790c91fe2f3436c5e1","f800cd76f1989cefb186bf5adabd77446e18afd91ce106c9cea69b70c0ceff13","faf8724f348fc4c4f173a0c2354864b6f3989119ebeed815ca3430217e5707f5"])
| Tier:="Hash-High" | Indicator:=SHA256HashString;
in(field=MD5HashString, values=["36cb9b3e7abdc66cf78dabdfbc33c105","16998cbd9b84c2c01283c39b1ec46bb7","3f159d0ac03bc46eaab64019b80c8ada","2adb9db2fd4dd69db2371cfe2cfa88c5","d1df6ac32001f9c5bb339cf209d18732","1f8919d7e2fbff3ec678934d6d633c37","7f7eba684a6b7f50e92514e864407375","1662967f2224d6edda52f162ccdee0f5","06508287e5503294d83db16efb5579ec","472c221c7a03e3d927da66ae0cb35274","bcc90aaf24c6432b13a33510f617807d","5ce0d80f4e910f2c6c3d6d502bd2ecec","7eb0f83edf6e13f72fe4b45a70b37866","d48347b55c5ca9c24b6ceba9f2822f6c","4168aaafde0756e8e0a9b63abb7386bd"])
| Tier:="Hash-High" | Indicator:=MD5HashString;
}
| groupBy([ComputerName, Indicator, Tier, #event_simpleName],
function=[count(as=Hits), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
collect([RemotePort, ImageFileName, TargetFileName], limit=10)])
| formatTime("%Y-%m-%d %H:%M:%S", field=FirstSeen, as=FirstSeen)
| formatTime("%Y-%m-%d %H:%M:%S", field=LastSeen, as=LastSeen)
| sort(Tier)
