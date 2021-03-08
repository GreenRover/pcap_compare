# Compare pcaps

You can run tcpdump on 2 computer. A sending and a receiving one.
This tool helps you to diff the dump/pcap file to find what is lost while transport.

## Diff pcap files

```bash
java jar X.jar ch.mtrail.pcap_compare.pcapComp -- C:\tmp\rma-a.tcmpdump.filtered.pcap C:\tmp\rma-b.tcmpdump.filtered.pcap 10.172.160.251 239.192.9.7
```

This prints you:
```
Missing: 63978_729ef288c9dad0e7746ae9d76748400c38504b72
Missing: 64489_dc6e2ca1ea9895d6d5c0ff1de0fe8748e54ef8db
Missing: 32496_0e499b43f6d4f2d239d48983dfc094ac7a47fb5b
Missing: 64334_590fe620b17ebcd663532018bb29ebe4994be968
...
to_much: 30191_96b70d96bc7f5f71adc25cf3a6cad092a2c7e53a
to_much: 42571_e6e034420aec7cb0e545f481ac65dd448433c9a0
PackagesIdents: A=142’166, B=142’561
Packages: A=142’166, B=142’561
Counter: 
	missing = 278
	to_much = 673
	ok = 141’888
```

### Possible states:

- ok: Package was successfully transmitted
- missing: Package get lost while transmission
- received_duplicated: Package was send once but received >=2 times
- id_changed: The package was received, but the ip id was change will transmission.
- to_much: Unable to find package in tcpdump on sender side


## Find package by ipId

Get information by ip id

```bash
java -jar X.jar "C:\tmp\rma-a.tcmpdump.filtered.pcap" "C:\tmp\rma-b.tcmpdump.filtered.pcap" 30191
```

This prints out:
```
IPid in pcapFileA:
	45033 payload sha1 hash:dea92e1021683004a7f57789a382058dacc4a785 ts:1615107445394
	45033 payload sha1 hash:f5f3182318dc8cad855eed1c06c14bb0e691da7a ts:1615107452350
	45033 payload sha1 hash:1481c7502ed7d65614f5ea5dda83043418bab7fd ts:1615107455344
IPid in pcapFileB:
	45033 payload sha1 hash:5cdc5118e573802b6ac0e7fe843db63c5886b7d5 ts:1615107443239
	45033 payload sha1 hash:dea92e1021683004a7f57789a382058dacc4a785 ts:1615107445393
	45033 payload sha1 hash:f5f3182318dc8cad855eed1c06c14bb0e691da7a ts:1615107452349
	45033 payload sha1 hash:1481c7502ed7d65614f5ea5dda83043418bab7fd ts:1615107455343
Hash reverse pcapFileA:
	45033 payload sha1 hash:dea92e1021683004a7f57789a382058dacc4a785 ts:1615107445394
	45033 payload sha1 hash:f5f3182318dc8cad855eed1c06c14bb0e691da7a ts:1615107452350
	45033 payload sha1 hash:1481c7502ed7d65614f5ea5dda83043418bab7fd ts:1615107455344
Hash reverse pcapFileB:
	45033 payload sha1 hash:5cdc5118e573802b6ac0e7fe843db63c5886b7d5 ts:1615107443239
	45033 payload sha1 hash:dea92e1021683004a7f57789a382058dacc4a785 ts:1615107445393
	45033 payload sha1 hash:f5f3182318dc8cad855eed1c06c14bb0e691da7a ts:1615107452349
	45033 payload sha1 hash:1481c7502ed7d65614f5ea5dda83043418bab7fd ts:1615107455343
```