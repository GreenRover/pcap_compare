package ch.mtrail.pcap_compare;

import ch.mtrail.pcap_compare.processors.PcapPackageFinder;

public class pcapFindPackage {
	public static void main(String[] args) throws Exception {
		if (args.length < 3) {
			System.err.println("Usage: pcapFindPackage source.pcap dest.pcap ipIdToFind");
			System.exit(1);
		}
		PcapPackageFinder comp = new PcapPackageFinder(
				args[0],
				args[1]
		);
		comp.findByIpId(Integer.parseInt(args[2]));
	}
}
