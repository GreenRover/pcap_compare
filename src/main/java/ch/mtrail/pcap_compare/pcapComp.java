package ch.mtrail.pcap_compare;

import ch.mtrail.pcap_compare.processors.PcapComparator;

public class pcapComp {
	public static void main(String[] args) throws Exception {
		if (args.length < 4) {
			System.err.println("Usage: pcapComp source.pcap dest.pcap source.ip.v.4 dest.ip.v.4");
			System.exit(1);
		}
		PcapComparator comp = new PcapComparator(
				args[0],
				args[2],
				args[1],
				args[3]
		);
		comp.diff();
	}
}
