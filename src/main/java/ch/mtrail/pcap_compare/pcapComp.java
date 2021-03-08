package ch.mtrail.pcap_compare;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class pcapComp {
	public static void main(String[] args) throws Exception {
		if (args.length < 5) {
			System.err.println("Usage: pcapComp source.pcap dest.pcap source.ip.v.4 dest.ip.v.4");
			System.exit(1);
		}
		PcapComparator comp = new PcapComparator(
				args[1],
				args[3],
				args[2],
				args[4]
		);
		comp.diff();
	}
}
