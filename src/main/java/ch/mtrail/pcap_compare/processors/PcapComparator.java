package ch.mtrail.pcap_compare.processors;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.IpV4Packet;

public class PcapComparator {

	private final String pcapFileA;
	private final InetAddress sourceIp;
	private final String pcapFileB;
	private final InetAddress destIp;

	private final NumberFormat numberFormat;

	public PcapComparator(String pcapFileA, String sourceIp, String pcapFileB, String destIp) throws UnknownHostException {
		this.pcapFileA = pcapFileA;
		this.sourceIp = InetAddress.getByName(sourceIp);
		this.pcapFileB = pcapFileB;
		this.destIp = InetAddress.getByName(destIp);

		numberFormat = Utils.getNumberFormatter();
	}

	public void diff() throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {

		Predicate<IpV4Packet.IpV4Header> ipFilter = ipHeader ->
				Objects.equals(ipHeader.getSrcAddr(), sourceIp) &&
				Objects.equals(ipHeader.getDstAddr(), destIp);

		PcapIpPacketDiffer differ = new PcapIpPacketDiffer(
				PcapReader.readPcapFile(pcapFileA, ipFilter),
				PcapReader.readPcapFile(pcapFileB, ipFilter)
		);
		differ.compareA2B();
		differ.compareB2A();
		differ.detectDoubleTransmission();

		int packagesACount = differ.getPackagesA().values().stream().mapToInt(Collection::size).sum();
		int packagesBCount = differ.getPackagesB().values().stream().mapToInt(Collection::size).sum();

		System.out.println("Packages: "
				+ "A=" +  numberFormat.format(packagesACount) +
				", B=" +  numberFormat.format(packagesBCount));
		System.out.println("Counter: ");
		differ.getCounter().forEach((key, value) -> System.out.printf(
				"\t%s = %s | %.3f%%%n",
				key,
				numberFormat.format(value),
				(double)value.get() / (double)packagesACount * 100d
			));
	}

	private static class PcapIpPacketDiffer {
		private final Map<String, List<IpPacketIdent>> packagesA;
		private final Map<String, List<IpPacketIdent>> packagesB;
		private final Map<String, List<IpPacketIdent>> packagesAByHash;
		private final Map<String, List<IpPacketIdent>> packagesBByHash;

		private final Map<String, AtomicInteger> counter = new HashMap<>();

		PcapIpPacketDiffer(List<IpPacketIdent> packagesA, List<IpPacketIdent> packagesB) {
			this.packagesA = packagesA.stream()
					.collect(Collectors.groupingBy(
							p -> p.getId() + "_" + p.getPayloadHash(),
							Collectors.toList()
					));
			this.packagesB = packagesB.stream()
					.collect(Collectors.groupingBy(
							p -> p.getId() + "_" + p.getPayloadHash(),
							Collectors.toList()
					));

			packagesAByHash = packagesA.stream()
					.collect(Collectors.groupingBy(
							IpPacketIdent::getPayloadHash,
							Collectors.toList()
					));

			packagesBByHash = packagesB.stream()
					.collect(Collectors.groupingBy(
							IpPacketIdent::getPayloadHash,
							Collectors.toList()
					));
		}

		void compareA2B() {
			for (Map.Entry<String, List<IpPacketIdent>> packagesA : packagesA.entrySet()) {
				final List<IpPacketIdent> packagesB = this.packagesB.get(packagesA.getKey());

				if (packagesA.getValue().size() > 1) {
					System.out.println("Duplicated submitted package: " + packagesA.getKey());

					counter.computeIfAbsent("submitted_duplicated", id -> new AtomicInteger()).addAndGet(packagesA.getValue().size() - 1);
				}

				if (packagesB == null) {
					handleMissedPackage(packagesA);
					continue;
				}

				if (packagesA.getValue().size() >= 1
						&&  packagesA.getValue().size() == packagesB.size()
						&& Objects.equals(
								packagesA.getValue().get(0).getPayloadHash(),
								packagesB.get(0).getPayloadHash())
					) {

					counter.computeIfAbsent("ok", id -> new AtomicInteger()).addAndGet(packagesB.size());
					continue;
				}

				// ####### Really rare edge case #######

				if (packagesA.getValue().size() > packagesB.size()) {
					// Same package was multiple times but no all was transmitted.
					System.out.println("Partly missing: " + packagesA.getKey());

					counter.computeIfAbsent("ok", id -> new AtomicInteger()).addAndGet(packagesB.size());
					counter.computeIfAbsent("missing", id -> new AtomicInteger()).addAndGet(packagesA.getValue().size() - packagesB.size());
				} else {
					System.out.println("Duplicated received package: " + packagesA.getKey());

					counter.computeIfAbsent("ok", id -> new AtomicInteger()).addAndGet(packagesB.size());
					counter.computeIfAbsent("received_duplicated", id -> new AtomicInteger()).addAndGet(packagesB.size() - packagesA.getValue().size() );
				}
			}
		}

		private void handleMissedPackage(Map.Entry<String, List<IpPacketIdent>> packagesA) {
			// There is package in receiving pcap matching this submitted package.
			// Try to detect package with same content (hash based) but different ip id.
			for (IpPacketIdent packageA : packagesA.getValue()) {
				List<IpPacketIdent> packagesB = packagesBByHash.get(packageA.getPayloadHash());
				if (packagesB != null) {
					packagesB.forEach(packageB -> System.out.println("ID changed A: " + packagesA.getKey() + " => " + packageB.getId()));

					counter.computeIfAbsent("id_changed", id -> new AtomicInteger()).addAndGet(packagesB.size());
				} else {
					System.out.println("Missing: " + packagesA.getKey());
					counter.computeIfAbsent("missing", id -> new AtomicInteger()).incrementAndGet();
				}
			}
		}

		void compareB2A() {
			for (Map.Entry<String, List<IpPacketIdent>> packagesB : packagesB.entrySet()) {
				List<IpPacketIdent> packagesA = this.packagesA.get(packagesB.getKey());
				if (packagesA == null) {
					for (IpPacketIdent packageB : packagesB.getValue()) {
						List<IpPacketIdent> packageA = packagesAByHash.get(packageB.getPayloadHash());

						if (packageA == null) {
							// Find really no matching submitted package.
							System.out.println("to_much: " + packagesB.getKey());
							counter.computeIfAbsent("to_much", id -> new AtomicInteger()).incrementAndGet();
						} else {
							// Found a submitted package with same content but different msgs id.
							System.out.println("id_changed: " + packagesB.getKey());
							counter.computeIfAbsent("id_changed", id -> new AtomicInteger()).incrementAndGet();
						}
					}
				}
			}
		}

		void detectDoubleTransmission() {
			packagesAByHash.forEach((hash, packages) -> {
				if (packages.size() > 1) {
					System.out.println("submitted " + packages.size() + " times: " + hash);
					counter.computeIfAbsent("multi_submitted", id -> new AtomicInteger()).addAndGet(packages.size());
				}
			});
			packagesBByHash.forEach((hash, packages) -> {
				if (packages.size() > 1) {
					System.out.println("received " + packages.size() + " times: " + hash);
					counter.computeIfAbsent("multi_received", id -> new AtomicInteger()).addAndGet(packages.size());
				}
			});
		}

		Map<String, List<IpPacketIdent>> getPackagesA() {
			return packagesA;
		}

		Map<String, List<IpPacketIdent>> getPackagesB() {
			return packagesB;
		}

		Map<String, AtomicInteger> getCounter() {
			return counter;
		}
	}
}
