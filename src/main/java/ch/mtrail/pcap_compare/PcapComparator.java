package ch.mtrail.pcap_compare;

import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

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

		Locale locale = new Locale("de", "CH");
		numberFormat = NumberFormat.getInstance(locale);
	}

	public void diff() throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {

		PcapIpPacketDiffer differ = new PcapIpPacketDiffer(
				readPcapFile(pcapFileA),
				readPcapFile(pcapFileB)
		);
		differ.compareA2B();
		differ.compareB2A();

		System.out.println("Packages: "
				+ "A=" +  numberFormat.format(differ.getPackagesA().values().stream().mapToInt(Collection::size).sum()) +
				", B=" +  numberFormat.format(differ.getPackagesB().values().stream().mapToInt(Collection::size).sum()));
		System.out.println("Counter: ");
		differ.getCounter().forEach((key, value) ->
				System.out.println("\t" + key + " = " + numberFormat.format(value)));
	}

	private Map<String, List<IpPacketIdent>> readPcapFile(String pcapFile) throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {
		PcapHandle handle = Pcaps.openOffline(pcapFile);

		MessageDigest md = MessageDigest.getInstance("SHA-1");

		Map<String, List<IpPacketIdent>> packages = new HashMap<>();
		while (true) {
			try {
				Packet packet = handle.getNextPacketEx();
				IpV4Packet ipPacket = packet.get(IpV4Packet.class);

				if (!Objects.equals(ipPacket.getHeader().getSrcAddr(), sourceIp) ||
					!Objects.equals(ipPacket.getHeader().getDstAddr(), destIp)) {
					continue;
				}

				Integer id = ipPacket.getHeader().getIdentificationAsInt();
				byte[] hash;
				if (ipPacket.getPayload() instanceof UdpPacket) {
					UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
					hash = md.digest(udpPacket.getPayload().getRawData());
				} else if (ipPacket.getPayload() instanceof TcpPacket) {
					TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
					hash = md.digest(tcpPacket.getPayload().getRawData());
				} else {
					continue;
				}

				long ts = handle.getTimestamp().getTime();

				packages
						.computeIfAbsent(id + "_" + byteArray2Hex(hash), _id -> new ArrayList<>())
						.add(new IpPacketIdent(id, hash, ts));

			} catch (TimeoutException e) {
				// continue;
			} catch (EOFException e) {
				break;
			}
		}

		return packages;
	}

	private static String byteArray2Hex(final byte[] hash) {
		Formatter formatter = new Formatter();
		for (byte b : hash) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}

	private static class PcapIpPacketDiffer {
		private final Map<String, List<IpPacketIdent>> packagesA;
		private final Map<String, List<IpPacketIdent>> packagesB;
		private final Map<byte[], IpPacketIdent> packagesAByHash;
		private final Map<byte[], IpPacketIdent> packagesBByHash;

		private final Map<String, AtomicInteger> counter = new HashMap<>();

		PcapIpPacketDiffer(Map<String, List<IpPacketIdent>> packagesA, Map<String, List<IpPacketIdent>> packagesB) {
			this.packagesA = packagesA;
			this.packagesB = packagesB;

			packagesAByHash = packagesA.values().stream()
					.flatMap(List::stream)
					.collect(Collectors.toMap(
							IpPacketIdent::	getHash,
							Function.identity()
					));

			packagesBByHash = packagesB.values().stream()
					.flatMap(List::stream)
					.collect(Collectors.toMap(
							IpPacketIdent::	getHash,
							Function.identity()
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

				// ####### Really rare edge case #######

				if (packagesA.getValue().size() >= 1 && packagesA.getValue().size() == packagesB.size()) {
					counter.computeIfAbsent("ok", id -> new AtomicInteger()).addAndGet(packagesB.size());
					continue;
				}

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
				IpPacketIdent packageB = packagesBByHash.get(packageA.getHash());
				if (packageB != null) {
					System.out.println("ID changed A: " + packagesA.getKey() + " => " + packageB.getId());
					counter.computeIfAbsent("id_changed_a", id -> new AtomicInteger()).incrementAndGet();
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
						IpPacketIdent packageA = packagesAByHash.get(packageB.getHash());

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
