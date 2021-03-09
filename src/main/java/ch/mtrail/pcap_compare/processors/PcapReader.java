package ch.mtrail.pcap_compare.processors;

import java.io.EOFException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PcapReader {
	public static List<IpPacketIdent> readPcapFile(String pcapFile) throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {
		return readPcapFile(pcapFile, null);
	}

	public static List<IpPacketIdent> readPcapFile(String pcapFile, Predicate<IpV4Packet.IpV4Header> filter) throws PcapNativeException, NotOpenException, NoSuchAlgorithmException {
		PcapHandle handle = Pcaps.openOffline(pcapFile);

		MessageDigest md = MessageDigest.getInstance("SHA-1");

		List<IpPacketIdent> packages = new ArrayList<>();
		while (true) {
			try {
				Packet packet = handle.getNextPacketEx();
				IpV4Packet ipPacket = packet.get(IpV4Packet.class);

				if (filter != null && !filter.test(ipPacket.getHeader())) {
					continue;
				}

				Integer id = ipPacket.getHeader().getIdentificationAsInt();
				byte[] hash;
				md.reset();
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

				packages.add(new IpPacketIdent(id, byteArray2Hex(hash), ts));

			} catch (TimeoutException e) {
				// continue;
			} catch (EOFException e) {
				break;
			}
		}

		return packages;
	}

	public static String byteArray2Hex(final byte[] hash) {
		Formatter formatter = new Formatter();
		for (byte b : hash) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}
}
