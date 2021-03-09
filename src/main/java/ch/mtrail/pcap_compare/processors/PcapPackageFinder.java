package ch.mtrail.pcap_compare.processors;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class PcapPackageFinder {

	private final List<IpPacketIdent> packagesA;
	private final List<IpPacketIdent> packagesB;

	public PcapPackageFinder(String pcapFileA, String pcapFileB) throws PcapNativeException, NoSuchAlgorithmException, NotOpenException {
		this.packagesA = PcapReader.readPcapFile(pcapFileA);
		this.packagesB = PcapReader.readPcapFile(pcapFileB);
	}

	public void findByIpId(Integer ipId) {
		Set<String> hashes = new HashSet<>();

		System.out.println("IPid in pcapFileA:");
		hashes.addAll(findByIpId(packagesA, ipId));
		System.out.println("IPid in pcapFileB:");
		hashes.addAll(findByIpId(packagesB, ipId));

		System.out.println("Hash reverse pcapFileA:");
		findByIpHash(packagesA, hashes);
		System.out.println("Hash reverse pcapFileB:");
		findByIpHash(packagesB, hashes);
	}

	private List<String> findByIpId(List<IpPacketIdent> packages, Integer ipId) {
		List<IpPacketIdent> matchingPackages = packages.stream()
				.filter(p -> Objects.equals(ipId, p.getId()))
				.collect(Collectors.toList());

		List<String> hashes = new ArrayList<>();
		if (matchingPackages.isEmpty()) {
			System.out.println("\tNo matches");
			return hashes;
		}
		matchingPackages.forEach(matchingPackage -> {
			System.out.println("\t" + matchingPackage.getId() + " payload sha1 hash:" + matchingPackage
					.getPayloadHash() + " ts:" + matchingPackage.getTs());
			hashes.add(matchingPackage.getPayloadHash());
		});
		return hashes;
	}

	private void findByIpHash(List<IpPacketIdent> packages, Set<String> hashes) {
		List<IpPacketIdent> matchingPackages = packages.stream()
				.filter(p -> hashes.contains(p.getPayloadHash()))
				.collect(Collectors.toList());

		if (matchingPackages.isEmpty()) {
			System.out.println("\tNo matches");
			return;
		}
		matchingPackages.forEach(matchingPackage -> {
			System.out.println("\t" + matchingPackage.getId() + " payload sha1 hash:" + matchingPackage
					.getPayloadHash() + " ts:" + matchingPackage.getTs());
		});
	}

}
