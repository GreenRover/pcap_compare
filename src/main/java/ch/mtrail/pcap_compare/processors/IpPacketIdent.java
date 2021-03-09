package ch.mtrail.pcap_compare.processors;

import java.util.Objects;

public class IpPacketIdent {
	private final Integer id;
	private final String payloadHash;
	private final long ts;

	public IpPacketIdent(Integer id, String hash, long ts) {
		this.id = id;
		this.payloadHash = hash;
		this.ts = ts;
	}

	public Integer getId() {
		return id;
	}

	public String getPayloadHash() {
		return payloadHash;
	}

	public long getTs() {
		return ts;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		IpPacketIdent that = (IpPacketIdent) o;
		return Objects.equals(id, that.id) && Objects.equals(payloadHash, that.payloadHash);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(id);
		result = 31 * result + payloadHash.hashCode();
		return result;
	}
}
