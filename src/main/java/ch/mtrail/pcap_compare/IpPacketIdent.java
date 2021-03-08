package ch.mtrail.pcap_compare;

import java.util.Arrays;
import java.util.Objects;

public class IpPacketIdent {
	private final Integer id;
	private final byte[] hash;
	private final long ts;

	public IpPacketIdent(Integer id, byte[] hash, long ts) {
		this.id = id;
		this.hash = hash;
		this.ts = ts;
	}

	public Integer getId() {
		return id;
	}

	public byte[] getHash() {
		return hash;
	}

	public long getTs() {
		return ts;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		IpPacketIdent that = (IpPacketIdent) o;
		return Objects.equals(id, that.id) && Arrays.equals(hash, that.hash);
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(id);
		result = 31 * result + Arrays.hashCode(hash);
		return result;
	}
}
