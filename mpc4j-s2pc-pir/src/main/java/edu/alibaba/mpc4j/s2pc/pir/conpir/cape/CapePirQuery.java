package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * CAPE PIR query for one boolean keyword query.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapePirQuery {
    /**
     * anchor keyword bytes, kept only by the client.
     */
    private final byte[] anchorKeywordBytes;
    /**
     * FUSE_PIR column queries for the anchor keyword.
     */
    private final List<byte[]> fusepirColumnQueries;
    /**
     * Deprecated test-only bit-column queries. Formal CAPE query payloads do not include this component.
     */
    private final List<byte[]> fusepirBitColumnQueries;
    /**
     * CAPE compressed LWE row-bit queries for the anchor keyword.
     */
    private final List<byte[]> compressedRowBitQueries;
    /**
     * Deprecated test-only encrypted Bloom Filter query payload. Formal CAPE query payloads use coefficient chunks
     * instead of this bit-level query.
     */
    private final List<byte[]> encryptedBloomFilter;
    /**
     * coefficient-encoded encrypted Bloom Filter query chunks for the real CAPE score path.
     */
    private final List<byte[]> encryptedCoeffBloomFilters;
    /**
     * number of one-bits in the plaintext query Bloom Filter, kept only by the client.
     */
    private final int bloomOneCount;
    /**
     * boolean keyword num.
     */
    private final int boolKeywordNum;

    CapePirQuery(byte[] anchorKeywordBytes, List<byte[]> fusepirColumnQueries, List<byte[]> fusepirEncryptedRowBits,
                List<byte[]> encryptedCoeffBloomFilters, int bloomOneCount, int boolKeywordNum) {
        this(anchorKeywordBytes, fusepirColumnQueries, List.of(), fusepirEncryptedRowBits, List.of(),
            encryptedCoeffBloomFilters, bloomOneCount, boolKeywordNum);
    }

    /**
     * Legacy constructor retained only for tests around deprecated payload shapes.
     */
    @Deprecated
    CapePirQuery(byte[] anchorKeywordBytes, List<byte[]> fusepirColumnQueries, List<byte[]> fusepirBitColumnQueries,
                List<byte[]> fusepirEncryptedRowBits, List<byte[]> encryptedBloomFilter,
                List<byte[]> encryptedCoeffBloomFilters, int bloomOneCount, int boolKeywordNum) {
        this.anchorKeywordBytes = BytesUtils.clone(anchorKeywordBytes);
        this.fusepirColumnQueries = fusepirColumnQueries.stream().map(BytesUtils::clone).toList();
        this.fusepirBitColumnQueries = fusepirBitColumnQueries.stream().map(BytesUtils::clone).toList();
        this.compressedRowBitQueries = fusepirEncryptedRowBits.stream().map(BytesUtils::clone).toList();
        this.encryptedBloomFilter = encryptedBloomFilter.stream().map(BytesUtils::clone).toList();
        this.encryptedCoeffBloomFilters = encryptedCoeffBloomFilters.stream().map(BytesUtils::clone).toList();
        this.bloomOneCount = bloomOneCount;
        this.boolKeywordNum = boolKeywordNum;
    }

    byte[] getAnchorKeywordBytes() {
        return BytesUtils.clone(anchorKeywordBytes);
    }

    List<byte[]> getFusePirColumnQueries() {
        return fusepirColumnQueries.stream().map(BytesUtils::clone).toList();
    }

    @Deprecated
    List<byte[]> getFusePirBitColumnQueries() {
        return fusepirBitColumnQueries.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getFusePirEncryptedRowBits() {
        return List.of();
    }

    List<byte[]> getCompressedRowBitQueries() {
        return compressedRowBitQueries.stream().map(BytesUtils::clone).toList();
    }

    @Deprecated
    List<byte[]> getEncryptedBloomFilter() {
        return encryptedBloomFilter.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getEncryptedCoeffBloomFilters() {
        return encryptedCoeffBloomFilters.stream().map(BytesUtils::clone).toList();
    }

    int getBloomOneCount() {
        return bloomOneCount;
    }

    int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    List<byte[]> getServerPayload() {
        List<byte[]> payload = new ArrayList<>(
            fusepirColumnQueries.size() + compressedRowBitQueries.size() + encryptedCoeffBloomFilters.size()
        );
        payload.addAll(getFusePirColumnQueries());
        payload.addAll(getCompressedRowBitQueries());
        payload.addAll(getEncryptedCoeffBloomFilters());
        return payload;
    }

    /**
     * Returns the deprecated bit-column query payload for legacy tests only. Formal server code must not call this.
     */
    @Deprecated
    List<byte[]> getServerPayloadForLegacyBitColumnTest() {
        List<byte[]> payload = new ArrayList<>(
            fusepirColumnQueries.size() + fusepirBitColumnQueries.size() + compressedRowBitQueries.size()
                + encryptedCoeffBloomFilters.size()
        );
        payload.addAll(getFusePirColumnQueries());
        payload.addAll(getFusePirBitColumnQueries());
        payload.addAll(getCompressedRowBitQueries());
        payload.addAll(getEncryptedCoeffBloomFilters());
        return payload;
    }

    /**
     * Returns a payload that leaks the anchor keyword. This helper exists only for legacy correctness tests that have
     * not yet been migrated to encrypted slot/item candidate retrieval. It is not a valid CAPE protocol message.
     */
    @Deprecated
    List<byte[]> getServerPayloadWithPlainAnchorForTest() {
        List<byte[]> payload = new ArrayList<>(
            1 + fusepirColumnQueries.size() + compressedRowBitQueries.size() + encryptedBloomFilter.size()
        );
        payload.add(getAnchorKeywordBytes());
        payload.addAll(getServerPayload());
        return payload;
    }
}
