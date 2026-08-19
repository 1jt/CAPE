package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * CAPE_C PIR query for one boolean keyword query.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
class CapeCPirQuery {
    /**
     * anchor keyword bytes, kept only by the client for response decoding.
     */
    private final byte[] anchorKeywordBytes;
    /**
     * compressed anchor query.
     */
    private final byte[] compressedAnchorQuery;
    /**
     * coefficient-encoded encrypted Bloom query chunks.
     */
    private final List<byte[]> encryptedPackedBloomQuery;
    /**
     * number of one-bits in the plaintext query Bloom Filter, kept only by the client.
     */
    private final int bloomOneCount;
    /**
     * boolean keyword num.
     */
    private final int boolKeywordNum;

    CapeCPirQuery(byte[] anchorKeywordBytes, byte[] compressedAnchorQuery, List<byte[]> encryptedPackedBloomQuery,
                 int bloomOneCount, int boolKeywordNum) {
        this.anchorKeywordBytes = BytesUtils.clone(anchorKeywordBytes);
        this.compressedAnchorQuery = BytesUtils.clone(compressedAnchorQuery);
        this.encryptedPackedBloomQuery = encryptedPackedBloomQuery.stream().map(BytesUtils::clone).toList();
        this.bloomOneCount = bloomOneCount;
        this.boolKeywordNum = boolKeywordNum;
    }

    byte[] getAnchorKeywordBytes() {
        return BytesUtils.clone(anchorKeywordBytes);
    }

    byte[] getCompressedAnchorQuery() {
        return BytesUtils.clone(compressedAnchorQuery);
    }

    List<byte[]> getEncryptedPackedBloomQuery() {
        return encryptedPackedBloomQuery.stream().map(BytesUtils::clone).toList();
    }

    int getBloomOneCount() {
        return bloomOneCount;
    }

    int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    List<byte[]> getServerPayload() {
        List<byte[]> payload = new ArrayList<>(1 + encryptedPackedBloomQuery.size());
        payload.add(getCompressedAnchorQuery());
        payload.addAll(getEncryptedPackedBloomQuery());
        return payload;
    }
}
