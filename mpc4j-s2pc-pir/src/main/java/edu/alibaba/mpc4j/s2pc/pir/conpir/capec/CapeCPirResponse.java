package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.List;

/**
 * CAPE_C PIR response.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
class CapeCPirResponse {
    /**
     * packed result ciphertexts.
     */
    private final List<byte[]> packedResultCiphertexts;

    CapeCPirResponse(List<byte[]> packedResultCiphertexts) {
        this.packedResultCiphertexts = packedResultCiphertexts.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getPackedResultCiphertexts() {
        return packedResultCiphertexts.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getServerPayload() {
        return getPackedResultCiphertexts();
    }
}
