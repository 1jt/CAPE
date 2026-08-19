package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.List;

/**
 * FUSE_PIR response for one keyword.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class FusePirStdKwPirResponse {
    /**
     * payload block ciphertexts
     */
    private final List<byte[]> payloadBlockCiphertexts;

    FusePirStdKwPirResponse(List<byte[]> payloadBlockCiphertexts) {
        this.payloadBlockCiphertexts = payloadBlockCiphertexts.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getPayloadBlockCiphertexts() {
        return payloadBlockCiphertexts.stream().map(BytesUtils::clone).toList();
    }
}
