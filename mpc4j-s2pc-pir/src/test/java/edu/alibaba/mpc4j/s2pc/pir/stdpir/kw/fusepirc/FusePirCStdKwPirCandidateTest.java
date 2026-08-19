package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

/**
 * FUSE_PIR_C candidate-parameter minimal protocol test.
 *
 * <p>CMUX_128_CANDIDATE is runnable as a paper-aligned candidate. Estimator validation is still pending, so this
 * test must not be interpreted as a production-security claim.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/17
 */
public class FusePirCStdKwPirCandidateTest {
    /**
     * random state.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    public void testFusePirCJavaClientServerMinimalKeywordQueryWithDefaultCandidateParams() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkCandidateSecureLweToRgswCmux());
        FusePirCStdKwPirClient.MinimalSetupMaterial setupMaterial =
            FusePirCStdKwPirClient.generateMinimalSetupMaterial();
        int rowNum = 24;
        int colNum = 1;
        int payloadBlockNum = 1;
        int rowStride = 1;
        int[] flatPositions = new int[]{
            1, 5, 9,
            0, 4, 8,
            2, 6, 10
        };
        long[] values = new long[]{7, 10, 13};
        FusePirCStdKwPirServer.MinimalServerState serverState = FusePirCStdKwPirServer.initMinimalServer(
            setupMaterial.circuitBootstrapParams, setupMaterial.evaluationKey, flatPositions, values, rowNum,
            colNum, payloadBlockNum, rowStride
        );
        try {
            byte[] bffSeed = BytesUtils.randomByteArray(16, SECURE_RANDOM);
            byte[] query = FusePirCStdKwPirClient.generateMinimalCompressedQuery(
                setupMaterial, bffSeed, new int[]{0, 4, 8}, rowNum, colNum
            );
            int[] queryBytes = FusePirCStdKwPirClient.onlineQuerySizeBreakdown(query);
            Assert.assertEquals(32, queryBytes[0]);
            Assert.assertEquals(30, queryBytes[1]);
            Assert.assertEquals(44, queryBytes[2]);
            Assert.assertEquals(106, queryBytes[3]);
            Assert.assertEquals(62, queryBytes[4]);
            Assert.assertEquals(2, queryBytes[5]);
            byte[] response = FusePirCStdKwPirServer.answerMinimal(serverState, query);
            long[] decoded = FusePirCStdKwPirClient.decryptMinimalRawResponse(setupMaterial, response);
            Assert.assertEquals(1, decoded.length);
            Assert.assertEquals(10, decoded[0]);
        } finally {
            FusePirCStdKwPirServer.destroyMinimalServer(serverState);
        }
    }
}
