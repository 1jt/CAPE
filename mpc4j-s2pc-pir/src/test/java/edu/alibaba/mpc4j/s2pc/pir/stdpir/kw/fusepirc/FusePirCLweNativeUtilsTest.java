package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FUSE_PIR_C LWE primitive native tests.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCLweNativeUtilsTest {
    /**
     * random state.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    public void testPrgSameDomainConsistent() {
        byte[] seed = BytesUtils.randomByteArray(32, SECURE_RANDOM);
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkPrgSameDomain(seed, 7, FusePirCLweParams.DEBUG_SMALL));
    }

    @Test
    public void testPrgDifferentDomainSeparated() {
        byte[] seed = BytesUtils.randomByteArray(32, SECURE_RANDOM);
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkPrgDifferentDomain(seed, 7, 8, FusePirCLweParams.DEBUG_SMALL));
    }

    @Test
    public void testLweEncryptDecryptBit() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkLweEncryptDecrypt(0, FusePirCLweParams.DEBUG_SMALL));
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkLweEncryptDecrypt(1, FusePirCLweParams.DEBUG_SMALL));
    }

    @Test
    public void testCompressedQueryRecover() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkCompressedQueryRecover(FusePirCLweParams.DEBUG_SMALL));
    }

    @Test
    public void testRawPolyRawRlweAndGadget() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawPolyMonomial());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawPolyAutomorphism());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkGadgetExact());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawRlweEncryptDecrypt());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawNttRoot());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawNttNegacyclicMulSmall());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawNttNegacyclicMulCandidateSparse());
    }

    @Test
    public void testMvFbsPrimitiveChecks() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkMvFbsModSwitchSign());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkMvFbsTestPolynomialLayout());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawExternalProductContract());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawRgswCmuxContract());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawExternalProductCachedNttConsistency());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkMvFbsNoSampleExtractBit0Bit1());
    }

    @Test
    public void testHomTracePrimitiveChecks() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawAutomorphismKeySwitchPhase());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkHomTraceKillsNonconstantTerms());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkHomTraceManyMvFbsOutput());
    }

    @Test
    public void testSchemeSwitchPrimitiveChecks() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSchemeSwitchKeyGeneration());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSchemeSwitchRawRgswLayout());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSchemeSwitchCmuxSemantics());
    }

    @Test
    public void testCircuitBootstrapPrimitiveChecks() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkCircuitBootstrapKeyGeneration());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkTraceInverseScalingModInverse());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSecureLweToRgswBit0Bit1Cmux());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSecureLweBitsToRgswBatch());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSecureLweBitsToRgswBatchWorkspaceConsistency());
    }

    @Test
    public void testSelectorPrimitiveChecks() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSelectorBitDecomposition());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSelectorLweBitPhase());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawRlwePrimeBasic());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawRgswMulRlwePrime());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkOneHotSelectorFromSecureLweBits());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkOneHotColumnSelection());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkOneHotSelectorBoundOne());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkSelectorNoPlainIndexDependency());
    }

    @Test
    public void testFusePirCNativeGenerateReplyMinimalRaw() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkFusePirCNativeGenerateReplyMinimalRaw());
    }

    @Test
    public void testCompressedQuerySizeWithZeroColumnBits() {
        int rowBitNum = 11;
        int colBitNum = 0;
        int bElementByteLength = 2;
        byte[] seed = new byte[32];
        byte[] bArray = new byte[3 * rowBitNum * bElementByteLength];
        FusePirCCompressedQuery query = new FusePirCCompressedQuery(
            seed, bArray, rowBitNum, colBitNum, 3, 571, 1024, bElementByteLength
        );
        byte[] encoded = query.toByteArray();
        FusePirCCompressedQuery decoded = FusePirCCompressedQuery.fromByteArray(encoded);
        Assert.assertEquals(colBitNum, decoded.getColBitNum());
        Assert.assertEquals(rowBitNum, decoded.getRowBitNum());
        Assert.assertEquals(3 * rowBitNum * bElementByteLength, decoded.getBArrayByteLength());
        Assert.assertEquals(32 + 3 * rowBitNum * bElementByteLength,
            decoded.getSeedByteLength() + decoded.getBArrayByteLength());
    }

    @Test
    public void testFusePirCPublicGenerateReplyWithEvalKeyHandleMinimalRaw() {
        List<byte[]> material = FusePirCStdKwPirNativeUtils.generateCircuitBootstrapKeyMaterialForCheck();
        Assert.assertEquals(5, material.size());
        long handle = FusePirCStdKwPirNativeUtils.createCircuitBootstrapEvaluationKey(material.get(0), material.get(2));
        long rawMatrixHandle = FusePirCStdKwPirNativeUtils.createRawMatrix(material.get(4), material.get(0));
        try {
            byte[] response = FusePirCStdKwPirNativeUtils.generateReply(material.get(3), handle, material.get(0),
                rawMatrixHandle);
            Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawReplyForCheck(response, material.get(1),
                material.get(0)));
        } finally {
            FusePirCStdKwPirNativeUtils.destroyRawMatrix(rawMatrixHandle);
            FusePirCStdKwPirNativeUtils.destroyCircuitBootstrapEvaluationKey(handle);
        }
    }

    @Test
    public void testEvalKeyHandleLifecycle() {
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkEvalKeyHandleLifecycle());
        Assert.assertTrue(FusePirCStdKwPirNativeUtils.checkRawMatrixHandleLifecycle());
    }

    @Test
    public void testCmux128CandidateParamsValidation() {
        FusePirCStdKwPirParams params = FusePirCStdKwPirParams.CMUX_128_CANDIDATE_PARAMS;
        FusePirCLweParams lweParams = params.getLweParams();
        FusePirCCircuitBootstrapParams cbParams = params.getCircuitBootstrapParams();
        Assert.assertEquals(FusePirCStdKwPirParams.ParameterSet.CMUX_128_CANDIDATE, params.getParameterSet());
        Assert.assertEquals(571, lweParams.getDimension());
        Assert.assertEquals(1024, lweParams.getModulus());
        Assert.assertEquals(512, lweParams.getDelta());
        Assert.assertEquals(2048, cbParams.getRawRlweDegree());
        Assert.assertEquals(18014398509404161L, cbParams.getRawRlweModulus());
        Assert.assertEquals(1, cbParams.getRawRlweModulus() % 4096);
        Assert.assertEquals(1, gcd(cbParams.getRawRlweDegree(), cbParams.getRawRlweModulus()));
        Assert.assertEquals(64L, cbParams.getGadgetBase());
        Assert.assertEquals(5, cbParams.getGadgetLength());
        Assert.assertTrue(cbParams.getSecurityLabel().contains("estimator pending"));
    }

    @Test
    public void testPayloadBlockNumComputationCheck() {
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(40, 16, 3, true);
        params.initPirParams(3);
        int payloadBitLength = 40 + 3 * 16 * Byte.SIZE;
        Assert.assertEquals(payloadBitLength, params.getPayloadBitLength());
        Assert.assertEquals(16, params.getPayloadElementBitLength());
        Assert.assertEquals((payloadBitLength + 15) / 16, params.getPayloadBlockNum());
    }

    @Test
    public void testPayloadPackingLayoutCheck() {
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(FusePirCStdKwPirParams.CMUX_128_CANDIDATE_PARAMS);
        params.initPirParams(3);
        Assert.assertTrue(params.getBlocksPerPackedMatrix() > 1 || params.getPayloadBlockNum() == 1);
        Assert.assertEquals(params.getBlocksPerPackedMatrix(), params.getRowStride());
        Assert.assertEquals(
            (params.getPayloadBlockNum() + params.getBlocksPerPackedMatrix() - 1) / params.getBlocksPerPackedMatrix(),
            params.getPackedMatrixGroupNum()
        );
        Assert.assertTrue(params.getMatrixRowNum() * params.getBlocksPerPackedMatrix()
            <= params.getRawRlweDegree());
        int colBitNum = ceilLog2(params.getMatrixColNum());
        int rowBitNum = ceilLog2(params.getMatrixRowNum());
        int bElementBytes = 2;
        Assert.assertEquals(3 * rowBitNum * bElementBytes, 3 * (colBitNum + rowBitNum) * bElementBytes);
    }

    @Test
    public void testResponsePackingTargetCheck() {
        checkResponsePackingEstimate(512, 1 << 13, 1024, 50_000_000L, 60_000_000L);
        checkResponsePackingEstimate(512, 1 << 14, 1024, 100_000_000L, 110_000_000L);
        checkResponsePackingEstimate(256, 1 << 15, 1024, 200_000_000L, 215_000_000L);
    }

    @Test
    public void testRawBffAdditiveStorageCheck() {
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(
            FusePirCStdKwPirParams.ParameterSet.RAW_CORRECTNESS, 40, 1, 1, true
        );
        params.initPirParams(3);
        Map<ByteBuffer, long[]> keywordPayloadBlocks = new LinkedHashMap<>();
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{0}), new long[]{1, 2, 3});
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{1}), new long[]{10, 20, 30});
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{2}), new long[]{100, 200, 300});
        FusePirCStdKwPirUtils.RawBffStorage storage = FusePirCStdKwPirUtils.buildRawAdditiveBffStorage(
            keywordPayloadBlocks, keywordPayloadBlocks.size(), new byte[FusePirCStdKwPirUtils.BFF_SEED_BYTE_LENGTH],
            params
        );
        Assert.assertEquals(params.getPayloadBlockNum(), storage.storageByBlock.length);
        Assert.assertTrue(storage.seedTryCount >= 1);
        for (Map.Entry<ByteBuffer, long[]> entry : keywordPayloadBlocks.entrySet()) {
            int[] positions = FusePirCStdKwPirUtils.getHashPositions(
                entry.getKey(), keywordPayloadBlocks.size(), storage.seed, params
            );
            for (int p = 0; p < params.getPayloadBlockNum(); p++) {
                long sum = 0L;
                for (int position : positions) {
                    sum = addMod(sum, storage.storageByBlock[p][position], params.getRawRlweModulus());
                }
                Assert.assertEquals(FusePirCStdKwPirUtils.rawEncodePayloadBlock(entry.getValue()[p], params), sum);
            }
        }
    }

    @Test
    public void testPackedMatrixFromBffStorageShapeCheck() {
        FusePirCStdKwPirClient.MinimalSetupMaterial setupMaterial =
            FusePirCStdKwPirClient.generateRawCorrectnessSetupMaterial();
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(
            FusePirCStdKwPirParams.ParameterSet.RAW_CORRECTNESS, 40, 1, 1, true
        );
        params.initPirParams(3);
        Map<ByteBuffer, long[]> keywordPayloadBlocks = new LinkedHashMap<>();
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{0}), new long[]{1, 2, 3});
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{1}), new long[]{10, 20, 30});
        keywordPayloadBlocks.put(ByteBuffer.wrap(new byte[]{2}), new long[]{100, 200, 300});
        FusePirCStdKwPirUtils.RawBffStorage storage = FusePirCStdKwPirUtils.buildRawAdditiveBffStorage(
            keywordPayloadBlocks, keywordPayloadBlocks.size(), new byte[FusePirCStdKwPirUtils.BFF_SEED_BYTE_LENGTH],
            params
        );
        Assert.assertEquals(3, params.getPayloadBlockNum());
        Assert.assertEquals(params.getPayloadBlockNum(), params.getBlocksPerPackedMatrix());
        Assert.assertEquals(1, params.getPackedMatrixGroupNum());
        Assert.assertTrue(params.getMatrixRowNum() * params.getBlocksPerPackedMatrix()
            <= params.getRawRlweDegree());
        byte[] encodedMatrix = FusePirCStdKwPirNativeUtils.encodeRawMatrixFromBffStorageBlocks(
            storage.storageByBlock, params.getBffSlotNum(), params.getMatrixRowNum(), params.getMatrixColNum(),
            params.getPayloadBlockNum(), params.getRowStride(), setupMaterial.circuitBootstrapParams
        );
        long rawMatrixHandle = FusePirCStdKwPirNativeUtils.createRawMatrix(
            encodedMatrix, setupMaterial.circuitBootstrapParams
        );
        FusePirCStdKwPirNativeUtils.destroyRawMatrix(rawMatrixHandle);
    }

    @Test
    public void testFusePirCJavaClientServerMinimalKeywordQuery() {
        FusePirCStdKwPirClient.MinimalSetupMaterial setupMaterial =
            FusePirCStdKwPirClient.generateRawCorrectnessSetupMaterial();
        int rowNum = 4;
        int colNum = 4;
        int payloadBlockNum = 3;
        int rowStride = payloadBlockNum;
        int[] flatPositions = new int[]{
            1, 6, 11,
            0, 4, 8,
            2, 7, 12
        };
        long[] values = new long[]{
            7, 70, 700,
            10, 100, 1000,
            13, 130, 1300
        };
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
            Assert.assertEquals(12, queryBytes[1]);
            Assert.assertEquals(44, queryBytes[2]);
            Assert.assertEquals(query.length, queryBytes[3]);
            Assert.assertEquals(queryBytes[0] + queryBytes[1] + queryBytes[2], queryBytes[3]);
            Assert.assertEquals(queryBytes[0] + queryBytes[1], queryBytes[4]);
            Assert.assertEquals(1, queryBytes[5]);
            Assert.assertTrue(serverState.setupEvaluationKeyBytes > queryBytes[3]);
            byte[] response = FusePirCStdKwPirServer.answerMinimal(serverState, query);
            long[] decoded = FusePirCStdKwPirClient.decryptMinimalRawResponse(setupMaterial, response);
            Assert.assertEquals(payloadBlockNum, decoded.length);
            boolean decodesOnePackedEntry =
                (decoded[0] == 7 && decoded[1] == 70 && decoded[2] == 700)
                    || (decoded[0] == 10 && decoded[1] == 100 && decoded[2] == 1000)
                    || (decoded[0] == 13 && decoded[1] == 130 && decoded[2] == 1300);
            Assert.assertTrue(decodesOnePackedEntry);
            int rawResponseVectorHeaderBytes = 5 * Integer.BYTES + Integer.BYTES + Long.BYTES;
            int oneRawResponseCipherBytes = 2 * 16 * Long.BYTES;
            int packedMatrixGroupNum = 1;
            Assert.assertEquals(rawResponseVectorHeaderBytes + packedMatrixGroupNum * oneRawResponseCipherBytes,
                response.length);
        } finally {
            FusePirCStdKwPirServer.destroyMinimalServer(serverState);
        }
    }

    private static long gcd(long a, long b) {
        long x = Math.abs(a);
        long y = Math.abs(b);
        while (y != 0) {
            long t = x % y;
            x = y;
            y = t;
        }
        return x;
    }

    private static long addMod(long a, long b, long modulus) {
        long result = (a + b) % modulus;
        return result >= 0 ? result : result + modulus;
    }

    private static int ceilLog2(int bound) {
        int bitNum = 0;
        int value = 1;
        while (value < bound) {
            value <<= 1;
            bitNum++;
        }
        return bitNum;
    }

    private static void checkResponsePackingEstimate(int keywordNum, int valueNumPerKey, int entryBitLength,
                                                     long lowerBound, long upperBound) {
        Assert.assertEquals(0, entryBitLength % Byte.SIZE);
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(40, entryBitLength / Byte.SIZE, valueNumPerKey, true);
        params.initPirParams(keywordNum);
        int expectedPayloadBlockNum = (params.getFingerprintBitLength() + valueNumPerKey * entryBitLength
            + params.getPayloadElementBitLength() - 1) / params.getPayloadElementBitLength();
        Assert.assertEquals(expectedPayloadBlockNum, params.getPayloadBlockNum());
        Assert.assertEquals(128, params.getLegacyBlocksPerPackedMatrix());
        Assert.assertEquals(328, params.getBlocksPerPackedMatrix());
        Assert.assertEquals(
            (params.getPayloadBlockNum() + params.getBlocksPerPackedMatrix() - 1)
                / params.getBlocksPerPackedMatrix(),
            params.getPackedMatrixGroupNum()
        );
        Assert.assertEquals(2L * params.getRawRlweDegree() * Long.BYTES, params.getOneRawResponseCipherBytes());
        Assert.assertTrue(params.getExpectedResponseBytes() >= lowerBound);
        Assert.assertTrue(params.getExpectedResponseBytes() <= upperBound);
        Assert.assertTrue(params.getExpectedResponseBytes() < params.getLegacyExpectedResponseBytes());
        Assert.assertTrue(params.getBlocksPerPackedMatrix() > params.getLegacyBlocksPerPackedMatrix());
        Assert.assertTrue(params.getMatrixRowNum() * params.getBlocksPerPackedMatrix()
            <= params.getRawRlweDegree());
    }

}
