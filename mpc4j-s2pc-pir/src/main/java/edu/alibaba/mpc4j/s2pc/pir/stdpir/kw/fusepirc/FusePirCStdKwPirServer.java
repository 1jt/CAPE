package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirServer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirPtoDesc.getInstance;

/**
 * FUSE_PIR_C standard keyword PIR server.
 *
 * <p>The server answers compressed FUSE_PIR_C queries by recovering LWE row/column
 * bits from {@code seed + bArray}, converting every bit with
 * {@code secure_lwe_to_rgsw}, constructing a Pirouette-style one-hot RLWE'
 * column selector, selecting plaintext raw columns by exact gadget
 * decomposition, and applying raw row-to-zero BlindRotate. It does not use the
 * old FUSE_PIR RLWE column query or FUSE_PIR native generateReply path.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCStdKwPirServer<T> extends AbstractStdKwPirServer<T> {
    /**
     * Lightweight FUSE_PIR_C performance log switch.
     */
    private static final boolean FUSE_PIR_C_PERF_LOG = false;
    /**
     * BFF seed byte length.
     */
    private static final int BFF_SEED_BYTE_LENGTH = 16;
    /**
     * params.
     */
    private final FusePirCStdKwPirParams params;
    /**
     * circuit bootstrap params.
     */
    private byte[] circuitBootstrapParams;
    /**
     * server-side evaluation key handle.
     */
    private long evalKeyHandle;
    /**
     * server-side raw matrix handle.
     */
    private long rawMatrixHandle;
    /**
     * BFF seed.
     */
    private byte[] bffSeed;
    /**
     * Last BFF seed try count.
     */
    private int bffSeedTryCount;
    /**
     * Last BFF peel time.
     */
    private long bffPeelMs;
    /**
     * Last BFF share assignment time.
     */
    private long bffShareAssignmentMs;
    /**
     * Last raw matrix pack time.
     */
    private long rawMatrixPackMs;
    /**
     * Estimated serialized raw matrix size.
     */
    private long rawEncodedMatrixBytes;
    static class MinimalServerState {
        final byte[] circuitBootstrapParams;
        final long evalKeyHandle;
        final long rawMatrixHandle;
        final int setupEvaluationKeyBytes;
        final int rawEncodedMatrixBytes;

        MinimalServerState(byte[] circuitBootstrapParams, long evalKeyHandle, long rawMatrixHandle,
                           int setupEvaluationKeyBytes, int rawEncodedMatrixBytes) {
            this.circuitBootstrapParams = circuitBootstrapParams;
            this.evalKeyHandle = evalKeyHandle;
            this.rawMatrixHandle = rawMatrixHandle;
            this.setupEvaluationKeyBytes = setupEvaluationKeyBytes;
            this.rawEncodedMatrixBytes = rawEncodedMatrixBytes;
        }
    }

    public FusePirCStdKwPirServer(Rpc serverRpc, Party clientParty, FusePirCStdKwPirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        params = new FusePirCStdKwPirParams(config.getParams());
    }

    @Override
    public void init(Map<T, byte[]> keyValueMap, int l, int maxBatchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.INIT_BEGIN);
        List<byte[]> setupPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal());
        stopWatch.start();
        MpcAbortPreconditions.checkArgument(setupPayload.size() == 2);
        circuitBootstrapParams = setupPayload.get(0);
        byte[] evaluationKey = setupPayload.get(1);
        long evalStart = System.nanoTime();
        evalKeyHandle = FusePirCStdKwPirNativeUtils.createCircuitBootstrapEvaluationKey(
            circuitBootstrapParams, evaluationKey
        );
        logPerf("server.init.nativeCreateCircuitBootstrapEvaluationKeyMs=" + elapsedMs(evalStart)
            + ", setupEvaluationKeyBytes=" + evaluationKey.length);
        setInitInput(keyValueMap, l, maxBatchNum);
        params.initPirParams(n);
        bffSeed = new byte[BFF_SEED_BYTE_LENGTH];
        new SecureRandom().nextBytes(bffSeed);
        long encodeStart = System.nanoTime();
        rawMatrixHandle = createRawMatrixHandle(keyValueMap);
        logPerf("server.init.rawMatrixEncodingAndSerializationMs=" + elapsedMs(encodeStart)
            + ", estimatedRawEncodedMatrixBytes=" + rawEncodedMatrixBytes);
        logPerf("server.init.nativeCreateRawMatrixMs=0"
            + ", rawMatrixHandle=" + rawMatrixHandle);
        sendOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal(), Collections.singletonList(bffSeed));
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime,
            "Server initializes FUSE_PIR_C raw state"
                + ", parameterSet=" + params.getParameterSet()
                + ", rawRlweN=" + params.getRawRlweDegree()
                + ", rawRlweQ=" + params.getRawRlweModulus()
                + ", bffSlotNum=" + params.getBffSlotNum()
                + ", rowStride=" + params.getRowStride()
                + ", oldRowNum=" + params.getOldSqrtMatrixRowNum()
                + ", oldColNum=" + params.getOldSqrtMatrixColNum()
                + ", newRowNum=" + params.getMatrixRowNum()
                + ", newColNum=" + params.getMatrixColNum()
                + ", fingerprintBitLength=" + params.getFingerprintBitLength()
                + ", value_num_per_key=" + params.getMaxValueNumPerKeyword()
                + ", entry_bit_length=" + (params.getValueByteLength() * Byte.SIZE)
                + ", payloadElementBitLength=" + params.getPayloadElementBitLength()
                + ", payloadBitLength=" + params.getPayloadBitLength()
                + ", payloadBlockNum=" + params.getPayloadBlockNum()
                + ", oldBlocksPerPackedMatrix=" + params.getLegacyBlocksPerPackedMatrix()
                + ", newBlocksPerPackedMatrix=" + params.getBlocksPerPackedMatrix()
                + ", packedMatrixGroupNum=" + params.getPackedMatrixGroupNum()
                + ", oldPackedMatrixGroupNum=" + params.getLegacyPackedMatrixGroupNum()
                + ", oneRawResponseCipherBytes=" + params.getOneRawResponseCipherBytes()
                + ", targetResponseBytesPerPayloadBlock=" + params.getTargetResponseBytesPerPayloadBlock()
                + ", expectedResponseBytes=" + params.getExpectedResponseBytes()
                + ", oldExpectedResponseBytes=" + params.getLegacyExpectedResponseBytes()
                + ", oldRowBlindRotateCount=" + (3L * params.getLegacyPackedMatrixGroupNum())
                + ", newRowBlindRotateCount=" + (3L * params.getPackedMatrixGroupNum())
                + ", setupEvaluationKeyBytes=" + evaluationKey.length
                + " (offline, not online query)"
                + ", rawEncodedMatrixBytes=" + rawEncodedMatrixBytes
                + " (offline, not online query)"
                + ", bffSeedTryCount=" + bffSeedTryCount
                + ", bffPeelMs=" + bffPeelMs
                + ", bffShareAssignmentMs=" + bffShareAssignmentMs
                + ", rawMatrixPackMs=" + rawMatrixPackMs
                + ", BFF preprocessing is included"
                + ", securityLabel=" + params.getSecurityLabel()
        );
        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public void pir(int batchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.PTO_BEGIN);
        setPtoInput(batchNum);
        for (int i = 0; i < batchNum; i++) {
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_COMPRESSED_QUERY.ordinal());
            stopWatch.start();
            MpcAbortPreconditions.checkArgument(queryPayload.size() == 1);
            long nativeStart = System.nanoTime();
            byte[] response = FusePirCStdKwPirNativeUtils.generateReply(
                queryPayload.get(0), evalKeyHandle, circuitBootstrapParams, rawMatrixHandle
            );
            logPerf("server.query.publicGenerateReplyMs=" + elapsedMs(nativeStart)
                + ", compressedQueryBytes=" + queryPayload.get(0).length
                + ", responseBytes=" + response.length
                + ", payloadBlockNum=" + params.getPayloadBlockNum()
                + ", blocksPerPackedMatrix=" + params.getBlocksPerPackedMatrix()
                + ", packedMatrixGroupNum=" + params.getPackedMatrixGroupNum()
                + ", expectedResponseBytes=" + params.getExpectedResponseBytes()
                + ", oldPackedMatrixGroupNum=" + params.getLegacyPackedMatrixGroupNum()
                + ", oldExpectedResponseBytes=" + params.getLegacyExpectedResponseBytes()
                + ", rawMatrixHandle=" + rawMatrixHandle);
            List<byte[]> responsePayload = Collections.singletonList(response);
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), responsePayload);
            stopWatch.stop();
            long replyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 1, replyTime, "Server handles FUSE_PIR_C compressed query");
        }
        logPhaseInfo(PtoState.PTO_END);
    }

    @Override
    public void destroy() {
        if (rawMatrixHandle != 0) {
            FusePirCStdKwPirNativeUtils.destroyRawMatrix(rawMatrixHandle);
            rawMatrixHandle = 0;
        }
        if (evalKeyHandle != 0) {
            FusePirCStdKwPirNativeUtils.destroyCircuitBootstrapEvaluationKey(evalKeyHandle);
            evalKeyHandle = 0;
        }
        super.destroy();
    }

    private long createRawMatrixHandle(Map<T, byte[]> keyValueMap) {
        Map<T, long[]> keywordPayloadBlocks = new LinkedHashMap<>(keyValueMap.size());
        for (Map.Entry<T, byte[]> entry : keyValueMap.entrySet()) {
            long[] blocks = FusePirCStdKwPirUtils.payloadToBlocks(entry.getKey(), entry.getValue(), params);
            keywordPayloadBlocks.put(entry.getKey(), blocks);
        }
        long encodeStart = System.nanoTime();
        FusePirCStdKwPirUtils.RawBffMatrixHandle rawBffMatrix = FusePirCStdKwPirUtils.createRawMatrixHandleFromAdditiveBffStorage(
            keywordPayloadBlocks, n, bffSeed, params, circuitBootstrapParams
        );
        bffSeed = rawBffMatrix.seed;
        bffSeedTryCount = rawBffMatrix.seedTryCount;
        bffPeelMs = rawBffMatrix.peelMs;
        bffShareAssignmentMs = rawBffMatrix.shareAssignmentMs;
        rawMatrixPackMs = rawBffMatrix.rawMatrixPackMs;
        rawEncodedMatrixBytes = rawBffMatrix.estimatedRawEncodedMatrixBytes;
        logPerf("server.init.bffEncodeStart"
            + ", bffSeedTryCount=" + bffSeedTryCount
            + ", bffPeelMs=" + bffPeelMs
            + ", bffShareAssignmentMs=" + bffShareAssignmentMs
            + ", rawMatrixPackMs=" + rawMatrixPackMs
            + ", rawMatrixEncodeTotalMs=" + elapsedMs(encodeStart)
            + ", payloadBlockNum=" + params.getPayloadBlockNum()
            + ", blocksPerPackedMatrix=" + params.getBlocksPerPackedMatrix()
            + ", packedMatrixGroupNum=" + params.getPackedMatrixGroupNum()
            + ", bffSlotNum=" + params.getBffSlotNum()
            + ", estimatedRawEncodedMatrixBytes=" + rawEncodedMatrixBytes);
        return rawBffMatrix.rawMatrixHandle;
    }

    static MinimalServerState initMinimalServer(byte[] circuitBootstrapParams, byte[] evaluationKey,
                                                int[] flatPositions, long[] values, int rowNum, int colNum,
                                                int payloadBlockNum, int rowStride) {
        long handle = FusePirCStdKwPirNativeUtils.createCircuitBootstrapEvaluationKey(circuitBootstrapParams,
            evaluationKey);
        byte[] encodedRawMatrix = FusePirCStdKwPirNativeUtils.encodeRawMatrixForEntries(
            flatPositions, values, rowNum, colNum, payloadBlockNum, rowStride, circuitBootstrapParams
        );
        long rawMatrixHandle = FusePirCStdKwPirNativeUtils.createRawMatrix(encodedRawMatrix, circuitBootstrapParams);
        return new MinimalServerState(circuitBootstrapParams, handle, rawMatrixHandle, evaluationKey.length,
            encodedRawMatrix.length);
    }

    static byte[] answerMinimal(MinimalServerState state, byte[] compressedQuery) {
        if (state.evalKeyHandle == 0 || state.rawMatrixHandle == 0) {
            throw new IllegalStateException("FUSE_PIR_C server handles are not initialized");
        }
        return FusePirCStdKwPirNativeUtils.generateReply(
            compressedQuery, state.evalKeyHandle, state.circuitBootstrapParams, state.rawMatrixHandle
        );
    }

    static void destroyMinimalServer(MinimalServerState state) {
        if (state != null) {
            FusePirCStdKwPirNativeUtils.destroyRawMatrix(state.rawMatrixHandle);
            FusePirCStdKwPirNativeUtils.destroyCircuitBootstrapEvaluationKey(state.evalKeyHandle);
        }
    }

    private static long elapsedMs(long startNanos) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
    }

    private static void logPerf(String message) {
        if (FUSE_PIR_C_PERF_LOG) {
            System.err.println("[FusePIR-C-PERF] " + message);
        }
    }
}
