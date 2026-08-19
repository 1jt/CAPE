package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirClient;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirPtoDesc.getInstance;

/**
 * FUSE_PIR_C standard keyword PIR client.
 *
 * <p>FUSE_PIR_C uses PirouetteH-style compressed bit queries. The client sends only
 * {@code seed + bArray + metadata}: for each BFF hash position it LWE-encrypts
 * little-endian column bits and row bits. It does not send an RLWE column query,
 * RGSW row bits, a RawRLWE(X^col) selector, or plaintext row/column indices.
 * Circuit-bootstrap evaluation keys are setup material and are not counted in
 * online query size.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCStdKwPirClient<T> extends AbstractStdKwPirClient<T> {
    /**
     * Lightweight FUSE_PIR_C performance log switch.
     */
    private static final boolean FUSE_PIR_C_PERF_LOG = false;
    /**
     * params.
     */
    private final FusePirCStdKwPirParams params;
    /**
     * circuit bootstrap params.
     */
    private byte[] circuitBootstrapParams;
    /**
     * client-only secret state.
     */
    private byte[] clientSecretState;
    /**
     * setup evaluation key sent to the server.
     */
    private byte[] evaluationKey;
    /**
     * BFF seed.
     */
    private byte[] bffSeed;

    static class MinimalSetupMaterial {
        final byte[] circuitBootstrapParams;
        final byte[] clientSecretState;
        final byte[] evaluationKey;

        MinimalSetupMaterial(List<byte[]> payload) {
            if (payload.size() != 3) {
                throw new IllegalArgumentException("FUSE_PIR_C setup material must contain params, client secret, eval key");
            }
            circuitBootstrapParams = payload.get(0);
            clientSecretState = payload.get(1);
            evaluationKey = payload.get(2);
        }
    }

    public FusePirCStdKwPirClient(Rpc clientRpc, Party serverParty, FusePirCStdKwPirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        params = new FusePirCStdKwPirParams(config.getParams());
    }

    @Override
    public void init(int n, int l, int maxBatchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.INIT_BEGIN);
        stopWatch.start();
        setInitInput(n, l, maxBatchNum);
        params.initPirParams(n);
        long setupStart = System.nanoTime();
        List<byte[]> setupMaterial = FusePirCStdKwPirNativeUtils.generateCircuitBootstrapSetupMaterial();
        logPerf("client.init.generateSetupMaterialTotalMs=" + elapsedMs(setupStart));
        MpcAbortPreconditions.checkArgument(setupMaterial.size() == 3);
        circuitBootstrapParams = setupMaterial.get(0);
        clientSecretState = setupMaterial.get(1);
        evaluationKey = setupMaterial.get(2);
        logPerf("client.init.setupMaterialBytes"
            + ", circuitBootstrapParamsBytes=" + circuitBootstrapParams.length
            + ", clientSecretStateBytes=" + clientSecretState.length
            + ", setupEvaluationKeyBytes=" + evaluationKey.length);
        List<byte[]> setupPayload = new ArrayList<>(2);
        setupPayload.add(circuitBootstrapParams);
        setupPayload.add(evaluationKey);
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal(), setupPayload);
        List<byte[]> seedPayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal());
        MpcAbortPreconditions.checkArgument(seedPayload.size() == 1);
        bffSeed = seedPayload.get(0);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime,
            "Client initializes FUSE_PIR_C setup"
                + ", setupEvaluationKeyBytes=" + evaluationKey.length
                + " (offline, not online query)"
                + ", securityLabel=" + params.getSecurityLabel());
        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public byte[][] pir(ArrayList<T> keys) throws MpcAbortException {
        logPhaseInfo(PtoState.PTO_BEGIN);
        setPtoInput(keys);
        byte[][] entries = new byte[batchNum][];
        for (int i = 0; i < batchNum; i++) {
            stopWatch.start();
            byte[] queryPayload = generateCompressedQuery(keys.get(i));
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_COMPRESSED_QUERY.ordinal(), List.of(queryPayload));
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, buildQuerySizeLog(queryPayload));

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            MpcAbortPreconditions.checkArgument(responsePayload.size() == 1);
            long[] coeffs = FusePirCStdKwPirNativeUtils.decryptRawResponse(
                responsePayload.get(0), clientSecretState, circuitBootstrapParams
            );
            entries[i] = decodeRawResponse(keys.get(i), coeffs);
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles FUSE_PIR_C reply");
        }
        logPhaseInfo(PtoState.PTO_END);
        return entries;
    }

    private byte[] generateCompressedQuery(T key) {
        long bffStart = System.nanoTime();
        int[] positions = FusePirCStdKwPirUtils.getHashPositions(key, n, bffSeed, params);
        logPerf("client.query.bffPositionComputationMs=" + elapsedMs(bffStart));
        long nativeStart = System.nanoTime();
        byte[] query = FusePirCStdKwPirNativeUtils.generateCompressedQueryFromClientSecret(
            clientSecretState, bffSeed, positions, params.getMatrixRowNum(), params.getMatrixColNum(),
            circuitBootstrapParams
        );
        logPerf("client.query.nativeBArrayAndSerializationMs=" + elapsedMs(nativeStart)
            + ", queryBytes=" + query.length);
        return query;
    }

    private byte[] decodeRawResponse(T key, long[] coeffs) {
        return FusePirCStdKwPirUtils.decodeBlocks(key, coeffs, byteL, params);
    }

    static MinimalSetupMaterial generateMinimalSetupMaterial() {
        return new MinimalSetupMaterial(FusePirCStdKwPirNativeUtils.generateCircuitBootstrapSetupMaterial());
    }

    static MinimalSetupMaterial generateRawCorrectnessSetupMaterial() {
        List<byte[]> material = FusePirCStdKwPirNativeUtils.generateCircuitBootstrapKeyMaterialForCheck();
        return new MinimalSetupMaterial(material.subList(0, 3));
    }

    static byte[] generateMinimalCompressedQuery(MinimalSetupMaterial setupMaterial, byte[] bffSeed, int[] positions,
                                                 int rowNum, int colNum) {
        return FusePirCStdKwPirNativeUtils.generateCompressedQueryFromClientSecret(
            setupMaterial.clientSecretState, bffSeed, positions, rowNum, colNum,
            setupMaterial.circuitBootstrapParams
        );
    }

    static long[] decryptMinimalRawResponse(MinimalSetupMaterial setupMaterial, byte[] rawResponse) {
        return FusePirCStdKwPirNativeUtils.decryptRawResponse(
            rawResponse, setupMaterial.clientSecretState, setupMaterial.circuitBootstrapParams
        );
    }

    static int[] onlineQuerySizeBreakdown(byte[] compressedQuery) {
        FusePirCCompressedQuery query = FusePirCCompressedQuery.fromByteArray(compressedQuery);
        int seedBytes = query.getSeedByteLength();
        int bArrayBytes = query.getBArrayByteLength();
        int metadataBytes = query.getMetadataByteLength();
        int implementationOnlineQueryBytes = seedBytes + bArrayBytes + metadataBytes;
        int canonicalOnlineQueryBytes = seedBytes + bArrayBytes;
        return new int[]{
            seedBytes, bArrayBytes, metadataBytes, implementationOnlineQueryBytes, canonicalOnlineQueryBytes,
            query.getBElementByteLength()
        };
    }

    private String buildQuerySizeLog(byte[] compressedQuery) {
        FusePirCCompressedQuery query = FusePirCCompressedQuery.fromByteArray(compressedQuery);
        int[] size = onlineQuerySizeBreakdown(compressedQuery);
        return "Client generates FUSE_PIR_C compressed query"
            + ", parameterSet=" + params.getParameterSet()
            + ", lweN=" + params.getLweParams().getDimension()
            + ", lweQ=" + params.getLweParams().getModulus()
            + ", lweDelta=" + params.getLweParams().getDelta()
            + ", rawRlweN=" + params.getRawRlweDegree()
            + ", rawRlweQ=" + params.getRawRlweModulus()
            + ", gadgetBase=" + params.getCircuitBootstrapParams().getGadgetBase()
            + ", gadgetLength=" + params.getCircuitBootstrapParams().getGadgetLength()
            + ", bffSlotNum=" + params.getBffSlotNum()
            + ", rawRlweDegree=" + params.getRawRlweDegree()
            + ", rowStride=" + params.getRowStride()
            + ", oldRowNum=" + params.getOldSqrtMatrixRowNum()
            + ", oldColNum=" + params.getOldSqrtMatrixColNum()
            + ", newRowNum=" + params.getMatrixRowNum()
            + ", newColNum=" + params.getMatrixColNum()
            + ", colBitNum=" + query.getColBitNum()
            + ", rowBitNum=" + query.getRowBitNum()
            + ", oneHotSelectorLeafCount=" + oneHotLeafCount(params.getMatrixColNum())
            + ", seedBytes=" + size[0]
            + ", bElementBytes=" + size[5]
            + ", bArrayBytes=" + size[1]
            + ", metadataBytes=" + size[2]
            + ", implementationOnlineQueryBytes=" + size[3]
            + ", canonicalOnlineQueryBytes=" + size[4]
            + ", setupEvaluationKeyBytes=offline"
            + ", securityLabel=" + params.getSecurityLabel();
    }

    private static long elapsedMs(long startNanos) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
    }

    private static void logPerf(String message) {
        if (FUSE_PIR_C_PERF_LOG) {
            System.err.println("[FusePIR-C-PERF] " + message);
        }
    }

    private static int oneHotLeafCount(int bound) {
        if (bound <= 1) {
            return 1;
        }
        int leaves = 1;
        while (leaves < bound) {
            leaves <<= 1;
        }
        return leaves;
    }
}
