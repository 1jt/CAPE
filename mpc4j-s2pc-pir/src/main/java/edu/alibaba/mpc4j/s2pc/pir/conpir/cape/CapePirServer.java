package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirPtoDesc.getInstance;

/**
 * CAPE PIR server.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirServer<T> extends AbstractTwoPartyPto {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CapePirServer.class);
    /**
     * CAPE perf log prefix.
     */
    private static final String PERF_PREFIX = "[CAPE-PERF]";
    /**
     * CAPE always-on checkpoint log prefix.
     */
    private static final String CHECKPOINT_PREFIX = "[CAPE-CHECKPOINT]";
    /**
     * Detailed CAPE perf logs are disabled by default to avoid perturbing timings.
     */
    private static final boolean PERF_LOG_ENABLED = Boolean.getBoolean("mpc4j.cape.perf");
    /**
     * Maximum attempts for selecting one seed that peels both formal BFFs.
     */
    private static final int MAX_SAME_SEED_ATTEMPTS = 1 << 10;
    /**
     * config.
     */
    private final CapePirConfig config;
    /**
     * params.
     */
    private final CapePirParams params;
    /**
     * keyword num.
     */
    private int keywordNum;
    /**
     * max batch num.
     */
    private int maxBatchNum;
    /**
     * cached forward index: value -> keyword set.
     */
    private Map<ByteBuffer, List<T>> valueKeywordMap;
    /**
     * cached value Bloom Filters: value -> BF(keyword-set(value)).
     */
    private Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters;
    /**
     * Deprecated test-only keyword payloads: keyword -> fingerprint || (value || value BF)*.
     */
    private Map<T, byte[]> keywordPayloadMap;
    /**
     * Deprecated test-only keyword payloads keyed by CAPE's canonical keyword byte encoding. This is used only by legacy
     * test helpers that intentionally bypass private FUSE_PIR candidate retrieval.
     */
    private Map<ByteBuffer, byte[]> keywordObjectPayloadMap;
    /**
     * Deprecated test-only FUSE_PIR-style packed full-payload BFF matrices.
     */
    private long[][][] fusepirMatrices;
    /**
     * value-only candidate matrices for the real CAPE response path.
     */
    private long[][][] valueOnlyMatrices;
    /**
     * Bloom-only candidate matrices for encrypted score computation.
     */
    private long[][][] bloomOnlyMatrices;
    /**
     * Deprecated test-only encoded FUSE_PIR-style full-payload matrices.
     */
    private List<byte[]> encodedFusePirMatrices;
    /**
     * encoded value-only matrices.
     */
    private List<byte[]> encodedValueOnlyMatrices;
    /**
     * encoded Bloom-only matrices.
     */
    private List<byte[]> encodedBloomOnlyMatrices;
    /**
     * value-only same-seed BFF storage for tests and formal matrixization.
     */
    private long[][] valueOnlyBffStorage;
    /**
     * Bloom-only same-seed BFF storage for tests and lazy deprecated bit-matrix helpers.
     */
    private long[][] bloomOnlyBffStorage;
    /**
     * Deprecated test-only Bloom-only matrices with one payload block per matrix group.
     */
    private long[][][] bloomOnlyBitMatrices;
    /**
     * BFF seed.
     */
    private byte[] bffSeed;
    /**
     * public key.
     */
    private byte[] publicKey;
    /**
     * relinearization keys for CtCt score products.
     */
    private byte[] relinKeys;
    /**
     * galois keys for Bloom slot-sum.
     */
    private byte[] galoisKeys;
    /**
     * setup-time LWE-to-RGSW evaluation key. It is held only between chunked receive and native handle creation.
     */
    private List<byte[]> lweToRgswKey;
    /**
     * Native handle for parsed LWE-to-RGSW evaluation key. 0 means uninitialized.
     */
    private long lweToRgswKeyHandle;
    /**
     * accumulated FUSE_PIR candidate retrieval time.
     */
    private long fusepirCandidateRetrievalTime;
    /**
     * accumulated Bloom inner product time.
     */
    private long bloomInnerProductTime;
    /**
     * accumulated encrypted value response bytes.
     */
    private long encryptedValueResponseByteLength;
    /**
     * accumulated encrypted score response bytes.
     */
    private long encryptedScoreResponseByteLength;

    public CapePirServer(Rpc serverRpc, Party clientParty, CapePirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(Map<T, List<byte[]>> keywordValueMap, int maxBatchNum) throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_num", keywordValueMap.size());
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        logCheckpoint("server init begin: keywordNum=%d, maxBatchNum=%d", keywordValueMap.size(), maxBatchNum);
        keywordNum = keywordValueMap.size();
        this.maxBatchNum = maxBatchNum;
        keywordPayloadMap = null;
        keywordObjectPayloadMap = null;
        fusepirMatrices = null;
        encodedFusePirMatrices = null;
        bloomOnlyBitMatrices = null;
        logPhaseInfo(PtoState.INIT_BEGIN);
        stopWatch.start();
        long totalInitStartTime = System.nanoTime();
        int valueByteLength = keywordValueMap.values().stream()
            .flatMap(List::stream)
            .findFirst()
            .map(value -> value.length)
            .orElseThrow(() -> new IllegalArgumentException("CAPE database must contain at least one value"));
        long stageStartTime = System.nanoTime();
        valueKeywordMap = CapePirUtils.buildForwardIndex(keywordValueMap);
        logPerf("buildForwardIndex time = %d ms", elapsedMillis(stageStartTime));
        int maxValueNumPerKeyword = keywordValueMap.values().stream().mapToInt(List::size).max().orElse(1);
        int maxValueKeywordSetSize = Math.max(1, valueKeywordMap.values().stream().mapToInt(List::size).max().orElse(1));
        params.initPirParams(
            keywordNum, valueByteLength, maxValueNumPerKeyword, config.getBoolKeywordNum(), maxValueKeywordSetSize
        );
        int exponent40BloomBitLength = CapePirParams.bloomBitSize(maxValueKeywordSetSize, CommonConstants.STATS_BIT_LENGTH);
        logPerf("alignedToFusePirParams = %s", params.alignedToFusePirParams());
        logPerf(
            "CAPE/FUSE_PIR params: polyModulusDegree=%d, plainModulus=%d, sealBfvCoeffModulus=BFVDefault(tc128), payloadElementBitLength=%d",
            params.getPolyModulusDegree(), params.getPlainModulus(), params.getPayloadElementBitLength()
        );
        logPerf("bloomExpectedInsertionsSource = maxValueKeywordSetSize");
        logPerf("maxValueKeywordSetSize = %d", maxValueKeywordSetSize);
        logPerf("bloomFalsePositiveExponent = %d", params.getBloomFalsePositiveExponent());
        logPerf("bloomFalsePositiveRate = 2^-%d", params.getBloomFalsePositiveExponent());
        logPerf("bloomExpectedInsertions = %d", params.getBloomExpectedInsertions());
        logPerf("bloomHashNum = %d", params.getBloomHashNum());
        logPerf("bloomBitLength before(exponent=40) = %d", exponent40BloomBitLength);
        logPerf("bloomBitLength after(exponent=10) = %d", params.getBloomBitLength());
        stageStartTime = System.nanoTime();
        valueBloomFilters = CapePirUtils.buildValueBloomFilters(valueKeywordMap, params);
        logPerf("buildValueBloomFilters time = %d ms", elapsedMillis(stageStartTime));
        logPerf("buildKeywordPayloadMap time = 0 ms (not built in formal init)");
        logPerf("build full payload BFF time = 0 ms (not built in formal init)");
        logPerf("matrixize full payload BFF time = 0 ms (not built in formal init)");
        logPerf("preprocess full payload matrices time = 0 ms (not built in formal init)");
        stageStartTime = System.nanoTime();
        Map<T, long[]> valueOnlyPayloadMap = buildValueOnlyLongPayloadMap(keywordValueMap);
        logPerf("buildValueOnlyPayloadMap time = %d ms", elapsedMillis(stageStartTime));
        stageStartTime = System.nanoTime();
        Map<ByteBuffer, List<byte[]>> canonicalKeywordValueMap = buildCanonicalKeywordValueMap(keywordValueMap);
        logPerf("buildBloomOnlyLongPayloadMap time = %d ms (streamed into BFF)", elapsedMillis(stageStartTime));
        Map<ByteBuffer, long[]> canonicalValueOnlyPayloadMap = CapePirUtils.toCanonicalLongPayloadMap(
            valueOnlyPayloadMap
        );
        ensureEncryptionParamsInitialized();
        stageStartTime = System.nanoTime();
        IndexedBloomPayloadPlan indexedBloomPayloadPlan = buildIndexedBloomPayloadPlan(
            canonicalKeywordValueMap, valueBloomFilters
        );
        long indexedPayloadPlanBuildTime = elapsedMillis(stageStartTime);
        logPerf("indexedPayloadPlanBuildTime = %d ms", indexedPayloadPlanBuildTime);
        stageStartTime = System.nanoTime();
        SameSeedBffBuildResult sameSeedBff = chooseSameSeedValueAndBloomBff(
            canonicalValueOnlyPayloadMap, indexedBloomPayloadPlan, params
        );
        bffSeed = sameSeedBff.seed;
        valueOnlyBffStorage = copyLongMatrix(sameSeedBff.valueBffStorage);
        bloomOnlyBffStorage = null;
        encodedBloomOnlyMatrices = sameSeedBff.encodedBloomOnlyMatrices.stream()
            .map(bytes -> Arrays.copyOf(bytes, bytes.length))
            .collect(Collectors.toList());
        long sameSeedBffTime = elapsedMillis(stageStartTime);
        logPerf("build value-only BFF time = %d ms (same-seed selection)", sameSeedBffTime);
        logPerf("build bloom-only BFF time = %d ms (same-seed streaming selection)", sameSeedBffTime);
        stageStartTime = System.nanoTime();
        valueOnlyMatrices = CapePirUtils.matrixizePackedBff(
            valueOnlyBffStorage, params, CapePirUtils.valueOnlyPayloadBlockNum(params),
            params.getValueBlocksPerPackedMatrix()
        );
        logPerf("matrixize value-only time = %d ms", elapsedMillis(stageStartTime));
        bloomOnlyMatrices = null;
        logPerf("matrixize bloom-only long payload time = 0 ms (streaming group-wise)");
        logPerf("build bloomOnlyBitMatrices time = 0 ms (not built in formal init)");
        stageStartTime = System.nanoTime();
        encodedValueOnlyMatrices = CapePirNativeUtils.preprocessDatabase(
            params.encryptionParams, valueOnlyMatrices, new long[0][]
        );
        logPerf("preprocess value-only matrices time = %d ms", elapsedMillis(stageStartTime));
        logPerf("preprocess bloom-only matrices time = %d ms (streaming group-wise)",
            sameSeedBff.bloomStats.getPreprocessTotalTimeMillis());
        logMemorySensitiveSizes(maxValueNumPerKeyword);
        logPerf("total init time = %d ms", elapsedMillis(totalInitStartTime));
        initState();
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);
        logPhaseInfo(PtoState.INIT_END);
        logCheckpoint("server init end: initTimeMs=%d, valueOnlyPayloadBlockNum=%d, bloomOnlyPayloadBlockNum=%d",
            initTime, CapePirUtils.valueOnlyPayloadBlockNum(params), params.getBloomPackedPayloadBlockNum());
    }

    public void receivePublicKeys() throws MpcAbortException {
        logCheckpoint("server receivePublicKeys begin: waiting for BFV keys");
        List<byte[]> bfvKeysPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_BFV_KEYS.ordinal());
        MpcAbortPreconditions.checkArgument(bfvKeysPayload.size() == 3);
        publicKey = bfvKeysPayload.get(0);
        relinKeys = bfvKeysPayload.get(1);
        galoisKeys = bfvKeysPayload.get(2);
        long publicKeyBytes = publicKey.length;
        long relinKeysBytes = relinKeys.length;
        long galoisKeysBytes = galoisKeys.length;
        logCheckpoint(
            "server received BFV keys: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d",
            publicKeyBytes, relinKeysBytes, galoisKeysBytes
        );
        logCheckpoint("server waiting LWE-to-RGSW meta");
        CapeSetupPayloadUtils.SetupMeta meta;
        try {
            meta = CapeSetupPayloadUtils.decodeMeta(
                receiveOtherPartyPayload(PtoStep.CLIENT_SEND_LWE_TO_RGSW_KEY_META.ordinal())
            );
        } catch (IllegalArgumentException e) {
            throw new MpcAbortException("invalid LWE-to-RGSW setup key metadata", e);
        }
        logCheckpoint(
            "server received LWE-to-RGSW meta: itemCount=%d, chunkCount=%d, totalBytes=%d, maxChunkBytes=%d",
            meta.getItemCount(), meta.getChunkCount(), meta.getTotalBytes(), meta.getMaxChunkBytes()
        );
        lweToRgswKey = new ArrayList<>(meta.getItemCount());
        long receivedLweToRgswKeyBytes = 0L;
        int receivedLweToRgswKeyItems = 0;
        for (int expectedChunkIndex = 0; expectedChunkIndex < meta.getChunkCount(); expectedChunkIndex++) {
            logCheckpoint("server waiting LWE-to-RGSW chunk %d/%d", expectedChunkIndex + 1, meta.getChunkCount());
            CapeSetupPayloadUtils.DecodedChunk chunk;
            try {
                chunk = CapeSetupPayloadUtils.decodeChunk(
                    receiveOtherPartyPayload(PtoStep.CLIENT_SEND_LWE_TO_RGSW_KEY_CHUNK.ordinal())
                );
            } catch (IllegalArgumentException e) {
                throw new MpcAbortException("invalid LWE-to-RGSW setup key chunk", e);
            }
            MpcAbortPreconditions.checkArgument(chunk.getChunkIndex() == expectedChunkIndex);
            MpcAbortPreconditions.checkArgument(chunk.getItemCount() == chunk.getItems().size());
            if (chunk.getByteLength() + 2L * Integer.BYTES > meta.getMaxChunkBytes()) {
                MpcAbortPreconditions.checkArgument(chunk.getItemCount() == 1);
                LOGGER.warn(
                    "{} server received oversized single-item LWE-to-RGSW chunk: chunkIndex={}, chunkBytes={}, "
                        + "maxChunkBytes={}",
                    CHECKPOINT_PREFIX, chunk.getChunkIndex(), chunk.getByteLength(), meta.getMaxChunkBytes()
                );
            }
            lweToRgswKey.addAll(chunk.getItems());
            receivedLweToRgswKeyItems += chunk.getItemCount();
            receivedLweToRgswKeyBytes += chunk.getByteLength();
            logCheckpoint(
                "server received LWE-to-RGSW chunk %d/%d: chunkBytes=%d, chunkItems=%d, receivedItemsSoFar=%d",
                chunk.getChunkIndex() + 1, meta.getChunkCount(), chunk.getByteLength(), chunk.getItemCount(),
                receivedLweToRgswKeyItems
            );
        }
        MpcAbortPreconditions.checkArgument(receivedLweToRgswKeyItems == meta.getItemCount());
        MpcAbortPreconditions.checkArgument(receivedLweToRgswKeyBytes == meta.getTotalBytes());
        long lweToRgswKeyBytes = receivedLweToRgswKeyBytes;
        long totalSetupBytes = publicKeyBytes + relinKeysBytes + galoisKeysBytes + lweToRgswKeyBytes;
        logCheckpoint(
            "server receivePublicKeys end: lweToRgswKeyItemCount=%d, lweToRgswKeyBytes=%d, totalSetupBytes=%d, "
                + "setupChunkCount=%d, maxSetupChunkBytes=%d",
            lweToRgswKey.size(), lweToRgswKeyBytes, totalSetupBytes, meta.getChunkCount(), meta.getMaxChunkBytes()
        );
        logCheckpoint(
            "server setup payload bytes: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d, "
                + "lweToRgswKeyBytes=%d, totalSetupBytes=%d, setupDataPacketNum=%d",
            publicKeyBytes, relinKeysBytes, galoisKeysBytes, lweToRgswKeyBytes, totalSetupBytes,
            2 + meta.getChunkCount()
        );
        logPerf(
            "setup/offline bytes: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d, lweToRgswKeyBytes=%d",
            publicKey.length, relinKeys.length, galoisKeys.length, byteLength(lweToRgswKey)
        );
        logPerf("setupLweToRgswKeyBytes = %d", byteLength(lweToRgswKey));
        ensureEncryptionParamsInitialized();
        long createHandleStartTime = System.nanoTime();
        logCheckpoint(
            "server createLweToRgswKeyHandle begin: serializedLweToRgswKeyBytes=%d, "
                + "serializedLweToRgswKeyItemCount=%d",
            lweToRgswKeyBytes, lweToRgswKey.size()
        );
        lweToRgswKeyHandle = CapePirNativeUtils.createLweToRgswKeyHandle(
            params.encryptionParams, publicKey, lweToRgswKey
        );
        if (lweToRgswKeyHandle == 0L) {
            throw new MpcAbortException("CAPE native LWE-to-RGSW key handle creation failed");
        }
        long nativeCreateMs = elapsedMillis(createHandleStartTime);
        logCheckpoint("server createLweToRgswKeyHandle end: handle=%d, nativeCreateMs=%d",
            lweToRgswKeyHandle, nativeCreateMs);
        lweToRgswKey.clear();
        lweToRgswKey = null;
        logCheckpoint("server released Java lweToRgswKey list");
    }

    private void ensureEncryptionParamsInitialized() {
        if (params.encryptionParams == null) {
            params.encryptionParams = CapePirNativeUtils.generateEncryptionParams(
                params.getPolyModulusDegree(), params.getPlainModulus(), params.getCoeffModulusBits()
            );
            logCheckpoint(
                "server generated encryption params before setup handle creation: polyModulusDegree=%d, "
                    + "plainModulus=%d, sealBfvCoeffModulus=BFVDefault(tc128), encryptionParamsBytes=%d",
                params.getPolyModulusDegree(), params.getPlainModulus(), params.encryptionParams.length
            );
        }
    }

    public void sendBffSeed() {
        if (bffSeed == null) {
            throw new IllegalStateException("BFF seed is not initialized");
        }
        byte[] bloomParams = params.serializeBloomParams();
        logPerf("bffSeedBytes = %d", bffSeed.length);
        logPerf("bloomParamsBytes = %d", bloomParams.length);
        logCheckpoint("server sendBffSeed: bffSeedBytes=%d, bloomParamsBytes=%d", bffSeed.length, bloomParams.length);
        sendOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal(), List.of(bffSeed, bloomParams));
    }

    public void pir(int batchNum) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", batchNum, maxBatchNum);
        if (!config.getQueryMethod().equals(CapePirQueryMethod.AND)) {
            throw new UnsupportedOperationException("CAPE currently only supports AND queries");
        }
        logPhaseInfo(PtoState.PTO_BEGIN);
        fusepirCandidateRetrievalTime = 0L;
        bloomInnerProductTime = 0L;
        encryptedValueResponseByteLength = 0L;
        encryptedScoreResponseByteLength = 0L;
        int expectedQueryPayloadSize = params.getBffHashNum() + params.getBffHashNum()
            + params.getCoeffBloomCiphertextNum();
        for (int batchIndex = 0; batchIndex < batchNum; batchIndex++) {
            logCheckpoint("server receive query before: batchIndex=%d, expectedPayloadCount=%d", batchIndex,
                expectedQueryPayloadSize);
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal());
            logCheckpoint("server receive query after: batchIndex=%d, queryPayloadCount=%d, queryPayloadBytes=%d",
                batchIndex, queryPayload.size(), byteLength(queryPayload));
            stopWatch.start();
            long parseStartTime = System.nanoTime();
            if (queryPayload.size() != expectedQueryPayloadSize) {
                logCheckpoint(
                    "server query payload count mismatch: expected=%d, actual=%d, bffHashNum=%d, "
                        + "packedQueryBloomCiphertextNum=%d, blocksPerPackedMatrix=%d, bloomBitLength=%d",
                    expectedQueryPayloadSize, queryPayload.size(), params.getBffHashNum(),
                    params.getCoeffBloomCiphertextNum(), params.getBlocksPerPackedMatrix(),
                    params.getBloomBitLength()
                );
            }
            MpcAbortPreconditions.checkArgument(queryPayload.size() == expectedQueryPayloadSize);
            List<byte[]> columnQueries = new ArrayList<>(params.getBffHashNum());
            List<byte[]> compressedRowBitQueries = new ArrayList<>(params.getBffHashNum());
            for (int positionIndex = 0; positionIndex < params.getBffHashNum(); positionIndex++) {
                columnQueries.add(queryPayload.get(positionIndex));
            }
            int rowBitOffset = params.getBffHashNum();
            for (int positionIndex = 0; positionIndex < params.getBffHashNum(); positionIndex++) {
                compressedRowBitQueries.add(queryPayload.get(rowBitOffset + positionIndex));
            }
            int bloomBitOffset = rowBitOffset + params.getBffHashNum();
            List<byte[]> encryptedCoeffBloomFilters = queryPayload.subList(bloomBitOffset, queryPayload.size());
            logPerf("parse query time = %d ms", elapsedMillis(parseStartTime));
            long rowConversionStartTime = System.nanoTime();
            logCheckpoint("compressed row conversion begin: compressedRowBitQueryCount=%d, compressedRowBitQueryBytes=%d",
                compressedRowBitQueries.size(), byteLength(compressedRowBitQueries));
            List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(compressedRowBitQueries);
            logCheckpoint("compressed row conversion end: rgswRowBitCount=%d, rgswRowBitBytes=%d, timeMs=%d",
                encryptedRowBits.size(), byteLength(encryptedRowBits), elapsedMillis(rowConversionStartTime));
            logPerf("compressed row conversion time = %d ms", elapsedMillis(rowConversionStartTime));
            long candidateStartTime = System.nanoTime();
            logCheckpoint("value candidate reply begin: valueOnlyPayloadBlockNum=%d, expectedValueCiphertextCount=%d",
                CapePirUtils.valueOnlyPayloadBlockNum(params), getExpectedValueCiphertextCount());
            if (PERF_LOG_ENABLED) {
                logPerf("valuePayloadByteLength = %d", CapePirUtils.valueOnlyPayloadByteLength(params));
                logPerf("valueItemByteLength = %d", CapePirUtils.valueOnlyItemByteLength(params));
                logPerf("fingerprintByteLength = %d", params.getFingerprintByteLength());
                logPerf("maxValueNumPerKeyword = %d", params.getMaxValueNumPerKeyword());
                logPerf("payloadElementBitLength = %d", params.getPayloadElementBitLength());
                logPerf("valuePayloadElementNum = %d", CapePirUtils.valueOnlyPayloadBlockNum(params));
                logPerf("valueBlocksPerPackedMatrix = %d", params.getValueBlocksPerPackedMatrix());
                logPerf("bloomPackedCoefficientStride = %d", params.getBloomPackedCoefficientStride());
                logPerf("bloomPerPackedBlock = %d", params.getBloomPerPackedBlock());
                logPerf("valueReplyCiphertextCount expected = %d", getExpectedValueCiphertextCount());
            }
            List<byte[]> encryptedValuePayloads = generateCandidateReplyGroups(
                columnQueries, encryptedRowBits, encodedValueOnlyMatrices, CapePirUtils.valueOnlyPayloadBlockNum(params)
            );
            logCheckpoint("value candidate reply end: valueCiphertextCount=%d, valueReplyBytes=%d, timeMs=%d",
                encryptedValuePayloads.size(), byteLength(encryptedValuePayloads), elapsedMillis(candidateStartTime));
            logPerf("value candidate reply generation time = %d ms", elapsedMillis(candidateStartTime));
            logPerf("valueReplyCiphertextCount actual = %d", encryptedValuePayloads.size());
            MpcAbortPreconditions.checkArgument(encryptedValuePayloads.size() == getExpectedValueCiphertextCount());
            int bloomGroupCount = 0;
            if (PERF_LOG_ENABLED) {
                int bloomPayloadBlockNum = params.getBloomPackedPayloadBlockNum();
                bloomGroupCount = getPackedMatrixGroupNum(bloomPayloadBlockNum);
                logPerf("bloom-only payloadBlockNum = %d", bloomPayloadBlockNum);
                logPerf("bloom-only packed group count = %d", bloomGroupCount);
                logPerf("bloomBitLength = %d", params.getBloomBitLength());
                logPerf("maxValueNumPerKeyword = %d", params.getMaxValueNumPerKeyword());
                logPerf("compactPerValueCoeffBloomCiphertextNum = %d", params.getCompactCoeffBloomCiphertextNum());
                logPerf("globalTiledCoeffBloomCiphertextNum = %d", params.getGlobalTiledCoeffBloomCiphertextNum());
                logPerf("oldEncryptedCoeffBloomFilterCount = %d", params.getPackedBloomQueryCiphertextNum());
                logPerf("packedQueryBloomCiphertextNum = %d", params.getPackedQueryBloomCiphertextNum());
                logPerf("polyModulusDegree = %d", params.getPolyModulusDegree());
                logPerf("encryptedCoeffBloomFilters count = %d", encryptedCoeffBloomFilters.size());
                logPerf("encryptedCoeffBloomFilters bytes = %d", byteLength(encryptedCoeffBloomFilters));
                logPerf("nativeCallCountBefore = %d", bloomGroupCount + 1);
                logPerf("nativeCallCountAfter = 1");
                logPerf("old bloom candidate reply generation skipped in fused formal path");
                logPerf("old score inner product skipped in fused formal path");
            }
            long fusedStartTime = System.nanoTime();
            logCheckpoint(
                "packed Bloom score generation begin: packedBloomQueryCiphertextCount=%d, packedBloomQueryBytes=%d, "
                    + "if no end log appears, packed Bloom score generation is the bottleneck; "
                    + "suggestion=continue BKPIR-style packed Bloom query vector",
                encryptedCoeffBloomFilters.size(), byteLength(encryptedCoeffBloomFilters)
            );
            List<byte[]> encryptedScores = generateFusedPackedCoeffScoresPackedBloom(
                columnQueries, encryptedRowBits, encryptedCoeffBloomFilters
            );
            long fusedTime = elapsedMillis(fusedStartTime);
            logCheckpoint("packed Bloom score generation end: scoreCiphertextCount=%d, scoreReplyBytes=%d, timeMs=%d",
                encryptedScores.size(), byteLength(encryptedScores), fusedTime);
            logPerf("packed Bloom score generation time = %d ms", fusedTime);
            logPerf("avg fused group time = %d ms", bloomGroupCount == 0 ? 0 : fusedTime / bloomGroupCount);
            logPerf("matrix selection / row selection / serialization time = included in fused native time");
            logPerf("Java list append / candidateBloomReplies construction time = 0 ms (not returned in formal path)");
            fusepirCandidateRetrievalTime += TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - candidateStartTime);
            bloomInnerProductTime += fusedTime;
            long valueReplyBytes = byteLength(encryptedValuePayloads);
            long scoreReplyBytes = byteLength(encryptedScores);
            long mergeStartTime = System.nanoTime();
            List<byte[]> packedResultCiphertexts = mergePackedResultResponse(encryptedValuePayloads, encryptedScores);
            long mergeTime = elapsedMillis(mergeStartTime);
            long packedResultBytes = byteLength(packedResultCiphertexts);
            encryptedValueResponseByteLength += packedResultBytes;
            encryptedScoreResponseByteLength += 0L;
            int packedScoreCapacity = getPackedScoreCapacity();
            int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
            MpcAbortPreconditions.checkArgument(encryptedScores.size() == expectedScoreCiphertextCount);
            if (PERF_LOG_ENABLED) {
                logPerf("valueReplyBytes = %d", valueReplyBytes);
                logPerf("valueReplyCiphertextCount before = 2");
                logPerf("valueReplyCiphertextCount after = %d", encryptedValuePayloads.size());
                logPerf("scoreReplyBytesBefore = not generated in packed formal path");
                logPerf("scoreReplyBytes = %d", scoreReplyBytes);
                logPerf("scoreReplyCiphertextCount = %d", encryptedScores.size());
                logPerf("scoreCiphertextCountBefore = %d", params.getMaxValueNumPerKeyword());
                logPerf("scoreCiphertextCountAfter = %d", encryptedScores.size());
                logPerf("packedScoreCapacity = %d", packedScoreCapacity);
                logPerf("maxValueNumPerKeyword = %d", params.getMaxValueNumPerKeyword());
                logPerf("polyModulusDegree = %d", params.getPolyModulusDegree());
                logPerf("expectedScoreCiphertextCount = %d", expectedScoreCiphertextCount);
                logPerf("valuePayloadCoeffNum = %d", params.getValuePayloadCoeffNum());
                logPerf("scoreCoeffNum = %d", params.getScoreCoeffNum());
                logPerf("scoreOffset = %d", params.getScoreOffset());
                logPerf("totalResultCoeffNum = %d", params.getTotalResultCoeffNum());
                logPerf("expectedResultCiphertextCount = %d", params.getExpectedPackedResultCiphertextCount());
                logPerf("actualResultCiphertextCount = %d", packedResultCiphertexts.size());
                logPerf("oldSeparateResponseCiphertextCount = %d",
                    encryptedValuePayloads.size() + encryptedScores.size());
                logPerf("oldSeparateResponseBytes = %d", valueReplyBytes + scoreReplyBytes);
                logPerf("newPackedResultResponseBytes = %d", packedResultBytes);
                logPerf("score merge / packed result assembly time = %d ms", mergeTime);
            }
            long responseSerializationStartTime = System.nanoTime();
            List<byte[]> responsePayload = packedResultCiphertexts;
            logPerf("response serialization time = %d ms", elapsedMillis(responseSerializationStartTime));
            if (PERF_LOG_ENABLED) {
                long responseBytes = byteLength(responsePayload);
                logPerf("response bytes = %d", responseBytes);
                logPerf("totalResponseBytes = %d", responseBytes);
            }
            logCheckpoint("response send before: responsePayloadCount=%d, responsePayloadBytes=%d, sendOnceConfirmed=true",
                responsePayload.size(), byteLength(responsePayload));
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), responsePayload);
            logCheckpoint("response send after: responsePayloadCount=%d, responsePayloadBytes=%d, sendOnceConfirmed=true",
                responsePayload.size(), byteLength(responsePayload));
            stopWatch.stop();
            long replyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 1, replyTime, "Server generates CAPE reply");
        }
        logPhaseInfo(PtoState.PTO_END);
    }

    CapePirResponse generateReply(CapePirQuery query) {
        checkInitialized();
        if (publicKey == null || relinKeys == null || galoisKeys == null || lweToRgswKeyHandle == 0L) {
            throw new IllegalStateException(
                "publicKey, relinKeys, galoisKeys, and LWE-to-RGSW key handle must be set before generating CAPE reply"
            );
        }
        long rowConversionStartTime = System.nanoTime();
        List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(query.getCompressedRowBitQueries());
        logPerf("compressed row conversion time = %d ms", elapsedMillis(rowConversionStartTime));
        long candidateStartTime = System.nanoTime();
        List<byte[]> encryptedValuePayloads = generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedValueOnlyMatrices,
            CapePirUtils.valueOnlyPayloadBlockNum(params)
        );
        logPerf("value candidate reply generation time = %d ms", elapsedMillis(candidateStartTime));
        if (encryptedValuePayloads.size() != getExpectedValueCiphertextCount()) {
            throw new IllegalStateException("CAPE candidate retrieval returned invalid payload ciphertexts");
        }
        long fusedStartTime = System.nanoTime();
        List<byte[]> encryptedScores = generateFusedPackedCoeffScoresPackedBloom(
            query.getFusePirColumnQueries(), encryptedRowBits, query.getEncryptedCoeffBloomFilters()
        );
        logPerf("packed Bloom score generation time = %d ms", elapsedMillis(fusedStartTime));
        if (PERF_LOG_ENABLED) {
            long valueReplyBytes = byteLength(encryptedValuePayloads);
            long scoreReplyBytes = byteLength(encryptedScores);
            List<byte[]> packedResultCiphertexts = mergePackedResultResponse(encryptedValuePayloads, encryptedScores);
            logPerf("valueReplyBytes = %d", valueReplyBytes);
            logPerf("scoreReplyBytes = %d", scoreReplyBytes);
            logPerf("oldSeparateResponseBytes = %d", valueReplyBytes + scoreReplyBytes);
            logPerf("newPackedResultResponseBytes = %d", byteLength(packedResultCiphertexts));
            logPerf("response bytes = %d", byteLength(packedResultCiphertexts));
            logPerf("totalResponseBytes = %d", byteLength(packedResultCiphertexts));
        }
        return CapePirResponse.createPackedResultResponse(mergePackedResultResponse(encryptedValuePayloads, encryptedScores));
    }

    @Deprecated
    CapePirResponse generateGlobalTiledReplyForTest(CapePirQuery query, List<byte[]> globalTiledEncryptedCoeffBloomFilters) {
        checkInitialized();
        List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(query.getCompressedRowBitQueries());
        List<byte[]> encryptedValuePayloads = generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedValueOnlyMatrices,
            CapePirUtils.valueOnlyPayloadBlockNum(params)
        );
        if (encryptedValuePayloads.size() != getExpectedValueCiphertextCount()) {
            throw new IllegalStateException("CAPE candidate retrieval returned invalid payload ciphertexts");
        }
        List<byte[]> encryptedScores = generateFusedPackedCoeffScoresGlobalTiled(
            query.getFusePirColumnQueries(), encryptedRowBits, globalTiledEncryptedCoeffBloomFilters
        );
        return new CapePirResponse(encryptedValuePayloads, encryptedScores);
    }

    /**
     * Test-only diagnostic helper for comparing direct and compressed row-bit candidate retrieval. The formal server
     * path must use compressed row-bit queries.
     */
    @Deprecated
    List<byte[]> generateValueCandidateReplyWithRowBitsForTest(CapePirQuery query, List<byte[]> encryptedRowBits) {
        checkInitialized();
        if (publicKey == null) {
            throw new IllegalStateException("publicKey must be set before generating CAPE value reply");
        }
        return generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedValueOnlyMatrices,
            CapePirUtils.valueOnlyPayloadBlockNum(params)
        );
    }

    /**
     * Test-only diagnostic helper for exposing compressed row-bit conversion output. The formal server path does not
     * expose intermediate row bits.
     */
    @Deprecated
    List<byte[]> convertCompressedRowBitQueriesForTest(List<byte[]> compressedRowBitQueries) {
        return convertCompressedRowBitQueries(compressedRowBitQueries);
    }

    CapePirResponse generateTwoStageReplyForTest(CapePirQuery query) {
        return generateTwoStageReplyForTest(query, query.getEncryptedCoeffBloomFilters());
    }

    @Deprecated
    CapePirResponse generateTwoStageReplyForTest(CapePirQuery query, List<byte[]> encryptedCoeffBloomFilters) {
        checkInitialized();
        if (publicKey == null || relinKeys == null || galoisKeys == null || lweToRgswKeyHandle == 0L) {
            throw new IllegalStateException(
                "publicKey, relinKeys, galoisKeys, and LWE-to-RGSW key handle must be set before generating CAPE reply"
            );
        }
        List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(query.getCompressedRowBitQueries());
        List<byte[]> encryptedValuePayloads = generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedValueOnlyMatrices,
            CapePirUtils.valueOnlyPayloadBlockNum(params)
        );
        List<byte[]> encryptedBloomGroups = generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedBloomOnlyMatrices,
            CapePirUtils.bloomOnlyPayloadByteLength(params)
        );
        if (encryptedValuePayloads.size() != getExpectedValueCiphertextCount()) {
            throw new IllegalStateException("CAPE candidate retrieval returned invalid payload ciphertexts");
        }
        List<byte[]> encryptedScores = generatePackedCoeffScores(encryptedCoeffBloomFilters, encryptedBloomGroups);
        return new CapePirResponse(encryptedValuePayloads, encryptedScores);
    }

    private List<byte[]> generateFusedPackedCoeffScores(List<byte[]> columnQueries, List<byte[]> encryptedRowBits,
                                                        List<byte[]> encryptedCoeffBloomFilters) {
        if (params.getMaxValueNumPerKeyword() > getPackedScoreCapacity()) {
            throw new IllegalStateException("CAPE packed score response requires maxValueNumPerKeyword <= packedScoreCapacity");
        }
        List<byte[]> encryptedScores = CapePirNativeUtils.generateFusedPackedCoeffCtCtBloomScores(
            params.encryptionParams, publicKey, relinKeys, galoisKeys, columnQueries, encryptedRowBits,
            encodedBloomOnlyMatrices, encryptedCoeffBloomFilters, CapePirUtils.bloomOnlyPayloadByteLength(params),
            params.getMatrixRowNum(), params.getMatrixColNum(), params.getBlocksPerPackedMatrix(),
            params.getMaxValueNumPerKeyword()
        );
        int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
        if (encryptedScores.size() != expectedScoreCiphertextCount) {
            throw new IllegalStateException("CAPE packed score ciphertext count mismatch");
        }
        return encryptedScores;
    }

    private List<byte[]> generateFusedPackedCoeffScoresGlobalTiled(List<byte[]> columnQueries,
                                                                   List<byte[]> encryptedRowBits,
                                                                   List<byte[]> encryptedCoeffBloomFilters) {
        if (params.getMaxValueNumPerKeyword() > getPackedScoreCapacity()) {
            throw new IllegalStateException("CAPE packed score response requires maxValueNumPerKeyword <= packedScoreCapacity");
        }
        List<byte[]> encryptedScores = CapePirNativeUtils.generateFusedPackedCoeffCtCtBloomScoresGlobalTiled(
            params.encryptionParams, publicKey, relinKeys, galoisKeys, columnQueries, encryptedRowBits,
            encodedBloomOnlyMatrices, encryptedCoeffBloomFilters, params.getBloomPackedPayloadBlockNum(),
            params.getMatrixRowNum(), params.getMatrixColNum(), params.getBlocksPerPackedMatrix(),
            params.getMaxValueNumPerKeyword(), params.getBloomBitLength()
        );
        int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
        if (encryptedScores.size() != expectedScoreCiphertextCount) {
            throw new IllegalStateException("CAPE packed score ciphertext count mismatch");
        }
        return encryptedScores;
    }

    private List<byte[]> generateFusedPackedCoeffScoresPackedBloom(List<byte[]> columnQueries,
                                                                   List<byte[]> encryptedRowBits,
                                                                   List<byte[]> encryptedCoeffBloomFilters) {
        if (params.getMaxValueNumPerKeyword() > getPackedScoreCapacity()) {
            throw new IllegalStateException("CAPE packed score response requires maxValueNumPerKeyword <= packedScoreCapacity");
        }
        List<byte[]> encryptedScores = CapePirNativeUtils.generateFusedPackedCoeffCtCtBloomScoresPackedBloom(
            params.encryptionParams, publicKey, relinKeys, galoisKeys, columnQueries, encryptedRowBits,
            encodedBloomOnlyMatrices, encryptedCoeffBloomFilters, params.getBloomPackedPayloadBlockNum(),
            params.getMatrixRowNum(), params.getMatrixColNum(), params.getBloomPackedMatrixColumnCapacity(),
            params.getBlocksPerPackedMatrix(),
            params.getBloomPackedCoefficientStride(),
            params.getMaxValueNumPerKeyword(), params.getBloomBitLength()
        );
        int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
        if (encryptedScores.size() != expectedScoreCiphertextCount) {
            throw new IllegalStateException("CAPE packed score ciphertext count mismatch");
        }
        return encryptedScores;
    }

    private List<byte[]> generatePackedCoeffScores(List<byte[]> encryptedCoeffBloomFilters,
                                                   List<byte[]> encryptedBloomGroups) {
        if (params.getMaxValueNumPerKeyword() > getPackedScoreCapacity()) {
            throw new IllegalStateException("CAPE packed score response requires maxValueNumPerKeyword <= packedScoreCapacity");
        }
        List<byte[]> encryptedScores = CapePirNativeUtils.generatePackedCoeffCtCtBloomInnerProductsFromGroupQueries(
            params.encryptionParams, publicKey, relinKeys, galoisKeys, encryptedCoeffBloomFilters, encryptedBloomGroups,
            params.getMaxValueNumPerKeyword()
        );
        int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
        if (encryptedScores.size() != expectedScoreCiphertextCount) {
            throw new IllegalStateException("CAPE packed score ciphertext count mismatch");
        }
        return encryptedScores;
    }

    private List<byte[]> convertCompressedRowBitQueries(List<byte[]> compressedRowBitQueries) {
        if (lweToRgswKeyHandle == 0L) {
            throw new IllegalStateException("CAPE LWE-to-RGSW setup key handle is not initialized");
        }
        if (compressedRowBitQueries.size() != params.getBffHashNum()) {
            throw new IllegalArgumentException("CAPE compressed row-bit query count mismatch");
        }
        int rowBitNum = ceilLog2(params.getMatrixRowNum());
        List<CapeLweCiphertext> recoveredLweBits = new ArrayList<>(params.getBffHashNum() * rowBitNum);
        for (byte[] compressedRowBitQuery : compressedRowBitQueries) {
            CapeCompressedLweBitQuery compressedQuery = CapeCompressedLweBitQuery.fromByteArray(compressedRowBitQuery);
            if (compressedQuery.getBitNum() != rowBitNum) {
                throw new IllegalArgumentException(
                    "CAPE compressed row-bit bitNum mismatch: expected=" + rowBitNum
                        + ", actual=" + compressedQuery.getBitNum()
                        + ", matrixRowNum=" + params.getMatrixRowNum()
                );
            }
            recoveredLweBits.addAll(CapeLwePrgUtils.recoverLweBitCiphertexts(compressedQuery));
        }
        long[][] aArray = new long[recoveredLweBits.size()][];
        long[] bArray = new long[recoveredLweBits.size()];
        for (int bitIndex = 0; bitIndex < recoveredLweBits.size(); bitIndex++) {
            aArray[bitIndex] = recoveredLweBits.get(bitIndex).getA();
            bArray[bitIndex] = recoveredLweBits.get(bitIndex).getB();
        }
        long conversionStartTime = System.nanoTime();
        List<byte[]> rowBits = CapePirNativeUtils.convertCompressedRowBitsToRgswWithHandle(
            params.encryptionParams, publicKey, lweToRgswKeyHandle, aArray, bArray
        );
        logPerf("compressedRowConversionWithHandleMs = %d", elapsedMillis(conversionStartTime));
        int expectedRowBitSize = params.getBffHashNum() * rowBitNum;
        if (rowBits.size() != expectedRowBitSize) {
            throw new IllegalStateException("CAPE converted RGSW row-bit count mismatch");
        }
        return rowBits;
    }

    byte[] generateBloomPayloadForTest(CapePirQuery query) {
        List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(query.getCompressedRowBitQueries());
        List<byte[]> encryptedBloomPayloads = generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedBloomOnlyMatrices,
            CapePirUtils.bloomOnlyPayloadByteLength(params)
        );
        if (encryptedBloomPayloads.isEmpty()) {
            throw new IllegalStateException("CAPE candidate Bloom retrieval returned empty payload");
        }
        return encryptedBloomPayloads.get(0);
    }

    /**
     * Returns encrypted candidate Bloom groups for tests. Real protocol code must only use these ciphertexts
     * internally to compute CtCt scores and must not send them to the client.
     */
    List<byte[]> generateBloomPayloadGroupsForTest(CapePirQuery query) {
        List<byte[]> encryptedRowBits = convertCompressedRowBitQueries(query.getCompressedRowBitQueries());
        return generateCandidateReplyGroups(
            query.getFusePirColumnQueries(), encryptedRowBits, encodedBloomOnlyMatrices,
            CapePirUtils.bloomOnlyPayloadByteLength(params)
        );
    }

    /**
     * Legacy correctness helper that leaks the anchor keyword and encrypts plaintext candidate fields on the server.
     * This is not a valid CAPE protocol path. The real protocol must retrieve encrypted candidate items, split
     * {@code Enc(item)} into {@code Enc(value)} and {@code Enc(B_v)}, and then compute CtCt Bloom scores.
     */
    @Deprecated
    CapePirResponse generateReplyForTest(CapePirQuery query) {
        checkInitialized();
        if (publicKey == null || relinKeys == null || galoisKeys == null) {
            throw new IllegalStateException("publicKey, relinKeys, and galoisKeys must be set before generating CAPE reply");
        }
        ensureLegacyKeywordObjectPayloadMap();
        byte[] anchorPayload = keywordObjectPayloadMap.get(ByteBuffer.wrap(query.getAnchorKeywordBytes()));
        List<CapePirUtils.ValueWithBloomFilter> candidateItems = anchorPayload == null
            ? List.of()
            : CapePirUtils.parseKeywordPayloadItems(anchorPayload, params);
        List<byte[]> encryptedValuePayloads = encryptCandidateValues(candidateItems);
        List<byte[]> encryptedScores = CapePirNativeUtils.generateCtCtBloomInnerProducts(
            params.encryptionParams, publicKey, relinKeys, galoisKeys, query.getEncryptedBloomFilter(),
            encryptCandidateBloomFilters(candidateItems)
        );
        return new CapePirResponse(encryptedValuePayloads, encryptedScores);
    }

    public Map<ByteBuffer, List<T>> getValueKeywordMap() {
        return valueKeywordMap;
    }

    CapePirParams getCapeParams() {
        return params;
    }

    Map<ByteBuffer, CapeBloomFilterAdapter> getValueBloomFilters() {
        return valueBloomFilters;
    }

    Map<T, byte[]> getKeywordPayloadMap() {
        ensureLegacyKeywordPayloadMap();
        return keywordPayloadMap.entrySet().stream()
            .collect(Collectors.toMap(
                Map.Entry::getKey,
                entry -> Arrays.copyOf(entry.getValue(), entry.getValue().length),
                (left, right) -> left,
                LinkedHashMap::new
            ));
    }

    long[][][] getFusePirMatrices() {
        ensureLegacyFusePirMatrices();
        return Arrays.stream(fusepirMatrices)
            .map(matrix -> Arrays.stream(matrix)
                .map(row -> Arrays.copyOf(row, row.length))
                .toArray(long[][]::new))
            .toArray(long[][][]::new);
    }

    List<byte[]> getEncodedFusePirMatrices() {
        ensureLegacyEncodedFusePirMatrices();
        return encodedFusePirMatrices.stream()
            .map(bytes -> Arrays.copyOf(bytes, bytes.length))
            .collect(Collectors.toList());
    }

    byte[] getBffSeed() {
        return Arrays.copyOf(bffSeed, bffSeed.length);
    }

    List<ByteBuffer> getValueOrder() {
        return valueBloomFilters.keySet().stream()
            .map(value -> {
                ByteBuffer duplicate = value.asReadOnlyBuffer();
                duplicate.rewind();
                byte[] bytes = new byte[duplicate.remaining()];
                duplicate.get(bytes);
                return ByteBuffer.wrap(bytes);
            })
            .collect(Collectors.toList());
    }

    void setPublicKey(byte[] publicKey) {
        this.publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    void setGaloisKeys(byte[] galoisKeys) {
        this.galoisKeys = Arrays.copyOf(galoisKeys, galoisKeys.length);
    }

    void setRelinKeys(byte[] relinKeys) {
        this.relinKeys = Arrays.copyOf(relinKeys, relinKeys.length);
    }

    void setLweToRgswKey(List<byte[]> lweToRgswKey) {
        this.lweToRgswKey = new ArrayList<>(lweToRgswKey);
        if (lweToRgswKeyHandle != 0L) {
            CapePirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        if (publicKey != null && params.encryptionParams != null && !this.lweToRgswKey.isEmpty()) {
            lweToRgswKeyHandle = CapePirNativeUtils.createLweToRgswKeyHandle(
                params.encryptionParams, publicKey, this.lweToRgswKey
            );
            this.lweToRgswKey.clear();
            this.lweToRgswKey = null;
        }
    }

    void releaseLargeStateForTest() {
        if (lweToRgswKeyHandle != 0L) {
            CapePirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        publicKey = null;
        relinKeys = null;
        galoisKeys = null;
        lweToRgswKey = null;
        encodedValueOnlyMatrices = null;
        encodedBloomOnlyMatrices = null;
        encodedFusePirMatrices = null;
        fusepirMatrices = null;
        bloomOnlyBitMatrices = null;
    }

    long getLweToRgswKeyHandleForTest() {
        return lweToRgswKeyHandle;
    }

    boolean isJavaLweToRgswKeyReleasedForTest() {
        return lweToRgswKey == null || lweToRgswKey.isEmpty();
    }

    @Override
    public void destroy() {
        if (lweToRgswKeyHandle != 0L) {
            logCheckpoint("server destroyLweToRgswKeyHandle handle=%d", lweToRgswKeyHandle);
            CapePirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        if (lweToRgswKey != null) {
            lweToRgswKey.clear();
            lweToRgswKey = null;
        }
        super.destroy();
    }

    public long getFusePirCandidateRetrievalTime() {
        return fusepirCandidateRetrievalTime;
    }

    public long getBloomInnerProductTime() {
        return bloomInnerProductTime;
    }

    public long getEncryptedValueResponseByteLength() {
        return encryptedValueResponseByteLength;
    }

    public long getEncryptedScoreResponseByteLength() {
        return encryptedScoreResponseByteLength;
    }

    long[][] getValueOnlyBffStorage() {
        return copyLongMatrix(valueOnlyBffStorage);
    }

    long[][] getBloomOnlyBffStorage() {
        if (bloomOnlyBffStorage == null) {
            bloomOnlyBffStorage = buildBloomOnlyBffStorageForTest();
        }
        return copyLongMatrix(bloomOnlyBffStorage);
    }

    boolean isLegacyFullPayloadBuilt() {
        return keywordPayloadMap != null || keywordObjectPayloadMap != null || fusepirMatrices != null
            || encodedFusePirMatrices != null;
    }

    boolean isBloomOnlyBitMatricesBuilt() {
        return bloomOnlyBitMatrices != null;
    }

    private Map<T, byte[]> buildKeywordPayloadMap(Map<T, List<byte[]>> keywordValueMap,
                                                  Map<ByteBuffer, CapeBloomFilterAdapter> bloomFilters) {
        Map<T, byte[]> payloadMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) -> payloadMap.put(
            keyword, CapePirUtils.buildKeywordPayload(keyword, values, bloomFilters, params)
        ));
        return payloadMap;
    }

    private Map<T, byte[]> buildValueOnlyPayloadMap(Map<T, List<byte[]>> keywordValueMap) {
        Map<T, byte[]> payloadMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) -> payloadMap.put(
            keyword, CapePirUtils.buildValueOnlyPayload(keyword, values, params)
        ));
        return payloadMap;
    }

    private Map<T, long[]> buildValueOnlyLongPayloadMap(Map<T, List<byte[]>> keywordValueMap) {
        Map<T, long[]> payloadMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) -> payloadMap.put(
            keyword, CapePirUtils.buildValueOnlyLongPayload(keyword, values, params)
        ));
        return payloadMap;
    }

    private Map<T, long[]> buildBloomOnlyLongPayloadMap(Map<T, List<byte[]>> keywordValueMap,
                                                        Map<ByteBuffer, CapeBloomFilterAdapter> bloomFilters) {
        Map<T, long[]> payloadMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) -> payloadMap.put(
            keyword, CapePirUtils.buildBloomOnlyLongPayload(values, bloomFilters, params)
        ));
        return payloadMap;
    }

    private IndexedBloomPayloadPlan buildIndexedBloomPayloadPlan(Map<ByteBuffer, List<byte[]>> keywordValueMap,
                                                                 Map<ByteBuffer, CapeBloomFilterAdapter> bloomFilters) {
        return new IndexedBloomPayloadPlan(
            keywordValueMap, bloomFilters, params.getBloomBitLength(), params.getBloomPerPackedBlock()
        );
    }

    private long[][] buildBloomOnlyBffStorageForTest() {
        if (bffSeed == null) {
            throw new IllegalStateException("BFF seed is not initialized");
        }
        Map<ByteBuffer, List<byte[]>> canonicalKeywordValueMap = buildCanonicalKeywordValueMap(
            buildKeywordValueMapFromForwardIndex()
        );
        IndexedBloomPayloadPlan indexedBloomPayloadPlan = buildIndexedBloomPayloadPlan(
            canonicalKeywordValueMap, valueBloomFilters
        );
        return CapePirUtils.buildLongBinaryFuseFilters(
            indexedBloomPayloadPlan.keys, CapePirUtils.bloomOnlyPayloadByteLength(params), params, bffSeed,
            (key, blockIndex) -> indexedBloomPayloadPlan.get(indexedBloomPayloadPlan.keyIndexMap.get(key), blockIndex)
        );
    }

    private List<byte[]> encryptCandidateValues(List<CapePirUtils.ValueWithBloomFilter> candidateItems) {
        List<byte[]> encryptedValues = new ArrayList<>(candidateItems.size());
        for (CapePirUtils.ValueWithBloomFilter candidateItem : candidateItems) {
            long[] valueCoeffs = new long[params.getPolyModulusDegree()];
            byte[] value = candidateItem.getValue();
            for (int i = 0; i < value.length; i++) {
                valueCoeffs[i] = value[i] & 0xFFL;
            }
            encryptedValues.add(CapePirNativeUtils.encryptCoeffPlain(params.encryptionParams, publicKey, valueCoeffs));
        }
        return encryptedValues;
    }

    private List<byte[]> encryptCandidateBloomFilters(List<CapePirUtils.ValueWithBloomFilter> candidateItems) {
        List<byte[]> encryptedBloomFilters = new ArrayList<>(candidateItems.size() * params.getBloomCiphertextNum());
        for (CapePirUtils.ValueWithBloomFilter candidateItem : candidateItems) {
            encryptedBloomFilters.addAll(CapePirNativeUtils.encryptBloomFilter(
                params.encryptionParams, publicKey, CapeBloomFilterAdapter.storageToLongBitVector(
                    candidateItem.getBloomFilterBytes(), params.getBloomBitLength()
                )
            ));
        }
        return encryptedBloomFilters;
    }

    private List<byte[]> generateCandidateReplyGroups(List<byte[]> columnQueries, List<byte[]> encryptedRowBits,
                                                      List<byte[]> encodedMatrices, int payloadBlockNum) {
        int valueBlocksPerPackedMatrix = params.getValueBlocksPerPackedMatrix();
        int groupNum = (payloadBlockNum + valueBlocksPerPackedMatrix - 1) / valueBlocksPerPackedMatrix;
        if (payloadBlockNum <= params.getPolyModulusDegree()) {
            return CapePirNativeUtils.generateFusePirCandidateReply(
                params.encryptionParams, publicKey, columnQueries, encryptedRowBits, encodedMatrices,
                payloadBlockNum, params.getMatrixRowNum(), params.getMatrixColNum(), valueBlocksPerPackedMatrix
            );
        }
        List<byte[]> replies = new ArrayList<>(groupNum);
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            int fromIndex = groupIndex * params.getMatrixRowNum();
            int toIndex = fromIndex + params.getMatrixRowNum();
            int groupPayloadBlockNum = Math.min(
                valueBlocksPerPackedMatrix,
                payloadBlockNum - groupIndex * valueBlocksPerPackedMatrix
            );
            replies.addAll(CapePirNativeUtils.generateFusePirCandidateReply(
                params.encryptionParams, publicKey, columnQueries, encryptedRowBits,
                encodedMatrices.subList(fromIndex, toIndex), groupPayloadBlockNum, params.getMatrixRowNum(),
                params.getMatrixColNum(), valueBlocksPerPackedMatrix
            ));
        }
        return replies;
    }

    private List<byte[]> mergePackedResultResponse(List<byte[]> encryptedValuePayloads, List<byte[]> encryptedScores) {
        List<byte[]> packedResultCiphertexts = CapePirNativeUtils.mergePackedValueAndScoreReplies(
            params.encryptionParams, encryptedValuePayloads, encryptedScores, params.getScoreOffset(),
            params.getScoreCoeffNum()
        );
        if (packedResultCiphertexts.size() != params.getExpectedPackedResultCiphertextCount()) {
            throw new IllegalStateException("CAPE packed result ciphertext count mismatch");
        }
        return packedResultCiphertexts;
    }

    /**
     * Legacy bit-by-bit candidate Bloom retrieval kept only as a reference for tests. This path preprocesses one
     * matrix per Bloom bit online and must not be called by the real CAPE protocol.
     */
    @Deprecated
    private List<byte[]> generateCandidateBitRepliesForTest(List<byte[]> bitColumnQueries, List<byte[]> encryptedRowBits,
                                                            int payloadBlockNum) {
        ensureBloomOnlyBitMatrices();
        List<byte[]> replies = new ArrayList<>(payloadBlockNum);
        for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
            long[][][] singleBitMatrix = new long[][][]{bloomOnlyBitMatrices[blockIndex]};
            List<byte[]> encodedSingleBitMatrix = CapePirNativeUtils.preprocessDatabase(
                params.encryptionParams, singleBitMatrix, new long[0][]
            );
            replies.addAll(CapePirNativeUtils.generateFusePirCandidateReply(
                params.encryptionParams, publicKey, bitColumnQueries, encryptedRowBits,
                encodedSingleBitMatrix, 1, params.getMatrixRowNum(),
                params.getMatrixColNum(), 1
            ));
        }
        return replies;
    }

    private int getPackedScoreCapacity() {
        return params.getPolyModulusDegree();
    }

    private int getPackedMatrixGroupNum(int payloadBlockNum) {
        return (payloadBlockNum + params.getValueBlocksPerPackedMatrix() - 1)
            / params.getValueBlocksPerPackedMatrix();
    }

    private int getExpectedPackedScoreCiphertextCount() {
        int packedScoreCapacity = getPackedScoreCapacity();
        return (params.getMaxValueNumPerKeyword() + packedScoreCapacity - 1) / packedScoreCapacity;
    }

    private int getExpectedValueCiphertextCount() {
        return CapePirUtils.valueOnlyPayloadBlockNum(params) <= params.getPolyModulusDegree()
            ? 1
            : getPackedMatrixGroupNum(CapePirUtils.valueOnlyPayloadBlockNum(params));
    }

    private SameSeedBffBuildResult chooseSameSeedValueAndBloomBff(Map<ByteBuffer, long[]> valueOnlyPayloadMap,
                                                                  IndexedBloomPayloadPlan indexedBloomPayloadPlan,
                                                                  CapePirParams params) {
        SecureRandom secureRandom = new SecureRandom();
        int bloomPayloadBlockNum = params.getBloomPackedPayloadBlockNum();
        for (int attempt = 0; attempt < MAX_SAME_SEED_ATTEMPTS; attempt++) {
            byte[] seed = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
            secureRandom.nextBytes(seed);
            try {
                long graphStartTime = System.nanoTime();
                CapePirUtils.SameSeedFuseGraph<ByteBuffer> graph = CapePirUtils.buildSameSeedFuseGraph(
                    indexedBloomPayloadPlan.keys, params, seed
                );
                if (graph == null) {
                    throw new IllegalStateException("Cannot build same-seed CAPE Binary Fuse Filter graph");
                }
                long graphBuildTimeMillis = elapsedMillis(graphStartTime);
                long[][] valueBffStorage = CapePirUtils.buildLongBinaryFuseFilters(
                    graph, CapePirUtils.valueOnlyPayloadBlockNum(params), params,
                    (keyIndex, blockIndex) -> valueOnlyPayloadMap.get(indexedBloomPayloadPlan.keys.get(keyIndex))[blockIndex]
                );
                CapePirUtils.LongBffBuildStats bloomStats = new CapePirUtils.LongBffBuildStats();
                List<byte[]> encodedStreamingBloomMatrices = CapePirUtils.buildAndPreprocessPackedBloomBinaryFuseFiltersStreaming(
                    graph, params, indexedBloomPayloadPlan::getPackedCoefficient,
                    matrices -> CapePirNativeUtils.preprocessDatabase(params.encryptionParams, matrices, new long[0][]),
                    graphBuildTimeMillis,
                    bloomStats
                );
                logBloomOnlyLongBffStats(bloomStats);
                return new SameSeedBffBuildResult(seed, valueBffStorage, encodedStreamingBloomMatrices, bloomStats);
            } catch (IllegalStateException e) {
                // Try another seed. Failing closed below avoids silently changing the protocol path.
            }
        }
        throw new IllegalStateException("CAPE same-seed BFF seed selection failed");
    }

    private void logBloomOnlyLongBffStats(CapePirUtils.LongBffBuildStats stats) {
        logPerf("bloomOnlyPayloadBlockNum = %d", stats.getPayloadBlockNum());
        logPerf("oldScalarBloomPayloadBlockNum = %d", params.getScalarBloomPayloadBlockNumForTest());
        logPerf("newBloomPackedPayloadBlockNum = %d", params.getBloomPackedPayloadBlockNum());
        logPerf("polyModulusDegree = %d", params.getPolyModulusDegree());
        logPerf("bloomBitLength = %d", params.getBloomBitLength());
        logPerf("maxValueNumPerKeyword = %d", params.getMaxValueNumPerKeyword());
        logPerf("bloomPerPackedBlock = %d", params.getBloomPerPackedBlock());
        logPerf(
            "packedBloomPayloadReductionRatio = %.2f",
            params.getScalarBloomPayloadBlockNumForTest() / (double) params.getBloomPackedPayloadBlockNum()
        );
        logPerf("keywordNum = %d", stats.getKeywordNum());
        logPerf("filterLength = %d", stats.getFilterLength());
        logPerf("packedGroupNum = %d", stats.getPackedGroupNum());
        logPerf("blocksPerPackedMatrix = %d", stats.getBlocksPerPackedMatrix());
        logPerf(
            "positionHashCallsBeforeReference = %d",
            (long) stats.getKeywordNum() * stats.getPayloadBlockNum()
        );
        logPerf("positionHashCallsAfter = %d", stats.getKeywordNum());
        logPerf("blockMapAllocated = false");
        logPerf("graphBuildTime = %d ms", stats.getGraphBuildTimeMillis());
        logPerf("groupAssignmentTotalTime = %d ms", stats.getAssignmentTotalTimeMillis());
        logPerf("groupMatrixizeTotalTime = %d ms", stats.getMatrixizeTotalTimeMillis());
        logPerf("groupPreprocessTotalTime = %d ms", stats.getPreprocessTotalTimeMillis());
        logPerf(
            "estimatedFullBloomStorageBytes = %d",
            Long.BYTES * (long) params.getScalarBloomPayloadBlockNumForTest() * stats.getFilterLength()
        );
        logPerf(
            "streamingGroupStorageBytes = %d",
            Long.BYTES * (long) stats.getBlocksPerPackedMatrix() * stats.getFilterLength()
        );
        logPerf(
            "estimatedReductionFactor = %.2f",
            params.getScalarBloomPayloadBlockNumForTest() / (double) stats.getBlocksPerPackedMatrix()
        );
        logPerf("fullBloomStorageMaterialized = %s", stats.isFullBloomStorageMaterialized());
        logPerf("bloomOnlyMatricesMaterialized = %s", stats.isBloomOnlyMatricesMaterialized());
        logPerf("innerLoopMapLookup = %s", stats.isInnerLoopMapLookup());
        logPerf("innerLoopByteBufferWrap = %s", stats.isInnerLoopByteBufferWrap());
    }

    private void ensureLegacyKeywordPayloadMap() {
        if (keywordPayloadMap == null) {
            keywordPayloadMap = buildKeywordPayloadMap(buildKeywordValueMapFromForwardIndex(), valueBloomFilters);
        }
    }

    private void ensureLegacyKeywordObjectPayloadMap() {
        ensureLegacyKeywordPayloadMap();
        if (keywordObjectPayloadMap == null) {
            keywordObjectPayloadMap = keywordPayloadMap.entrySet().stream()
                .collect(Collectors.toMap(
                    entry -> ByteBuffer.wrap(CapePirUtils.keywordToByteArray(entry.getKey())),
                    entry -> Arrays.copyOf(entry.getValue(), entry.getValue().length),
                    (left, right) -> left,
                    LinkedHashMap::new
                ));
        }
    }

    private void ensureLegacyFusePirMatrices() {
        if (fusepirMatrices == null) {
            ensureLegacyKeywordPayloadMap();
            Map<ByteBuffer, byte[]> canonicalKeywordPayloadMap = CapePirUtils.toCanonicalBytePayloadMap(keywordPayloadMap);
            CapePirUtils.BinaryFuseFilterData fullBffData = CapePirUtils.buildBinaryFuseFilters(
                canonicalKeywordPayloadMap, params.getPayloadByteLength(), params, new SecureRandom(), bffSeed
            );
            fusepirMatrices = CapePirUtils.matrixizePackedBff(fullBffData.getStorage(), params);
        }
    }

    private void ensureLegacyEncodedFusePirMatrices() {
        if (encodedFusePirMatrices == null) {
            ensureLegacyFusePirMatrices();
            encodedFusePirMatrices = CapePirNativeUtils.preprocessDatabase(
                params.encryptionParams, fusepirMatrices, new long[0][]
            );
        }
    }

    private void ensureBloomOnlyBitMatrices() {
        if (bloomOnlyBffStorage == null) {
            bloomOnlyBffStorage = buildBloomOnlyBffStorageForTest();
        }
        if (bloomOnlyBitMatrices == null) {
            bloomOnlyBitMatrices = CapePirUtils.matrixizePackedBff(
                bloomOnlyBffStorage, params, CapePirUtils.bloomOnlyPayloadByteLength(params), 1
            );
        }
    }

    private void logMemorySensitiveSizes(int maxValueNumPerKeyword) {
        if (!PERF_LOG_ENABLED) {
            return;
        }
        logPerf("keywordNum = %d", keywordNum);
        logPerf("maxValueNumPerKeyword = %d", maxValueNumPerKeyword);
        logPerf("bloomBitLength = %d", params.getBloomBitLength());
        logPerf("valueOnlyPayloadByteLength = %d", CapePirUtils.valueOnlyPayloadByteLength(params));
        logPerf("oldScalarBloomPayloadBlockNum = %d", params.getScalarBloomPayloadBlockNumForTest());
        logPerf("bloomPackedPayloadBlockNum = %d", params.getBloomPackedPayloadBlockNum());
        logPerf("bloomPerPackedBlock = %d", params.getBloomPerPackedBlock());
        logPerf("bloomPackedCoefficientStride = %d", params.getBloomPackedCoefficientStride());
        logPerf("bloomOnlyPayloadLongLength = %d", params.getBloomPackedPayloadBlockNum());
        logPerf("bloomOnlyPayloadByteLength = %d", (long) params.getBloomPackedPayloadBlockNum() * Long.BYTES);
        logPerf("fullPayloadByteLength = %d", params.getPayloadByteLength());
        logPerf("valueOnly payloadBlockNum = %d", CapePirUtils.valueOnlyPayloadBlockNum(params));
        logPerf("bloomOnly payloadBlockNum = %d", params.getBloomPackedPayloadBlockNum());
        logPerf("encodedFusePirMatrices bytes = 0");
        logPerf("encodedValueOnlyMatrices bytes = %d", byteLength(encodedValueOnlyMatrices));
        logPerf("encodedBloomOnlyMatrices bytes = %d", byteLength(encodedBloomOnlyMatrices));
        logPerf("bloomOnlyBitMatrices bytes = 0");
    }

    private void logPerf(String format, Object... args) {
        if (PERF_LOG_ENABLED) {
            LOGGER.info(PERF_PREFIX + " " + String.format(format, args));
        }
    }

    private void logCheckpoint(String format, Object... args) {
        LOGGER.info(CHECKPOINT_PREFIX + " " + String.format(format, args));
    }

    private static long elapsedMillis(long startTime) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
    }

    private static long[][] copyLongMatrix(long[][] matrix) {
        return Arrays.stream(matrix)
            .map(row -> Arrays.copyOf(row, row.length))
            .toArray(long[][]::new);
    }

    private Map<T, List<byte[]>> buildKeywordValueMapFromForwardIndex() {
        Map<T, List<byte[]>> keywordValueMap = new LinkedHashMap<>(keywordNum);
        valueKeywordMap.forEach((value, keywords) -> {
            ByteBuffer duplicateValue = value.asReadOnlyBuffer();
            duplicateValue.rewind();
            byte[] valueBytes = new byte[duplicateValue.remaining()];
            duplicateValue.get(valueBytes);
            for (T keyword : keywords) {
                keywordValueMap.computeIfAbsent(keyword, ignored -> new ArrayList<>())
                    .add(Arrays.copyOf(valueBytes, valueBytes.length));
            }
        });
        return keywordValueMap;
    }

    private Map<ByteBuffer, List<byte[]>> buildCanonicalKeywordValueMap(Map<T, List<byte[]>> keywordValueMap) {
        Map<ByteBuffer, List<byte[]>> canonicalMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) ->
            canonicalMap.put(ByteBuffer.wrap(CapePirUtils.keywordToByteArray(keyword)), new ArrayList<>(values))
        );
        return canonicalMap;
    }

    private static class SameSeedBffBuildResult {
        private final byte[] seed;
        private final long[][] valueBffStorage;
        private final List<byte[]> encodedBloomOnlyMatrices;
        private final CapePirUtils.LongBffBuildStats bloomStats;

        private SameSeedBffBuildResult(byte[] seed, long[][] valueBffStorage,
                                       List<byte[]> encodedBloomOnlyMatrices,
                                       CapePirUtils.LongBffBuildStats bloomStats) {
            this.seed = Arrays.copyOf(seed, seed.length);
            this.valueBffStorage = copyLongMatrix(valueBffStorage);
            this.encodedBloomOnlyMatrices = encodedBloomOnlyMatrices.stream()
                .map(bytes -> Arrays.copyOf(bytes, bytes.length))
                .collect(Collectors.toList());
            this.bloomStats = bloomStats;
        }
    }

    static class IndexedBloomPayloadPlan {
        private final List<ByteBuffer> keys;
        private final Map<ByteBuffer, Integer> keyIndexMap;
        private final int[][] keywordValueIds;
        private final CapeBloomFilterAdapter[] valueBloomFilterArray;
        private final int bloomBitLength;
        private final int bloomPerPackedBlock;

        IndexedBloomPayloadPlan(Map<ByteBuffer, List<byte[]>> keywordValueMap,
                                Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters,
                                int bloomBitLength, int bloomPerPackedBlock) {
            this.keys = new ArrayList<>(keywordValueMap.keySet());
            this.keys.sort(IndexedBloomPayloadPlan::compareByteBuffers);
            this.keyIndexMap = new LinkedHashMap<>(keys.size());
            for (int keyIndex = 0; keyIndex < keys.size(); keyIndex++) {
                keyIndexMap.put(keys.get(keyIndex), keyIndex);
            }
            Map<ByteBuffer, Integer> valueIdMap = new LinkedHashMap<>(valueBloomFilters.size());
            valueBloomFilterArray = new CapeBloomFilterAdapter[valueBloomFilters.size()];
            int valueId = 0;
            for (Map.Entry<ByteBuffer, CapeBloomFilterAdapter> entry : valueBloomFilters.entrySet()) {
                valueIdMap.put(copyByteBuffer(entry.getKey()), valueId);
                valueBloomFilterArray[valueId] = entry.getValue();
                valueId++;
            }
            keywordValueIds = new int[keys.size()][];
            for (int keyIndex = 0; keyIndex < keys.size(); keyIndex++) {
                List<byte[]> values = keywordValueMap.get(keys.get(keyIndex));
                int[] valueIds = new int[values.size()];
                for (int valueIndex = 0; valueIndex < values.size(); valueIndex++) {
                    Integer foundValueId = valueIdMap.get(ByteBuffer.wrap(values.get(valueIndex)));
                    if (foundValueId == null) {
                        throw new IllegalArgumentException("Missing value Bloom Filter");
                    }
                    valueIds[valueIndex] = foundValueId;
                }
                keywordValueIds[keyIndex] = valueIds;
            }
            this.bloomBitLength = bloomBitLength;
            this.bloomPerPackedBlock = bloomPerPackedBlock;
        }

        long get(int keyIndex, int blockIndex) {
            int valueIndex = blockIndex / bloomBitLength;
            if (valueIndex >= keywordValueIds[keyIndex].length) {
                return 0L;
            }
            int bloomBitIndex = blockIndex % bloomBitLength;
            int valueId = keywordValueIds[keyIndex][valueIndex];
            if (valueId < 0) {
                return 0L;
            }
            return valueBloomFilterArray[valueId].getBit(bloomBitIndex);
        }

        long getPackedCoefficient(int keyIndex, int packedBlockIndex, int coefficientOffset) {
            int localValueIndex = coefficientOffset / bloomBitLength;
            int bloomBitIndex = coefficientOffset % bloomBitLength;
            if (localValueIndex >= bloomPerPackedBlock) {
                return 0L;
            }
            int valueIndex = packedBlockIndex * bloomPerPackedBlock + localValueIndex;
            if (valueIndex >= keywordValueIds[keyIndex].length) {
                return 0L;
            }
            int valueId = keywordValueIds[keyIndex][valueIndex];
            if (valueId < 0) {
                return 0L;
            }
            return valueBloomFilterArray[valueId].getBit(bloomBitIndex);
        }

        List<ByteBuffer> getKeysForTest() {
            return new ArrayList<>(keys);
        }

        int getValueIdForTest(int keyIndex, int valueIndex) {
            return keywordValueIds[keyIndex][valueIndex];
        }

        private static ByteBuffer copyByteBuffer(ByteBuffer value) {
            ByteBuffer duplicate = value.asReadOnlyBuffer();
            duplicate.rewind();
            byte[] bytes = new byte[duplicate.remaining()];
            duplicate.get(bytes);
            return ByteBuffer.wrap(bytes);
        }

        private static int compareByteBuffers(ByteBuffer left, ByteBuffer right) {
            ByteBuffer leftDuplicate = left.asReadOnlyBuffer();
            ByteBuffer rightDuplicate = right.asReadOnlyBuffer();
            leftDuplicate.rewind();
            rightDuplicate.rewind();
            while (leftDuplicate.hasRemaining() && rightDuplicate.hasRemaining()) {
                int cmp = Byte.compare(leftDuplicate.get(), rightDuplicate.get());
                if (cmp != 0) {
                    return cmp;
                }
            }
            return Integer.compare(leftDuplicate.remaining(), rightDuplicate.remaining());
        }
    }

    private static int ceilLog2(int n) {
        int log = 0;
        int pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }
}
