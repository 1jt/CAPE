package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirParams;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirPtoDesc.getInstance;

/**
 * CAPE_C PIR server.
 *
 * <p>The formal query contains one compressed anchor query plus packed Bloom query ciphertexts. The formal response
 * contains packed result ciphertexts whose coefficients are laid out as value payload coefficients followed by Bloom
 * score coefficients.</p>
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirServer<T> extends AbstractTwoPartyPto {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CapeCPirServer.class);
    /**
     * checkpoint log prefix.
     */
    private static final String CHECKPOINT_PREFIX = "[CAPE-C-CHECKPOINT]";
    /**
     * init log prefix.
     */
    private static final String INIT_PREFIX = "[CAPE-C-INIT]";
    /**
     * query log prefix.
     */
    private static final String QUERY_PREFIX = "[CAPE-C-QUERY]";
    /**
     * config.
     */
    private final CapeCPirConfig config;
    /**
     * params.
     */
    private final CapeCPirParams params;
    /**
     * keyword value map.
     */
    private Map<T, List<byte[]>> keywordValueMap;
    /**
     * max batch num.
     */
    private int maxBatchNum;
    /**
     * BFV public key.
     */
    private byte[] publicKey;
    /**
     * BFV relinearization keys.
     */
    private byte[] relinKeys;
    /**
     * BFV Galois keys.
     */
    private byte[] galoisKeys;
    /**
     * native LWE-to-RGSW key handle.
     */
    private long lweToRgswKeyHandle;
    /**
     * setup LWE-to-RGSW key bytes.
     */
    private long setupLweToRgswKeyBytes;
    /**
     * last max value-keyword set size.
     */
    private int maxValueKeywordSetSize;
    /**
     * last value-only native preprocess time.
     */
    private long lastValueOnlyPreprocessMs;
    /**
     * last Bloom-only native preprocess time.
     */
    private long lastBloomOnlyPreprocessMs;
    /**
     * BFF seed.
     */
    private byte[] bffSeed;
    /**
     * encoded value-only matrices.
     */
    private List<byte[]> encodedValueOnlyMatrices;
    /**
     * encoded Bloom-only matrices.
     */
    private List<byte[]> encodedBloomOnlyMatrices;
    /**
     * last expected query payload count.
     */
    private int lastExpectedQueryPayloadCount;
    /**
     * last actual query payload count.
     */
    private int lastActualQueryPayloadCount;
    /**
     * last value ciphertext count.
     */
    private int lastValueCiphertextCount;
    /**
     * last score ciphertext count.
     */
    private int lastScoreCiphertextCount;
    /**
     * last packed result ciphertext count.
     */
    private int lastPackedResultCiphertextCount;
    /**
     * last packed result bytes.
     */
    private long lastPackedResultBytes;
    /**
     * BFF seed retry bound.
     */
    private static final int MAX_BFF_SEED_TRIES = 1 << 10;

    public CapeCPirServer(Rpc serverRpc, Party clientParty, CapeCPirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(Map<T, List<byte[]>> keywordValueMap, int valueByteLength, int maxValueNumPerKeyword,
                     int maxBatchNum) throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_value_map.size", keywordValueMap.size());
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        this.keywordValueMap = keywordValueMap;
        this.maxBatchNum = maxBatchNum;
        logPhaseInfo(PtoState.INIT_BEGIN);
        long initStartTime = System.nanoTime();
        Map<ByteBuffer, List<T>> valueKeywordMap = CapeCPirUtils.buildForwardIndex(keywordValueMap);
        maxValueKeywordSetSize = Math.max(1, valueKeywordMap.values().stream().mapToInt(List::size).max().orElse(1));
        params.initPirParams(
            keywordValueMap.size(), valueByteLength, maxValueNumPerKeyword, config.getBoolKeywordNum(),
            maxValueKeywordSetSize
        );
        if (params.encryptionParams == null) {
            params.encryptionParams = CapeCPirNativeUtils.generateEncryptionParams(
                params.getPolyModulusDegree(), params.getPlainModulus(), params.getCoeffModulusBits()
            );
        }
        logInitParams(keywordValueMap.size());
        Map<T, long[]> valueOnlyPayloadMap = buildValueOnlyLongPayloadMap(keywordValueMap, params);
        selectBffSeedAndPreprocessMatrices(keywordValueMap, valueOnlyPayloadMap);
        LOGGER.info("{} valueOnlyPreprocessMs={}", INIT_PREFIX, lastValueOnlyPreprocessMs);
        LOGGER.info("{} bloomOnlyPreprocessMs={}", INIT_PREFIX, lastBloomOnlyPreprocessMs);
        LOGGER.info("{} totalInitMs={}", INIT_PREFIX, elapsedMillis(initStartTime));
        initState();
        logStepInfo(PtoState.INIT_STEP, 1, 1, 0);
        logPhaseInfo(PtoState.INIT_END);
    }

    public void receivePublicKeysAndSendSeed() throws MpcAbortException {
        checkInitialized();
        List<byte[]> bfvKeyPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_BFV_KEYS.ordinal());
        MpcAbortPreconditions.checkArgument(bfvKeyPayload.size() == 3);
        publicKey = BytesUtils.clone(bfvKeyPayload.get(0));
        relinKeys = BytesUtils.clone(bfvKeyPayload.get(1));
        galoisKeys = BytesUtils.clone(bfvKeyPayload.get(2));
        List<byte[]> metaPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_ANCHOR_EVAL_KEY_META.ordinal());
        MpcAbortPreconditions.checkArgument(metaPayload.size() == 1);
        SetupKeyMeta meta = decodeSetupKeyMeta(metaPayload.get(0));
        List<byte[]> lweToRgswKey = new ArrayList<>(meta.itemCount);
        for (int keyItemIndex = 0; keyItemIndex < meta.itemCount; keyItemIndex++) {
            List<byte[]> keyItemPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_ANCHOR_EVAL_KEY_CHUNK.ordinal());
            MpcAbortPreconditions.checkArgument(keyItemPayload.size() == 1);
            lweToRgswKey.add(BytesUtils.clone(keyItemPayload.get(0)));
        }
        setupLweToRgswKeyBytes = byteLength(lweToRgswKey);
        MpcAbortPreconditions.checkArgument(setupLweToRgswKeyBytes == meta.totalBytes);
        if (lweToRgswKeyHandle != 0L) {
            CapeCPirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        lweToRgswKeyHandle = CapeCPirNativeUtils.createLweToRgswKeyHandle(
            params.encryptionParams, publicKey, lweToRgswKey
        );
        if (lweToRgswKeyHandle == 0L) {
            throw new MpcAbortException("CAPE_C native LWE-to-RGSW key handle creation failed");
        }
        sendOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal(), List.of(
            BytesUtils.clone(bffSeed), encodeBloomParams()
        ));
    }

    public void pir(int batchNum) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", batchNum, maxBatchNum);
        logPhaseInfo(PtoState.PTO_BEGIN);
        for (int i = 0; i < batchNum; i++) {
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal());
            CapeCPirQuery query = parseQueryPayload(queryPayload);
            CapeCPirResponse response = generateReply(query);
            MpcAbortPreconditions.checkArgument(
                response.getPackedResultCiphertexts().size() == params.getExpectedPackedResultCiphertextCount()
            );
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), response.getServerPayload());
        }
        logPhaseInfo(PtoState.PTO_END);
    }

    CapeCPirResponse generateReply(CapeCPirQuery query) {
        return generatePhase5PackedResultReply(query);
    }

    List<byte[]> generateCompressedAnchorValueCandidateReply(CapeCPirQuery query) {
        return generateCompressedAnchorValueCandidateReply(query, recoverCompressedAnchorQuery(query));
    }

    List<byte[]> generateCompressedAnchorValueCandidateReply(CapeCPirQuery query,
                                                             RecoveredAnchorQuery recoveredAnchorQuery) {
        if (encodedValueOnlyMatrices == null || encodedValueOnlyMatrices.isEmpty()) {
            throw new IllegalStateException("CAPE_C encoded value-only matrices are not initialized");
        }
        return CapeCPirNativeUtils.generateCapeCCandidateReply(
            params.encryptionParams, publicKey, flatten(recoveredAnchorQuery.getColRgswBits()),
            flatten(recoveredAnchorQuery.getRowRgswBits()), encodedValueOnlyMatrices,
            params.getValuePayloadCoeffNum(), params.getMatrixRowNum(), params.getMatrixColNum(),
            params.getValueBlocksPerPackedMatrix()
        );
    }

    List<byte[]> generateCompressedAnchorPackedBloomScores(CapeCPirQuery query) {
        return generateCompressedAnchorPackedBloomScores(query, recoverCompressedAnchorQuery(query));
    }

    List<byte[]> generateCompressedAnchorPackedBloomScores(CapeCPirQuery query,
                                                           RecoveredAnchorQuery recoveredAnchorQuery) {
        if (encodedBloomOnlyMatrices == null || encodedBloomOnlyMatrices.isEmpty()) {
            throw new IllegalStateException("CAPE_C encoded Bloom-only matrices are not initialized");
        }
        return CapeCPirNativeUtils.generateCapeCFusedPackedCoeffCtCtBloomScoresPackedBloom(
            params.encryptionParams, publicKey, relinKeys, galoisKeys,
            flatten(recoveredAnchorQuery.getColRgswBits()), flatten(recoveredAnchorQuery.getRowRgswBits()),
            encodedBloomOnlyMatrices, query.getEncryptedPackedBloomQuery(),
            params.getBloomPackedPayloadBlockNum(), params.getMatrixRowNum(), params.getMatrixColNum(),
            CapeCPirUtils.bloomPackedMatrixColumnCapacity(params), params.getValueBlocksPerPackedMatrix(),
            CapeCPirUtils.bloomPackedCoefficientStride(params), params.getMaxValueNumPerKeyword(),
            params.getBloomBitLength()
        );
    }

    CapeCPirResponse generatePhase5PackedResultReply(CapeCPirQuery query) {
        long totalStartTime = System.nanoTime();
        long stageStartTime = System.nanoTime();
        RecoveredAnchorQuery recoveredAnchorQuery = recoverCompressedAnchorQuery(query);
        long recoverMs = elapsedMillis(stageStartTime);
        stageStartTime = System.nanoTime();
        List<byte[]> encryptedValuePayloads = generateCompressedAnchorValueCandidateReply(query, recoveredAnchorQuery);
        long valueMs = elapsedMillis(stageStartTime);
        stageStartTime = System.nanoTime();
        List<byte[]> encryptedScores = generateCompressedAnchorPackedBloomScores(query, recoveredAnchorQuery);
        long scoreMs = elapsedMillis(stageStartTime);
        stageStartTime = System.nanoTime();
        List<byte[]> packedResultCiphertexts = CapeCPirNativeUtils.mergePackedValueAndScoreReplies(
            params.encryptionParams, encryptedValuePayloads, encryptedScores,
            params.getScoreOffset(), params.getScoreCoeffNum()
        );
        long mergeMs = elapsedMillis(stageStartTime);
        if (packedResultCiphertexts.size() != params.getExpectedPackedResultCiphertextCount()) {
            throw new IllegalStateException("CAPE_C packed result ciphertext count mismatch");
        }
        lastValueCiphertextCount = encryptedValuePayloads.size();
        lastScoreCiphertextCount = encryptedScores.size();
        lastPackedResultCiphertextCount = packedResultCiphertexts.size();
        lastPackedResultBytes = byteLength(packedResultCiphertexts);
        LOGGER.info(
            "{} response bytes: valueCiphertextCount={}, scoreCiphertextCount={}, "
                + "packedResultCiphertextCount={}, packedResultBytes={}",
            CHECKPOINT_PREFIX, lastValueCiphertextCount, lastScoreCiphertextCount,
            lastPackedResultCiphertextCount, lastPackedResultBytes
        );
        LOGGER.info("{} recoverCompressedAnchorMs={}", QUERY_PREFIX, recoverMs);
        LOGGER.info("{} valueCandidateReplyMs={}", QUERY_PREFIX, valueMs);
        LOGGER.info("{} packedBloomScoreMs={}", QUERY_PREFIX, scoreMs);
        LOGGER.info("{} mergePackedResultMs={}", QUERY_PREFIX, mergeMs);
        LOGGER.info("{} totalQueryMs={}", QUERY_PREFIX, elapsedMillis(totalStartTime));
        return new CapeCPirResponse(packedResultCiphertexts);
    }

    CapeCPirQuery parseQueryPayload(List<byte[]> queryPayload) {
        int expectedPayloadCount = 1 + params.getPackedQueryBloomCiphertextNum();
        lastExpectedQueryPayloadCount = expectedPayloadCount;
        lastActualQueryPayloadCount = queryPayload.size();
        if (queryPayload.size() != expectedPayloadCount) {
            throw new IllegalArgumentException("CAPE_C query payload count mismatch");
        }
        byte[] compressedAnchorQuery = queryPayload.get(0);
        CapeCCompressedAnchorQuery anchorQuery = CapeCCompressedAnchorQuery.fromByteArray(compressedAnchorQuery);
        if (anchorQuery.getBffHashNum() != params.getBffHashNum()) {
            throw new IllegalArgumentException("CAPE_C compressed anchor BFF hash num mismatch");
        }
        if (anchorQuery.getRowBitNum() != CapeCPirUtils.ceilLog2(params.getMatrixRowNum())) {
            throw new IllegalArgumentException("CAPE_C compressed anchor row bit num mismatch");
        }
        if (anchorQuery.getColBitNum() != CapeCPirUtils.ceilLog2(params.getMatrixColNum())) {
            throw new IllegalArgumentException("CAPE_C compressed anchor col bit num mismatch");
        }
        return new CapeCPirQuery(new byte[0], compressedAnchorQuery,
            queryPayload.subList(1, queryPayload.size()), 0, config.getBoolKeywordNum());
    }

    RecoveredAnchorQuery recoverCompressedAnchorQuery(CapeCPirQuery query) {
        if (lweToRgswKeyHandle == 0L) {
            throw new IllegalStateException("CAPE_C LWE-to-RGSW setup key handle is not initialized");
        }
        CapeCCompressedAnchorQuery compressedQuery = CapeCCompressedAnchorQuery.fromByteArray(
            query.getCompressedAnchorQuery()
        );
        validateCompressedAnchorQuery(compressedQuery);
        List<CapeCPirUtils.LweCiphertext> recoveredLweBits = CapeCPirUtils.recoverLweBitCiphertexts(compressedQuery);
        int expectedBitCount = params.getBffHashNum()
            * (compressedQuery.getRowBitNum() + compressedQuery.getColBitNum());
        if (recoveredLweBits.size() != expectedBitCount) {
            throw new IllegalStateException("CAPE_C recovered LWE bit count mismatch");
        }
        long[][] aArray = new long[recoveredLweBits.size()][];
        long[] bArray = new long[recoveredLweBits.size()];
        for (int bitIndex = 0; bitIndex < recoveredLweBits.size(); bitIndex++) {
            aArray[bitIndex] = recoveredLweBits.get(bitIndex).getA();
            bArray[bitIndex] = recoveredLweBits.get(bitIndex).getB();
        }
        List<byte[]> rgswBits = CapeCPirNativeUtils.convertCompressedBitsToRgswWithHandle(
            params.encryptionParams, publicKey, lweToRgswKeyHandle, aArray, bArray
        );
        if (rgswBits.size() != expectedBitCount) {
            throw new IllegalStateException("CAPE_C converted RGSW bit count mismatch");
        }
        return splitRecoveredAnchorBits(compressedQuery, recoveredLweBits, rgswBits);
    }

    RecoveredAnchorQuery recoverCompressedAnchorQueryForTest(CapeCPirQuery query, List<byte[]> convertedRgswBits) {
        CapeCCompressedAnchorQuery compressedQuery = CapeCCompressedAnchorQuery.fromByteArray(
            query.getCompressedAnchorQuery()
        );
        validateCompressedAnchorQuery(compressedQuery);
        List<CapeCPirUtils.LweCiphertext> recoveredLweBits = CapeCPirUtils.recoverLweBitCiphertexts(compressedQuery);
        int expectedBitCount = params.getBffHashNum()
            * (compressedQuery.getRowBitNum() + compressedQuery.getColBitNum());
        if (recoveredLweBits.size() != expectedBitCount || convertedRgswBits.size() != expectedBitCount) {
            throw new IllegalStateException("CAPE_C recovered bit count mismatch");
        }
        return splitRecoveredAnchorBits(compressedQuery, recoveredLweBits, convertedRgswBits);
    }

    private void validateCompressedAnchorQuery(CapeCCompressedAnchorQuery anchorQuery) {
        if (anchorQuery.getBffHashNum() != params.getBffHashNum()) {
            throw new IllegalArgumentException("CAPE_C compressed anchor BFF hash num mismatch");
        }
        if (anchorQuery.getRowBitNum() != CapeCPirUtils.ceilLog2(params.getMatrixRowNum())) {
            throw new IllegalArgumentException("CAPE_C compressed anchor row bit num mismatch");
        }
        if (anchorQuery.getColBitNum() != CapeCPirUtils.ceilLog2(params.getMatrixColNum())) {
            throw new IllegalArgumentException("CAPE_C compressed anchor col bit num mismatch");
        }
    }

    private RecoveredAnchorQuery splitRecoveredAnchorBits(CapeCCompressedAnchorQuery query,
                                                         List<CapeCPirUtils.LweCiphertext> lweBits,
                                                         List<byte[]> rgswBits) {
        int bffHashNum = query.getBffHashNum();
        int rowBitNum = query.getRowBitNum();
        int colBitNum = query.getColBitNum();
        CapeCPirUtils.LweCiphertext[][] rowLweBits = new CapeCPirUtils.LweCiphertext[bffHashNum][rowBitNum];
        CapeCPirUtils.LweCiphertext[][] colLweBits = new CapeCPirUtils.LweCiphertext[bffHashNum][colBitNum];
        byte[][][] rowRgswBits = new byte[bffHashNum][rowBitNum][];
        byte[][][] colRgswBits = new byte[bffHashNum][colBitNum][];
        int flatIndex = 0;
        for (int hashIndex = 0; hashIndex < bffHashNum; hashIndex++) {
            for (int rowBitIndex = 0; rowBitIndex < rowBitNum; rowBitIndex++) {
                rowLweBits[hashIndex][rowBitIndex] = lweBits.get(flatIndex);
                rowRgswBits[hashIndex][rowBitIndex] = BytesUtils.clone(rgswBits.get(flatIndex));
                flatIndex++;
            }
            for (int colBitIndex = 0; colBitIndex < colBitNum; colBitIndex++) {
                colLweBits[hashIndex][colBitIndex] = lweBits.get(flatIndex);
                colRgswBits[hashIndex][colBitIndex] = BytesUtils.clone(rgswBits.get(flatIndex));
                flatIndex++;
            }
        }
        return new RecoveredAnchorQuery(rowLweBits, colLweBits, rowRgswBits, colRgswBits, flatIndex);
    }

    Map<T, List<byte[]>> getKeywordValueMap() {
        return keywordValueMap;
    }

    CapeCPirParams getCapeCParams() {
        return params;
    }

    void setEncodedValueOnlyMatricesForTest(List<byte[]> encodedValueOnlyMatrices) {
        this.encodedValueOnlyMatrices = encodedValueOnlyMatrices.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getEncodedValueOnlyMatricesForTest() {
        return encodedValueOnlyMatrices.stream().map(BytesUtils::clone).toList();
    }

    void setEncodedBloomOnlyMatricesForTest(List<byte[]> encodedBloomOnlyMatrices) {
        this.encodedBloomOnlyMatrices = encodedBloomOnlyMatrices.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getEncodedBloomOnlyMatricesForTest() {
        return encodedBloomOnlyMatrices.stream().map(BytesUtils::clone).toList();
    }

    byte[] getBffSeed() {
        return BytesUtils.clone(bffSeed);
    }

    byte[] getSerializedBloomParamsForTest() {
        return params.serializeCapeCBloomParams();
    }

    void setStateForTest(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int maxBatchNum,
                         byte[] bffSeed) {
        this.maxBatchNum = maxBatchNum;
        params.initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, config.getBoolKeywordNum());
        this.bffSeed = BytesUtils.clone(bffSeed);
        initState();
    }

    long getSetupLweToRgswKeyBytes() {
        return setupLweToRgswKeyBytes;
    }

    long getLweToRgswKeyHandle() {
        return lweToRgswKeyHandle;
    }

    void setSetupForTest(byte[] publicKey, List<byte[]> lweToRgswKey) {
        this.publicKey = BytesUtils.clone(publicKey);
        if (lweToRgswKeyHandle != 0L) {
            CapeCPirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        setupLweToRgswKeyBytes = byteLength(lweToRgswKey);
        lweToRgswKeyHandle = CapeCPirNativeUtils.createLweToRgswKeyHandle(
            params.encryptionParams, this.publicKey, lweToRgswKey
        );
    }

    void setBfvEvaluationKeysForTest(byte[] relinKeys, byte[] galoisKeys) {
        this.relinKeys = BytesUtils.clone(relinKeys);
        this.galoisKeys = BytesUtils.clone(galoisKeys);
    }

    int getExpectedValueCiphertextCount() {
        return (params.getValuePayloadCoeffNum() + params.getPolyModulusDegree() - 1)
            / params.getPolyModulusDegree();
    }

    int getExpectedScoreCiphertextCount() {
        return 1;
    }

    int getLastExpectedQueryPayloadCount() {
        return lastExpectedQueryPayloadCount;
    }

    int getLastActualQueryPayloadCount() {
        return lastActualQueryPayloadCount;
    }

    int getLastValueCiphertextCount() {
        return lastValueCiphertextCount;
    }

    int getLastScoreCiphertextCount() {
        return lastScoreCiphertextCount;
    }

    int getLastPackedResultCiphertextCount() {
        return lastPackedResultCiphertextCount;
    }

    long getLastPackedResultBytes() {
        return lastPackedResultBytes;
    }

    int getMaxValueKeywordSetSize() {
        return maxValueKeywordSetSize;
    }

    @Override
    public void destroy() {
        if (lweToRgswKeyHandle != 0L) {
            CapeCPirNativeUtils.destroyLweToRgswKeyHandle(lweToRgswKeyHandle);
            lweToRgswKeyHandle = 0L;
        }
        super.destroy();
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    private byte[] encodeBloomParams() {
        return params.serializeCapeCBloomParams();
    }

    private static List<byte[]> flatten(byte[][][] bits) {
        return java.util.Arrays.stream(bits)
            .flatMap(hashBits -> java.util.Arrays.stream(hashBits).map(BytesUtils::clone))
            .toList();
    }

    private static SetupKeyMeta decodeSetupKeyMeta(byte[] encoded) {
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(encoded));
        int itemCount = buffer.getInt();
        long totalBytes = buffer.getLong();
        MathPreconditions.checkPositive("setup_key_item_count", itemCount);
        MathPreconditions.checkNonNegative("setup_key_total_bytes", totalBytes);
        MathPreconditions.checkEqual("setup_key_meta.remaining", "0", buffer.remaining(), 0);
        return new SetupKeyMeta(itemCount, totalBytes);
    }

    private record SetupKeyMeta(int itemCount, long totalBytes) {
    }

    private void selectBffSeedAndPreprocessMatrices(Map<T, List<byte[]>> keywordValueMap,
                                                    Map<T, long[]> valueOnlyPayloadMap) {
        SecureRandom secureRandom = new SecureRandom();
        bffSeed = null;
        encodedValueOnlyMatrices = null;
        encodedBloomOnlyMatrices = null;
        IllegalStateException lastSeedFailure = null;
        for (int seedTry = 0; seedTry < MAX_BFF_SEED_TRIES; seedTry++) {
            byte[] candidateSeed = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
            secureRandom.nextBytes(candidateSeed);
            try {
                long bloomStartTime = System.nanoTime();
                CapeCPirUtils.SameSeedPreprocessResult preprocessResult =
                    CapeCPirUtils.buildSameSeedValueAndBloomPreprocess(
                        keywordValueMap, valueOnlyPayloadMap, params, candidateSeed
                    );
                long bloomPreprocessMs = elapsedMillis(bloomStartTime);
                long[][][] valueOnlyMatrices = matrixizePackedBff(
                    preprocessResult.valueOnlyBffStorage(), params, params.getValuePayloadCoeffNum(),
                    params.getValueBlocksPerPackedMatrix()
                );
                long valueStartTime = System.nanoTime();
                List<byte[]> candidateEncodedValueOnlyMatrices = CapeCPirNativeUtils.preprocessDatabase(
                    params.encryptionParams, valueOnlyMatrices
                );
                long valuePreprocessMs = elapsedMillis(valueStartTime);
                bffSeed = BytesUtils.clone(preprocessResult.seed());
                encodedValueOnlyMatrices = candidateEncodedValueOnlyMatrices;
                encodedBloomOnlyMatrices = preprocessResult.encodedBloomOnlyMatrices();
                lastValueOnlyPreprocessMs = valuePreprocessMs;
                lastBloomOnlyPreprocessMs = bloomPreprocessMs;
                return;
            } catch (IllegalStateException e) {
                if (!isSameSeedBffFailure(e)) {
                    throw e;
                }
                lastSeedFailure = e;
            }
        }
        throw new IllegalStateException("Cannot build same-seed CAPE_C Binary Fuse Filter", lastSeedFailure);
    }

    private void logInitParams(int keywordNum) {
        LOGGER.info("{} keywordNum={}", INIT_PREFIX, keywordNum);
        LOGGER.info("{} maxValueKeywordSetSize={}", INIT_PREFIX, maxValueKeywordSetSize);
        LOGGER.info("{} bloomExpectedInsertions={}", INIT_PREFIX, params.getBloomExpectedInsertions());
        LOGGER.info("{} bloomBitLength={}", INIT_PREFIX, params.getBloomBitLength());
        LOGGER.info("{} matrixRowNum={}", INIT_PREFIX, params.getMatrixRowNum());
        LOGGER.info("{} matrixColNum={}", INIT_PREFIX, params.getMatrixColNum());
        LOGGER.info("{} colBitNum={}", INIT_PREFIX, CapeCPirUtils.ceilLog2(params.getMatrixColNum()));
        LOGGER.info("{} rowBitNum={}", INIT_PREFIX, CapeCPirUtils.ceilLog2(params.getMatrixRowNum()));
        LOGGER.info("{} bloomPerPackedBlock={}", INIT_PREFIX, params.getBloomPerPackedBlock());
        LOGGER.info("{} bloomPackedPayloadBlockNum={}", INIT_PREFIX, params.getBloomPackedPayloadBlockNum());
        LOGGER.info("{} bloomPackedMatrixColumnCapacity={}", INIT_PREFIX,
            CapeCPirUtils.bloomPackedMatrixColumnCapacity(params));
        int bloomPackedMatrixColumnCapacity = CapeCPirUtils.bloomPackedMatrixColumnCapacity(params);
        LOGGER.info("{} bloomPackedMatrixColumnTileNum={}", INIT_PREFIX,
            (params.getMatrixColNum() + bloomPackedMatrixColumnCapacity - 1) / bloomPackedMatrixColumnCapacity);
    }

    private static long elapsedMillis(long startTime) {
        return (System.nanoTime() - startTime) / 1_000_000L;
    }

    private static boolean isSameSeedBffFailure(IllegalStateException e) {
        String message = e.getMessage();
        return message != null && message.contains("Cannot build same-seed");
    }

    @SuppressWarnings("unchecked")
    private static <T> Map<T, long[]> buildValueOnlyLongPayloadMap(Map<T, List<byte[]>> keywordValueMap,
                                                                   CapeCPirParams params) {
        Map<T, long[]> valueOnlyPayloadMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) ->
            valueOnlyPayloadMap.put(keyword, invokeCapePirUtils(
                "buildValueOnlyLongPayload", new Class<?>[]{Object.class, List.class, CapePirParams.class},
                keyword, values, params
            ))
        );
        return valueOnlyPayloadMap;
    }

    @SuppressWarnings("unchecked")
    private static <T> long[][] buildLongBinaryFuseFilters(Map<T, long[]> keywordPayloadMap, int payloadBlockNum,
                                                           CapeCPirParams params, byte[] seed) {
        return invokeCapePirUtils(
            "buildLongBinaryFuseFilters", new Class<?>[]{Map.class, int.class, CapePirParams.class, byte[].class},
            keywordPayloadMap, payloadBlockNum, params, seed
        );
    }

    private static long[][][] matrixizePackedBff(long[][] dPrimes, CapeCPirParams params, int payloadBlockNum,
                                                 int blocksPerPackedMatrix) {
        return invokeCapePirUtils(
            "matrixizePackedBff", new Class<?>[]{long[][].class, CapePirParams.class, int.class, int.class},
            dPrimes, params, payloadBlockNum, blocksPerPackedMatrix
        );
    }

    @SuppressWarnings("unchecked")
    private static <R> R invokeCapePirUtils(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Class<?> utilsClass = Class.forName("edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirUtils");
            Method method = utilsClass.getDeclaredMethod(methodName, parameterTypes);
            method.setAccessible(true);
            return (R) method.invoke(null, args);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {
            throw new IllegalStateException("Cannot access CAPE value-only layout helper: " + methodName, e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("CAPE value-only layout helper failed: " + methodName, cause);
        }
    }

    static class RecoveredAnchorQuery {
        /**
         * row LWE bits, indexed by hash then row bit.
         */
        private final CapeCPirUtils.LweCiphertext[][] rowLweBits;
        /**
         * column LWE bits, indexed by hash then column bit.
         */
        private final CapeCPirUtils.LweCiphertext[][] colLweBits;
        /**
         * row RGSW bits, indexed by hash then row bit.
         */
        private final byte[][][] rowRgswBits;
        /**
         * column RGSW bits, indexed by hash then column bit.
         */
        private final byte[][][] colRgswBits;
        /**
         * recovered bit count.
         */
        private final int recoveredBitCount;

        RecoveredAnchorQuery(CapeCPirUtils.LweCiphertext[][] rowLweBits,
                             CapeCPirUtils.LweCiphertext[][] colLweBits,
                             byte[][][] rowRgswBits, byte[][][] colRgswBits, int recoveredBitCount) {
            this.rowLweBits = rowLweBits;
            this.colLweBits = colLweBits;
            this.rowRgswBits = rowRgswBits;
            this.colRgswBits = colRgswBits;
            this.recoveredBitCount = recoveredBitCount;
        }

        int getRowBitNum() {
            return rowRgswBits.length == 0 ? 0 : rowRgswBits[0].length;
        }

        int getColBitNum() {
            return colRgswBits.length == 0 ? 0 : colRgswBits[0].length;
        }

        int getRecoveredLweBitCount() {
            return recoveredBitCount;
        }

        CapeCPirUtils.LweCiphertext[][] getRowLweBits() {
            return rowLweBits.clone();
        }

        CapeCPirUtils.LweCiphertext[][] getColLweBits() {
            return colLweBits.clone();
        }

        int getConvertedRgswBitCount() {
            return count(rowRgswBits) + count(colRgswBits);
        }

        byte[][][] getRowRgswBits() {
            return clone3d(rowRgswBits);
        }

        byte[][][] getColRgswBits() {
            return clone3d(colRgswBits);
        }

        private static int count(byte[][][] bits) {
            int count = 0;
            for (byte[][] hashBits : bits) {
                count += hashBits.length;
            }
            return count;
        }

        private static byte[][][] clone3d(byte[][][] input) {
            byte[][][] output = new byte[input.length][][];
            for (int i = 0; i < input.length; i++) {
                output[i] = new byte[input[i].length][];
                for (int j = 0; j < input[i].length; j++) {
                    output[i][j] = BytesUtils.clone(input[i][j]);
                }
            }
            return output;
        }
    }
}
