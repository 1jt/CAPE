package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirPtoDesc.getInstance;

/**
 * CAPE PIR client.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirClient<T> extends AbstractTwoPartyPto {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CapePirClient.class);
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
     * secret key.
     */
    private byte[] secretKey;
    /**
     * public key.
     */
    private byte[] publicKey;
    /**
     * relinearization keys.
     */
    private byte[] relinKeys;
    /**
     * galois keys.
     */
    private byte[] galoisKeys;
    /**
     * binary LWE secret key for compressed row-bit queries.
     */
    private long[] lweSecretKey;
    /**
     * setup-time LWE-to-RGSW evaluation key.
     */
    private List<byte[]> lweToRgswKey;
    /**
     * BFF seed for anchor FUSE_PIR query positions.
     */
    private byte[] bffSeed;
    /**
     * last generated queries, kept locally by client.
     */
    private List<CapePirQuery> lastQueries;
    /**
     * accumulated FUSE_PIR query bytes.
     */
    private long fusepirQueryByteLength;
    /**
     * accumulated encrypted Bloom query bytes.
     */
    private long encryptedBloomQueryByteLength;
    /**
     * accumulated encrypted value response bytes.
     */
    private long encryptedValueResponseByteLength;
    /**
     * accumulated encrypted score response bytes.
     */
    private long encryptedScoreResponseByteLength;
    /**
     * accumulated FUSE_PIR query generation time.
     */
    private long fusepirQueryGenerationTime;
    /**
     * accumulated Bloom query encryption time.
     */
    private long bloomQueryEncryptionTime;
    /**
     * accumulated score decrypt time.
     */
    private long scoreDecryptTime;
    /**
     * accumulated value decrypt / decode time.
     */
    private long valueDecryptDecodeTime;

    public CapePirClient(Rpc clientRpc, Party serverParty, CapePirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int maxBatchNum)
        throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        this.keywordNum = keywordNum;
        this.maxBatchNum = maxBatchNum;
        logPhaseInfo(PtoState.INIT_BEGIN);
        stopWatch.start();
        params.initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, config.getBoolKeywordNum());
        if (params.encryptionParams == null) {
            params.encryptionParams = CapePirNativeUtils.generateEncryptionParams(
                params.getPolyModulusDegree(), params.getPlainModulus(), params.getCoeffModulusBits()
            );
        }
        List<byte[]> keyPair = CapePirNativeUtils.keyGen(params.encryptionParams);
        MathPreconditions.checkEqual("keyPair.size", "4", keyPair.size(), 4);
        secretKey = keyPair.get(CapePirNativeUtils.SECRET_KEY_INDEX);
        publicKey = keyPair.get(CapePirNativeUtils.PUBLIC_KEY_INDEX);
        relinKeys = keyPair.get(CapePirNativeUtils.RELIN_KEYS_INDEX);
        galoisKeys = keyPair.get(CapePirNativeUtils.GALOIS_KEYS_INDEX);
        logPerf("alignedToFusePirParams = %s", params.alignedToFusePirParams());
        logPerf(
            "CAPE/FUSE_PIR params: polyModulusDegree=%d, plainModulus=%d, sealBfvCoeffModulus=BFVDefault(tc128), payloadElementBitLength=%d",
            params.getPolyModulusDegree(), params.getPlainModulus(), params.getPayloadElementBitLength()
        );
        logPerf(
            "setup/offline bytes before LWE key: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d",
            publicKey.length, relinKeys.length, galoisKeys.length
        );
        lweSecretKey = generateBinaryLweSecretKey();
        lweToRgswKey = CapePirNativeUtils.generateLweToRgswKey(
            params.encryptionParams, publicKey, lweSecretKey
        );
        logPerf("setupLweToRgswKeyBytes = %d", byteLength(lweToRgswKey));
        logCheckpoint(
            "client init keys generated: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d, "
                + "lweToRgswKeyBytes=%d, lweToRgswKeyItemCount=%d, totalSetupBytes=%d",
            publicKey.length, relinKeys.length, galoisKeys.length, byteLength(lweToRgswKey),
            lweToRgswKey.size(), publicKey.length + relinKeys.length + galoisKeys.length + byteLength(lweToRgswKey)
        );
        logCheckpoint(
            "client LWE-to-RGSW item bytes: itemCount=%d, minItemBytes=%d, maxItemBytes=%d, "
                + "avgItemBytes=%.2f, totalBytes=%d",
            lweToRgswKey.size(), minByteLength(lweToRgswKey), maxByteLength(lweToRgswKey),
            averageByteLength(lweToRgswKey), byteLength(lweToRgswKey)
        );
        lastQueries = new ArrayList<>();
        initState();
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);
        logPhaseInfo(PtoState.INIT_END);
    }

    public List<byte[]>[] pir(ArrayList<List<T>> queries) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", queries.size(), maxBatchNum);
        if (!config.getQueryMethod().equals(CapePirQueryMethod.AND)) {
            throw new UnsupportedOperationException("CAPE currently only supports AND queries");
        }
        logPhaseInfo(PtoState.PTO_BEGIN);
        fusepirQueryByteLength = 0L;
        encryptedBloomQueryByteLength = 0L;
        encryptedValueResponseByteLength = 0L;
        encryptedScoreResponseByteLength = 0L;
        fusepirQueryGenerationTime = 0L;
        bloomQueryEncryptionTime = 0L;
        scoreDecryptTime = 0L;
        valueDecryptDecodeTime = 0L;
        lastQueries = new ArrayList<>(queries.size());
        @SuppressWarnings("unchecked")
        List<byte[]>[] entries = new List[queries.size()];
        for (int i = 0; i < queries.size(); i++) {
            stopWatch.start();
            CapePirQuery query = generateCapeQuery(queries.get(i));
            lastQueries.add(query);
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal(), query.getServerPayload());
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, "Client generates CAPE query");

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            MpcAbortPreconditions.checkArgument(responsePayload.size() == params.getExpectedPackedResultCiphertextCount());
            encryptedValueResponseByteLength += byteLength(responsePayload);
            encryptedScoreResponseByteLength += 0L;
            CapePirResponse response = CapePirResponse.createPackedResultResponse(responsePayload);
            entries[i] = decodeResponse(query, response);
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles CAPE reply");
        }
        logPhaseInfo(PtoState.PTO_END);
        return entries;
    }

    public void sendPublicKeysAndReceiveSeed() throws MpcAbortException {
        checkInitialized();
        if (lweToRgswKey == null || lweToRgswKey.isEmpty()) {
            throw new IllegalStateException("CAPE LWE-to-RGSW setup key is not initialized");
        }
        logCheckpoint("client sendPublicKeysAndReceiveSeed begin");
        long publicKeyBytes = publicKey.length;
        long relinKeysBytes = relinKeys.length;
        long galoisKeysBytes = galoisKeys.length;
        long lweToRgswKeyBytes = byteLength(lweToRgswKey);
        long totalSetupBytes = publicKeyBytes + relinKeysBytes + galoisKeysBytes + lweToRgswKeyBytes;
        logCheckpoint(
            "client setup payload bytes: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d, "
                + "lweToRgswKeyBytes=%d, lweToRgswKeyItemCount=%d, totalSetupBytes=%d",
            publicKeyBytes, relinKeysBytes, galoisKeysBytes, lweToRgswKeyBytes, lweToRgswKey.size(),
            totalSetupBytes
        );
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_BFV_KEYS.ordinal(), List.of(publicKey, relinKeys, galoisKeys));
        logCheckpoint(
            "client sent BFV keys: publicKeyBytes=%d, relinKeysBytes=%d, galoisKeysBytes=%d",
            publicKeyBytes, relinKeysBytes, galoisKeysBytes
        );
        int maxChunkBytes = CapeSetupPayloadUtils.DEFAULT_MAX_SETUP_CHUNK_BYTES;
        List<CapeSetupPayloadUtils.SetupChunk> chunks = CapeSetupPayloadUtils.planChunks(lweToRgswKey, maxChunkBytes);
        sendOtherPartyPayload(
            PtoStep.CLIENT_SEND_LWE_TO_RGSW_KEY_META.ordinal(),
            CapeSetupPayloadUtils.encodeMeta(lweToRgswKey.size(), chunks.size(), lweToRgswKeyBytes, maxChunkBytes)
        );
        logCheckpoint(
            "client sent LWE-to-RGSW meta: itemCount=%d, chunkCount=%d, totalBytes=%d, maxChunkBytes=%d",
            lweToRgswKey.size(), chunks.size(), lweToRgswKeyBytes, maxChunkBytes
        );
        for (CapeSetupPayloadUtils.SetupChunk chunk : chunks) {
            if (chunk.getByteLength() + 2L * Integer.BYTES > maxChunkBytes && chunk.getItems().size() == 1) {
                LOGGER.warn(
                    "{} client sending oversized single-item LWE-to-RGSW chunk: chunkIndex={}, chunkBytes={}, "
                        + "maxChunkBytes={}",
                    CHECKPOINT_PREFIX, chunk.getChunkIndex(), chunk.getByteLength(), maxChunkBytes
                );
            }
            sendOtherPartyPayload(
                PtoStep.CLIENT_SEND_LWE_TO_RGSW_KEY_CHUNK.ordinal(), CapeSetupPayloadUtils.encodeChunk(chunk)
            );
            logCheckpoint(
                "client sent LWE-to-RGSW chunk %d/%d: chunkBytes=%d, chunkItems=%d",
                chunk.getChunkIndex() + 1, chunks.size(), chunk.getByteLength(), chunk.getItems().size()
            );
            chunk.clearItems();
        }
        logCheckpoint("client sent all LWE-to-RGSW chunks: chunkCount=%d, totalBytes=%d",
            chunks.size(), lweToRgswKeyBytes);
        chunks.clear();
        lweToRgswKey.clear();
        lweToRgswKey = null;
        logCheckpoint("client released Java LWE-to-RGSW setup key after send: releasedBytes=%d", lweToRgswKeyBytes);
        logCheckpoint("client waiting bff seed");
        List<byte[]> seedPayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal());
        logCheckpoint("client received bff seed: seedPayloadCount=%d, seedPayloadBytes=%d",
            seedPayload.size(), byteLength(seedPayload));
        MpcAbortPreconditions.checkArgument(seedPayload.size() == 2);
        bffSeed = seedPayload.get(0);
        byte[] bloomParams = seedPayload.get(1);
        params.applySerializedBloomParams(bloomParams);
        logPerf("bffSeedBytes = %d", bffSeed.length);
        logPerf("bloomParamsBytes = %d", bloomParams.length);
        logPerf(
            "client/server Bloom params synchronized: bloomFalsePositiveExponent=%d, bloomFalsePositiveRate=2^-%d, "
                + "bloomExpectedInsertions=%d, bloomBitLength=%d, bloomHashNum=%d",
            params.getBloomFalsePositiveExponent(), params.getBloomFalsePositiveExponent(),
            params.getBloomExpectedInsertions(), params.getBloomBitLength(), params.getBloomHashNum()
        );
    }

    public int getKeywordNum() {
        return keywordNum;
    }

    CapePirParams getCapeParams() {
        return params;
    }

    CapePirQuery generateCapeQuery(List<T> queryKeywords) {
        checkInitialized();
        if (!config.getQueryMethod().equals(CapePirQueryMethod.AND)) {
            throw new UnsupportedOperationException("CAPE currently only supports AND queries");
        }
        MathPreconditions.checkEqual(
            "queryKeywords.size", "bool_keyword_num", queryKeywords.size(), config.getBoolKeywordNum()
        );
        if (bffSeed == null) {
            throw new IllegalStateException("BFF seed is not initialized");
        }
        T anchorKeyword = queryKeywords.get(0);
        List<T> remainingKeywords = queryKeywords.subList(1, queryKeywords.size());
        long anchorStartTime = System.nanoTime();
        byte[] anchorKeywordBytes = CapePirUtils.keywordToByteArray(anchorKeyword);
        int[] positions = CapePirUtils.getHashPositionsFromKeywordBytes(anchorKeywordBytes, keywordNum, bffSeed, params);
        int[] rows = new int[positions.length];
        int[] cols = new int[positions.length];
        for (int i = 0; i < positions.length; i++) {
            rows[i] = positions[i] % params.getMatrixRowNum();
            cols[i] = positions[i] / params.getMatrixRowNum();
        }
        logPerf("anchor position computation time = %d ms", elapsedMillis(anchorStartTime));
        List<byte[]> columnQueries = new ArrayList<>(params.getBffHashNum());
        List<byte[]> compressedRowBitQueries = new ArrayList<>(params.getBffHashNum());
        long fusepirStartTime = System.nanoTime();
        long columnStartTime = System.nanoTime();
        for (int col : cols) {
            columnQueries.add(CapePirNativeUtils.generatePackedColumnQuery(
                params.encryptionParams, publicKey, secretKey, col, params.getMatrixColNum(),
                params.getBlocksPerPackedMatrix()
            ));
        }
        logPerf("columnQueries generation time = %d ms", elapsedMillis(columnStartTime));
        logPerf("bitColumnQueries generation time = 0 ms (skipped in formal query)");
        long rowBitsStartTime = System.nanoTime();
        for (int row : rows) {
            compressedRowBitQueries.add(generateCompressedRowBitQuery(row, params.getMatrixRowNum()).toByteArray());
        }
        logPerf("encryptedRowBits generation time = 0 ms (skipped in compressed formal query)");
        logPerf("compressedRowBitQueries generation time = %d ms", elapsedMillis(rowBitsStartTime));
        fusepirQueryGenerationTime += TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - fusepirStartTime);
        long columnQueriesBytes = byteLength(columnQueries);
        long compressedRowBitBytes = byteLength(compressedRowBitQueries);
        fusepirQueryByteLength += columnQueriesBytes + compressedRowBitBytes;
        CapeBloomFilterAdapter queryBloomFilter = CapePirUtils.buildQueryBloomFilter(remainingKeywords, params);
        long bloomStartTime = System.nanoTime();
        long[] queryBloomBits = queryBloomFilter.toLongBitVector();
        logPerf("encryptedBloomFilter generation time = 0 ms (skipped in formal query)");
        long encryptedCoeffBloomStartTime = System.nanoTime();
        List<byte[]> encryptedCoeffBloomFilters = generatePackedBloomQueryCiphertexts(queryBloomBits);
        logPerf("encryptedCoeffBloomFilters generation time = %d ms", elapsedMillis(encryptedCoeffBloomStartTime));
        bloomQueryEncryptionTime += TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - bloomStartTime);
        long encryptedCoeffBloomFiltersBytes = byteLength(encryptedCoeffBloomFilters);
        encryptedBloomQueryByteLength += encryptedCoeffBloomFiltersBytes;
        long metadataBytes = 0L;
        if (PERF_LOG_ENABLED) {
            logPerf("denseCoeffBloomCiphertextNum = %d", params.getMaxValueNumPerKeyword() * params.getBloomBitLength());
            logPerf("compactPerValueCoeffBloomCiphertextNum = %d", params.getCompactCoeffBloomCiphertextNum());
            logPerf("globalTiledCoeffBloomCiphertextNum = %d", params.getGlobalTiledCoeffBloomCiphertextNum());
            logPerf("oldEncryptedCoeffBloomFilterCount = %d", params.getPackedBloomQueryCiphertextNum());
            logPerf("packedQueryBloomCiphertextNum = %d", params.getPackedQueryBloomCiphertextNum());
            logPerf("bloomBitLength = %d", params.getBloomBitLength());
            logPerf("polyModulusDegree = %d", params.getPolyModulusDegree());
            logPerf(
                "online query bytes by component: columnQueriesBytes=%d, encryptedRowBitsBytes=%d, "
                + "compressedRowBitBytes=%d, compactPerValueEncryptedCoeffBloomFiltersBytes=reference, "
                    + "globalTiledEncryptedCoeffBloomFiltersBytes=reference, packedQueryBloomCiphertextBytes=%d, "
                    + "metadataBytes=%d, "
                    + "bitColumnQueriesBytes=0, encryptedBloomFilterBytes=0, totalOnlineQueryBytes=%d",
                columnQueriesBytes, 0L, compressedRowBitBytes, encryptedCoeffBloomFiltersBytes, metadataBytes,
                columnQueriesBytes + compressedRowBitBytes + encryptedCoeffBloomFiltersBytes + metadataBytes
            );
        }
        return new CapePirQuery(
            anchorKeywordBytes, columnQueries, compressedRowBitQueries, encryptedCoeffBloomFilters,
            queryBloomFilter.countOnes(), config.getBoolKeywordNum()
        );
    }

    private CapeCompressedLweBitQuery generateCompressedRowBitQuery(int rowIndex, int rowNum) {
        return CapeLwePrgUtils.generateCompressedRowBitQuery(
            rowIndex, rowNum, lweSecretKey, CapePirNativeUtils.LWE_MODULUS, CapePirNativeUtils.DELTA_BIT
        );
    }

    private List<byte[]> generatePackedBloomQueryCiphertexts(long[] queryBloomBits) {
        if (queryBloomBits.length != params.getBloomBitLength()) {
            throw new IllegalArgumentException("CAPE query Bloom bit length mismatch");
        }
        int capacity = params.getPolyModulusDegree();
        int groupNum = params.getPackedQueryBloomCiphertextNum();
        List<byte[]> chunks = new ArrayList<>(groupNum);
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            long[] chunk = new long[Math.min(capacity, queryBloomBits.length - groupIndex * capacity)];
            int groupOffset = groupIndex * capacity;
            for (int blockOffset = 0; blockOffset < chunk.length; blockOffset++) {
                int bitIndex = groupOffset + blockOffset;
                if (bitIndex < queryBloomBits.length) {
                    chunk[blockOffset] = queryBloomBits[bitIndex];
                }
            }
            chunks.add(CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
                params.encryptionParams, publicKey, secretKey, chunk
            ));
        }
        return chunks;
    }

    @Deprecated
    List<byte[]> generateGlobalTiledEncryptedCoeffBloomFilterChunksForTest(long[] queryBloomBits) {
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        int bloomPayloadBlockNum = params.getMaxValueNumPerKeyword() * params.getBloomBitLength();
        int groupNum = (bloomPayloadBlockNum + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        List<byte[]> chunks = new ArrayList<>(params.getGlobalTiledCoeffBloomCiphertextNum());
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            long[] chunk = new long[blocksPerPackedMatrix];
            int groupOffset = groupIndex * blocksPerPackedMatrix;
            for (int blockOffset = 0; blockOffset < blocksPerPackedMatrix; blockOffset++) {
                int globalBitIndex = groupOffset + blockOffset;
                if (globalBitIndex < bloomPayloadBlockNum) {
                    chunk[blockOffset] = queryBloomBits[globalBitIndex % params.getBloomBitLength()];
                }
            }
            chunks.add(CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
                params.encryptionParams, publicKey, secretKey, chunk
            ));
        }
        return chunks;
    }

    @Deprecated
    List<byte[]> generateCompactPerValueEncryptedCoeffBloomFilterChunksForTest(long[] queryBloomBits) {
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        int bloomPayloadBlockNum = params.getMaxValueNumPerKeyword() * params.getBloomBitLength();
        int groupNum = (bloomPayloadBlockNum + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        List<byte[]> chunks = new ArrayList<>(params.getCompactCoeffBloomCiphertextNum());
        for (int valueIndex = 0; valueIndex < params.getMaxValueNumPerKeyword(); valueIndex++) {
            for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
                long[] chunk = new long[blocksPerPackedMatrix];
                int groupOffset = groupIndex * blocksPerPackedMatrix;
                int valueOffset = valueIndex * params.getBloomBitLength();
                for (int blockOffset = 0; blockOffset < blocksPerPackedMatrix; blockOffset++) {
                    int bitIndex = groupOffset + blockOffset - valueOffset;
                    if (bitIndex >= 0 && bitIndex < queryBloomBits.length) {
                        chunk[blockOffset] = queryBloomBits[bitIndex];
                    }
                }
                chunks.add(CapePirNativeUtils.generateEncryptedCoeffBloomFilter(
                    params.encryptionParams, publicKey, secretKey, chunk
                ));
            }
        }
        return chunks;
    }

    void setBffSeed(byte[] bffSeed) {
        this.bffSeed = BytesUtils.clone(bffSeed);
    }

    byte[] getSecretKey() {
        return Arrays.copyOf(secretKey, secretKey.length);
    }

    byte[] getPublicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    byte[] getGaloisKeys() {
        return Arrays.copyOf(galoisKeys, galoisKeys.length);
    }

    byte[] getRelinKeys() {
        return Arrays.copyOf(relinKeys, relinKeys.length);
    }

    long[] getLweSecretKey() {
        return Arrays.copyOf(lweSecretKey, lweSecretKey.length);
    }

    List<byte[]> getLweToRgswKey() {
        return new ArrayList<>(lweToRgswKey);
    }

    void releaseLargeKeysForTest() {
        secretKey = null;
        publicKey = null;
        relinKeys = null;
        galoisKeys = null;
        lweSecretKey = null;
        lweToRgswKey = null;
        lastQueries = null;
    }

    List<CapePirQuery> getLastQueries() {
        return lastQueries;
    }

    List<byte[]> decodeResponse(CapePirQuery query, CapePirResponse response) {
        checkInitialized();
        if (!response.getPackedResultCiphertexts().isEmpty()) {
            return decodePackedResultResponse(query, response.getPackedResultCiphertexts());
        }
        List<byte[]> encryptedScores = response.getEncryptedBloomInnerProducts();
        List<byte[]> results = new ArrayList<>();
        if (encryptedScores.isEmpty()) {
            return results;
        }
        int expectedScoreCiphertextCount = getExpectedPackedScoreCiphertextCount();
        if (encryptedScores.size() != expectedScoreCiphertextCount) {
            throw new IllegalStateException("CAPE packed score ciphertext count mismatch");
        }
        long scoreDecryptStartTime = System.nanoTime();
        List<long[]> decryptedScoreBlocks = new ArrayList<>(encryptedScores.size());
        for (byte[] encryptedScore : encryptedScores) {
            decryptedScoreBlocks.add(CapePirNativeUtils.decryptPackedScoreCoeffReply(
                params.encryptionParams, secretKey, encryptedScore
            ));
        }
        long packedScoreDecryptTime = elapsedMillis(scoreDecryptStartTime);
        scoreDecryptTime += packedScoreDecryptTime;
        logPerf("packed score decrypt time = %d ms", packedScoreDecryptTime);
        long scoreUnpackStartTime = System.nanoTime();
        long[] scores = new long[params.getMaxValueNumPerKeyword()];
        int copiedScoreNum = 0;
        for (long[] decryptedScoreBlock : decryptedScoreBlocks) {
            int copyLength = Math.min(decryptedScoreBlock.length, scores.length - copiedScoreNum);
            if (copyLength <= 0) {
                break;
            }
            System.arraycopy(decryptedScoreBlock, 0, scores, copiedScoreNum, copyLength);
            copiedScoreNum += copyLength;
        }
        if (copiedScoreNum < scores.length) {
            throw new IllegalStateException("CAPE packed score response does not contain enough scores");
        }
        logPerf("score unpack time = %d ms", elapsedMillis(scoreUnpackStartTime));
        long resultFilterStartTime = System.nanoTime();
        List<Integer> hitIndexes = new ArrayList<>();
        long inversePackedScoreScale = inverseMod(params.getPolyModulusDegree() % params.getPlainModulus(),
            params.getPlainModulus());
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            long score = Math.floorMod(scores[i] * inversePackedScoreScale, params.getPlainModulus());
            if (score == query.getBloomOneCount()) {
                hitIndexes.add(i);
            }
        }
        logPerf("result filter time = %d ms", elapsedMillis(resultFilterStartTime));
        long valueStartTime = System.nanoTime();
        List<byte[]> encryptedValues = response.getEncryptedValuePayloads();
        if (encryptedValues.size() != getExpectedValueCiphertextCount()) {
            throw new IllegalStateException("CAPE value response ciphertext count mismatch");
        }
        long[] valueCoeffs = new long[CapePirUtils.valueOnlyPayloadBlockNum(params)];
        int copiedValueCoeffNum = 0;
        for (byte[] encryptedValue : encryptedValues) {
            long[] segmentCoeffs = CapePirNativeUtils.decryptCoeffReply(params.encryptionParams, secretKey, encryptedValue);
            int copyLength = Math.min(
                params.getValueBlocksPerPackedMatrix(), valueCoeffs.length - copiedValueCoeffNum
            );
            if (copyLength <= 0) {
                break;
            }
            System.arraycopy(segmentCoeffs, 0, valueCoeffs, copiedValueCoeffNum, copyLength);
            copiedValueCoeffNum += copyLength;
        }
        if (copiedValueCoeffNum < valueCoeffs.length) {
            throw new IllegalStateException("CAPE value response does not contain enough payload coefficients");
        }
        List<byte[]> candidateValues = CapePirUtils.decodeValueOnlyPayload(query.getAnchorKeywordBytes(), valueCoeffs, params);
        for (int hitIndex : hitIndexes) {
            if (hitIndex < candidateValues.size()) {
                results.add(candidateValues.get(hitIndex));
            }
        }
        long valueDecryptTime = elapsedMillis(valueStartTime);
        valueDecryptDecodeTime += valueDecryptTime;
        logPerf("value decrypt time = %d ms", valueDecryptTime);
        return results;
    }

    private List<byte[]> decodePackedResultResponse(CapePirQuery query, List<byte[]> packedResultCiphertexts) {
        if (packedResultCiphertexts.size() != params.getExpectedPackedResultCiphertextCount()) {
            throw new IllegalStateException("CAPE packed result response ciphertext count mismatch");
        }
        long decryptStartTime = System.nanoTime();
        long[] resultCoeffs = new long[params.getTotalResultCoeffNum()];
        int copiedCoeffNum = 0;
        for (byte[] packedResultCiphertext : packedResultCiphertexts) {
            long[] coeffs = CapePirNativeUtils.decryptCoeffReply(params.encryptionParams, secretKey, packedResultCiphertext);
            int copyLength = Math.min(params.getPolyModulusDegree(), resultCoeffs.length - copiedCoeffNum);
            if (copyLength <= 0) {
                break;
            }
            System.arraycopy(coeffs, 0, resultCoeffs, copiedCoeffNum, copyLength);
            copiedCoeffNum += copyLength;
        }
        if (copiedCoeffNum < resultCoeffs.length) {
            throw new IllegalStateException("CAPE packed result response does not contain enough coefficients");
        }
        long packedResultDecryptTime = elapsedMillis(decryptStartTime);
        scoreDecryptTime += packedResultDecryptTime;
        logPerf("packed result decrypt time = %d ms", packedResultDecryptTime);

        long scoreUnpackStartTime = System.nanoTime();
        long[] scores = new long[params.getMaxValueNumPerKeyword()];
        System.arraycopy(resultCoeffs, params.getScoreOffset(), scores, 0, scores.length);
        logPerf("score unpack time = %d ms", elapsedMillis(scoreUnpackStartTime));

        long resultFilterStartTime = System.nanoTime();
        List<Integer> hitIndexes = new ArrayList<>();
        long inversePackedScoreScale = inverseMod(params.getPolyModulusDegree() % params.getPlainModulus(),
            params.getPlainModulus());
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            long score = Math.floorMod(scores[i] * inversePackedScoreScale, params.getPlainModulus());
            if (score == query.getBloomOneCount()) {
                hitIndexes.add(i);
            }
        }
        logPerf("result filter time = %d ms", elapsedMillis(resultFilterStartTime));

        long valueStartTime = System.nanoTime();
        long[] valueCoeffs = Arrays.copyOf(resultCoeffs, params.getValuePayloadCoeffNum());
        List<byte[]> candidateValues = CapePirUtils.decodeValueOnlyPayload(query.getAnchorKeywordBytes(), valueCoeffs, params);
        List<byte[]> results = new ArrayList<>();
        for (int hitIndex : hitIndexes) {
            if (hitIndex < candidateValues.size()) {
                results.add(candidateValues.get(hitIndex));
            }
        }
        long valueDecryptTime = elapsedMillis(valueStartTime);
        valueDecryptDecodeTime += valueDecryptTime;
        logPerf("value decrypt time = %d ms", valueDecryptTime);
        return results;
    }

    public long getFusePirQueryByteLength() {
        return fusepirQueryByteLength;
    }

    public long getEncryptedBloomQueryByteLength() {
        return encryptedBloomQueryByteLength;
    }

    public long getEncryptedValueResponseByteLength() {
        return encryptedValueResponseByteLength;
    }

    public long getEncryptedScoreResponseByteLength() {
        return encryptedScoreResponseByteLength;
    }

    public long getFusePirQueryGenerationTime() {
        return fusepirQueryGenerationTime;
    }

    public long getBloomQueryEncryptionTime() {
        return bloomQueryEncryptionTime;
    }

    public long getScoreDecryptTime() {
        return scoreDecryptTime;
    }

    public long getValueDecryptDecodeTime() {
        return valueDecryptDecodeTime;
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    private static int minByteLength(List<byte[]> payload) {
        return payload.stream().mapToInt(bytes -> bytes.length).min().orElse(0);
    }

    private static int maxByteLength(List<byte[]> payload) {
        return payload.stream().mapToInt(bytes -> bytes.length).max().orElse(0);
    }

    private static double averageByteLength(List<byte[]> payload) {
        return payload.isEmpty() ? 0.0 : (double) byteLength(payload) / payload.size();
    }

    private static long[] generateBinaryLweSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        long[] secretKey = new long[CapePirNativeUtils.LWE_DIMENSION];
        for (int i = 0; i < CapePirNativeUtils.LWE_DIMENSION; i++) {
            secretKey[i] = secureRandom.nextBoolean() ? 1L : 0L;
        }
        return secretKey;
    }

    private int getPackedScoreCapacity() {
        return params.getPolyModulusDegree();
    }

    private int getExpectedPackedScoreCiphertextCount() {
        int packedScoreCapacity = getPackedScoreCapacity();
        return (params.getMaxValueNumPerKeyword() + packedScoreCapacity - 1) / packedScoreCapacity;
    }

    private int getExpectedValueCiphertextCount() {
        return (CapePirUtils.valueOnlyPayloadBlockNum(params) + params.getValueBlocksPerPackedMatrix() - 1)
            / params.getValueBlocksPerPackedMatrix();
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

    private static long inverseMod(long value, long modulus) {
        long t = 0;
        long newT = 1;
        long r = modulus;
        long newR = Math.floorMod(value, modulus);
        while (newR != 0) {
            long quotient = r / newR;
            long nextT = t - quotient * newT;
            t = newT;
            newT = nextT;
            long nextR = r - quotient * newR;
            r = newR;
            newR = nextR;
        }
        if (r != 1) {
            throw new IllegalStateException("packed score scale is not invertible modulo plaintext modulus");
        }
        return Math.floorMod(t, modulus);
    }
}
