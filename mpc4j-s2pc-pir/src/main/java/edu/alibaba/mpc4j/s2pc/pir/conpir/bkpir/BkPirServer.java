package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirPtoDesc.getInstance;

/**
 * BKPIR server.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirServer<T> extends AbstractTwoPartyPto {
    /**
     * config.
     */
    private final BkPirConfig config;
    /**
     * params.
     */
    private final BkPirParams params;
    /**
     * keyword num.
     */
    private int keywordNum;
    /**
     * value space size.
     */
    private int valueSpaceSize;
    /**
     * max batch num.
     */
    private int maxBatchNum;
    /**
     * public key.
     */
    private byte[] publicKey;
    /**
     * relinearization keys.
     */
    private byte[] relinKeys;
    /**
     * Galois keys.
     */
    private byte[] galoisKeys;
    /**
     * encoded keyword codewords.
     */
    private List<byte[]> encodedKeywordCodewords;
    /**
     * encoded value maps.
     */
    private List<List<byte[]>> encodedValueMaps;
    /**
     * encoded value payloads.
     */
    private List<List<byte[]>> encodedValuePayloads;

    public BkPirServer(Rpc serverRpc, Party clientParty, BkPirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(Map<T, List<byte[]>> keywordValueMap, int maxBatchNum)
        throws MpcAbortException {
        init(keywordValueMap, collectValueSpace(keywordValueMap), maxBatchNum);
    }

    public void init(Map<T, List<byte[]>> keywordValueMap, List<byte[]> valueSpace, int maxBatchNum)
        throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_num", keywordValueMap.size());
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        MathPreconditions.checkPositive("value_space_size", valueSpace.size());
        keywordNum = keywordValueMap.size();
        valueSpaceSize = valueSpace.size();
        this.maxBatchNum = maxBatchNum;
        logPhaseInfo(PtoState.INIT_BEGIN);

        List<byte[]> publicKeysPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal());
        stopWatch.start();
        MpcAbortPreconditions.checkArgument(publicKeysPayload.size() == 3);
        publicKey = publicKeysPayload.get(0);
        relinKeys = publicKeysPayload.get(1);
        galoisKeys = publicKeysPayload.get(2);
        int valueByteLength = valueSpace.get(0).length;
        valueSpace.forEach(value ->
            MathPreconditions.checkEqual("value.length", "valueByteLength", value.length, valueByteLength)
        );
        params.initPirParams(keywordNum, valueSpaceSize, valueByteLength);
        List<T> keywordList = new ArrayList<>(keywordValueMap.keySet());
        Map<ByteBuffer, Integer> valueIndexMap = buildValueIndexMap(valueSpace);
        long[][] keywordCodewords = encodeKeywords(keywordList);
        long[][] valuePayloads = BkPirUtils.encodeValuePayloads(valueSpace, params);
        encodedValueMaps = new ArrayList<>(params.valueChunkNum);
        encodedValuePayloads = new ArrayList<>(params.valueChunkNum);
        for (int chunkIndex = 0; chunkIndex < params.valueChunkNum; chunkIndex++) {
            long[][] valueMaps = encodeValueMapChunk(keywordList, keywordValueMap, valueIndexMap, chunkIndex);
            long[][] chunkPayloads = new long[params.payloadPlaintextNumPerChunk][];
            System.arraycopy(valuePayloads, chunkIndex * params.payloadPlaintextNumPerChunk, chunkPayloads, 0,
                params.payloadPlaintextNumPerChunk);
            List<byte[]> encodedDatabase = BkPirNativeUtils.preprocessDatabase(
                params.encryptionParams, keywordCodewords, valueMaps, chunkPayloads
            );
            MpcAbortPreconditions.checkArgument(encodedDatabase.size() == 2 * keywordNum
                + params.payloadPlaintextNumPerChunk);
            if (chunkIndex == 0) {
                encodedKeywordCodewords = encodedDatabase.subList(0, keywordNum).stream()
                    .map(bytes -> bytes)
                    .collect(Collectors.toList());
            }
            encodedValueMaps.add(encodedDatabase.subList(keywordNum, 2 * keywordNum).stream()
                .map(bytes -> bytes)
                .collect(Collectors.toList()));
            encodedValuePayloads.add(encodedDatabase.subList(
                    2 * keywordNum, 2 * keywordNum + params.payloadPlaintextNumPerChunk
                ).stream()
                .map(bytes -> bytes)
                .collect(Collectors.toList()));
        }
        initState();
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);

        logPhaseInfo(PtoState.INIT_END);
    }

    public void pir(int batchNum) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", batchNum, maxBatchNum);
        if (!config.getQueryMethod().equals(BkPirQueryMethod.AND)) {
            throw new UnsupportedOperationException("BKPIR currently only supports AND queries");
        }
        logPhaseInfo(PtoState.PTO_BEGIN);

        for (int batchIndex = 0; batchIndex < batchNum; batchIndex++) {
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal());
            stopWatch.start();
            MathPreconditions.checkEqual("queryPayload.size()", "bool_keyword_num", queryPayload.size(),
                config.getBoolKeywordNum());
            MathPreconditions.checkGreaterOrEqual("queryPayload.size()", queryPayload.size(), 2);
            List<byte[]> response = switch (config.getQueryMethod()) {
                case AND -> generateAndReply(queryPayload);
                case OR -> throw new UnsupportedOperationException("BKPIR OR retrieval is not implemented yet");
                case NOT -> throw new UnsupportedOperationException("BKPIR NOT retrieval is not implemented yet");
            };
            MpcAbortPreconditions.checkArgument(response.size() == params.payloadPlaintextNum);
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), response);
            stopWatch.stop();
            long replyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 1, replyTime, "Server generates boolean reply");
        }

        logPhaseInfo(PtoState.PTO_END);
    }

    public int getKeywordNum() {
        return keywordNum;
    }

    public int getValueSpaceSize() {
        return valueSpaceSize;
    }

    private List<byte[]> collectValueSpace(Map<T, List<byte[]>> keywordValueMap) {
        Map<ByteBuffer, byte[]> valueSpaceMap = new LinkedHashMap<>();
        keywordValueMap.values().forEach(values -> values.forEach(value -> {
            ByteBuffer valueBuffer = ByteBuffer.wrap(value);
            valueSpaceMap.putIfAbsent(valueBuffer, value.clone());
        }));
        return new ArrayList<>(valueSpaceMap.values());
    }

    private Map<ByteBuffer, Integer> buildValueIndexMap(List<byte[]> valueSpace) {
        Map<ByteBuffer, Integer> valueIndexMap = new LinkedHashMap<>(valueSpace.size());
        for (int valueIndex = 0; valueIndex < valueSpace.size(); valueIndex++) {
            valueIndexMap.put(ByteBuffer.wrap(valueSpace.get(valueIndex)), valueIndex);
        }
        return valueIndexMap;
    }

    private long[][] encodeKeywords(List<T> keywordList) {
        long[][] keywordCodewords = new long[keywordNum][];
        for (int keywordIndex = 0; keywordIndex < keywordNum; keywordIndex++) {
            byte[] keywordBytes = ObjectUtils.objectToByteArray(keywordList.get(keywordIndex));
            keywordCodewords[keywordIndex] = BkPirUtils.cwEncode(
                BkPirUtils.hashKeywordToBigInteger(keywordBytes), params.getCodewordLength(), params.getCwWeight()
            );
        }
        return keywordCodewords;
    }

    private long[][] encodeValueMapChunk(List<T> keywordList, Map<T, List<byte[]>> keywordValueMap,
                                         Map<ByteBuffer, Integer> valueIndexMap, int chunkIndex) {
        long[][] valueMaps = new long[keywordNum][];
        for (int keywordIndex = 0; keywordIndex < keywordNum; keywordIndex++) {
            List<byte[]> values = keywordValueMap.get(keywordList.get(keywordIndex));
            List<Integer> valueIndices = values.stream()
                .map(value -> {
                    Integer valueIndex = valueIndexMap.get(ByteBuffer.wrap(value));
                    if (valueIndex == null) {
                        throw new IllegalArgumentException("Keyword value is not contained in the BKPIR value space");
                    }
                    return valueIndex;
                })
                .collect(Collectors.toList());
            valueMaps[keywordIndex] = BkPirUtils.encodeValueMapChunk(
                valueIndices.stream().collect(Collectors.toSet()), params, chunkIndex
            );
        }
        return valueMaps;
    }

    private List<byte[]> generateAndReply(List<byte[]> queryPayload) {
        List<byte[]> response = new ArrayList<>(params.payloadPlaintextNum);
        for (int chunkIndex = 0; chunkIndex < params.valueChunkNum; chunkIndex++) {
            response.addAll(BkPirNativeUtils.generateAndReply(
                params.encryptionParams, publicKey, relinKeys, galoisKeys, queryPayload,
                encodedKeywordCodewords, encodedValueMaps.get(chunkIndex), encodedValuePayloads.get(chunkIndex),
                params.getCwWeight()
            ));
        }
        return response;
    }
}
