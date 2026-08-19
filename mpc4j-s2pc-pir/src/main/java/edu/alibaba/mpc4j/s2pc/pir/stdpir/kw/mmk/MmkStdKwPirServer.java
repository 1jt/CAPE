package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.rpc.*;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirServer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirPtoDesc.getInstance;

/**
 * MMK standard keyword PIR server.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
public class MmkStdKwPirServer<T> extends AbstractStdKwPirServer<T> {
    /**
     * params
     */
    private final MmkStdKwPirParams params;
    /**
     * public key
     */
    private byte[] publicKey;
    /**
     * relinearization keys
     */
    private byte[] relinKeys;
    /**
     * Galois keys
     */
    private byte[] galoisKeys;
    /**
     * encoded keyword codewords
     */
    private List<byte[]> encodedKeywordCodewords;
    /**
     * encoded payloads
     */
    private List<byte[]> encodedPayloads;

    public MmkStdKwPirServer(Rpc serverRpc, Party clientParty, MmkStdKwPirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        params = config.getParams();
    }

    @Override
    public void init(Map<T, byte[]> keyValueMap, int l, int maxBatchNum) throws MpcAbortException {
        assert maxBatchNum <= params.maxRetrievalSize();
        setInitInput(keyValueMap, l, maxBatchNum);
        logPhaseInfo(PtoState.INIT_BEGIN);

        List<byte[]> publicKeysPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal());
        stopWatch.start();
        MpcAbortPreconditions.checkArgument(publicKeysPayload.size() == 3);
        publicKey = publicKeysPayload.get(0);
        relinKeys = publicKeysPayload.get(1);
        galoisKeys = publicKeysPayload.get(2);
        params.initPirParams(n, l);
        List<T> keywordList = new ArrayList<>(keyValueMap.keySet());
        long[][] keywordCodewords = encodeKeywords(keywordList);
        long[][] payloadPlaintexts = encodePayloads(keywordList, keyValueMap);
        List<byte[]> encodedDatabase = MmkStdKwPirNativeUtils.preprocessDatabase(
            params.encryptionParams, keywordCodewords, payloadPlaintexts
        );
        MpcAbortPreconditions.checkArgument(encodedDatabase.size() == n + n * params.payloadPlaintextNum);
        encodedKeywordCodewords = encodedDatabase.subList(0, n).stream()
            .map(bytes -> bytes)
            .collect(Collectors.toList());
        encodedPayloads = encodedDatabase.subList(n, n + n * params.payloadPlaintextNum).stream()
            .map(bytes -> bytes)
            .collect(Collectors.toList());
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);

        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public void pir(int batchNum) throws MpcAbortException {
        setPtoInput(batchNum);
        logPhaseInfo(PtoState.PTO_BEGIN);

        for (int i = 0; i < batchNum; i++) {
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal());
            stopWatch.start();
            MpcAbortPreconditions.checkArgument(queryPayload.size() == 1);
            List<byte[]> response = MmkStdKwPirNativeUtils.generateReply(
                params.encryptionParams, publicKey, relinKeys, galoisKeys, queryPayload.get(0),
                encodedKeywordCodewords, encodedPayloads, params.payloadPlaintextNum, params.getCwWeight()
            );
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), response);
            stopWatch.stop();
            long replyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 1, replyTime, "Server generates reply");
        }

        logPhaseInfo(PtoState.PTO_END);
    }

    private long[][] encodeKeywords(List<T> keywordList) {
        long[][] keywordCodewords = new long[n][];
        for (int i = 0; i < n; i++) {
            byte[] keywordBytes = ObjectUtils.objectToByteArray(keywordList.get(i));
            keywordCodewords[i] = MmkStdKwPirUtils.cwEncode(
                MmkStdKwPirUtils.hashKeywordToBigInteger(keywordBytes), params.getCodewordLength(), params.getCwWeight()
            );
        }
        return keywordCodewords;
    }

    private long[][] encodePayloads(List<T> keywordList, Map<T, byte[]> keyValueMap) {
        long[][] payloadPlaintexts = new long[n * params.payloadPlaintextNum][];
        for (int i = 0; i < n; i++) {
            long[][] keywordPayloads = MmkStdKwPirUtils.encodePayload(keyValueMap.get(keywordList.get(i)), params);
            for (int blockIndex = 0; blockIndex < params.payloadPlaintextNum; blockIndex++) {
                payloadPlaintexts[i * params.payloadPlaintextNum + blockIndex] = keywordPayloads[blockIndex];
            }
        }
        return payloadPlaintexts;
    }
}
