package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.CommonConstants;

import java.util.List;

/**
 * FUSE_PIR_C standard keyword PIR native utils.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
class FusePirCStdKwPirNativeUtils {
    /**
     * secret key index.
     */
    static final int SECRET_KEY_INDEX = 0;
    /**
     * public key index.
     */
    static final int PUBLIC_KEY_INDEX = 1;
    /**
     * LWE secret key index.
     */
    static final int LWE_SECRET_KEY_INDEX = 2;

    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

    private FusePirCStdKwPirNativeUtils() {
        // empty
    }

    static native byte[] generateEncryptionParams(int polyModulusDegree, long plainModulus, int[] coeffModulusBits);

    static native List<byte[]> keyGen(byte[] encryptionParams, FusePirCLweParams lweParams);

    static native byte[] generateCompressedQuery(byte[] encryptionParams, byte[] publicKey, byte[] secretKey,
                                                 byte[] lweSecretKey, byte[] bffSeed, int[] positions, int rowNum, int colNum,
                                                 FusePirCLweParams lweParams);

    static native boolean checkPrgSameDomain(byte[] seed, int domain, FusePirCLweParams lweParams);

    static native boolean checkPrgDifferentDomain(byte[] seed, int domain0, int domain1, FusePirCLweParams lweParams);

    static native boolean checkLweEncryptDecrypt(int bit, FusePirCLweParams lweParams);

    static native boolean checkCompressedQueryRecover(FusePirCLweParams lweParams);

    static native boolean checkRgswLayout(byte[] encryptionParams, byte[] publicKey);

    static native boolean checkCmux(byte[] encryptionParams, byte[] secretKey, byte[] publicKey);

    static native boolean checkRawPolyMonomial();

    static native boolean checkRawPolyAutomorphism();

    static native boolean checkGadgetExact();

    static native boolean checkRawRlweEncryptDecrypt();

    static native boolean checkRawNttRoot();

    static native boolean checkRawNttNegacyclicMulSmall();

    static native boolean checkRawNttNegacyclicMulCandidateSparse();

    static native boolean checkMvFbsModSwitchSign();

    static native boolean checkMvFbsTestPolynomialLayout();

    static native boolean checkRawExternalProductContract();

    static native boolean checkRawRgswCmuxContract();

    static native boolean checkRawExternalProductCachedNttConsistency();

    static native boolean checkMvFbsNoSampleExtractBit0Bit1();

    static native boolean checkRawAutomorphismKeySwitchPhase();

    static native boolean checkHomTraceKillsNonconstantTerms();

    static native boolean checkHomTraceManyMvFbsOutput();

    static native boolean checkSchemeSwitchKeyGeneration();

    static native boolean checkSchemeSwitchRawRgswLayout();

    static native boolean checkSchemeSwitchCmuxSemantics();

    static native boolean checkCircuitBootstrapKeyGeneration();

    static native boolean checkTraceInverseScalingModInverse();

    static native boolean checkSecureLweToRgswBit0Bit1Cmux();

    static native boolean checkSecureLweBitsToRgswBatch();

    static native boolean checkSecureLweBitsToRgswBatchWorkspaceConsistency();

    static native boolean checkCandidateSecureLweToRgswCmux();

    static native boolean checkSelectorBitDecomposition();

    static native boolean checkSelectorLweBitPhase();

    static native boolean checkRawRlwePrimeBasic();

    static native boolean checkRawRgswMulRlwePrime();

    static native boolean checkOneHotSelectorFromSecureLweBits();

    static native boolean checkOneHotColumnSelection();

    static native boolean checkOneHotSelectorBoundOne();

    static native boolean checkRowSelectorFromSecureLweBits();

    static native boolean checkSelectorNoPlainIndexDependency();

    static native boolean checkFusePirCNativeGenerateReplyMinimalRaw();

    static native boolean checkEvalKeyHandleLifecycle();

    static native List<byte[]> generateCircuitBootstrapKeyMaterialForCheck();

    static native List<byte[]> generateCircuitBootstrapSetupMaterial();

    static native byte[] generateCompressedQueryFromClientSecret(byte[] clientSecretState, byte[] bffSeed,
                                                                 int[] positions, int rowNum, int colNum,
                                                                 byte[] circuitBootstrapParams);

    static native byte[] encodeRawMatrixForEntries(int[] flatPositions, long[] values, int rowNum, int colNum,
                                                   int payloadBlockNum, int rowStride,
                                                   byte[] circuitBootstrapParams);

    static native byte[] encodeRawMatrixFromBffStorage(long[] storageByBlock, int bffSlotNum, int rowNum,
                                                       int colNum, int payloadBlockNum, int rowStride,
                                                       byte[] circuitBootstrapParams);

    static native byte[] encodeRawMatrixFromBffStorageBlocks(long[][] storageByBlock, int bffSlotNum, int rowNum,
                                                             int colNum, int payloadBlockNum, int rowStride,
                                                             byte[] circuitBootstrapParams);

    static native long createEmptyRawMatrix(int rowNum, int colNum, int payloadBlockNum, int rowStride,
                                            byte[] circuitBootstrapParams);

    static native void setRawMatrixPayloadBlock(long rawMatrixHandle, int payloadBlockIndex, long[] storageBlock,
                                                int bffSlotNum, byte[] circuitBootstrapParams);

    static native void finalizeRawMatrix(long rawMatrixHandle, byte[] circuitBootstrapParams);

    static native long createRawMatrix(byte[] encodedRawMatrix, byte[] circuitBootstrapParams);

    static native void destroyRawMatrix(long rawMatrixHandle);

    static native long createCircuitBootstrapEvaluationKey(byte[] circuitBootstrapParams,
                                                           byte[] serializedEvaluationKey);

    static native void destroyCircuitBootstrapEvaluationKey(long evalKeyHandle);

    static native byte[] generateReply(byte[] compressedQuery, long evalKeyHandle, byte[] circuitBootstrapParams,
                                       long rawMatrixHandle);

    static native byte[] generateReply(byte[] compressedQuery, long evalKeyHandle, byte[] circuitBootstrapParams,
                                       byte[] encodedRawMatrix);

    static native boolean checkRawMatrixHandleLifecycle();

    static native boolean checkRawReplyForCheck(byte[] rawResponse, byte[] clientSecretState,
                                                byte[] circuitBootstrapParams);

    static native long[] decryptRawResponse(byte[] rawResponse, byte[] clientSecretState,
                                            byte[] circuitBootstrapParams);

    static native List<byte[]> generateReply(byte[] encryptionParams, byte[] publicKey, byte[] compressedQuery,
                                             List<byte[]> encodedMatrices, int payloadBlockNum, int rowNum,
                                             int colNum, int blocksPerPackedMatrix,
                                             FusePirCCircuitBootstrapParams circuitBootstrapParams);

    static native long[][] decryptReply(byte[] encryptionParams, byte[] secretKey, List<byte[]> response);
}
