package edu.alibaba.mpc4j.s2pc.pir;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.rpc.main.MainPtoConfigUtils;
import edu.alibaba.mpc4j.common.structure.database.NaiveDatabase;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp64.Zp64;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.common.tool.utils.IntUtils;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * PIR utilities.
 *
 * @author Liqiang Peng
 * @date 2022/8/1
 */
public class PirUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(PirUtils.class);
    /**
     * random state
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * max batch num of PBC index PIR
     */
    public static final int MAX_BATCH_NUM = 1 << 12;

    /**
     * private constructor.
     */
    private PirUtils() {
        // empty
    }

    /**
     * Given retrieval index, compute indices in each dimension. For example, if database is divided into 2 dimensions
     * (n_1, n_2), and the retrieval index is x, then indices in these 2 dimension is (x / n_2, x / n_2 / 1).
     *
     * @param x             retrieval index x.
     * @param dimensionSize dimension size.
     * @return indices in each dimension.
     */
    public static int[] decomposeIndex(int x, int[] dimensionSize) {
        long longProduct = Arrays.stream(dimensionSize).asLongStream().reduce(1, (di, dj) -> di * dj);
        // since database size must be an integer, we have that d_1 * ... d_t <= n
        assert longProduct <= Integer.MAX_VALUE;
        int product = (int) longProduct;
        int[] indices = new int[dimensionSize.length];
        for (int i = 0; i < dimensionSize.length; i++) {
            product /= dimensionSize[i];
            int xi = x / product;
            indices[i] = xi;
            x -= xi * product;
        }
        return indices;
    }

    /**
     * Returns element size of plaintext.
     *
     * @param elementByteLength element byte length.
     * @param polyModulusDegree poly modulus degree.
     * @param coeffBitLength    coefficient bit length.
     * @return element size of plaintext.
     */
    public static int elementSizeOfPlaintext(int elementByteLength, int polyModulusDegree, int coeffBitLength) {
        // number of coefficients that can store one element
        int coeffSizeOfElement = CommonUtils.getUnitNum(Byte.SIZE * elementByteLength, coeffBitLength);
        int elementSizeOfPlaintext = polyModulusDegree / coeffSizeOfElement;
        assert elementSizeOfPlaintext > 0 : "N should be larger than the of coefficients needed to represent a database element";
        return elementSizeOfPlaintext;
    }

    /**
     * generate random bytebuffer sets.
     *
     * @param serverSetSize server set size.
     * @param clientSetSize client set size.
     * @param repeatTime    repeat time.
     * @return string sets.
     */
    public static List<Set<ByteBuffer>> generateByteBufferSets(int serverSetSize, int clientSetSize, int repeatTime) {
        assert serverSetSize >= 1 : "server must have at least 1 elements";
        assert clientSetSize >= 1 : "client must have at least 1 elements";
        assert repeatTime >= 1 : "repeat time must be greater than or equal to 1: " + repeatTime;
        // create server set
        Set<ByteBuffer> serverSet = IntStream.range(0, serverSetSize)
            .mapToObj(index -> ByteBuffer.wrap(("ID_" + index).getBytes()))
            .collect(Collectors.toSet());
        List<ByteBuffer> serverList = new ArrayList<>(serverSet);
        // create client set
        List<Set<ByteBuffer>> clientSets = IntStream.range(0, repeatTime)
            .mapToObj(repeatIndex -> {
                if (clientSetSize > 1) {
                    int matchedItemSize = clientSetSize / 2;
                    Set<ByteBuffer> clientSet = new HashSet<>(clientSetSize);
                    for (int index = 0; index < matchedItemSize; index++) {
                        clientSet.add(serverList.get(index));
                    }
                    for (int index = matchedItemSize; index < clientSetSize; index++) {
                        clientSet.add(ByteBuffer.wrap(("ID_" + index + "_DISTINCT").getBytes()));
                    }
                    return clientSet;
                } else {
                    Set<ByteBuffer> clientSet = new HashSet<>(clientSetSize);
                    int index = SECURE_RANDOM.nextInt(serverSetSize);
                    if (SECURE_RANDOM.nextBoolean()) {
                        clientSet.add(serverList.get(index));
                    } else {
                        clientSet.add(ByteBuffer.wrap(("ID_" + index + "_DISTINCT").getBytes()));
                    }
                    return clientSet;
                }
            })
            .collect(Collectors.toCollection(ArrayList::new));
        List<Set<ByteBuffer>> results = new ArrayList<>(2);
        results.add(serverSet);
        results.addAll(clientSets);
        return results;
    }

    /**
     * generate keyword label map.
     *
     * @param keywordSet      keyword set.
     * @param labelByteLength label byte length.
     * @return keyword label map.
     */
    public static Map<ByteBuffer, byte[]> generateKeywordByteBufferLabelMap(Set<ByteBuffer> keywordSet,
                                                                            int labelByteLength) {
        return keywordSet.stream()
            .collect(Collectors.toMap(
                keyword -> keyword,
                keyword -> {
                    byte[] label = new byte[labelByteLength];
                    SECURE_RANDOM.nextBytes(label);
                    return label;
                }
            ));
    }

    /**
     * Creates a random database.
     *
     * @param elementSize      database size.
     * @param elementBitLength element bit length.
     * @return random database.
     */
    public static NaiveDatabase generateDataBase(int elementSize, int elementBitLength) {
        return NaiveDatabase.createRandom(elementBitLength, elementSize, SECURE_RANDOM);
    }

    /**
     * generate random element array.
     *
     * @param elementSize      element size.
     * @param elementBitLength element bit length.
     * @return random element array.
     */
    public static byte[][] generateElementArray(int elementSize, int elementBitLength) {
        int elementByteLength = CommonUtils.getByteLength(elementBitLength);
        return IntStream.range(0, elementSize)
            .mapToObj(i -> BytesUtils.randomByteArray(elementByteLength, elementBitLength, SECURE_RANDOM))
            .toArray(byte[][]::new);
    }

    /**
     * generate a random retrieval index.
     *
     * @param elementSize element size.
     * @return a random retrieval index.
     */
    public static int generateRetrievalIndex(int elementSize) {
        return SECURE_RANDOM.nextInt(elementSize);
    }

    /**
     * generate random retrieval index set.
     *
     * @param elementSize   element size.
     * @param retrievalSize retrieval size.
     * @return random retrieval index set.
     */
    public static Set<Integer> generateRetrievalIndexSet(int elementSize, int retrievalSize) {
        Set<Integer> indexSet = new HashSet<>();
        while (indexSet.size() < retrievalSize) {
            int index = SECURE_RANDOM.nextInt(elementSize);
            indexSet.add(index);
        }
        return indexSet;
    }

    /**
     * server bytes prefix
     */
    public static final String BYTES_SERVER_PREFIX = "BYTES_SERVER";
    /**
     * client bytes prefix
     */
    public static final String BYTES_CLIENT_PREFIX = "BYTES_CLIENT";
    /**
     * MMK server prefix
     */
    public static final String MMK_SERVER_PREFIX = "MMK_SERVER";
    /**
     * MMK value space prefix
     */
    public static final String MMK_VALUE_SPACE_PREFIX = "MMK_VALUE_SPACE";
    /**
     * FUSE_PIR server prefix
     */
    public static final String FUSE_PIR_SERVER_PREFIX = "FUSE_PIR_SERVER";
    /**
     * FUSE_PIR value space prefix
     */
    public static final String FUSE_PIR_VALUE_SPACE_PREFIX = "FUSE_PIR_VALUE_SPACE";
    /**
     * BKPIR server prefix
     */
    public static final String BK_CON_SERVER_PREFIX = "BK_CON_SERVER";
    /**
     * BKPIR value space prefix
     */
    public static final String BK_CON_VALUE_SPACE_PREFIX = "BK_CON_VALUE_SPACE";
    /**
     * CON PIR query prefix.
     */
    public static final String CON_PIR_QUERY_PREFIX = "CON_PIR_QUERY";
    /**
     * CAPE server prefix
     */
    public static final String CAPE_CON_SERVER_PREFIX = "CAPE_CON_SERVER";
    /**
     * CAPE value space prefix
     */
    public static final String CAPE_CON_VALUE_SPACE_PREFIX = "CAPE_CON_VALUE_SPACE";
    /**
     * FUSE_PIR query prefix
     */
    public static final String FUSE_PIR_QUERY_PREFIX = "FUSE_PIR_QUERY";
    /**
     * Shared keyword-value-set server prefix.
     */
    public static final String KEYWORD_VALUE_SET_SERVER_PREFIX = "KW_VALUE_SET_SERVER";
    /**
     * Shared keyword-value-set value-space prefix.
     */
    public static final String KEYWORD_VALUE_SET_VALUE_SPACE_PREFIX = "KW_VALUE_SET_VALUE_SPACE";

    /**
     * generate bytes input files.
     *
     * @param setSize          set size.
     * @param elementBitLength element bit length.
     * @throws IOException create files failed.
     */
    public static void generateBytesInputFiles(int setSize, int elementBitLength) throws IOException {
        MathPreconditions.checkPositive("elementBitLength", elementBitLength);
        File serverInputFile = new File(getServerFileName(BYTES_SERVER_PREFIX, setSize, elementBitLength));
        if (serverInputFile.exists()) {
            return;
        }
        LOGGER.info("Lost some / all files, generate byte[] set files.");
        if (serverInputFile.exists()) {
            LOGGER.info("Delete server byte[] set file.");
            Preconditions.checkArgument(
                serverInputFile.delete(), "Fail to delete file: %s", serverInputFile.getName()
            );
        }
        byte[][] elementArray = generateElementArray(setSize, elementBitLength);
        FileWriter serverFileWriter = new FileWriter(serverInputFile);
        PrintWriter serverPrintWriter = new PrintWriter(serverFileWriter, true);
        IntStream.range(0, setSize)
            .mapToObj(i -> Hex.toHexString(elementArray[i]))
            .forEach(serverPrintWriter::println);
        serverPrintWriter.close();
        serverFileWriter.close();
    }

    /**
     * generate MMK keyword-value-set input files and the corresponding value-space file. Each keyword database line is
     * encoded as: keyword value_1 value_2 ... value_m, where all columns are hex strings with fixed byte lengths.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @throws IOException create files failed.
     */
    public static void generateMmkInputFiles(int keywordSize, int valueBitLength, int valueNumPerKey,
                                             int valueSpaceSize) throws IOException {
        generateKeywordValueSetInputFiles(
            keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize,
            getMmkServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize),
            getMmkValueSpaceFileName(valueSpaceSize, valueBitLength),
            "MMK"
        );
    }

    /**
     * generate FUSE_PIR keyword-value-set input files and the corresponding value-space file. The format is the same as
     * MMK: keyword value_1 value_2 ... value_m.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @throws IOException create files failed.
     */
    public static void generateFusePirInputFiles(int keywordSize, int valueBitLength, int valueNumPerKey,
                                              int valueSpaceSize) throws IOException {
        generateKeywordValueSetInputFiles(
            keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize,
            getFusePirServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize),
            getFusePirValueSpaceFileName(valueSpaceSize, valueBitLength),
            "FUSE_PIR"
        );
    }

    private static void generateKeywordValueSetInputFiles(int keywordSize, int valueBitLength, int valueNumPerKey,
                                                          int valueSpaceSize, String serverFileName,
                                                          String valueSpaceFileName, String ptoName)
        throws IOException {
        MathPreconditions.checkPositive("keywordSize", keywordSize);
        MathPreconditions.checkPositive("valueBitLength", valueBitLength);
        MathPreconditions.checkPositive("valueNumPerKey", valueNumPerKey);
        MathPreconditions.checkPositive("valueSpaceSize", valueSpaceSize);
        MathPreconditions.checkLessOrEqual("valueNumPerKey", valueNumPerKey, valueSpaceSize);
        File serverInputFile = new File(serverFileName);
        File valueSpaceInputFile = new File(valueSpaceFileName);
        if (serverInputFile.exists() && valueSpaceInputFile.exists()) {
            return;
        }
        LOGGER.info("Lost some / all files, generate {} keyword-value-set files.", ptoName);
        byte[][] valueSpace;
        if (valueSpaceInputFile.exists()) {
            valueSpace = readValueSpaceInputFile(valueSpaceInputFile, valueSpaceSize, valueBitLength);
        } else {
            valueSpace = generateElementArray(valueSpaceSize, valueBitLength);
            FileWriter valueSpaceFileWriter = new FileWriter(valueSpaceInputFile);
            PrintWriter valueSpacePrintWriter = new PrintWriter(valueSpaceFileWriter, true);
            Arrays.stream(valueSpace)
                .map(Hex::toHexString)
                .forEach(valueSpacePrintWriter::println);
            valueSpacePrintWriter.close();
            valueSpaceFileWriter.close();
        }
        FileWriter serverFileWriter = new FileWriter(serverInputFile);
        PrintWriter serverPrintWriter = new PrintWriter(serverFileWriter, true);
        for (int keywordIndex = 0; keywordIndex < keywordSize; keywordIndex++) {
            StringBuilder line = new StringBuilder(Hex.toHexString(IntUtils.intToByteArray(keywordIndex)));
            generateRetrievalIndexSet(valueSpaceSize, valueNumPerKey).stream()
                .map(valueIndex -> Hex.toHexString(valueSpace[valueIndex]))
                .forEach(valueHex -> line.append('\t').append(valueHex));
            serverPrintWriter.println(line);
        }
        serverPrintWriter.close();
        serverFileWriter.close();
    }

    private static byte[][] readValueSpaceInputFile(File valueSpaceInputFile, int valueSpaceSize, int valueBitLength)
        throws IOException {
        Scanner scanner = new Scanner(valueSpaceInputFile, CommonConstants.DEFAULT_CHARSET);
        List<byte[]> valueSpace = new ArrayList<>(valueSpaceSize);
        int valueByteLength = CommonUtils.getByteLength(valueBitLength);
        while (scanner.hasNextLine()) {
            byte[] value = Hex.decode(scanner.nextLine().trim());
            MathPreconditions.checkEqual("value.length", "valueByteLength", value.length, valueByteLength);
            valueSpace.add(value);
        }
        scanner.close();
        MathPreconditions.checkEqual("valueSpaceSize", "valueSpace.size()", valueSpaceSize, valueSpace.size());
        return valueSpace.toArray(byte[][]::new);
    }

    /**
     * generate BKPIR keyword-value-set input files and the corresponding value-space file. Each keyword database line
     * is encoded as: keyword value_1 value_2 ... value_m.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @throws IOException create files failed.
     */
    public static void generateBkPirInputFiles(int keywordSize, int valueBitLength, int valueNumPerKey,
                                               int valueSpaceSize) throws IOException {
        generateKeywordValueSetInputFiles(
            keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize,
            getBkPirServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize),
            getBkPirValueSpaceFileName(valueSpaceSize, valueBitLength),
            "BKPIR"
        );
    }

    /**
     * generate CAPE keyword-value-set input files and the corresponding value-space file. Each keyword database line is
     * encoded as: keyword value_1 value_2 ... value_m.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @throws IOException create files failed.
     */
    public static void generateCapePirInputFiles(int keywordSize, int valueBitLength, int valueNumPerKey,
                                                int valueSpaceSize) throws IOException {
        generateKeywordValueSetInputFiles(
            keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize,
            getCapePirServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize),
            getCapePirValueSpaceFileName(valueSpaceSize, valueBitLength),
            "CAPE"
        );
    }

    /**
     * generate BKPIR boolean query file. Each line contains boolKeywordNum keyword tokens separated by spaces.
     *
     * @param keywordSize    keyword size.
     * @param queryNum       query num.
     * @param boolKeywordNum boolean keyword num.
     * @param queryFileName  query file name.
     * @throws IOException create files failed.
     */
    public static void generateBkPirQueryInputFile(int keywordSize, int queryNum, int boolKeywordNum,
                                                   String queryFileName) throws IOException {
        generateConPirQueryInputFile(keywordSize, queryNum, boolKeywordNum, queryFileName);
    }

    /**
     * generate CAPE boolean query file. Each line contains boolKeywordNum keyword tokens separated by spaces.
     *
     * @param keywordSize    keyword size.
     * @param queryNum       query num.
     * @param boolKeywordNum boolean keyword num.
     * @param queryFileName  query file name.
     * @throws IOException create files failed.
     */
    public static void generateCapePirQueryInputFile(int keywordSize, int queryNum, int boolKeywordNum,
                                                    String queryFileName) throws IOException {
        generateConPirQueryInputFile(keywordSize, queryNum, boolKeywordNum, queryFileName);
    }

    private static void generateConPirQueryInputFile(int keywordSize, int queryNum, int boolKeywordNum,
                                                     String queryFileName) throws IOException {
        MathPreconditions.checkPositive("keywordSize", keywordSize);
        MathPreconditions.checkPositive("queryNum", queryNum);
        MathPreconditions.checkPositiveInRangeClosed("boolKeywordNum", boolKeywordNum, keywordSize);
        File queryInputFile = new File(queryFileName);
        if (isValidConPirQueryInputFile(queryInputFile, keywordSize, queryNum, boolKeywordNum)) {
            return;
        }
        LOGGER.info("Lost some / all files, generate CON PIR boolean query file.");
        FileWriter queryFileWriter = new FileWriter(queryInputFile);
        PrintWriter queryPrintWriter = new PrintWriter(queryFileWriter, true);
        for (int queryIndex = 0; queryIndex < queryNum; queryIndex++) {
            String queryLine = generateRetrievalIndexSet(keywordSize, boolKeywordNum).stream()
                .map(IntUtils::intToByteArray)
                .map(Hex::toHexString)
                .collect(Collectors.joining(" "));
            queryPrintWriter.println(queryLine);
        }
        queryPrintWriter.close();
        queryFileWriter.close();
    }

    private static boolean isValidConPirQueryInputFile(File queryInputFile, int keywordSize, int queryNum,
                                                       int boolKeywordNum) throws IOException {
        if (!queryInputFile.exists()) {
            return false;
        }
        Scanner scanner = new Scanner(queryInputFile, CommonConstants.DEFAULT_CHARSET);
        int lineNum = 0;
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine().trim();
            if (line.isEmpty()) {
                scanner.close();
                return false;
            }
            String[] columns = line.split("\\s+");
            if (columns.length != boolKeywordNum) {
                scanner.close();
                return false;
            }
            for (String column : columns) {
                int keywordIndex = IntUtils.byteArrayToInt(Hex.decode(column));
                if (keywordIndex < 0 || keywordIndex >= keywordSize) {
                    scanner.close();
                    return false;
                }
            }
            lineNum++;
        }
        scanner.close();
        return lineNum == queryNum;
    }

    /**
     * generate FUSE_PIR keyword query file. Each line contains one keyword token.
     *
     * @param keywordSize   keyword size.
     * @param queryNum      query num.
     * @param queryFileName query file name.
     * @throws IOException create files failed.
     */
    public static void generateFusePirQueryInputFile(int keywordSize, int queryNum, String queryFileName)
        throws IOException {
        MathPreconditions.checkPositive("keywordSize", keywordSize);
        MathPreconditions.checkPositive("queryNum", queryNum);
        File queryInputFile = new File(queryFileName);
        if (queryInputFile.exists()) {
            return;
        }
        LOGGER.info("Lost some / all files, generate FUSE_PIR keyword query file.");
        FileWriter queryFileWriter = new FileWriter(queryInputFile);
        PrintWriter queryPrintWriter = new PrintWriter(queryFileWriter, true);
        for (int queryIndex = 0; queryIndex < queryNum; queryIndex++) {
            queryPrintWriter.println(Hex.toHexString(IntUtils.intToByteArray(SECURE_RANDOM.nextInt(keywordSize))));
        }
        queryPrintWriter.close();
        queryFileWriter.close();
    }

    /**
     * generate retrieval index input files.
     *
     * @param retrievalSize retrieval size.
     * @throws IOException create files failed.
     */
    public static void generateIndexInputFiles(int elementSize, int retrievalSize)
        throws IOException {
        boolean b_decidingWhetherToRegenerateIndexOrNot = false;
        MathPreconditions.checkPositive("elementSize", elementSize);
        MathPreconditions.checkPositive("retrievalSize", retrievalSize);
        File clientInputFile = new File(getClientFileName(BYTES_CLIENT_PREFIX, retrievalSize, elementSize));
        if (clientInputFile.exists() && !b_decidingWhetherToRegenerateIndexOrNot) {
            return;
        }
        LOGGER.info("Lost some / all files, generate byte[] set files.");
        if (clientInputFile.exists()) {
            LOGGER.info("Delete server byte[] set file.");
            Preconditions.checkArgument(
                clientInputFile.delete(), "Fail to delete file: %s", clientInputFile.getName()
            );
        }
        Set<Integer> retrievalIndexSet = generateRetrievalIndexSet(elementSize, retrievalSize);
        FileWriter clientFileWriter = new FileWriter(clientInputFile);
        PrintWriter clientPrintWriter = new PrintWriter(clientFileWriter, true);
        retrievalIndexSet.stream()
            .map(IntUtils::intToByteArray)
            .map(Hex::toHexString)
            .forEach(clientPrintWriter::println);
        clientPrintWriter.close();
        clientPrintWriter.close();
    }

    /**
     * return server file name.
     *
     * @param prefix           prefix.
     * @param setSize          set size.
     * @param elementBitLength element bit length.
     * @return server file name.
     */
    public static String getServerFileName(String prefix, int setSize, int elementBitLength) {
        return MainPtoConfigUtils.getFileFolderName() + prefix + "_" + prefix + "_" + elementBitLength + "_" + setSize + ".input";
    }

    /**
     * return MMK server file name.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @return MMK server file name.
     */
    public static String getMmkServerFileName(int keywordSize, int valueBitLength, int valueNumPerKey,
                                              int valueSpaceSize) {
        return getKeywordValueSetServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize);
    }

    /**
     * return MMK value-space file name.
     *
     * @param valueSpaceSize value space size.
     * @param valueBitLength value bit length.
     * @return MMK value-space file name.
     */
    public static String getMmkValueSpaceFileName(int valueSpaceSize, int valueBitLength) {
        return getKeywordValueSetValueSpaceFileName(valueSpaceSize, valueBitLength);
    }

    /**
     * return FUSE_PIR server file name.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @return FUSE_PIR server file name.
     */
    public static String getFusePirServerFileName(int keywordSize, int valueBitLength, int valueNumPerKey,
                                               int valueSpaceSize) {
        return getKeywordValueSetServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize);
    }

    /**
     * return FUSE_PIR value-space file name.
     *
     * @param valueSpaceSize value space size.
     * @param valueBitLength value bit length.
     * @return FUSE_PIR value-space file name.
     */
    public static String getFusePirValueSpaceFileName(int valueSpaceSize, int valueBitLength) {
        return getKeywordValueSetValueSpaceFileName(valueSpaceSize, valueBitLength);
    }

    /**
     * return BKPIR server file name.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @return BKPIR server file name.
     */
    public static String getBkPirServerFileName(int keywordSize, int valueBitLength, int valueNumPerKey,
                                                int valueSpaceSize) {
        return getKeywordValueSetServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize);
    }

    /**
     * return BKPIR value-space file name.
     *
     * @param valueSpaceSize value space size.
     * @param valueBitLength value bit length.
     * @return BKPIR value-space file name.
     */
    public static String getBkPirValueSpaceFileName(int valueSpaceSize, int valueBitLength) {
        return getKeywordValueSetValueSpaceFileName(valueSpaceSize, valueBitLength);
    }

    /**
     * return BKPIR query file name.
     *
     * @param queryNum       query num.
     * @param boolKeywordNum boolean keyword num.
     * @param valueBitLength value bit length.
     * @return BKPIR query file name.
     */
    public static String getBkPirQueryFileName(int queryNum, int boolKeywordNum, int valueBitLength) {
        return getConPirQueryFileName(queryNum, boolKeywordNum, valueBitLength);
    }

    /**
     * return CAPE server file name.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @return CAPE server file name.
     */
    public static String getCapePirServerFileName(int keywordSize, int valueBitLength, int valueNumPerKey,
                                                 int valueSpaceSize) {
        return getKeywordValueSetServerFileName(keywordSize, valueBitLength, valueNumPerKey, valueSpaceSize);
    }

    /**
     * return CAPE value-space file name.
     *
     * @param valueSpaceSize value space size.
     * @param valueBitLength value bit length.
     * @return CAPE value-space file name.
     */
    public static String getCapePirValueSpaceFileName(int valueSpaceSize, int valueBitLength) {
        return getKeywordValueSetValueSpaceFileName(valueSpaceSize, valueBitLength);
    }

    /**
     * return shared keyword-value-set server file name.
     *
     * @param keywordSize    keyword size.
     * @param valueBitLength value bit length.
     * @param valueNumPerKey value num per key.
     * @param valueSpaceSize value space size.
     * @return shared keyword-value-set server file name.
     */
    public static String getKeywordValueSetServerFileName(int keywordSize, int valueBitLength, int valueNumPerKey,
                                                          int valueSpaceSize) {
        int valueSpaceLogSize = exactLog2(valueSpaceSize);
        return MainPtoConfigUtils.getFileFolderName() + KEYWORD_VALUE_SET_SERVER_PREFIX
            + "_" + keywordSize
            + "_" + valueNumPerKey
            + "_" + valueBitLength
            + "_" + valueSpaceLogSize
            + ".input";
    }

    /**
     * return shared keyword-value-set value-space file name.
     *
     * @param valueSpaceSize value space size.
     * @param valueBitLength value bit length.
     * @return shared keyword-value-set value-space file name.
     */
    public static String getKeywordValueSetValueSpaceFileName(int valueSpaceSize, int valueBitLength) {
        int valueSpaceLogSize = exactLog2(valueSpaceSize);
        return MainPtoConfigUtils.getFileFolderName() + KEYWORD_VALUE_SET_VALUE_SPACE_PREFIX
            + "_" + valueBitLength
            + "_" + valueSpaceLogSize
            + ".input";
    }

    private static int exactLog2(int value) {
        MathPreconditions.checkPositive("value", value);
        MathPreconditions.checkEqual("value", "power of two", Integer.bitCount(value), 1);
        return Integer.numberOfTrailingZeros(value);
    }

    /**
     * return CAPE query file name.
     *
     * @param queryNum       query num.
     * @param boolKeywordNum boolean keyword num.
     * @param valueBitLength value bit length.
     * @return CAPE query file name.
     */
    public static String getCapePirQueryFileName(int queryNum, int boolKeywordNum, int valueBitLength) {
        return getConPirQueryFileName(queryNum, boolKeywordNum, valueBitLength);
    }

    /**
     * return shared CON PIR query file name.
     *
     * @param queryNum       query num.
     * @param boolKeywordNum boolean keyword num.
     * @param valueBitLength value bit length.
     * @return shared CON PIR query file name.
     */
    public static String getConPirQueryFileName(int queryNum, int boolKeywordNum, int valueBitLength) {
        return MainPtoConfigUtils.getFileFolderName() + CON_PIR_QUERY_PREFIX
            + "_" + queryNum
            + "_" + boolKeywordNum
            + "_" + valueBitLength
            + ".input";
    }

    /**
     * return FUSE_PIR query file name.
     *
     * @param queryNum    query num.
     * @param keywordSize keyword size.
     * @return FUSE_PIR query file name.
     */
    public static String getFusePirQueryFileName(int queryNum, int keywordSize) {
        return MainPtoConfigUtils.getFileFolderName() + FUSE_PIR_QUERY_PREFIX + "_" + FUSE_PIR_QUERY_PREFIX
            + "_" + queryNum
            + "_" + keywordSize
            + ".input";
    }

    /**
     * return client file name.
     *
     * @param prefix  prefix.
     * @param setSize set size.
     * @return client file name.
     */
    public static String getClientFileName(String prefix, int setSize) {
        return MainPtoConfigUtils.getFileFolderName() + prefix + "_" + prefix + "_" + setSize + ".input";
    }

    public static String getClientFileName(String prefix, int setSize, int elementSize) {
        return MainPtoConfigUtils.getFileFolderName() + prefix + "_" + prefix + "_" + setSize + "_" + elementSize + ".input";
    }

    /**
     * convert byte array to coeff array.
     *
     * @param limit     coeff bit length.
     * @param offset    offset.
     * @param size      size of byte array.
     * @param byteArray byte array.
     * @return coeff array.
     */
    public static long[] convertBytesToCoeffs(int limit, int offset, int size, byte[] byteArray) {
        int longArraySize = CommonUtils.getUnitNum(Byte.SIZE * size, limit);
        long[] longArray = new long[longArraySize];
        int room = limit;
        int flag = 0;
        for (int i = 0; i < size; i++) {
            int src = byteArray[i + offset];
            if (src < 0) {
                src &= 0xFF;
            }
            int rest = Byte.SIZE;
            while (rest != 0) {
                if (room == 0) {
                    flag++;
                    room = limit;
                }
                int shift = Math.min(room, rest);
                long temp = longArray[flag] << shift;
                longArray[flag] = temp | (src >> (Byte.SIZE - shift));
                int remain = (1 << (Byte.SIZE - shift)) - 1;
                src = (src & remain) << shift;
                room -= shift;
                rest -= shift;
            }
        }
        longArray[flag] = longArray[flag] << room;
        return longArray;
    }


    /**
     * convert coeff array to byte array.
     *
     * @param coeffArray coeff array.
     * @param logt       coeff bit length.
     * @return byte array.
     */
    public static byte[] convertCoeffsToBytes(long[] coeffArray, int logt) {
        int len = CommonUtils.getUnitNum(coeffArray.length * logt, Byte.SIZE);
        byte[] byteArray = new byte[len];
        int room = Byte.SIZE;
        int j = 0;
        for (long l : coeffArray) {
            long src = l;
            int rest = logt;
            while (rest != 0 && j < byteArray.length) {
                int shift = Math.min(room, rest);
                byteArray[j] = (byte) (byteArray[j] << shift);
                byteArray[j] = (byte) (byteArray[j] | (src >> (logt - shift)));
                src = src << shift;
                room -= shift;
                rest -= shift;
                if (room == 0) {
                    j++;
                    room = Byte.SIZE;
                }
            }
        }
        return byteArray;
    }

    /**
     * return the bit length of the input integer.
     *
     * @param input input.
     * @return bit length.
     */
    public static int getBitLength(long input) {
        int count = 0;
        while (input != 0) {
            count++;
            input /= 2;
        }
        return count;
    }

    /**
     * return next power of two of the input integer.
     *
     * @param input input.
     * @return next power of two.
     */
    public static int getNextPowerOfTwo(int input) {
        if ((input & (input - 1)) == 0) {
            return input;
        }
        int numberOfBits = getBitLength(input);
        return (1 << numberOfBits);
    }

    /**
     * rotate vector column.
     *
     * @param coeffs coeff vector.
     * @return rotated coeff vector.
     */
    public static long[] rotateVectorCol(long[] coeffs) {
        int rowSize = coeffs.length / 2;
        long[] result = new long[coeffs.length];
        IntStream.range(0, rowSize).forEach(i -> {
            result[i] = coeffs[rowSize + i];
            result[rowSize + i] = coeffs[i];
        });
        return result;
    }

    /**
     * plaintext rotate.
     *
     * @param coeffs coefficients.
     * @param offset offset.
     * @return rotated plaintext.
     */
    public static long[] plaintextRotate(long[] coeffs, int offset) {
        int rowCount = coeffs.length / 2;
        offset = offset % rowCount;
        long[] rotatedCoeffs = new long[coeffs.length];
        for (int i = 0; i < rowCount; i++) {
            rotatedCoeffs[(i + offset) % rowCount] = coeffs[i];
            rotatedCoeffs[(i + offset) % rowCount + rowCount] = coeffs[i + rowCount];
        }
        return rotatedCoeffs;
    }

    /**
     * return length of each dimension.
     *
     * @param elementSize element size.
     * @return length of each dimension.
     */
    public static int[] computeDimensionLength(int elementSize, int dimension) {
        int[] dimensionLength = IntStream.range(0, dimension)
            .map(i -> (int) Math.max(2, Math.floor(Math.pow(elementSize, 1.0 / dimension))))
            .toArray();
        int product = 1;
        int j = 0;
        // if plaintext_num is not a d-power
        if (dimensionLength[0] != Math.pow(elementSize, 1.0 / dimension)) {
            while (product < elementSize && j < dimension) {
                product = 1;
                dimensionLength[j++]++;
                for (int i = 0; i < dimension; i++) {
                    product *= dimensionLength[i];
                }
            }
        }
        return dimensionLength;
    }

    /**
     * return length of each dimension.
     *
     * @param elementSize             element size.
     * @param firstDimensionSize      first dimension size.
     * @param subsequentDimensionSize subsequent dimension size.
     * @return length of each dimension.
     */
    public static int[] computeDimensionLength(int elementSize, int firstDimensionSize, int subsequentDimensionSize) {
        List<Integer> dimensionLength = new ArrayList<>();
        dimensionLength.add(firstDimensionSize);
        int product = firstDimensionSize;
        for (int i = elementSize / firstDimensionSize; i >= subsequentDimensionSize; i /= subsequentDimensionSize) {
            dimensionLength.add(subsequentDimensionSize);
            product *= subsequentDimensionSize;
        }
        int dimensionSize = dimensionLength.size();
        int[] dimensionArray = IntStream.range(0, dimensionSize).map(dimensionLength::get).toArray();
        while (product < elementSize) {
            dimensionArray[dimensionSize - 1]++;
            product = 1;
            product *= Arrays.stream(dimensionArray, 0, dimensionSize).reduce(1, (a, b) -> a * b);
        }
        if (dimensionSize == 1 && dimensionArray[0] > firstDimensionSize) {
            dimensionArray = new int[]{firstDimensionSize, subsequentDimensionSize};
        }
        return dimensionArray;
    }

    /**
     * Find smallest l, m such that l*m >= num * d and d divides l, where d is
     * the number of Z_p elements per DB entry determined by bit-length and p.
     *
     * @param num database size.
     * @param d   Z_p element num.
     * @return l and m.
     */
    public static int[] approxSquareDatabaseDims(int num, int d) {
        MathPreconditions.checkPositive("num", num);
        long rows = (long) Math.max(2, Math.ceil(Math.sqrt(d * num)));
        long rem = rows % d;
        if (rem != 0) {
            rows += d - rem;
        }
        long cols = (long) Math.ceil((double) d * num / rows);
        return new int[]{Math.toIntExact(rows), Math.toIntExact(cols)};
    }

    /**
     * compute powers.
     *
     * @param zp64      zp64.
     * @param base      base.
     * @param exponents exponents.
     * @return powers.
     */
    public static long[][] computePowers(Zp64 zp64, long[] base, int[] exponents) {
        long[][] result = new long[exponents.length][];
        assert exponents[0] == 1;
        result[0] = base;
        for (int i = 1; i < exponents.length; i++) {
            long[] temp = new long[base.length];
            for (int j = 0; j < base.length; j++) {
                temp[j] = zp64.pow(base[j], exponents[i]);
            }
            result[i] = temp;
        }
        return result;
    }
}
