package edu.alibaba.mpc4j.s2pc.pir.artifact;

import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.*;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.*;
import edu.alibaba.mpc4j.s2pc.pir.conpir.capec.*;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.*;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.*;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.*;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Standalone real-protocol experiment entry point for the CAPE artifact. */
public final class ArtifactRunner {
    private static final long DATASET_SEED = 2026L;
    private static final String HEADER = "scheme,keyword_num,values_per_keyword,value_bit_length,"
        + "conjunctive_keyword_num,preprocessing_ms,query_time_ms,query_size_bytes,response_size_bytes,"
        + "execution_status,correctness_status";

    private ArtifactRunner() { }

    public static void main(String[] args) throws Exception {
        Options options = Options.parse(args);
        Result result;
        int exitCode = 0;
        try {
            result = run(options);
        } catch (Throwable throwable) {
            throwable.printStackTrace(System.err);
            result = Result.failed(options, throwable instanceof CorrectnessFailure ? "FAILED" : "UNVERIFIED");
            exitCode = 2;
        }
        writeResult(options.output, result);
        System.out.println("[RESULT] " + result.toCsv());
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    private static Result run(Options options) throws Exception {
        return switch (options.scheme) {
            case "MMK" -> runMmk(options);
            case "BKPIR" -> runBkPir(options);
            case "FusePIR" -> runFusePir(options);
            case "FusePIR-C" -> runFusePirC(options);
            case "CAPE" -> runCape(options);
            case "CAPE-C" -> runCapeC(options);
            default -> throw new IllegalArgumentException("Unsupported public scheme: " + options.scheme);
        };
    }

    private static Result runMmk(Options o) throws Exception {
        MemoryRpcManager manager = new MemoryRpcManager(2);
        Rpc serverRpc = manager.getRpc(0), clientRpc = manager.getRpc(1);
        connect(serverRpc, clientRpc);
        int valueByteLength = byteLength(o.valueBitLength);
        int labelByteLength = valueByteLength * o.valuesPerKeyword;
        Map<ByteBuffer, byte[]> database = new LinkedHashMap<>();
        for (int i = 0; i < o.keywordNum; i++) {
            database.put(keyword(i), deterministicBytes(labelByteLength, i));
        }
        ByteBuffer query = keyword(Math.min(2, o.keywordNum - 1));
        byte[] expected = database.get(query);
        MmkStdKwPirConfig config = new MmkStdKwPirConfig.Builder().build();
        StdKwPirServer<ByteBuffer> server = StdKwPirFactory.createServer(serverRpc, clientRpc.ownParty(), config);
        StdKwPirClient<ByteBuffer> client = StdKwPirFactory.createClient(clientRpc, serverRpc.ownParty(), config);
        AtomicReference<byte[][]> answer = new AtomicReference<>();
        long preprocessing = runPair(
            () -> server.init(database, labelByteLength * Byte.SIZE, 1),
            () -> client.init(database.size(), labelByteLength * Byte.SIZE, 1), null
        );
        reset(serverRpc, clientRpc);
        AtomicLong serverMs = new AtomicLong();
        runPair(() -> server.pir(1), () -> answer.set(client.pir(new ArrayList<>(List.of(query)))), serverMs);
        boolean correct = answer.get() != null && answer.get().length == 1 && Arrays.equals(expected, answer.get()[0]);
        safeDestroy(server, client, serverRpc, clientRpc);
        requireCorrect(correct, "MMK decoded label mismatch");
        return Result.pass(o, preprocessing, serverMs.get(), clientRpc.getSendByteLength(),
            serverRpc.getSendByteLength(), "VERIFIED");
    }

    private static Result runFusePir(Options o) throws Exception {
        int valueByteLength = byteLength(o.valueBitLength);
        FusePirStdKwPirParams params = new FusePirStdKwPirParams(
            40, valueByteLength, o.valuesPerKeyword, true
        );
        FusePirStdKwPirConfig config = new FusePirStdKwPirConfig.Builder().setParams(params).build();
        Map<String, byte[]> database = singleKeywordDatabase(o, valueByteLength,
            values -> serializeFixed(values, valueByteLength, o.valuesPerKeyword));
        return runFuseStyle(o, database, "key-2", config, false);
    }

    private static Result runFusePirC(Options o) throws Exception {
        int valueByteLength = byteLength(o.valueBitLength);
        FusePirCStdKwPirParams params = new FusePirCStdKwPirParams(
            40, valueByteLength, o.valuesPerKeyword, true
        );
        FusePirCStdKwPirConfig config = new FusePirCStdKwPirConfig.Builder().setParams(params).build();
        Map<String, byte[]> database = singleKeywordDatabase(o, valueByteLength,
            values -> serializeFixed(values, valueByteLength, o.valuesPerKeyword));
        return runFuseStyle(o, database, "key-2", config, true);
    }

    private static Result runFuseStyle(Options o, Map<String, byte[]> database, String query,
                                       StdKwPirConfig config, boolean compressed) throws Exception {
        MemoryRpcManager manager = new MemoryRpcManager(2);
        Rpc serverRpc = manager.getRpc(0), clientRpc = manager.getRpc(1);
        connect(serverRpc, clientRpc);
        StdKwPirServer<String> server = StdKwPirFactory.createServer(serverRpc, clientRpc.ownParty(), config);
        StdKwPirClient<String> client = StdKwPirFactory.createClient(clientRpc, serverRpc.ownParty(), config);
        AtomicReference<byte[][]> answer = new AtomicReference<>();
        long preprocessing = runPair(
            () -> server.init(database, o.valueBitLength, 1),
            () -> client.init(database.size(), o.valueBitLength, 1), null
        );
        reset(serverRpc, clientRpc);
        AtomicLong serverMs = new AtomicLong();
        runPair(() -> server.pir(1), () -> answer.set(client.pir(new ArrayList<>(List.of(query)))), serverMs);
        boolean decodedMatches = answer.get() != null && answer.get().length == 1
            && Arrays.equals(database.get(query), answer.get()[0]);
        safeDestroy(server, client, serverRpc, clientRpc);
        requireCorrect(decodedMatches, (compressed ? "FusePIR-C" : "FusePIR") + " decoded payload mismatch");
        // DEFAULT N=16384 formal verification remains deferred even if this execution completes.
        return Result.pass(o, preprocessing, serverMs.get(), clientRpc.getSendByteLength(),
            serverRpc.getSendByteLength(), "UNVERIFIED");
    }

    private static Result runBkPir(Options o) throws Exception {
        ConjunctiveData data = conjunctiveData(o);
        MemoryRpcManager manager = new MemoryRpcManager(2);
        Rpc serverRpc = manager.getRpc(0), clientRpc = manager.getRpc(1);
        connect(serverRpc, clientRpc);
        BkPirConfig config = new BkPirConfig.Builder().setQueryMethod(BkPirQueryMethod.AND)
            .setBoolKeywordNum(o.q).build();
        BkPirServer<ByteBuffer> server = new BkPirServer<>(serverRpc, clientRpc.ownParty(), config);
        BkPirClient<ByteBuffer> client = new BkPirClient<>(clientRpc, serverRpc.ownParty(), config);
        AtomicReference<List<byte[]>[]> answer = new AtomicReference<>();
        long preprocessing = runPair(
            () -> server.init(data.database, 1),
            () -> client.init(data.database.size(), data.valueSpace, 1), null
        );
        reset(serverRpc, clientRpc);
        AtomicLong serverMs = new AtomicLong();
        ArrayList<List<ByteBuffer>> queries = new ArrayList<>(List.of(data.query));
        runPair(() -> server.pir(1), () -> answer.set(client.pir(queries)), serverMs);
        boolean correct = matchesSet(answer.get(), data.expected);
        safeDestroy(server, client, serverRpc, clientRpc);
        requireCorrect(correct, "BKPIR intersection mismatch");
        return Result.pass(o, preprocessing, serverMs.get(), clientRpc.getSendByteLength(),
            serverRpc.getSendByteLength(), "VERIFIED");
    }

    private static Result runCape(Options o) throws Exception {
        ConjunctiveData data = conjunctiveData(o);
        MemoryRpcManager manager = new MemoryRpcManager(2);
        Rpc serverRpc = manager.getRpc(0), clientRpc = manager.getRpc(1);
        connect(serverRpc, clientRpc);
        CapePirConfig config = new CapePirConfig.Builder().setQueryMethod(CapePirQueryMethod.AND)
            .setBoolKeywordNum(o.q).build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(serverRpc, clientRpc.ownParty(), config);
        CapePirClient<ByteBuffer> client = new CapePirClient<>(clientRpc, serverRpc.ownParty(), config);
        AtomicReference<List<byte[]>[]> answer = new AtomicReference<>();
        long preprocessing = runPair(
            () -> { server.init(data.database, 1); server.receivePublicKeys(); server.sendBffSeed(); },
            () -> { client.init(data.database.size(), byteLength(o.valueBitLength), o.valuesPerKeyword, 1);
                client.sendPublicKeysAndReceiveSeed(); }, null
        );
        reset(serverRpc, clientRpc);
        AtomicLong serverMs = new AtomicLong();
        ArrayList<List<ByteBuffer>> queries = new ArrayList<>(List.of(data.query));
        runPair(() -> server.pir(1), () -> answer.set(client.pir(queries)), serverMs);
        boolean decodedMatches = matchesSet(answer.get(), data.expected);
        safeDestroy(server, client, serverRpc, clientRpc);
        requireCorrect(decodedMatches, "CAPE decoded intersection mismatch");
        return Result.pass(o, preprocessing, serverMs.get(), clientRpc.getSendByteLength(),
            serverRpc.getSendByteLength(), "UNVERIFIED");
    }

    private static Result runCapeC(Options o) throws Exception {
        ConjunctiveData data = conjunctiveData(o);
        MemoryRpcManager manager = new MemoryRpcManager(2);
        Rpc serverRpc = manager.getRpc(0), clientRpc = manager.getRpc(1);
        connect(serverRpc, clientRpc);
        CapeCPirConfig config = new CapeCPirConfig.Builder().setQueryMethod(CapePirQueryMethod.AND)
            .setBoolKeywordNum(o.q).build();
        CapeCPirServer<ByteBuffer> server = new CapeCPirServer<>(serverRpc, clientRpc.ownParty(), config);
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(clientRpc, serverRpc.ownParty(), config);
        AtomicReference<List<byte[]>[]> answer = new AtomicReference<>();
        long preprocessing = runPair(
            () -> { server.init(data.database, byteLength(o.valueBitLength), o.valuesPerKeyword, 1);
                server.receivePublicKeysAndSendSeed(); },
            () -> { client.init(data.database.size(), byteLength(o.valueBitLength), o.valuesPerKeyword, 1);
                client.sendPublicKeysAndReceiveSeed(); }, null
        );
        reset(serverRpc, clientRpc);
        AtomicLong serverMs = new AtomicLong();
        ArrayList<List<ByteBuffer>> queries = new ArrayList<>(List.of(data.query));
        runPair(() -> server.pir(1), () -> answer.set(client.pir(queries)), serverMs);
        boolean decodedMatches = matchesSet(answer.get(), data.expected);
        safeDestroy(server, client, serverRpc, clientRpc);
        requireCorrect(decodedMatches, "CAPE-C decoded intersection mismatch");
        return Result.pass(o, preprocessing, serverMs.get(), clientRpc.getSendByteLength(),
            serverRpc.getSendByteLength(), "UNVERIFIED");
    }

    private static Map<String, byte[]> singleKeywordDatabase(Options o, int valueByteLength,
                                                              Encoder encoder) {
        Map<String, byte[]> database = new LinkedHashMap<>();
        for (int keyIndex = 0; keyIndex < o.keywordNum; keyIndex++) {
            List<byte[]> values = new ArrayList<>();
            for (int valueIndex = 0; valueIndex < o.valuesPerKeyword; valueIndex++) {
                values.add(deterministicValue(valueByteLength, keyIndex, valueIndex));
            }
            database.put("key-" + keyIndex, encoder.encode(values));
        }
        return database;
    }

    private static byte[] serializeFixed(List<byte[]> values, int valueByteLength, int capacity) {
        byte[] payload = new byte[valueByteLength * capacity];
        for (int i = 0; i < values.size(); i++) {
            if (values.get(i).length != valueByteLength) {
                throw new IllegalArgumentException("value byte length mismatch");
            }
            System.arraycopy(values.get(i), 0, payload, i * valueByteLength, valueByteLength);
        }
        return payload;
    }

    private static ConjunctiveData conjunctiveData(Options o) {
        int valueBytes = byteLength(o.valueBitLength);
        byte[] common = deterministicValue(valueBytes, 0, 0);
        Map<ByteBuffer, List<byte[]>> database = new LinkedHashMap<>();
        LinkedHashMap<String, byte[]> universe = new LinkedHashMap<>();
        for (int keyIndex = 0; keyIndex < o.keywordNum; keyIndex++) {
            List<byte[]> values = new ArrayList<>();
            if (keyIndex < o.q) {
                values.add(Arrays.copyOf(common, common.length));
            }
            for (int valueIndex = values.size(); valueIndex < o.valuesPerKeyword; valueIndex++) {
                values.add(deterministicValue(valueBytes, keyIndex + 1, valueIndex + 1));
            }
            database.put(keyword(keyIndex), values);
            for (byte[] value : values) {
                universe.putIfAbsent(Base64.getEncoder().encodeToString(value), value);
            }
        }
        List<ByteBuffer> query = new ArrayList<>();
        for (int i = 0; i < o.q; i++) query.add(keyword(i));
        return new ConjunctiveData(database, new ArrayList<>(universe.values()), query, List.of(common));
    }

    private static byte[] deterministicValue(int length, int keyIndex, int valueIndex) {
        return deterministicBytes(length, DATASET_SEED ^ ((long) keyIndex << 32) ^ valueIndex);
    }

    private static byte[] deterministicBytes(int length, long salt) {
        Random random = new Random(DATASET_SEED ^ salt);
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    private static ByteBuffer keyword(int index) {
        return ByteBuffer.wrap(("key-" + index).getBytes(StandardCharsets.UTF_8));
    }

    private static int byteLength(int bitLength) { return (bitLength + Byte.SIZE - 1) / Byte.SIZE; }

    private static boolean matchesSet(List<byte[]>[] actual, List<byte[]> expected) {
        if (actual == null || actual.length != 1 || actual[0].size() != expected.size()) return false;
        Set<String> left = new HashSet<>(), right = new HashSet<>();
        actual[0].forEach(v -> left.add(Base64.getEncoder().encodeToString(v)));
        expected.forEach(v -> right.add(Base64.getEncoder().encodeToString(v)));
        return left.equals(right);
    }

    private static long runPair(ThrowingRunnable server, ThrowingRunnable client, AtomicLong serverOnlineMs)
        throws Exception {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        long start = System.nanoTime();
        Thread serverThread = new Thread(() -> timedRun(server, failure, serverOnlineMs), "artifact-server");
        Thread clientThread = new Thread(() -> timedRun(client, failure, null), "artifact-client");
        serverThread.start(); clientThread.start(); serverThread.join(); clientThread.join();
        if (failure.get() != null) throw new Exception(failure.get());
        return (System.nanoTime() - start) / 1_000_000L;
    }

    private static void timedRun(ThrowingRunnable action, AtomicReference<Throwable> failure, AtomicLong elapsed) {
        long start = System.nanoTime();
        try { action.run(); } catch (Throwable t) { failure.compareAndSet(null, t); }
        finally { if (elapsed != null) elapsed.set((System.nanoTime() - start) / 1_000_000L); }
    }

    private static void connect(Rpc a, Rpc b) { a.connect(); b.connect(); }
    private static void reset(Rpc a, Rpc b) { a.reset(); b.reset(); }
    private static void safeDestroy(Object server, Object client, Rpc serverRpc, Rpc clientRpc) {
        try { if (server instanceof edu.alibaba.mpc4j.common.rpc.pto.TwoPartyPto p) p.destroy(); } catch (Throwable ignored) { }
        try { if (client instanceof edu.alibaba.mpc4j.common.rpc.pto.TwoPartyPto p) p.destroy(); } catch (Throwable ignored) { }
        try { serverRpc.disconnect(); } catch (Throwable ignored) { }
        try { clientRpc.disconnect(); } catch (Throwable ignored) { }
    }

    private static void requireCorrect(boolean correct, String message) {
        if (!correct) throw new CorrectnessFailure(message);
    }

    private static void writeResult(Path output, Result result) throws IOException {
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, HEADER + System.lineSeparator() + result.toCsv() + System.lineSeparator(),
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private interface Encoder { byte[] encode(List<byte[]> values); }
    private interface ThrowingRunnable { void run() throws Exception; }
    private static final class CorrectnessFailure extends RuntimeException {
        private CorrectnessFailure(String message) { super(message); }
    }
    private record ConjunctiveData(Map<ByteBuffer, List<byte[]>> database, List<byte[]> valueSpace,
                                   List<ByteBuffer> query, List<byte[]> expected) { }

    private record Result(String scheme, int keywordNum, int valuesPerKeyword, int valueBitLength, int q,
                          long preprocessingMs, long queryTimeMs, long queryBytes, long responseBytes,
                          String executionStatus, String correctnessStatus) {
        static Result pass(Options o, long prep, long query, long queryBytes, long responseBytes, String correctness) {
            return new Result(o.scheme, o.keywordNum, o.valuesPerKeyword, o.valueBitLength, o.q,
                prep, query, queryBytes, responseBytes, "PASS", correctness);
        }
        static Result failed(Options o, String correctness) {
            return new Result(o.scheme, o.keywordNum, o.valuesPerKeyword, o.valueBitLength, o.q,
                -1, -1, -1, -1, "FAIL", correctness);
        }
        String toCsv() {
            return String.join(",", scheme, Integer.toString(keywordNum), Integer.toString(valuesPerKeyword),
                Integer.toString(valueBitLength), Integer.toString(q), Long.toString(preprocessingMs),
                Long.toString(queryTimeMs), Long.toString(queryBytes), Long.toString(responseBytes),
                executionStatus, correctnessStatus);
        }
    }

    private record Options(String scheme, int keywordNum, int valuesPerKeyword, int valueBitLength, int q,
                           Path output) {
        static Options parse(String[] args) {
            Map<String, String> values = new HashMap<>();
            for (int i = 0; i < args.length; i += 2) {
                if (i + 1 >= args.length || !args[i].startsWith("--")) {
                    throw new IllegalArgumentException("Arguments must be --name value pairs");
                }
                values.put(args[i], args[i + 1]);
            }
            String scheme = require(values, "--scheme");
            int q = Integer.parseInt(values.getOrDefault("--q", isSingle(scheme) ? "1" : "3"));
            return new Options(scheme,
                Integer.parseInt(values.getOrDefault("--keyword-num", "32")),
                Integer.parseInt(values.getOrDefault("--values-per-keyword", "3")),
                Integer.parseInt(values.getOrDefault("--value-bit-length", "16")), q,
                Path.of(values.getOrDefault("--output", "results/" + scheme.replace('-', '_') + ".csv")));
        }
        private static String require(Map<String, String> values, String key) {
            String value = values.get(key);
            if (value == null) throw new IllegalArgumentException("Missing " + key);
            return value;
        }
        private static boolean isSingle(String scheme) {
            return scheme.equals("MMK") || scheme.equals("FusePIR") || scheme.equals("FusePIR-C");
        }
    }
}
