package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.PtoFactory;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirClient;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirServer;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirClient;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirServer;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirClient;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc.FusePirCStdKwPirServer;

/**
 * standard keyword PIR factory.
 *
 * @author Liqiang Peng
 * @date 2024/7/19
 */
public class StdKwPirFactory implements PtoFactory {
    /**
     * private constructor.
     */
    private StdKwPirFactory() {
        // empty
    }

    /**
     * protocol type
     */
    public enum StdKwPirType {
        /**
         * MMK
         */
        MMK,
        /**
         * FUSE_PIR
         */
        FUSE_PIR,
        /**
         * FUSE_PIR_C
         */
        FUSE_PIR_C,
    }

    /**
     * create a server.
     *
     * @param serverRpc   server RPC.
     * @param clientParty client party.
     * @param config      config.
     * @return a server.
     */
    public static <T> StdKwPirServer<T> createServer(Rpc serverRpc, Party clientParty, StdKwPirConfig config) {
        StdKwPirType type = config.getPtoType();
        switch (type) {
            case MMK -> {
                return new MmkStdKwPirServer<>(serverRpc, clientParty, (MmkStdKwPirConfig) config);
            }
            case FUSE_PIR -> {
                return new FusePirStdKwPirServer<>(serverRpc, clientParty, (FusePirStdKwPirConfig) config);
            }
            case FUSE_PIR_C -> {
                return new FusePirCStdKwPirServer<>(serverRpc, clientParty, (FusePirCStdKwPirConfig) config);
            }
            default -> throw new IllegalArgumentException("Invalid " + StdKwPirType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * create a client.
     *
     * @param clientRpc   client RPC.
     * @param serverParty server party.
     * @param config      config.
     * @return a client.
     */
    public static <T> StdKwPirClient<T> createClient(Rpc clientRpc, Party serverParty, StdKwPirConfig config) {
        StdKwPirType type = config.getPtoType();
        switch (type) {
            case MMK -> {
                return new MmkStdKwPirClient<>(clientRpc, serverParty, (MmkStdKwPirConfig) config);
            }
            case FUSE_PIR -> {
                return new FusePirStdKwPirClient<>(clientRpc, serverParty, (FusePirStdKwPirConfig) config);
            }
            case FUSE_PIR_C -> {
                return new FusePirCStdKwPirClient<>(clientRpc, serverParty, (FusePirCStdKwPirConfig) config);
            }
            default -> throw new IllegalArgumentException("Invalid " + StdKwPirType.class.getSimpleName() + ": " + type.name());
        }
    }
}
