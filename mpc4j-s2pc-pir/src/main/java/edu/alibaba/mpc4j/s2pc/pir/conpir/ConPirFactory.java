package edu.alibaba.mpc4j.s2pc.pir.conpir;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.rpc.pto.PtoFactory;
import edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirClient;
import edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirServer;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirClient;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirConfig;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirServer;
import edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirClient;
import edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirServer;

/**
 * conjunctive PIR factory.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class ConPirFactory implements PtoFactory {
    /**
     * private constructor.
     */
    private ConPirFactory() {
        // empty
    }

    /**
     * protocol type.
     */
    public enum ConPirType {
        /**
         * BKPIR.
         */
        BKPIR,
        /**
         * CAPE.
         */
        CAPE,
        /**
         * CAPE_C.
         */
        CAPE_C,
    }

    public static ConPirType readType(String name) {
        return ConPirType.valueOf(name.toUpperCase());
    }

    public static <T> AbstractTwoPartyPto createServer(Rpc serverRpc, Party clientParty, ConPirType type,
                                                       Object config) {
        switch (type) {
            case BKPIR -> {
                return new BkPirServer<T>(serverRpc, clientParty, (BkPirConfig) config);
            }
            case CAPE -> {
                return new CapePirServer<T>(serverRpc, clientParty, (CapePirConfig) config);
            }
            case CAPE_C -> {
                return new CapeCPirServer<T>(serverRpc, clientParty, (CapeCPirConfig) config);
            }
            default -> throw new IllegalArgumentException("Invalid " + ConPirType.class.getSimpleName() + ": "
                + type.name());
        }
    }

    public static <T> AbstractTwoPartyPto createClient(Rpc clientRpc, Party serverParty, ConPirType type,
                                                       Object config) {
        switch (type) {
            case BKPIR -> {
                return new BkPirClient<T>(clientRpc, serverParty, (BkPirConfig) config);
            }
            case CAPE -> {
                return new CapePirClient<T>(clientRpc, serverParty, (CapePirConfig) config);
            }
            case CAPE_C -> {
                return new CapeCPirClient<T>(clientRpc, serverParty, (CapeCPirConfig) config);
            }
            default -> throw new IllegalArgumentException("Invalid " + ConPirType.class.getSimpleName() + ": "
                + type.name());
        }
    }
}
