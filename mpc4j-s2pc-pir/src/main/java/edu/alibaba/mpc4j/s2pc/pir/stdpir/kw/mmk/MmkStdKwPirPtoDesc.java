package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * MMK standard keyword PIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
public class MmkStdKwPirPtoDesc implements PtoDesc {
    /**
     * protocol ID
     */
    private static final int PTO_ID = Math.abs((int) 3982639736260153864L);
    /**
     * protocol name
     */
    private static final String PTO_NAME = "MMK_STD_KW_PIR";

    /**
     * protocol step
     */
    enum PtoStep {
        /**
         * client sends public keys
         */
        CLIENT_SEND_PUBLIC_KEYS,
        /**
         * client sends query
         */
        CLIENT_SEND_QUERY,
        /**
         * server sends response
         */
        SERVER_SEND_RESPONSE,
    }

    /**
     * the singleton mode
     */
    private static final MmkStdKwPirPtoDesc INSTANCE = new MmkStdKwPirPtoDesc();

    /**
     * private constructor.
     */
    private MmkStdKwPirPtoDesc() {
        // empty
    }

    public static PtoDesc getInstance() {
        return INSTANCE;
    }

    static {
        PtoDescManager.registerPtoDesc(getInstance());
    }

    @Override
    public int getPtoId() {
        return PTO_ID;
    }

    @Override
    public String getPtoName() {
        return PTO_NAME;
    }
}
