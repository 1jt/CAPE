package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirQueryMethod;

/**
 * CAPE_C PIR config.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirConfig extends AbstractMultiPartyPtoConfig {
    /**
     * params.
     */
    private final CapeCPirParams params;
    /**
     * query method.
     */
    private final CapePirQueryMethod queryMethod;
    /**
     * boolean keyword num.
     */
    private final int boolKeywordNum;

    private CapeCPirConfig(Builder builder) {
        super(SecurityModel.SEMI_HONEST);
        params = new CapeCPirParams(builder.params);
        queryMethod = builder.queryMethod;
        boolKeywordNum = builder.boolKeywordNum;
    }

    public CapeCPirParams getParams() {
        return params;
    }

    public CapePirQueryMethod getQueryMethod() {
        return queryMethod;
    }

    public int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<CapeCPirConfig> {
        /**
         * params.
         */
        private CapeCPirParams params;
        /**
         * query method.
         */
        private CapePirQueryMethod queryMethod;
        /**
         * boolean keyword num.
         */
        private int boolKeywordNum;

        public Builder() {
            params = CapeCPirParams.DEFAULT_PARAMS;
            queryMethod = CapePirQueryMethod.AND;
            boolKeywordNum = 3;
        }

        public Builder setParams(CapeCPirParams params) {
            this.params = params;
            return this;
        }

        public Builder setQueryMethod(CapePirQueryMethod queryMethod) {
            this.queryMethod = queryMethod;
            return this;
        }

        public Builder setBoolKeywordNum(int boolKeywordNum) {
            MathPreconditions.checkGreaterOrEqual("bool_keyword_num", boolKeywordNum, 2);
            this.boolKeywordNum = boolKeywordNum;
            return this;
        }

        @Override
        public CapeCPirConfig build() {
            return new CapeCPirConfig(this);
        }
    }
}
