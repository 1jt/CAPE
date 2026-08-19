package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;

/**
 * CAPE PIR config.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirConfig extends AbstractMultiPartyPtoConfig {
    /**
     * params.
     */
    private final CapePirParams params;
    /**
     * query method.
     */
    private final CapePirQueryMethod queryMethod;
    /**
     * boolean keyword num.
     */
    private final int boolKeywordNum;

    private CapePirConfig(Builder builder) {
        super(SecurityModel.SEMI_HONEST);
        params = new CapePirParams(builder.params);
        queryMethod = builder.queryMethod;
        boolKeywordNum = builder.boolKeywordNum;
    }

    public CapePirParams getParams() {
        return params;
    }

    public CapePirQueryMethod getQueryMethod() {
        return queryMethod;
    }

    public int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<CapePirConfig> {
        /**
         * params.
         */
        private CapePirParams params;
        /**
         * query method.
         */
        private CapePirQueryMethod queryMethod;
        /**
         * boolean keyword num.
         */
        private int boolKeywordNum;

        public Builder() {
            params = CapePirParams.DEFAULT_PARAMS;
            queryMethod = CapePirQueryMethod.AND;
            boolKeywordNum = 3;
        }

        public Builder setParams(CapePirParams params) {
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
        public CapePirConfig build() {
            return new CapePirConfig(this);
        }
    }
}
