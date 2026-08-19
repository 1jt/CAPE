package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;

/**
 * BKPIR config.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirConfig extends AbstractMultiPartyPtoConfig {
    /**
     * params.
     */
    private final BkPirParams params;
    /**
     * query method.
     */
    private final BkPirQueryMethod queryMethod;
    /**
     * boolean keyword num.
     */
    private final int boolKeywordNum;

    private BkPirConfig(Builder builder) {
        super(SecurityModel.MALICIOUS);
        params = builder.params;
        queryMethod = builder.queryMethod;
        boolKeywordNum = builder.boolKeywordNum;
    }

    public BkPirParams getParams() {
        return params;
    }

    public BkPirQueryMethod getQueryMethod() {
        return queryMethod;
    }

    public int getBoolKeywordNum() {
        return boolKeywordNum;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<BkPirConfig> {
        /**
         * params.
         */
        private BkPirParams params;
        /**
         * query method.
         */
        private BkPirQueryMethod queryMethod;
        /**
         * boolean keyword num.
         */
        private int boolKeywordNum;

        public Builder() {
            params = BkPirParams.DEFAULT_PARAMS;
            queryMethod = BkPirQueryMethod.AND;
            boolKeywordNum = 3;
        }

        public Builder setParams(BkPirParams params) {
            this.params = params;
            return this;
        }

        public Builder setQueryMethod(BkPirQueryMethod queryMethod) {
            this.queryMethod = queryMethod;
            return this;
        }

        public Builder setBoolKeywordNum(int boolKeywordNum) {
            MathPreconditions.checkPositive("bool_keyword_num", boolKeywordNum);
            this.boolKeywordNum = boolKeywordNum;
            return this;
        }

        @Override
        public BkPirConfig build() {
            return new BkPirConfig(this);
        }
    }
}
