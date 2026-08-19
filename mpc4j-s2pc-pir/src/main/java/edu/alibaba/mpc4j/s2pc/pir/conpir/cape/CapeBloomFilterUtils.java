package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.structure.filter.BloomFilterFactory.BloomFilterType;
import java.util.Collection;

/**
 * CAPE Bloom Filter helper methods.
 *
 * <p>The actual adapter is {@link CapeBloomFilterAdapter}; this class is kept as a small utility facade.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapeBloomFilterUtils {
    /**
     * default Bloom Filter type.
     */
    static final BloomFilterType DEFAULT_BLOOM_FILTER_TYPE = BloomFilterType.NAIVE_RANDOM_BLOOM_FILTER;

    private CapeBloomFilterUtils() {
        // empty
    }

    static CapeBloomFilterAdapter create(Collection<byte[]> items, CapePirParams params) {
        return CapeBloomFilterAdapter.create(items, params);
    }
}
