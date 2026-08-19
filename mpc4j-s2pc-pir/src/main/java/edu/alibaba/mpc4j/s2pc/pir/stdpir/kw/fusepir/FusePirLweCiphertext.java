package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.LongUtils;

/**
 * LWE ciphertext recovered from an FUSE_PIR compressed row-bit query.
 *
 * @author Weiran Liu
 * @date 2026/06/10
 */
class FusePirLweCiphertext {
    /**
     * a component.
     */
    private final long[] a;
    /**
     * b component.
     */
    private final long b;
    /**
     * modulus.
     */
    private final long modulus;

    FusePirLweCiphertext(long[] a, long b, long modulus) {
        MathPreconditions.checkPositive("a.length", a.length);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        this.a = LongUtils.clone(a);
        this.b = b;
        this.modulus = modulus;
    }

    long[] getA() {
        return LongUtils.clone(a);
    }

    long getB() {
        return b;
    }

    long getModulus() {
        return modulus;
    }
}
