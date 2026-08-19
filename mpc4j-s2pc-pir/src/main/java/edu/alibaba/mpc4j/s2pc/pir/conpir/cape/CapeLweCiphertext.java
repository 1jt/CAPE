package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;

import java.util.Arrays;

/**
 * LWE ciphertext recovered from an CAPE compressed row-bit query.
 *
 * @author Weiran Liu
 * @date 2026/06/22
 */
class CapeLweCiphertext {
    /**
     * a vector.
     */
    private final long[] a;
    /**
     * b component.
     */
    private final long b;
    /**
     * LWE modulus.
     */
    private final long modulus;

    CapeLweCiphertext(long[] a, long b, long modulus) {
        MathPreconditions.checkPositive("a.length", a.length);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        this.a = Arrays.copyOf(a, a.length);
        this.b = b;
        this.modulus = modulus;
    }

    long[] getA() {
        return Arrays.copyOf(a, a.length);
    }

    long getB() {
        return b;
    }

    long getModulus() {
        return modulus;
    }
}
