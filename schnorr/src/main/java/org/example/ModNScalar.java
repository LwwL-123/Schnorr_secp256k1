package org.example;

import java.util.Arrays;


public class ModNScalar {

    public static final long orderWordZero = 3493216577L;
    public static final long orderWordOne = 3218235020L;
    public static final long orderWordTwo = 2940772411L;
    public static final long orderWordThree = 3132021990L;
    public static final long orderWordFour = 4294967294L;
    public static final long orderWordFive = 4294967295L;
    public static final long orderWordSix = 4294967295L;
    public static final long orderWordSeven = 4294967295L;

    private static final long orderComplementWordZero = (~orderWordZero) + 1;
    private static final long orderComplementWordOne = ~orderWordOne;
    private static final long orderComplementWordTwo = ~orderWordTwo;
    private static final long orderComplementWordThree = ~orderWordThree;

    private static final long uint32Mask = 4294967295L;

    public int[] n = new int[8];

    public boolean setByteSlice(byte[] b) {
        byte[] b32 = new byte[32];
        int bLen = constantTimeMin(b.length, 32);
        b = Arrays.copyOfRange(b, 0, bLen);
        System.arraycopy(b32, 0, b32, 32 - b.length, b.length);
        System.arraycopy(b, 0, b32, 32 - b.length, b.length);
        int setResult = this.setBytes(b32);
//        zeroArray32(b32);
        return setResult != 0;
    }

    private int setBytes(byte[] b32) {
        n[0] = (b32[31] & 0xFF) | ((b32[30] & 0xFF) << 8) | ((b32[29] & 0xFF) << 16) | ((b32[28] & 0xFF) << 24);
        n[1] = (b32[27] & 0xFF) | ((b32[26] & 0xFF) << 8) | ((b32[25] & 0xFF) << 16) | ((b32[24] & 0xFF) << 24);
        n[2] = (b32[23] & 0xFF) | ((b32[22] & 0xFF) << 8) | ((b32[21] & 0xFF) << 16) | ((b32[20] & 0xFF) << 24);
        n[3] = (b32[19] & 0xFF) | ((b32[18] & 0xFF) << 8) | ((b32[17] & 0xFF) << 16) | ((b32[16] & 0xFF) << 24);
        n[4] = (b32[15] & 0xFF) | ((b32[14] & 0xFF) << 8) | ((b32[13] & 0xFF) << 16) | ((b32[12] & 0xFF) << 24);
        n[5] = (b32[11] & 0xFF) | ((b32[10] & 0xFF) << 8) | ((b32[9] & 0xFF) << 16) | ((b32[8] & 0xFF) << 24);
        n[6] = (b32[7] & 0xFF) | ((b32[6] & 0xFF) << 8) | ((b32[5] & 0xFF) << 16) | ((b32[4] & 0xFF) << 24);
        n[7] = (b32[3] & 0xFF) | ((b32[2] & 0xFF) << 8) | ((b32[1] & 0xFF) << 16) | ((b32[0] & 0xFF) << 24);

        int needsReduce = overflows();
        reduce256(needsReduce);
        return needsReduce;
    }

    public int overflows() {
        // The intuition here is that the scalar is greater than the group order if
        // one of the higher individual words is greater than corresponding word of
        // the group order and all higher words in the scalar are equal to their
        // corresponding word of the group order.  Since this type is modulo the
        // group order, being equal is also an overflow back to 0.
        //
        // Note that the words 5, 6, and 7 are all the max uint32 value, so there is
        // no need to test if those individual words of the scalar exceeds them,
        // hence, only equality is checked for them.
        int highWordsEqual = constantTimeEq(this.n[7], orderWordSeven);
        highWordsEqual &= constantTimeEq(this.n[6], orderWordSix);
        highWordsEqual &= constantTimeEq(this.n[5], orderWordFive);
        int overflow = highWordsEqual & constantTimeGreater(this.n[4], orderWordFour);
        highWordsEqual &= constantTimeEq(this.n[4], orderWordFour);
        overflow |= highWordsEqual & constantTimeGreater(this.n[3], orderWordThree);
        highWordsEqual &= constantTimeEq(this.n[3], orderWordThree);
        overflow |= highWordsEqual & constantTimeGreater(this.n[2], orderWordTwo);
        highWordsEqual &= constantTimeEq(this.n[2], orderWordTwo);
        overflow |= highWordsEqual & constantTimeGreater(this.n[1], orderWordOne);
        highWordsEqual &= constantTimeEq(this.n[1], orderWordOne);
        overflow |= highWordsEqual & constantTimeGreaterOrEq(this.n[0], orderWordZero);

        return overflow;
    }

    public void reduce256(int overflows) {
        // Notice that since s < 2^256 < 2N (where N is the group order), the max
        // possible number of reductions required is one. Therefore, in the case a
        // reduction is needed, it can be performed with a single subtraction of N.
        // Also, recall that subtraction is equivalent to addition by the two's
        // complement while ignoring the carry.
        //
        // When s >= N, the overflows parameter will be 1. Conversely, it will be 0
        // when s < N. Thus multiplying by the overflows parameter will either
        // result in 0 or the multiplicand itself.
        //
        // Combining the above along with the fact that s + 0 = s, the following is
        // a constant time implementation that works by either adding 0 or the two's
        // complement of N as needed.
        //
        // The final result will be in the range 0 <= s < N as expected.
        long overflows64 = (long) overflows & 0xFFFFFFFFL;
        long c = (long) this.n[0] + overflows64 * orderComplementWordZero;
        this.n[0] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[1] + overflows64 * orderComplementWordOne;
        this.n[1] = (int) (c & uint32Mask);
        c = rightShiftWithoutSign(c,32) + (long) this.n[2] + overflows64 * orderComplementWordTwo;
        this.n[2] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[3] + overflows64 * orderComplementWordThree;
        this.n[3] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[4] + overflows64; // * 1
        this.n[4] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[5]; // + overflows64 * 0
        this.n[5] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[6]; // + overflows64 * 0
        this.n[6] = (int) (c & uint32Mask);

        c = rightShiftWithoutSign(c,32) + (long) this.n[7]; // + overflows64 * 0
        this.n[7] = (int) (c & uint32Mask);
    }

    public static int constantTimeMin(int a, int b) {
        return b ^ ((a ^ b) & -constantTimeLess(a, b));
    }

    public static int constantTimeLess(long a, long b) {
        long diff = a - b;
        return (int) ((diff >> 63) & 1);
    }

    // constantTimeEq returns 1 if a == b or 0 otherwise in constant time.
    public int constantTimeEq(long a, long b) {
        long diff = (a ^ b - 1);

        return (int) ((diff >> 63) & 1);
    }

    // constantTimeGreater returns 1 if a > b or 0 otherwise in constant time.
    public int constantTimeGreater(long a, long b) {
        return constantTimeLess(b, a);
    }

    public static int constantTimeGreaterOrEq(long a, long b) {
        return constantTimeLessOrEq(b, a);
    }

    public static int constantTimeLessOrEq(long a, long b) {
        return (int) ((a - (long) b - 1) >> 63);
    }

    public boolean isZero() {
        // The scalar can only be zero if no bits are set in any of the words.
        int bits = n[0] | n[1] | n[2] | n[3] | n[4] | n[5] | n[6] | n[7];
        return bits == 0;
    }

    public byte[] bytes() {
        byte[] b = new byte[32];
        putBytesUnchecked(b);
        return b;
    }

    public void putBytesUnchecked(byte[] b) {
        b[31] = (byte) n[0];
        b[30] = (byte) (n[0] >> 8);
        b[29] = (byte) (n[0] >> 16);
        b[28] = (byte) (n[0] >> 24);
        b[27] = (byte) n[1];
        b[26] = (byte) (n[1] >> 8);
        b[25] = (byte) (n[1] >> 16);
        b[24] = (byte) (n[1] >> 24);
        b[23] = (byte) n[2];
        b[22] = (byte) (n[2] >> 8);
        b[21] = (byte) (n[2] >> 16);
        b[20] = (byte) (n[2] >> 24);
        b[19] = (byte) n[3];
        b[18] = (byte) (n[3] >> 8);
        b[17] = (byte) (n[3] >> 16);
        b[16] = (byte) (n[3] >> 24);
        b[15] = (byte) n[4];
        b[14] = (byte) (n[4] >> 8);
        b[13] = (byte) (n[4] >> 16);
        b[12] = (byte) (n[4] >> 24);
        b[11] = (byte) n[5];
        b[10] = (byte) (n[5] >> 8);
        b[9] = (byte) (n[5] >> 16);
        b[8] = (byte) (n[5] >> 24);
        b[7] = (byte) n[6];
        b[6] = (byte) (n[6] >> 8);
        b[5] = (byte) (n[6] >> 16);
        b[4] = (byte) (n[6] >> 24);
        b[3] = (byte) n[7];
        b[2] = (byte) (n[7] >> 8);
        b[1] = (byte) (n[7] >> 16);
        b[0] = (byte) (n[7] >> 24);
    }

    public static long rightShiftWithoutSign(long value, int shift) {
        // Clear the sign bit and then perform the right shift
        long clearedValue = value & 0x00000000FFFFFFFFL;
        return clearedValue >>> shift;
    }
}
