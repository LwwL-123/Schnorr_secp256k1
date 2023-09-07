package org.example;


import java.util.Arrays;

public class RFC6979 {

    private static final int privKeyLen = 32;
    private static final int hashLen = 32;
    private static final int extraLen = 32;
    private static final int versionLen = 16;

    private static final byte[] oneInitializer = new byte[32];
    private static final byte[] zeroInitializer = new byte[64];
    private static final byte[] singleOne = new byte[]{0x01};
    private static final byte[] singleZero = new byte[]{0x00};

    static {
        Arrays.fill(oneInitializer, (byte) 0x01);
        Arrays.fill(zeroInitializer, (byte) 0x00);
    }

    public static byte[] nonceRFC6979(byte[] privKey, byte[] hash, byte[] extra, byte[] version, long extraIterations) {
        byte[] keyBuf = new byte[privKeyLen + hashLen + extraLen + versionLen];
        int offset = 0;

        if (privKey.length > privKeyLen) {
            privKey = Arrays.copyOf(privKey, privKeyLen);
        }
        if (hash.length > hashLen) {
            hash = Arrays.copyOf(hash, hashLen);
        }
        offset += privKeyLen - privKey.length;
        System.arraycopy(privKey, 0, keyBuf, offset, privKey.length);
        offset += privKey.length;

        offset += hashLen - hash.length;
        System.arraycopy(hash, 0, keyBuf, offset, hash.length);
        offset += hash.length;


        if (extra.length == extraLen) {
            offset += copyBytes(extra, keyBuf, offset, extra.length);
            if (version.length == versionLen) {
                offset += copyBytes(version, keyBuf, offset, version.length);
            }
        } else if (version.length == versionLen) {
            offset += privKeyLen;
            offset += copyBytes(version, keyBuf, offset, version.length);
        }
        byte[] key = Arrays.copyOfRange(keyBuf, 0, offset);

        byte[] v = Arrays.copyOf(oneInitializer, 32);
        byte[] k = Arrays.copyOf(zeroInitializer, hashLen);

        HmacSha256 hasher = new HmacSha256(k);
        hasher.write(oneInitializer);
        hasher.write(singleZero);
        hasher.write(key);
        k = hasher.sum();

        hasher.resetKey(k);
        hasher.write(v);
        v = hasher.sum();

        hasher.reset();
        hasher.write(v);
        hasher.write(singleOne);
        hasher.write(key);
        k = hasher.sum();

        hasher.resetKey(k);
        hasher.write(v);
        v = hasher.sum();

        int generated = 0;
        while (true) {
            hasher.reset();
            hasher.write(v);
            v = hasher.sum();

            ModNScalar secret = new ModNScalar();
            boolean overflow = secret.setByteSlice(v);
            if (!overflow && !secret.isZero()) {
                generated++;
                if (generated > extraIterations) {
                    return secret.bytes();
                }

            }

            hasher.reset();
            hasher.write(v);
            hasher.write(singleZero);
            k = hasher.sum();

            hasher.resetKey(k);
            hasher.write(v);
            v = hasher.sum();
        }
    }

    private static int copyBytes(byte[] src, byte[] dest, int destOffset, int length) {
        System.arraycopy(src, 0, dest, destOffset, length);
        return length;
    }
}
