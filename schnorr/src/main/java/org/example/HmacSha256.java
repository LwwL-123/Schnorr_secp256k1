package org.example;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HmacSha256 {

    private final MessageDigest inner;
    private final MessageDigest outer;
    private byte[] ipad;
    private byte[] opad;

    private static final int BLOCK_SIZE = 64;
    private static final byte[] zeroInitializer = new byte[64];
    static {
        Arrays.fill(zeroInitializer, (byte) 0x00);
    }

    public HmacSha256(byte[] key) {
        try {
            inner = MessageDigest.getInstance("SHA-256");
            outer = MessageDigest.getInstance("SHA-256");
            initKey(key);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found");
        }
    }

    private void initKey(byte[] key) {
        if (key.length > BLOCK_SIZE) {
            outer.update(key);
            key = outer.digest();
        }

        ipad = new byte[BLOCK_SIZE];
        opad = new byte[BLOCK_SIZE];

        Arrays.fill(ipad, (byte) 0x36);
        Arrays.fill(opad, (byte) 0x5c);

        for (int i = 0; i < key.length; i++) {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        inner.update(ipad);
    }

    public void resetKey(byte[] key) {
        inner.reset();
        outer.reset();
        System.arraycopy(zeroInitializer, 0, ipad, 0, zeroInitializer.length);
        System.arraycopy(zeroInitializer, 0, opad, 0, zeroInitializer.length);
        initKey(key);
    }

    public void reset() {
        inner.reset();
        inner.update(ipad);
    }

    public byte[] sum() {
        outer.reset();
        outer.update(opad);
        outer.update(inner.digest());
        return outer.digest();
    }

    public void write(byte[] data) {
        inner.update(data);
    }
}
