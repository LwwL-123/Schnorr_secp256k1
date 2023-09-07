package org.example;

import java.math.BigInteger;
import java.util.Arrays;

public class Schnorr {
    public static String sign(byte[] secKey, byte[] msg, byte[] auxRand) {
        if (msg.length != 32) {
            throw new RuntimeException("The message must be a 32-byte array.");

        }
        BigInteger secKey0 = Util.bigIntFromBytes(secKey);

        if (!(BigInteger.ONE.compareTo(secKey0) <= 0 && secKey0.compareTo(Point.getn().subtract(BigInteger.ONE)) <= 0)) {
            throw new RuntimeException("The secret key must be an integer in the range 1..n-1.");
        }
        // Step 4.
        //
        // P = 'd*G
        Point P = Point.mul(Point.getG(), secKey0);
        // Step 5.
        //
        // Negate d if P.y is odd.
        if (!P.hasEvenY()) {
            secKey0 = Point.getn().subtract(secKey0);
        }

        // Step 6.
        //
        // t = bytes(d) xor tagged_hash("BIP0340/aux", a)
        int len = Util.bytesFromBigInteger(secKey0).length + P.toBytes().length + msg.length;
        byte[] buf = new byte[len];
        byte[] t = Util.xor(Util.bytesFromBigInteger(secKey0), Point.taggedHash("BIP0340/aux", auxRand));
        System.arraycopy(t, 0, buf, 0, t.length);
        System.arraycopy(P.toBytes(), 0, buf, t.length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, t.length + P.toBytes().length, msg.length);
        // Step 7.
        //
        // rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)
        //
        // We snip off the first byte of the serialized pubkey, as we
        // only need the x coordinate and not the market byte.

        // Step 8.
        //
        // k'= int(rand) mod n
        byte[] b = Point.taggedHash("BIP0340/nonce", buf);
        BigInteger k0 = Util.bigIntFromBytes(b).mod(Point.getn());

        // Step 9.
        //
        // Fail if k' = 0
        if (k0.compareTo(BigInteger.ZERO) == 0) {
            throw new RuntimeException("Failure. This happens only with negligible probability.");
        }


        //
        // Step 10.
        //
        // R = kG
        Point R = Point.mul(Point.getG(), k0);

        // Step 11.
        //
        // Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
        //
        // Note that R must be in affine coordinates for this check.
        BigInteger k = null;
        if (!R.hasEvenY()) {
            k = Point.getn().subtract(k0);
        } else {
            k = k0;
        }
        len = R.toBytes().length + P.toBytes().length + msg.length;
        buf = new byte[len];
        System.arraycopy(R.toBytes(), 0, buf, 0, R.toBytes().length);
        System.arraycopy(P.toBytes(), 0, buf, R.toBytes().length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, R.toBytes().length + P.toBytes().length, msg.length);

        // Step 12.
        //
        // e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m) mod n
        BigInteger e = Util.bigIntFromBytes(Point.taggedHash("BIP0340/challenge", buf)).mod(Point.getn());


        // Step 13.
        //
        // s = k + e*d mod n
        BigInteger kes = k.add(e.multiply(secKey0)).mod(Point.getn());


        // Step 14.
        //
        // If Verify(bytes(P), m, sig) fails, abort.
        len = R.toBytes().length + Util.bytesFromBigInteger(kes).length;
        byte[] sig = new byte[len];
        System.arraycopy(R.toBytes(), 0, sig, 0, R.toBytes().length);
        System.arraycopy(Util.bytesFromBigInteger(kes), 0, sig, R.toBytes().length, Util.bytesFromBigInteger(kes).length);
        if (!verify(msg, P.toBytes(), sig)) {
            throw new RuntimeException("The signature does not pass verification.");
        }
        return Util.bytesToHex(sig);
    }

    public static String sign(byte[] secKey, byte[] msg) {
        if (msg.length != 32) {
            throw new RuntimeException("The message must be a 32-byte array.");

        }
        BigInteger secKey0 = Util.bigIntFromBytes(secKey);

        if (!(BigInteger.ONE.compareTo(secKey0) <= 0 && secKey0.compareTo(Point.getn().subtract(BigInteger.ONE)) <= 0)) {
            throw new RuntimeException("The secret key must be an integer in the range 1..n-1.");
        }
        // Step 4.
        //
        // P = 'd*G
        Point P = Point.mul(Point.getG(), secKey0);
        // Step 5.
        //
        // Negate d if P.y is odd.
        if (!P.hasEvenY()) {
            secKey0 = Point.getn().subtract(secKey0);
        }

        for (int i = 0; ; i++) {
            try {
                byte[] extra = Util.hexToBytes("a3eb4c182fae7ef4e810c6ee13b0e926686d71e87f394f799c00a52103cb4e17");
                byte[] version = new byte[0];
                byte[] byteArray = RFC6979.nonceRFC6979(Util.bytesFromBigInteger(secKey0), msg, extra, version, i);
                BigInteger k0 = Util.bigIntFromBytes(byteArray);
                //
                // Step 10.
                //
                // R = kG
                Point R = Point.mul(Point.getG(), k0);

                // Step 11.
                //
                // Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
                //
                // Note that R must be in affine coordinates for this check.
                BigInteger k = null;
                if (!R.hasEvenY()) {
                    k = Point.getn().subtract(k0);
                } else {
                    k = k0;
                }
                int len = R.toBytes().length + P.toBytes().length + msg.length;
                byte[] buf = new byte[len];
                System.arraycopy(R.toBytes(), 0, buf, 0, R.toBytes().length);
                System.arraycopy(P.toBytes(), 0, buf, R.toBytes().length, P.toBytes().length);
                System.arraycopy(msg, 0, buf, R.toBytes().length + P.toBytes().length, msg.length);

                // Step 12.
                //
                // e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m) mod n
                BigInteger e = Util.bigIntFromBytes(Point.taggedHash("BIP0340/challenge", buf)).mod(Point.getn());

                // Step 13.
                //
                // s = k + e*d mod n
                BigInteger kes = k.add(e.multiply(secKey0)).mod(Point.getn());

                // Step 14.
                //
                // If Verify(bytes(P), m, sig) fails, abort.
                len = R.toBytes().length + Util.bytesFromBigInteger(kes).length;
                byte[] sig = new byte[len];
                System.arraycopy(R.toBytes(), 0, sig, 0, R.toBytes().length);
                System.arraycopy(Util.bytesFromBigInteger(kes), 0, sig, R.toBytes().length, Util.bytesFromBigInteger(kes).length);
                if (!verify(msg, P.toBytes(), sig)) {
                    throw new RuntimeException("The signature does not pass verification.");
                }
                return Util.bytesToHex(sig);
            } catch (Exception e) {
                System.out.println("Error occurred: " + e.getMessage());
            }
        }
    }

    public static boolean verify(byte[] msg, byte[] pubkey, byte[] sig) {
        if (msg.length != 32) {
            throw new RuntimeException("The message must be a 32-byte array.");
        }
        if (pubkey.length != 32) {
            throw new RuntimeException("The public key must be a 32-byte array.");
        }
        if (sig.length != 64) {
            throw new RuntimeException("The signature must be a 64-byte array.");
        }

        Point P = Point.liftX(pubkey);
        if (P == null) {
            return false;
        }
        BigInteger r = Util.bigIntFromBytes(Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = Util.bigIntFromBytes(Arrays.copyOfRange(sig, 32, 64));
        if (r.compareTo(Point.getp()) >= 0 || s.compareTo(Point.getn()) >= 0) {
            return false;
        }
        int len = 32 + pubkey.length + msg.length;
        byte[] buf = new byte[len];
        System.arraycopy(sig, 0, buf, 0, 32);
        System.arraycopy(pubkey, 0, buf, 32, pubkey.length);
        System.arraycopy(msg, 0, buf, 32 + pubkey.length, msg.length);
        BigInteger e = Util.bigIntFromBytes(Point.taggedHash("BIP0340/challenge", buf)).mod(Point.getn());
        Point R = Point.add(Point.mul(Point.getG(), s), Point.mul(P, Point.getn().subtract(e)));
        return R != null && R.hasEvenY() && R.getX().compareTo(r) == 0;
    }
}

