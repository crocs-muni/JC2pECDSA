package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import javacard.framework.ISO7816;
import jc2pecdsa.Consts;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.*;
import java.util.Random;

public class ProtocolManager {
    public final CardManager cm;

    public final static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public final static ECPoint G = ecSpec.getG();
    private final static Random rnd = new Random();

    public ProtocolManager(CardManager cm) {
        this.cm = cm;
    }

    public void setup(BigInteger n, BigInteger nsq, BigInteger lambda, BigInteger mu) throws Exception {
        byte[] data = Util.concat(encodeBigInteger(n, 128), encodeBigInteger(nsq, 256));
        data = Util.concat(data, encodeBigInteger(lambda, 128));
        data = Util.concat(data, encodeBigInteger(mu, 128));
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JC2PECDSA,
                Consts.INS_SETUP,
                0,
                0,
                data
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public void sign1(byte[] message) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JC2PECDSA,
                Consts.INS_SIGN1,
                0,
                0,
                message
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public void sign2(byte[] pi1, ECPoint R1) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JC2PECDSA,
                Consts.INS_SIGN2,
                0,
                0,
                Util.concat(pi1, R1.getEncoded(false))
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public void sign3(BigInteger cs1) throws Exception {
        CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JC2PECDSA,
                Consts.INS_SIGN3,
                0,
                0,
                ProtocolManager.encodeBigInteger(cs1, 256)
        );
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assertions.assertNotNull(responseAPDU);
        Assertions.assertEquals(ISO7816.SW_NO_ERROR & 0xffff, responseAPDU.getSW());
    }

    public static BigInteger hash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] h = digest.digest(message);
        return new BigInteger(1, h);
    }

    public static BigInteger randomBigInt(int bytes) {
        return new BigInteger(bytes * 8, rnd);
    }

    public static byte[] encodeBigInteger(BigInteger x) {
        return encodeBigInteger(x, 32);
    }

    public static byte[] encodeBigInteger(BigInteger x, int bytes) {
        byte[] encoded = Util.trimLeadingZeroes(x.toByteArray());
        assert encoded.length <= bytes;
        while (encoded.length != bytes) {
            encoded = Util.concat(new byte[1], encoded);
        }
        return encoded;
    }

    public static byte[] rawToDer(BigInteger r, BigInteger s) {
        byte[] rBytes = ProtocolManager.encodeBigInteger(r);
        byte[] sBytes = ProtocolManager.encodeBigInteger(s);

        int totalLength = rBytes.length + sBytes.length + 4 + 2; // 4 bytes for the DER tags and lengths, and 2 bytes for each integer tag and its length
        byte[] der = new byte[totalLength];

        der[0] = 0x30; // DER sequence tag
        der[1] = (byte) (totalLength - 2); // length of sequence

        der[2] = 0x02; // DER integer tag
        der[3] = (byte) rBytes.length; // length of r
        System.arraycopy(rBytes, 0, der, 4, rBytes.length);

        int offset = 4 + rBytes.length;
        der[offset] = 0x02; // DER integer tag
        der[offset + 1] = (byte) sBytes.length; // length of s
        System.arraycopy(sBytes, 0, der, offset + 2, sBytes.length);

        return der;
    }

    public static boolean verifySignature(ECPoint pk, byte[] message, byte[] signature) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ECPublicKeySpec pkSpec = new ECPublicKeySpec(pk, ProtocolManager.ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        ecdsa.initVerify(kf.generatePublic(pkSpec));
        ecdsa.update(message);


        return ecdsa.verify(signature);
    }
}
