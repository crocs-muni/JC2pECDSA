package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

public class AppletTest extends BaseTest {
    public AppletTest() {
        setCardType(CardType.PHYSICAL);
        setSimulateStateful(false);
    }

    @Test
    public void testSign() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ProtocolManager pm = new ProtocolManager(connect());

        BigInteger order = ProtocolManager.G.getCurve().getOrder();
        BigInteger m = ProtocolManager.hash(new byte[32]);

        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);
        ECPoint X = ProtocolManager.G.multiply(x1).multiply(x2);

        BigInteger p = new BigInteger(1, new byte[]{(byte) 0xe0, (byte) 0xb6, (byte) 0xa1, (byte) 0xfc, (byte) 0x89, (byte) 0xcb, (byte) 0xcb, (byte) 0xf8, (byte) 0xf6, (byte) 0xdf, (byte) 0xa5, (byte) 0x06, (byte) 0x12, (byte) 0x68, (byte) 0x9e, (byte) 0x2b, (byte) 0xcc, (byte) 0x32, (byte) 0xe5, (byte) 0x81, (byte) 0xeb, (byte) 0x6c, (byte) 0xe4, (byte) 0xb7, (byte) 0x0d, (byte) 0x79, (byte) 0x26, (byte) 0xc2, (byte) 0x97, (byte) 0x3d, (byte) 0xd8, (byte) 0x02, (byte) 0x47, (byte) 0x1e, (byte) 0x09, (byte) 0xcf, (byte) 0x83, (byte) 0x93, (byte) 0xd0, (byte) 0x30, (byte) 0x1f, (byte) 0xbb, (byte) 0x98, (byte) 0x0d, (byte) 0x11, (byte) 0xfd, (byte) 0xd0, (byte) 0xcd, (byte) 0xbd, (byte) 0xc2, (byte) 0xc6, (byte) 0x50, (byte) 0xf7, (byte) 0xd9, (byte) 0x9c, (byte) 0x64, (byte) 0x93, (byte) 0xb6, (byte) 0x7f, (byte) 0xf4, (byte) 0x49, (byte) 0xb4, (byte) 0x08, (byte) 0x4e, (byte) 0x04, (byte) 0xa7, (byte) 0x7e, (byte) 0x32, (byte) 0x79, (byte) 0x2b, (byte) 0xe1, (byte) 0x22, (byte) 0x8f, (byte) 0xae, (byte) 0xdc, (byte) 0xd3, (byte) 0x32, (byte) 0xcf, (byte) 0x57, (byte) 0x31, (byte) 0x93, (byte) 0x1c, (byte) 0x8f, (byte) 0xe0, (byte) 0x26, (byte) 0x15, (byte) 0x87, (byte) 0x13, (byte) 0x88, (byte) 0xc2, (byte) 0xcb, (byte) 0xc2, (byte) 0x6a, (byte) 0x04, (byte) 0x07, (byte) 0x53, (byte) 0xf0, (byte) 0x44, (byte) 0xdb, (byte) 0x23, (byte) 0xb9, (byte) 0x0d, (byte) 0x37, (byte) 0xb0, (byte) 0x5a, (byte) 0xba, (byte) 0x04, (byte) 0x90, (byte) 0x6a, (byte) 0xc1, (byte) 0x3b, (byte) 0xd4, (byte) 0x58, (byte) 0x3f, (byte) 0x25, (byte) 0x08, (byte) 0x14, (byte) 0x25, (byte) 0x64, (byte) 0xbb, (byte) 0xcd, (byte) 0xf5, (byte) 0x67, (byte) 0x38, (byte) 0xc2, (byte) 0x51, (byte) 0x5b, (byte) 0x8b});
        BigInteger q = new BigInteger(1, new byte[]{(byte) 0x41, (byte) 0x20, (byte) 0xd0, (byte) 0xcf, (byte) 0x15, (byte) 0xfa, (byte) 0x22, (byte) 0xe2, (byte) 0x11, (byte) 0x1a, (byte) 0x61, (byte) 0x32, (byte) 0x75, (byte) 0x30, (byte) 0x17, (byte) 0x7e, (byte) 0xc3, (byte) 0xf3, (byte) 0x28, (byte) 0x87, (byte) 0x5a, (byte) 0x30, (byte) 0xe6, (byte) 0xb5, (byte) 0xd0, (byte) 0x8c, (byte) 0x45, (byte) 0x55, (byte) 0x98, (byte) 0x27, (byte) 0x57, (byte) 0xe8, (byte) 0xbd, (byte) 0xab, (byte) 0xa0, (byte) 0x4c, (byte) 0xf5, (byte) 0xe9, (byte) 0x06, (byte) 0x8a, (byte) 0xc7, (byte) 0x76, (byte) 0x1c, (byte) 0x2b, (byte) 0x8c, (byte) 0x30, (byte) 0x86, (byte) 0xa0, (byte) 0xc7, (byte) 0xde, (byte) 0xfd, (byte) 0x41, (byte) 0x5e, (byte) 0x44, (byte) 0xf9, (byte) 0x7a, (byte) 0x52, (byte) 0xc8, (byte) 0xb3, (byte) 0xae, (byte) 0xf8, (byte) 0x57, (byte) 0x35, (byte) 0x10, (byte) 0x67, (byte) 0x35, (byte) 0x35, (byte) 0xf3, (byte) 0x0d, (byte) 0x65, (byte) 0xd3, (byte) 0x98, (byte) 0x7a, (byte) 0x4b, (byte) 0x93, (byte) 0xe9, (byte) 0xeb, (byte) 0x6f, (byte) 0x09, (byte) 0x64, (byte) 0x00, (byte) 0x24, (byte) 0x0f, (byte) 0x71, (byte) 0xa5, (byte) 0x8c, (byte) 0x8c, (byte) 0x3b, (byte) 0x2b, (byte) 0xf2, (byte) 0x2f, (byte) 0x83, (byte) 0x46, (byte) 0x7f, (byte) 0x87, (byte) 0x5d, (byte) 0xd7, (byte) 0x34, (byte) 0x12, (byte) 0x8d, (byte) 0x0b, (byte) 0xc3, (byte) 0xb0, (byte) 0x5e, (byte) 0x3e, (byte) 0x0c, (byte) 0x82, (byte) 0x6f, (byte) 0x1a, (byte) 0x69, (byte) 0xa2, (byte) 0x67, (byte) 0x26, (byte) 0x90, (byte) 0xd3, (byte) 0x9b, (byte) 0x11, (byte) 0x17, (byte) 0x20, (byte) 0x56, (byte) 0xe4, (byte) 0x46, (byte) 0x54, (byte) 0xe8, (byte) 0xf9, (byte) 0xa8, (byte) 0xb4, (byte) 0x93});
        BigInteger n = p.multiply(q);
        BigInteger nsq = n.multiply(n);
        BigInteger g = n.add(BigInteger.ONE);
        BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger mu = lambda.modInverse(n);

        BigInteger cx2 = g.modPow(x2, nsq).multiply(ProtocolManager.randomBigInt(256).modPow(n, nsq)).mod(nsq);
        BigInteger pt = cx2.modPow(lambda, nsq).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
        assert pt.equals(x2);

        pm.setup(n, nsq, lambda, mu, X);

        // Host sends m to card
        byte[] comm = pm.sign1(new byte[32]);

        // Card sends commitment to host
        BigInteger k1 = ProtocolManager.randomBigInt(32);
        ECPoint R1 = ProtocolManager.G.multiply(k1);

        // Host sends pi1, R1 to card
        BigInteger proof1r = ProtocolManager.randomBigInt(32);
        ECPoint proof1R = ProtocolManager.G.multiply(proof1r);
        BigInteger proof1e = ProtocolManager.hash(proof1R.getEncoded(false));
        BigInteger proof1s = proof1r.subtract(proof1e.multiply(k1)).mod(order);

        byte[] resp = pm.sign2(proof1e, proof1s, R1);
        // Card sends pi2, R2 to host
        Assertions.assertArrayEquals(ProtocolManager.encodeBigInteger(ProtocolManager.hash(resp)), comm);
        byte[] proof2 = Arrays.copyOfRange(resp, 0, 64);
        BigInteger proof2e = new BigInteger(1, Arrays.copyOfRange(proof2, 0, 32));
        BigInteger proof2s = new BigInteger(1, Arrays.copyOfRange(proof2, 32, 64));
        ECPoint R2 = ProtocolManager.G.getCurve().decodePoint(Arrays.copyOfRange(resp, 64, 64 + 65));

        ECPoint proof2R = ProtocolManager.G.multiply(proof2s).add(R2.multiply(proof2e));
        Assertions.assertEquals(ProtocolManager.hash(proof2R.getEncoded(false)), proof2e);

        ECPoint R = R2.multiply(k1);
        BigInteger Rx = R.normalize().getRawXCoord().toBigInteger();

        BigInteger rho = ProtocolManager.randomBigInt(128);
        BigInteger rtilda = ProtocolManager.randomBigInt(256);
        BigInteger c1_prime = rho.multiply(order).add(k1.modInverse(order).multiply(m).mod(order)).mod(rtilda);
        BigInteger c1 = g.modPow(c1_prime, nsq).multiply(ProtocolManager.randomBigInt(256).modPow(n, nsq)).mod(nsq);
        BigInteger v = k1.modInverse(order).multiply(Rx).multiply(x1).mod(order);
        BigInteger c2 = cx2.modPow(v, nsq);
        BigInteger cs1 = c1.multiply(c2).mod(nsq);

        // Host sends cs1 to card
        byte[] signature = pm.sign3(cs1);
        Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
    }
}