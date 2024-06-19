package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

public class AppletTest extends BaseTest {
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
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

        BigInteger p = new BigInteger(1, new byte[]{(byte) 0xd1, (byte) 0xf2, (byte) 0xd3, (byte) 0xe4, (byte) 0xfc, (byte) 0x7c, (byte) 0x39, (byte) 0x95, (byte) 0xd2, (byte) 0xc8, (byte) 0x05, (byte) 0xa3, (byte) 0xc1, (byte) 0x7d, (byte) 0x7a, (byte) 0x4a, (byte) 0xf6, (byte) 0x2b, (byte) 0x5f, (byte) 0x6a, (byte) 0x7b, (byte) 0xc3, (byte) 0x15, (byte) 0xe8, (byte) 0x84, (byte) 0xd7, (byte) 0x65, (byte) 0xcc, (byte) 0x06, (byte) 0x47, (byte) 0x37, (byte) 0xf2, (byte) 0x8a, (byte) 0xf2, (byte) 0xd8, (byte) 0x7d, (byte) 0x83, (byte) 0xbd, (byte) 0x48, (byte) 0xbd, (byte) 0x4c, (byte) 0xd7, (byte) 0x13, (byte) 0x9e, (byte) 0x77, (byte) 0xfb, (byte) 0xe7, (byte) 0xb6, (byte) 0xea, (byte) 0x10, (byte) 0x46, (byte) 0x44, (byte) 0x58, (byte) 0x4e, (byte) 0x3c, (byte) 0xdd, (byte) 0x15, (byte) 0xf0, (byte) 0x88, (byte) 0x48, (byte) 0x3e, (byte) 0xfc, (byte) 0x50, (byte) 0x79});
        BigInteger q = new BigInteger(1, new byte[]{(byte) 0x37, (byte) 0x16, (byte) 0x4f, (byte) 0xd4, (byte) 0xbc, (byte) 0x18, (byte) 0xbf, (byte) 0x40, (byte) 0xa1, (byte) 0xde, (byte) 0xca, (byte) 0x0c, (byte) 0x61, (byte) 0xc7, (byte) 0x60, (byte) 0xe0, (byte) 0xc7, (byte) 0xd7, (byte) 0x97, (byte) 0x48, (byte) 0x2b, (byte) 0x7f, (byte) 0x1a, (byte) 0x2c, (byte) 0xc6, (byte) 0xca, (byte) 0x65, (byte) 0x76, (byte) 0x7a, (byte) 0x6b, (byte) 0xd7, (byte) 0xfe, (byte) 0xec, (byte) 0x37, (byte) 0x2b, (byte) 0x4a, (byte) 0x07, (byte) 0xa2, (byte) 0xe0, (byte) 0xa3, (byte) 0x4f, (byte) 0xef, (byte) 0x16, (byte) 0x03, (byte) 0xef, (byte) 0x71, (byte) 0x7c, (byte) 0x0f, (byte) 0xf2, (byte) 0xf2, (byte) 0x6d, (byte) 0x00, (byte) 0x6f, (byte) 0xfd, (byte) 0x6c, (byte) 0x75, (byte) 0x7e, (byte) 0xb9, (byte) 0xaa, (byte) 0xe8, (byte) 0x65, (byte) 0x7d, (byte) 0x07, (byte) 0x47});
        BigInteger n = p.multiply(q);
        BigInteger nsq = n.multiply(n);
        BigInteger g = n.add(BigInteger.ONE);
        BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger mu = lambda.modInverse(n);

        BigInteger cx2 = g.modPow(x2, nsq).multiply(ProtocolManager.randomBigInt(128).modPow(n, nsq)).mod(nsq);
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

        BigInteger rho = ProtocolManager.randomBigInt(64);
        BigInteger rtilda = ProtocolManager.randomBigInt(128);
        BigInteger c1_prime = rho.multiply(order).add(k1.modInverse(order).multiply(m).mod(order)).mod(rtilda);
        BigInteger c1 = g.modPow(c1_prime, nsq).multiply(ProtocolManager.randomBigInt(128).modPow(n, nsq)).mod(nsq);
        BigInteger v = k1.modInverse(order).multiply(Rx).multiply(x1).mod(order);
        BigInteger c2 = cx2.modPow(v, nsq);
        BigInteger cs1 = c1.multiply(c2).mod(nsq);

        // Host sends cs1 to card
        byte[] signature = pm.sign3(cs1);
        Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
    }
}