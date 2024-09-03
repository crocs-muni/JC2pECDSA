package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

import java.io.FileWriter;
import java.io.PrintWriter;
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
        PrintWriter file = new PrintWriter(new FileWriter("sign.csv", false));

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ProtocolManager pm = new ProtocolManager(connect());

        BigInteger order = ProtocolManager.G.getCurve().getOrder();
        BigInteger m = ProtocolManager.hash(new byte[32]);

        BigInteger x1 = ProtocolManager.randomBigInt(32);
        BigInteger x2 = ProtocolManager.randomBigInt(32);
        ECPoint X = ProtocolManager.G.multiply(x1).multiply(x2);

        BigInteger p = new BigInteger(1, new byte[]{(byte)0xf6, (byte)0x57, (byte)0x57, (byte)0xe1, (byte)0x5d, (byte)0x4d, (byte)0x5d, (byte)0xcb, (byte)0xdd, (byte)0x6a, (byte)0x13, (byte)0x4a, (byte)0xe4, (byte)0x18, (byte)0xb7, (byte)0x7e, (byte)0x00, (byte)0x59, (byte)0x03, (byte)0xdc, (byte)0x33, (byte)0xbf, (byte)0x91, (byte)0x85, (byte)0xbf, (byte)0x24, (byte)0x6c, (byte)0x88, (byte)0x84, (byte)0x4f, (byte)0xd1, (byte)0x80, (byte)0xa2, (byte)0x6b, (byte)0xb9, (byte)0x1a, (byte)0x68, (byte)0x94, (byte)0xfb, (byte)0xa5, (byte)0x6e, (byte)0xed, (byte)0x99, (byte)0x55, (byte)0x61, (byte)0xd8, (byte)0xae, (byte)0xd6, (byte)0x59, (byte)0x66, (byte)0xd0, (byte)0xfc, (byte)0x2e, (byte)0x29, (byte)0xdd, (byte)0x60, (byte)0xe5, (byte)0xd8, (byte)0xd4, (byte)0xb4, (byte)0x12, (byte)0x95, (byte)0x44, (byte)0x48, (byte)0x36, (byte)0xb3, (byte)0x73, (byte)0xb1, (byte)0xa1, (byte)0x2d, (byte)0xf6, (byte)0x64, (byte)0x34, (byte)0xa5, (byte)0x67, (byte)0x02, (byte)0x29, (byte)0xc9, (byte)0x96, (byte)0x12, (byte)0xff, (byte)0xc5, (byte)0xb6, (byte)0xd2, (byte)0xd9, (byte)0x82, (byte)0xf3, (byte)0xcd, (byte)0xdd, (byte)0xa5, (byte)0xca, (byte)0x69, (byte)0xff, (byte)0xd1, (byte)0x77, (byte)0xe4, (byte)0x2a, (byte)0x12, (byte)0xfe, (byte)0x2a, (byte)0x74, (byte)0x93, (byte)0xca, (byte)0xcf, (byte)0xe4, (byte)0x49, (byte)0xec, (byte)0x0a, (byte)0x43, (byte)0x1b, (byte)0x23, (byte)0x4e, (byte)0x86, (byte)0x42, (byte)0xca, (byte)0x16, (byte)0x11, (byte)0x53, (byte)0xcb, (byte)0x4b, (byte)0x15, (byte)0x2f, (byte)0x19, (byte)0xa2, (byte)0x90, (byte)0x4b, (byte)0xf2, (byte)0xba, (byte)0xe9, (byte)0x59, (byte)0x4e, (byte)0x7e, (byte)0xdf, (byte)0xa2, (byte)0xc0, (byte)0x9b, (byte)0xd7, (byte)0x3f, (byte)0x5a, (byte)0x51, (byte)0xf8, (byte)0x0a, (byte)0x98, (byte)0xc2, (byte)0xaf, (byte)0x1a, (byte)0x2f, (byte)0x38, (byte)0xda, (byte)0x31, (byte)0x0e, (byte)0x36, (byte)0x37, (byte)0x13, (byte)0x3c, (byte)0x1c, (byte)0x12, (byte)0xd2, (byte)0xa0, (byte)0x31, (byte)0x66, (byte)0xa7, (byte)0xd1, (byte)0xed, (byte)0x87, (byte)0xb3, (byte)0x0c, (byte)0xc8, (byte)0xc1, (byte)0x04, (byte)0x1e, (byte)0x52, (byte)0x9c, (byte)0x57, (byte)0xe8, (byte)0x46, (byte)0x88, (byte)0x45, (byte)0x67, (byte)0xe7, (byte)0xe4, (byte)0x7b, (byte)0x7b, (byte)0x3c, (byte)0xd5, (byte)0x46, (byte)0xe6, (byte)0x85, (byte)0x45, (byte)0x87, (byte)0xa4, (byte)0xaa, (byte)0xa0, (byte)0x31, (byte)0x82, (byte)0x6b, (byte)0x5f, (byte)0xbd, (byte)0x62, (byte)0x6e, (byte)0xfa, (byte)0xe8, (byte)0x63, (byte)0x92, (byte)0x92, (byte)0xfd, (byte)0x20, (byte)0x59, (byte)0xc3, (byte)0xf7, (byte)0xd3, (byte)0x03, (byte)0xd9, (byte)0x36, (byte)0x77, (byte)0x50, (byte)0xa3, (byte)0xeb, (byte)0xbf, (byte)0x60, (byte)0xbc, (byte)0xba, (byte)0xcc, (byte)0x1b, (byte)0x96, (byte)0x8e, (byte)0xca, (byte)0x93, (byte)0x60, (byte)0x0c, (byte)0xd4, (byte)0x2c, (byte)0x6d, (byte)0xe7, (byte)0x99, (byte)0x71, (byte)0x2d, (byte)0xd6, (byte)0x04, (byte)0x20, (byte)0x9e, (byte)0x60, (byte)0x46, (byte)0x0b, (byte)0x8b, (byte)0xa8, (byte)0x46, (byte)0xdf, (byte)0x1b, (byte)0x8d, (byte)0x14, (byte)0x55, (byte)0x37, (byte)0x34, (byte)0x7c, (byte)0x39});
        BigInteger q = new BigInteger(1, new byte[]{(byte)0x9f, (byte)0x81, (byte)0xda, (byte)0xc8, (byte)0xf7, (byte)0x2a, (byte)0xe6, (byte)0x4c, (byte)0xdf, (byte)0x7f, (byte)0x6f, (byte)0x9a, (byte)0xc5, (byte)0x93, (byte)0xb5, (byte)0x97, (byte)0xf5, (byte)0xac, (byte)0xde, (byte)0x7e, (byte)0xcd, (byte)0x07, (byte)0x7d, (byte)0x42, (byte)0x0f, (byte)0x9d, (byte)0x90, (byte)0x8e, (byte)0x69, (byte)0x17, (byte)0xc0, (byte)0x28, (byte)0x66, (byte)0x6c, (byte)0x33, (byte)0x08, (byte)0xcb, (byte)0x68, (byte)0x5f, (byte)0x3e, (byte)0x06, (byte)0xff, (byte)0xec, (byte)0x10, (byte)0x64, (byte)0x8a, (byte)0xc2, (byte)0x3f, (byte)0xc5, (byte)0x0d, (byte)0x67, (byte)0x8d, (byte)0x09, (byte)0x68, (byte)0x98, (byte)0x68, (byte)0x3b, (byte)0x8c, (byte)0xf6, (byte)0x17, (byte)0x72, (byte)0xea, (byte)0xa5, (byte)0xa5, (byte)0x47, (byte)0xbe, (byte)0xd3, (byte)0x70, (byte)0x28, (byte)0x7f, (byte)0xcf, (byte)0x05, (byte)0xc7, (byte)0x81, (byte)0x2d, (byte)0x30, (byte)0x33, (byte)0xd8, (byte)0xa4, (byte)0xe9, (byte)0x3e, (byte)0x2e, (byte)0xe7, (byte)0x59, (byte)0xf9, (byte)0x14, (byte)0x7f, (byte)0x08, (byte)0x84, (byte)0x57, (byte)0xc0, (byte)0x07, (byte)0x2a, (byte)0xf9, (byte)0xf9, (byte)0x9a, (byte)0xfa, (byte)0x2d, (byte)0xcd, (byte)0xa6, (byte)0xe2, (byte)0x57, (byte)0x94, (byte)0xd4, (byte)0xb9, (byte)0x89, (byte)0x8c, (byte)0x88, (byte)0x90, (byte)0xb1, (byte)0xe1, (byte)0x93, (byte)0x5f, (byte)0x8d, (byte)0x9c, (byte)0x94, (byte)0x25, (byte)0x22, (byte)0x75, (byte)0xc7, (byte)0x46, (byte)0x68, (byte)0xf3, (byte)0x64, (byte)0x77, (byte)0xed, (byte)0xc1, (byte)0x98, (byte)0x78, (byte)0x5a, (byte)0xd8, (byte)0x61, (byte)0xa0, (byte)0xc8, (byte)0x27, (byte)0x8e, (byte)0xf9, (byte)0xa1, (byte)0x67, (byte)0xb3, (byte)0xaa, (byte)0x7f, (byte)0xbc, (byte)0x8e, (byte)0xb4, (byte)0x53, (byte)0x1d, (byte)0x6b, (byte)0x61, (byte)0xad, (byte)0x72, (byte)0xa8, (byte)0xab, (byte)0xc9, (byte)0xab, (byte)0xad, (byte)0x9b, (byte)0xa2, (byte)0x8f, (byte)0x5e, (byte)0x9c, (byte)0x90, (byte)0x48, (byte)0xe4, (byte)0x7c, (byte)0x99, (byte)0x89, (byte)0x5f, (byte)0xc9, (byte)0xc2, (byte)0x4f, (byte)0x9b, (byte)0x7e, (byte)0xa0, (byte)0x41, (byte)0x3f, (byte)0x3e, (byte)0x32, (byte)0xc4, (byte)0x54, (byte)0xda, (byte)0xbb, (byte)0xcd, (byte)0x0f, (byte)0x5e, (byte)0x88, (byte)0x24, (byte)0xef, (byte)0xe7, (byte)0xc7, (byte)0xbc, (byte)0x03, (byte)0xc5, (byte)0xa0, (byte)0x32, (byte)0x52, (byte)0x69, (byte)0x32, (byte)0x27, (byte)0xa6, (byte)0xe4, (byte)0x56, (byte)0xd0, (byte)0x03, (byte)0x4e, (byte)0x89, (byte)0xb7, (byte)0x20, (byte)0x8d, (byte)0xac, (byte)0x8d, (byte)0x99, (byte)0xc6, (byte)0x5c, (byte)0x6f, (byte)0xa0, (byte)0x80, (byte)0xa0, (byte)0x4c, (byte)0xf1, (byte)0xaa, (byte)0xdf, (byte)0x31, (byte)0x00, (byte)0x25, (byte)0x94, (byte)0xef, (byte)0x80, (byte)0x20, (byte)0x30, (byte)0xac, (byte)0xd5, (byte)0x6f, (byte)0xe6, (byte)0xd7, (byte)0xb9, (byte)0x01, (byte)0xc6, (byte)0x43, (byte)0x10, (byte)0x51, (byte)0x34, (byte)0xaa, (byte)0x9a, (byte)0x6d, (byte)0xac, (byte)0x4e, (byte)0xbd, (byte)0xc1, (byte)0xeb, (byte)0x0c, (byte)0x27, (byte)0x09, (byte)0x28, (byte)0x35, (byte)0xb3});
        BigInteger n = p.multiply(q);
        BigInteger nsq = n.multiply(n);
        BigInteger g = n.add(BigInteger.ONE);
        BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger mu = lambda.modInverse(n);
        BigInteger t = BigInteger.valueOf(2).pow(4096).mod(p.pow(2));

        BigInteger cx2 = g.modPow(x2, nsq).multiply(ProtocolManager.randomBigInt(256).modPow(n, nsq)).mod(nsq);
        BigInteger pt = cx2.modPow(lambda, n.multiply(n)).subtract(BigInteger.ONE).divide(n).multiply(mu).mod(n);
        assert pt.equals(x2);

        BigInteger lambdap = p.subtract(BigInteger.ONE);
        BigInteger mup = g.modPow(lambdap, p.pow(2)).subtract(BigInteger.ONE).divide(p).modInverse(p);

        pm.setup(p, p.pow(2), lambdap, mup, t, X);

        for(int i = 0; i < 100; ++i) {
            // Host sends m to card
            byte[] comm = pm.sign1(new byte[32]);
            file.printf("%d,", pm.cm.getLastTransmitTime());

            // Card sends commitment to host
            BigInteger k1 = ProtocolManager.randomBigInt(32);
            ECPoint R1 = ProtocolManager.G.multiply(k1);

            // Host sends pi1, R1 to card
            BigInteger proof1r = ProtocolManager.randomBigInt(32);
            ECPoint proof1R = ProtocolManager.G.multiply(proof1r);
            BigInteger proof1e = ProtocolManager.hash(proof1R.getEncoded(false));
            BigInteger proof1s = proof1r.subtract(proof1e.multiply(k1)).mod(order);

            byte[] resp = pm.sign2(proof1e, proof1s, R1);
            file.printf("%d,", pm.cm.getLastTransmitTime());
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
            BigInteger rtilda = ProtocolManager.randomBigInt(256);
            BigInteger c1_prime = rho.multiply(order).add(k1.modInverse(order).multiply(m).mod(order)).mod(rtilda);
            BigInteger c1 = g.modPow(c1_prime, nsq).multiply(ProtocolManager.randomBigInt(256).modPow(n, nsq)).mod(nsq);
            BigInteger v = k1.modInverse(order).multiply(Rx).multiply(x1).mod(order);
            BigInteger c2 = cx2.modPow(v, nsq);
            BigInteger cs1 = c1.multiply(c2).mod(nsq);

            // Host sends cs1 to card
            byte[] signature = pm.sign3(cs1);
            file.printf("%d\n", pm.cm.getLastTransmitTime());
            Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
        }

        file.close();
    }
}