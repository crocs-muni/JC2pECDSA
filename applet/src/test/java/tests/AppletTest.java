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
        BigInteger q = ProtocolManager.G.getCurve().getOrder();

        // ProtocolManager pm = new ProtocolManager(connect());
        // byte[] signature = ProtocolManager.rawToDer(Rx, s);
        // Assertions.assertTrue(ProtocolManager.verifySignature(X, new byte[32], signature));
    }
}
