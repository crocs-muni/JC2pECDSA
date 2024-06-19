package jc2pecdsa;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import jc2pecdsa.jcmathlib.*;


public class JC2pECDSA extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;

    private final byte[] largeBuffer = new byte[1024];
    private final RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    private final Signature ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
    private ECPoint publicKey;
    private BigNat n, nsq, lambda, mu;
    private BigNat k2;
    private BigNat bn;
    private ECPoint point1, point2;
    private final byte[] m = new byte[32];

    private boolean initialized = false;
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JC2pECDSA(bArray, bOffset, bLength);
    }

    public JC2pECDSA(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_JC2PECDSA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        if (!initialized)
            initialize();

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_SETUP:
                    setup(apdu);
                    break;
                case Consts.INS_SIGN1:
                    sign1(apdu);
                    break;
                case Consts.INS_SIGN2:
                    sign2(apdu);
                    break;
                case Consts.INS_SIGN3:
                    sign3(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select() {
        if (initialized)
            curve.updateAfterReset();
        return true;
    }

    public void deselect() {}

    private void initialize() {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        rm = new ResourceManager((short) 256, (short) 2048);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);
        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        publicKey = new ECPoint(curve);

        n = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        nsq = new BigNat((short) 256, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        lambda = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        mu = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        k2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        bn = new BigNat((short) 256, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        n.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 128);
        nsq.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 128), (short) 256);
        lambda.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 128 + 256), (short) 128);
        mu.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 2 * 128 + 256), (short) 128);
        publicKey.setW(apduBuffer, (short) (apdu.getOffsetCdata() + 3 * 128 + 256), (short) 65);
        ecdsa.init(publicKey.asPublicKey(), Signature.MODE_VERIFY);
        apdu.setOutgoing();
    }

    private void sign1(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), m, (short) 0, (short) 32);
        randomData.nextBytes(ramArray, (short) 0, (short) 32);
        k2.fromByteArray(ramArray, (short) 0, (short) 32);
        point1.setW(curve.G, (short) 0, (short) curve.G.length);
        point1.multiplication(k2);

        // TODO compute pi2
        // TODO commit to pi2 || R2
        apdu.setOutgoing();
    }

    private void sign2(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 65);
        point2.multiplication(k2);
        apdu.setOutgoingAndSend((short) 0, point1.getW(apdu.getBuffer(), (short) 0));
    }
    private void sign3(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        bn.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 256);

        bn.modExp(lambda, nsq);
        bn.decrement();
        bn.divide(n);
        bn.modMult(mu, n);
        bn.shrink();
        bn.mod(curve.rBN);
        k2.modInv(curve.rBN);
        k2.modMult(bn, curve.rBN);

        apduBuffer = apdu.getBuffer();
        apduBuffer[0] = (byte) 0x30;
        apduBuffer[1] = (byte) 0x44;
        apduBuffer[2] = (byte) 0x02;
        apduBuffer[3] = (byte) 0x20;
        point2.getX(apduBuffer, (short) 4);
        apduBuffer[36] = (byte) 0x02;
        apduBuffer[37] = (byte) 0x20;
        k2.copyToByteArray(apduBuffer, (short) 38);

        if (!ecdsa.verify(m, (short) 0, (short) 32, apduBuffer, (short) 0, (short) (32 * 2 + 6))) {
            // ISOException.throwIt((short) 0x1234); // sometimes fails in simulator but not on card
        }
        apdu.setOutgoingAndSend((short) 0, (short) 70);
    }

    private byte[] loadApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = (short) (apdu.setIncomingAndReceive() + apdu.getOffsetCdata());
        if (apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA) {
            return apduBuffer;
        }
        short written = 0;
        while (recvLen > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, largeBuffer, written, recvLen);
            written += recvLen;
            recvLen = apdu.receiveBytes((short) 0);
        }
        return largeBuffer;
    }
}
