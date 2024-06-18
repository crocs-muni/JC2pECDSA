package jc2pecdsa;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import jc2pecdsa.jcmathlib.*;


public class JC2pECDSA extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;

    private final byte[] largeBuffer = new byte[2048];
    private BigNat n, nsq, lambda, mu;

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

        rm = new ResourceManager((short) 256);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);

        n = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        nsq = new BigNat((short) 256, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        lambda = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        mu = new BigNat((short) 128, JCSystem.MEMORY_TYPE_PERSISTENT, rm);

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        n.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 128);
        nsq.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 128), (short) 256);
        lambda.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 128 + 256), (short) 128);
        mu.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 2 * 128 + 256), (short) 128);
        apdu.setOutgoing();
    }

    private void sign1(APDU apdu) {
        apdu.setOutgoing();
    }

    private void sign2(APDU apdu) {
        apdu.setOutgoing();
    }
    private void sign3(APDU apdu) {
        apdu.setOutgoing();
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
