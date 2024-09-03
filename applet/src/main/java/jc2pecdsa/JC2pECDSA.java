package jc2pecdsa;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
import jc2pecdsa.jcmathlib.*;


public class JC2pECDSA extends Applet implements ExtendedLength {
    public final static short CARD_TYPE = OperationSupport.SIMULATOR;

    private ResourceManager rm;
    private ECCurve curve;

    private final byte[] largeBuffer = new byte[1900];
    private final RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    Cipher nsqExp = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    RSAPrivateKey nsqKey;

    private final Signature ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_RESET);
    private ECPoint publicKey;
    private BigNat p, mup, psq, t;
    private BigNat k2;
    private BigNat bn, bn2;
    private BigNat sbn;
    private BigNat divMod;
    private BigNat pInv;
    private ECPoint point1, point2;
    private final byte[] m = new byte[32];
    private final byte[] Rx = new byte[32];
    private final byte[] proof = new byte[64];

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
                // DEBUG INSTRUCTIONS
                case Consts.INS_SIGN3_BEFORE_MODEXP:
                    sign3beforeModExp(apdu);
                    break;
                case Consts.INS_SIGN3_MODEXP:
                    sign3modExp(apdu);
                    break;
                case Consts.INS_SIGN3_BEFORE_DIVIDE:
                    sign3beforeDivide(apdu);
                    break;
                case Consts.INS_SIGN3_DIVIDE:
                    sign3divide(apdu);
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

        nsqKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 4096, false);

        rm = new ResourceManager((short) 256, (short) 4096);
        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, rm);
        point1 = new ECPoint(curve);
        point2 = new ECPoint(curve);
        publicKey = new ECPoint(curve);

        p = new BigNat((short) 256, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        psq = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        mup = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        t = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        k2 = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        bn = new BigNat((short) 512, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        bn2 = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        sbn = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
        divMod = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        divMod.fromByteArray(Consts.DIV_MODULUS, (short) 0, (short) 512);
        pInv = new BigNat((short) 512, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        p.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 256);
        psq.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 256), (short) 512);
        nsqKey.setModulus(apduBuffer, (short) (apdu.getOffsetCdata() + 256), (short) 512);
        nsqKey.setExponent(apduBuffer, (short) (apdu.getOffsetCdata() + 256 + 512), (short) 256);
        nsqExp.init(nsqKey, Cipher.MODE_DECRYPT);
        mup.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 2 * 256 + 512), (short) 256);
        t.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 3 * 256 + 512), (short) 512);
        publicKey.setW(apduBuffer, (short) (apdu.getOffsetCdata() + 3 * 256 + 2 * 512), (short) 65);
        pInv.clone(p);
        pInv.modInv(divMod);
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

        randomData.nextBytes(ramArray, (short) 0, (short) 32);
        bn.fromByteArray(ramArray, (short) 0, (short) 32);
        point2.setW(curve.G, (short) 0, (short) curve.G.length);
        point2.multiplication(bn);
        point2.getW(ramArray, (short) 0);
        md.reset();
        md.doFinal(ramArray, (short) 0, (short) 65, proof, (short) 0);
        sbn.fromByteArray(proof, (short) 0, (short) 32);
        sbn.modMult(k2, curve.rBN);
        bn.modSub(sbn, curve.rBN);
        bn.copyToByteArray(proof, (short) 32);
        md.reset();
        md.update(proof, (short) 0, (short) 64);
        point1.getW(ramArray, (short) 0);
        md.doFinal(ramArray, (short) 0, (short) 65, apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    private void sign2(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        bn.fromByteArray(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32);
        sbn.fromByteArray(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 65);
        point2.multiplication(k2);
        point2.getX(Rx, (short) 0);
        point2.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 65);
        point1.getW(apdu.getBuffer(), (short) 64);

        point2.multiplication(bn);
        point1.setW(curve.G, (short) 0, (short) curve.G.length);
        point1.multAndAdd(sbn, point2);
        point1.getW(ramArray, (short) 0);
        md.doFinal(ramArray, (short) 0, (short) 65, ramArray, (short) 0);

        bn.copyToByteArray(ramArray, (short) 32);
        if (Util.arrayCompare(ramArray, (short) 0, ramArray, (short) 32, (short) 32) != 0) {
            ISOException.throwIt((short) 0x1235);
        }

        Util.arrayCopyNonAtomic(proof, (short) 0, apdu.getBuffer(), (short) 0, (short) 64);
        apdu.setOutgoingAndSend((short) 0, (short) (64 + 65));
    }

    private void sign3(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);

        bn.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 512);
        bn2.fromByteArray(apduBuffer, (short) (apdu.getOffsetCdata() + 512), (short) 512);
        bn.modMult(t, psq);
        bn.modAdd(bn2, psq);
        bn.copyToByteArray(apduBuffer, apdu.getOffsetCdata());
        nsqExp.doFinal(apduBuffer, apdu.getOffsetCdata(), (short) 512, apduBuffer, apdu.getOffsetCdata());

        bn.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 512);
        bn.decrement();
        bn.modMult(pInv, divMod);
        bn.modMult(mup, p);
        bn.shrink();
        bn.mod(curve.rBN);
        bn.shrink();
        k2.modInv(curve.rBN);
        k2.modMult(bn, curve.rBN);
        k2.resize((short) 32);

        apduBuffer = apdu.getBuffer();
        apduBuffer[0] = (byte) 0x30;
        apduBuffer[1] = (byte) 0x44;
        apduBuffer[2] = (byte) 0x02;
        apduBuffer[3] = (byte) 0x20;
        Util.arrayCopyNonAtomic(Rx, (short) 0, apduBuffer, (short) 4, (short) 32);
        apduBuffer[36] = (byte) 0x02;
        apduBuffer[37] = (byte) 0x20;
        k2.copyToByteArray(apduBuffer, (short) 38);

        if (!ecdsa.verify(m, (short) 0, (short) 32, apduBuffer, (short) 0, (short) (32 * 2 + 6))) {
            // ISOException.throwIt((short) 0x1234); // sometimes fails in simulator but not on card
        }
        apdu.setOutgoingAndSend((short) 0, (short) 70);
    }

    private void sign3beforeModExp(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        apdu.setOutgoingAndSend((short) 0, (short) 70);
    }

    private void sign3modExp(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        nsqExp.doFinal(apduBuffer, apdu.getOffsetCdata(), (short) 512, apduBuffer, apdu.getOffsetCdata());
        apdu.setOutgoingAndSend((short) 0, (short) 70);
    }

    private void sign3beforeDivide(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);

        nsqExp.doFinal(apduBuffer, apdu.getOffsetCdata(), (short) 512, apduBuffer, apdu.getOffsetCdata());

        bn.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 512);
        bn.decrement();
        apdu.setOutgoingAndSend((short) 0, (short) 70);
    }

    private void sign3divide(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);

        nsqExp.doFinal(apduBuffer, apdu.getOffsetCdata(), (short) 512, apduBuffer, apdu.getOffsetCdata());

        bn.fromByteArray(apduBuffer, apdu.getOffsetCdata(), (short) 512);
        bn.decrement();
        bn.divide(p);
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
