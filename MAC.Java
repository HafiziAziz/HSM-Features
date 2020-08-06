package safenet.ptkj.samples.MAC;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.math.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

import au.com.safenet.crypto.provider.SAFENETProvider;
import au.com.safenet.crypto.WrappingKeyStore;
import au.com.safenet.crypto.spec.*;

/**
 * This to get MAC Value follow Paynet Spec
 *
 */
public class MAC
{
    static public Provider provider = null;
    static byte[] iv = new byte[0] ;

    /** simplified use of System.out.println */
    static void println(String s)
    {
        System.out.println(s);
    }

    /**
     * Transform the specified byte into a Hex String form.
     *
     * @param bArray    The byte array to transform.
     * @return        The Hex String.
     */
    public static final String bytesToHexStr(byte[] bArray)
    {
        String lookup = "0123456789abcdef";
        StringBuffer s = new StringBuffer(bArray.length * 2);

        for (int i = 0; i < bArray.length; i++)
        {
            s.append(lookup.charAt((bArray[i] >>> 4) & 0x0f));
            s.append(lookup.charAt(bArray[i] & 0x0f));
        }

        return s.toString();
    }

    /**
     * Transform the specified Hex String into a byte array.
     *
     * @param s        the hex string to convert.
     * @return        The resulting byte array.
     */
    public static final byte[] hexStrToBytes(String    s)
    {
        byte[]    bytes;

        bytes = new byte[s.length() / 2];

        for (int i = 0; i < bytes.length; i++)
        {
            bytes[i] = (byte)Integer.parseInt(
                    s.substring(2 * i, 2 * i + 2), 16);
        }

        return bytes;
    }

    // Encrypt, Symmetric Algorithm
    public static byte[] encrypt(String algorithm, String mode, String padding, SecretKey secretKey, byte[] clearBytes) throws GeneralSecurityException
    {
        // Instantiate Cipher
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, provider.getName());

        // Initialise Cipher
        if (mode.equals("CBC"))
        {
            // If IV not yet set, generate random IV
            if (iv.length == 0)
            {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                iv = cipher.getIV();
            }
            else
            {
                // If IV set, use it
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            }
        }
        else
        {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        // Encrypt and Return Encrypted Bytes
        return cipher.doFinal(clearBytes);
    }

    public static void main(String[] args)
    {

        /*
         * Variable Declaration
         */
        String slotHSM = null;
        String slotPIN = null;   
        String keyName = null; // Local No password // Prod need to use password provided
        String databuffer = null; //  Mac data buffer
        byte[] cipherText = null;
        // String decryptText = null;

        /*
         * examine all the command line arguments
         */
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-slotHSM")) {
                slotHSM = args[++i];             
            } else if (args[i].equalsIgnoreCase("-slotPIN")) {
                slotPIN = args[++i];
            } else if (args[i].equalsIgnoreCase("-keyName")) {
                keyName = args[++i];
            } else if(args[i].equalsIgnoreCase("-databuffer")) {
                databuffer = args[++i];

            } else {
                println("unknown param at i="+i);
            }
        }

        /*
         * validate the arguments
         */
        if (slotHSM == null) {
            System.err.println("Must specify -slotHSM.");
            System.exit(1);
        } else if (databuffer == null) {
            System.err.println("Must specify -databuffer.");
            System.exit(1);
        } else if (keyName == null) {
            System.err.println("Must specify -keyName.");
            System.exit(1);
        }

        try {
       
            /* make sure that we have access to the safenet provider */
            /* SAFENETProvider(<N>) constructor is available. 
             * Default SAFENETProvider() constructor operates with a default slot of 0.
             * <N> := 0 - 63
             * Slot <N> must be created!
             */
            int slot = Integer.parseInt(slotHSM);
            provider = new SAFENETProvider(slot);
            Security.addProvider(provider);

            /* get the safenet keystore - access to the adapter */
            KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", provider.getName());
            if (slotPIN == null) {
                keyStore.load(null, null);
            } else {
                keyStore.load(null, slotPIN.toCharArray());
            }

            SecretKey secretKey = (SecretKey)keyStore.getKey(keyName, null);
            if (secretKey == null) {
                System.err.println("Cannot find secretKey key " + keyName);
                System.exit(1);
            }

            Mac desMac = Mac.getInstance("DESede", provider.getName());
            desMac.init(secretKey);
            byte[] mac = desMac.doFinal(databuffer.getBytes());
            // byte[] mac = desMac.doFinal(databuffer);
            String hexStr2 = bytesToHexStr(mac);

            println(hexStr2);
            System.exit(0);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}