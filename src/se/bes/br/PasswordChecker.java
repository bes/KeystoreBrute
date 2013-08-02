/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package se.bes.br;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author mewer
 */
public class PasswordChecker {
    public static final int HASH_LENGTH = 20;
    private MessageDigest md = null;
    public byte[] bytes = null;
    private byte[] actual = new byte[HASH_LENGTH];
    private static final byte[] MAGIC_STRING;
    static {
        byte[] bucket = null;
        try {
            bucket = "Mighty Aphrodite".getBytes("UTF8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(PasswordChecker.class.getName()).log(Level.SEVERE, null, ex);
        }
        MAGIC_STRING = bucket;
    }
    
    /**
     * Checks if the given password yields a SHA digest matching the one at the
     * end of the keystore stream.  One instance should not have this method run
     * more than once at a time; it reuses one MessageDigest for the instance.
     * Also reuses several arrays in the same way.
     */
    public boolean passwordMatches(InputStream stream, int length, char[] password)
        throws IOException, NoSuchAlgorithmException, CertificateException {
        DataInputStream dis;

        md = getPreKeyedHash(password);
        dis = new DataInputStream(new DigestInputStream(stream, md));

        dis.readFully(bytes);
            
        byte[] computed = md.digest();
        dis.readFully(actual);
        for (int i = 0; i < HASH_LENGTH; i++) {
            if (computed[i] != actual[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * To guard against tampering with the keystore, we append a keyed
     * hash with a bit of whitener.
     */
    private MessageDigest getPreKeyedHash(char[] password)
        throws NoSuchAlgorithmException, UnsupportedEncodingException
    {
        int i, j;

        if (md == null) {
            md = MessageDigest.getInstance("SHA");
        } else {
            md.reset();
        }
        byte[] passwdBytes = new byte[password.length * 2];
        for (i=0, j=0; i<password.length; i++) {
            passwdBytes[j++] = (byte)(password[i] >> 8);
            passwdBytes[j++] = (byte)password[i];
        }
        md.update(passwdBytes);
        md.update(MAGIC_STRING);
        return md;
    }
}