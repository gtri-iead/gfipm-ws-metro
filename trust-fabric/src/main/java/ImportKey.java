
import java.io.*;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
/**
 * ImportKey.java
 *
 * <p>This class imports a key and a certificate into a keystore
 * (<code>$home/keystore.ImportKey</code>). If the keystore is
 * already present, it is simply deleted. Both the key and the
 * certificate file must be in <code>DER</code>-format. The key must be
 * encoded with <code>PKCS#8</code>-format. The certificate must be
 * encoded in <code>X.509</code>-format.</p>
 *
 * <p>Key format:</p>
 * <p><code>openssl pkcs8 -topk8 -nocrypt -in YOUR.KEY -out YOUR.KEY.der
 * -outform der</code></p>
 * <p>Format of the certificate:</p>
 * <p><code>openssl x509 -in YOUR.CERT -out YOUR.CERT.der -outform
 * der</code></p>
 * <p>Import key and certificate:</p>
 * <p><code>java comu.ImportKey YOUR.KEY.der YOUR.CERT.der</code></p><br />
 *
 * <p><em>Caution:</em> the old <code>keystore.ImportKey</code>-file is
 * deleted and replaced with a keystore only containing <code>YOUR.KEY</code>
 * and <code>YOUR.CERT</code>. The keystore and the key has no password; 
 * they can be set by the <code>keytool -keypasswd</code>-command for setting
 * the key password, and the <code>keytool -storepasswd</code>-command to set
 * the keystore password.
 * <p>The key and the certificate is stored under the alias
 * <code>importkey</code>; to change this, use <code>keytool -keyclone</code>.
 *
 * Created: Fri Apr 13 18:15:07 2001
 * Updated: Fri Apr 19 11:03:00 2002
 *
 * @author Joachim Karrer, Jens Carlberg
 * @version 1.1
 **/
public class ImportKey  {
    
    /**
     * <p>Creates an InputStream from a file, and fills it with the complete
     * file. Thus, available() on the returned InputStream will return the
     * full number of bytes the file contains</p>
     * @param fname The filename
     * @return The filled InputStream
     * @exception IOException, if the Streams couldn't be created.
     **/
    private static InputStream fullStream ( String fname ) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }

private static String readFileAsString(String filePath) throws IOException{
    byte[] buffer = new byte[(int) new File(filePath).length()];
    BufferedInputStream f = null;
    try {
        f = new BufferedInputStream(new FileInputStream(filePath));
        f.read(buffer);
    } finally {
        if (f != null) try { f.close(); } catch (IOException ignored) { }
    }
    return new String(buffer);
}
    
        
    /**
     * <p>Takes two file names for a key and the certificate for the key, 
     * and imports those into a keystore. Optionally it takes an alias
     * for the key.
     * <p>The first argument is the filename for the key. The key should be
     * in PKCS8-format.
     * <p>The second argument is the filename for the certificate for the key.
     * <p>If a third argument is given it is used as the alias. If missing,
     * the key is imported with the alias importkey
     * <p>The name of the keystore file can be controlled by setting
     * the keystore property (java -Dkeystore=mykeystore). If no name
     * is given, the file is named <code>keystore.ImportKey</code>
     * and placed in your home directory.
     * @param args [0] Name of the key file, [1] Name of the certificate file
     * [2] Alias for the key.
     **/
    public static void main ( String args[]) {
        
        // change this if you want another password by default
        String keypass = "changeit";
        // change this if you want another alias by default
        String alias = null; 
        // change this if you want another keystorefile by default
        String keystorename = null;
        // parsing command line input
        String keyfile = null;
        String certfile = null;

        if (args.length != 4) {
            System.out.println("Usage: java ImportKey keyfile certfile alias keystorename");
            System.exit(0);
        } else {
            keyfile = args[0];
            certfile = args[1];
	    alias = args[2];
	    keystorename = args[3];
        }

        try {
            // initializing and clearing keystore 
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load( null , keypass.toCharArray());
            System.out.println("Using keystore-file : "+keystorename);
            ks.store(new FileOutputStream ( keystorename  ),
                    keypass.toCharArray());
            ks.load(new FileInputStream ( keystorename ),
                    keypass.toCharArray());

            // loading Private Key
            InputStream fl = fullStream (keyfile);
            byte[] key = new byte[fl.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            fl.read ( key, 0, fl.available() );
            fl.close();
            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec ( key );
            PrivateKey ff = kf.generatePrivate (keysp);
	    /*
	    String pemPrivateKeyString = readFileAsString(keyfile);
	    pemPrivateKeyString = pemPrivateKeyString.replace("-----BEGIN RSA PRIVATE KEY-----\n","");
	    pemPrivateKeyString = pemPrivateKeyString.replace("-----END RSA PRIVATE KEY-----","");
	    System.out.println("Private KEY: " + pemPrivateKeyString);
	    byte[] encodedPrivateKey = javax.xml.bind.DatatypeConverter.parseBase64Binary(pemPrivateKeyString);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec (encodedPrivateKey);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    PrivateKey ff = kf.generatePrivate(keySpec);
	    */

            // loading CertificateChain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certstream = fullStream (certfile);

            Collection c = cf.generateCertificates(certstream) ;
            Certificate[] certs = new Certificate[c.toArray().length];

            if (c.size() == 1) {
                certstream = fullStream (certfile);
                System.out.println("One certificate, no chain.");
                Certificate cert = cf.generateCertificate(certstream) ;
                certs[0] = cert;
            } else {
                System.out.println("Certificate chain length: "+c.size());
                certs = (Certificate[])c.toArray();
            }

            // storing keystore
            ks.setKeyEntry(alias, ff, 
                           keypass.toCharArray(),
                           certs );
            System.out.println ("Key and certificate stored.");
            System.out.println ("Alias:"+alias+"  Password:"+keypass);
            ks.store(new FileOutputStream ( keystorename ),
                     keypass.toCharArray());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}// KeyStore
