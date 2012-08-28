/*
 * Copyright (c) 2012, Georgia Institute of Technology. All Rights Reserved.
 * This code was developed by Georgia Tech Research Institute (GTRI) under
 * a grant from the U.S. Dept. of Justice, Bureau of Justice Assistance.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.gfipm.trustfabric;

//import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import javax.xml.bind.DatatypeConverter;

/**
 * Class to manipulate a Java key store, such as adding or deleting certificates
 * in the key store, printing out the contents, or writing certificates to files
 * on disk. <p> This class is designed to interact with the certificates in the
 * GFIPM trust fabric document (class TrustFabric) for purposes of GFIPM Web
 * Services. <p> A command line program is available through the class
 * GFIPMTrust.
 *
 * @author Stefan Roth
 */
public class GFIPMKeystore {

    private String keyStoreFilename = "/home/gfipm/test/Tcacerts";
    private boolean keepEntityIdAsAlias = false;
    private KeyStore keyStore = null;
    // All Java key store entries will use this prefix for the alias name:
    // (must be all lower case)
    private String aliasPrefix = "gfipmcert";
    // The key store password:
    private char[] kspw = null;
    private boolean verboseOut = false;
    private boolean debugOut = false;
    // Indicates if key store has been modified (i.e., add, delete entry) since
    // it was loaded:
    private boolean modifiedFlag = false;

    // ======================================================================
    /**
     * Constructor to instantiate the GFIPMKeystore class to access and modify
     * the Java key store for the GFIPM web services.
     *
     */
    public GFIPMKeystore() {

        int ind = 17, i2 = 351, incr = 3;
        kspw = "&\ta%g^i\n".toCharArray();
        kspw[ind - (4 * 4)] = 'h';
        kspw[kspw.length - ind + 16] = 't';
        kspw[kspw.length - 3] = 'e';
        ind = ind + incr;
        kspw[0] = 'c';
        kspw[kspw.length - (ind - 15)] = 'n';
        kspw[incr] = 'n';
        ind = i2;
    }

    // ======================================================================
    public boolean setVerboseOut(boolean val) {
        verboseOut = val;

        return verboseOut;
    }

    // ======================================================================
    public boolean setDebugOut(boolean val) {
        debugOut = val;
        if (debugOut) {
            setVerboseOut(true);
        }

        return debugOut;
    }

    // ======================================================================
    public String getAliasPrefix() {
        return aliasPrefix;
    }

    // ======================================================================
    /**
     * Sets the aliasPrefix, which is used to preface the alias names used to
     * store certificates in the Java key store. The aliasPrefix is later used
     * to identify the aliases that were added to the key store with the methods
     * of this class. It is best to leave the default as is, unless another
     * value is always used in the future.
     *
     * @param aliasPrefix Sets the preface string for key store alias names.
     *
     */
    public void setAliasPrefix(String aliasPrefix) {
        this.aliasPrefix = aliasPrefix;
    }

    // ======================================================================
    /**
     * Sets the key store password. If not set, the original default is used,
     * which will work if it was not changed after the Java installation.
     *
     * @param kspw The new key store password as a character array.
     *
     */
    public void setKspw(char[] kspw) {
        this.kspw = kspw;
    }

    // ======================================================================
    /**
     * Sets the instance variable keyStoreFilename. Setting it to null does not
     * have any effect.
     *
     * @param val New value for keyStoreFilename. If val is null, there is no
     * effect.
     *
     * @return new value of keyStoreFilename.
     *
     */
    public String setKeyStoreFilename(String val) {
        if (val != null) {
            keyStoreFilename = val;
        }
        return keyStoreFilename;
    }

    // ======================================================================
    /**
     * Gets the currently used Java key store file name.
     *
     * @return a string with the currently used Java key store file name.
     *
     */
    public String getKeyStoreFilename() {

        return keyStoreFilename;
    }

    // ======================================================================
    /**
     * Checks if a Java key store is loaded into this instance, ready for
     * manipulation.
     *
     * @return true if a key store is loaded; false otherwise
     *
     */
    public boolean isKeyStoreLoaded() {
        if (keyStore == null) {
            return false;
        } else {
            return true;
        }
    }

    // ======================================================================
    /**
     * Checks if the loaded Java key store has been modified since it was loaded
     * within the context of this instance of this running program.
     *
     * @return true if a key store is modified; false otherwise
     *
     */
    public boolean isKeyStoreModified() {
        return modifiedFlag;

    }

    // ======================================================================
    /**
     * Loads the Java key store from disk into the internal class object for
     * further manipulation. Writes error messages on failure.
     *
     * @return Returns true if the loading was successful; false otherwise.
     *
     */
    public boolean loadKeyStore() {

        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            modifiedFlag = false;

            if (verboseOut) {
                System.out.println("Load key store from file " + keyStoreFilename);
                System.out.flush();
            }

            try {
                FileInputStream fis = new FileInputStream(keyStoreFilename);
                keyStore.load(fis, kspw);
                fis.close();
            } catch (FileNotFoundException fex) {                
                keyStore.load(null, kspw);
                if (verboseOut) {
                    System.out.println("File does not exist, creating new keystore-file : " + keyStoreFilename);
                }
                keyStore.store(new FileOutputStream(keyStoreFilename), kspw);
                keyStore.load(new FileInputStream(keyStoreFilename), kspw);
            }

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.loadKeyStore failed: ");
            System.err.println(e.toString());
            System.err.flush();
            keyStore = null;
            modifiedFlag = false;
            return false;
        }

        return true;
    }  // end loadKeyStore

    // ======================================================================
    /**
     * Stores the Java key store to disk from the internal class object. Will
     * not perform the write operation if the key store was not modified. Writes
     * error messages on failure.
     *
     * @return Returns true if the storing was successful; false otherwise.
     *
     */
    public boolean storeKeyStore() {

        if (keyStore == null) {
            System.err.println("WARNING: GFIPMKeystore.storeKeyStore: key store is null. Nothing to save.");
            System.err.flush();
            return false;
        }

        if (!modifiedFlag) {
            if (verboseOut) {
                System.out.println("INFO: GFIPMKeystore.storeKeyStore: Key store was not modified. Not saved.");
            }
            return false;
        }

        try {
            FileOutputStream fos = new FileOutputStream(keyStoreFilename);
            if (verboseOut) {
                System.out.println("Saving keystore to file " + keyStoreFilename);
                System.out.flush();
            }

            keyStore.store(fos, kspw);

            modifiedFlag = false;
            fos.close();

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.storeKeyStore failed to file: " + keyStoreFilename);
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;
    }  // end storeKeyStore

    // ======================================================================
    /**
     * Takes a GFIPM entity ID (as found in the GFIPM trust document) and builds
     * a name suitable as a key store alias name, including adding a
     * GFIPM-specific prefix so that it is identifiable as a GFIPM entity at a
     * later time. A non-null entitytype is appended after a "0". A non-null
     * keyuse is appended after a "4".
     *
     * @param entityid A GFIPM entity ID as found in the GFIPM trust document.
     *
     * @param entitytype A GFIPM entity type such as "IDP" or "SP". Null means
     * no type.
     *
     * @param keyuse A key descriptor use from the trust document such as
     * "signing" or "encryption". Null means none.
     *
     * @return a Java key store alias name built from the entity ID
     */
    private String makeEntityAliasName(String entityid, String entitytype, String keyuse) {        
        if (entityid == null) {
            System.err.println("ERROR: GFIPMKeystore.makeEntityAliasName: entity id is null. Aborted.");
            System.err.flush();
            return null;
        }
        int len = entityid.length();
        if (len == 0) {
            System.err.println("ERROR: GFIPMKeystore.makeEntityAliasName: entity id is empty. Aborted.");
            System.err.flush();
            return null;
        }
        if(keepEntityIdAsAlias) return entityid;

        StringBuilder result = new StringBuilder();
        char ch;
        if (!entityid.startsWith(aliasPrefix)) {
            result.append(aliasPrefix);
        }

        for (int i = 0; i < len; i++) {
            ch = entityid.charAt(i);
            if (((ch >= 'a') && (ch <= 'z'))
                    || ((ch >= '0') && (ch <= '9'))) // add a lower-case letter or digit:
            {
                result.append(ch);
            } else if ((ch >= 'A') && (ch <= 'Z')) // add a lower-case letter instead of upper-case:
            {
                result.append(ch - 'A' + 'a');
            }
        }  // end for

        if ((entitytype != null) && (entitytype.length() != 0)) {
            result.append("0");
            result.append(entitytype.toLowerCase(Locale.ENGLISH));
        }

        if ((keyuse != null) && (keyuse.length() != 0)) {
            result.append("4");
            result.append(keyuse.toLowerCase(Locale.ENGLISH));
        }

        return result.toString();

    }  // end makeEntityAliasName

    // ======================================================================
    /**
     * Takes a GFIPM entity ID (as found in the GFIPM trust document) and builds
     * a name suitable as a key store alias name,including adding a
     * GFIPM-specific prefix so that it is identifiable as a GFIPM entity at a
     * later time.
     *
     * @param entityid A GFIPM entity ID as found in the GFIPM trust document.
     *
     * @return a Java key store alias name built from the entity ID
     */
    private String makeEntityAliasName(String entityid) {

        return makeEntityAliasName(entityid, null, null);

    }  // end makeEntityAliasName

    // ======================================================================
    /**
     * Takes a GFIPMCertificate and builds a name suitable as a key store alias
     * name, including adding a GFIPM-specific prefix so that it is identifiable
     * as a GFIPM entity at a later time.
     *
     * @param cert A GFIPMCertificate from which the entity ID, type and key use
     * is taken.
     *
     * @return a Java key store alias name built from the certificate
     *
     */
    private String makeEntityAliasName(GFIPMCertificate cert) {

        return makeEntityAliasName(cert.getEntityID(), cert.getEntityType(), cert.getKeyUse());

    }  // end makeEntityAliasName

    // ======================================================================
    /** 
     * Configures whether to keep an EntityId as an alias in the keystore.
     * @param keepEntityIdAsAlias true if EntityId will be used as an alias in the keystore.
     */
    public void setKeepEntityIdAsAlias(boolean keepEntityIdAsAlias) {
        this.keepEntityIdAsAlias = keepEntityIdAsAlias;
    }
    
    // ======================================================================
    /**
     * Takes a GFIPM entity ID or a Java key store entry alias name and deletes
     * its entry from the Java key store. Writes out an error messages on an
     * exception.
     *
     * @param entityid The GFIPM entity or key store alias to be deleted.
     *
     * @return true on success, false otherwise.
     */
    public boolean deleteEntry(String entityid) {

        if (entityid == null) {
            System.err.println("ERROR: GFIPMKeystore.deleteEntry: No entityid or alias name. Aborted.");
            System.err.flush();
            return false;
        }
        String alias = makeEntityAliasName(entityid);

        try {
            if (keyStore.containsAlias(alias)) {
                if (verboseOut) {
                    System.out.println("Key store: delete entry " + alias);
                    System.out.flush();
                }
                keyStore.deleteEntry(alias);
                modifiedFlag = true;

            } else {
                if (verboseOut) {
                    System.out.println("Key store: Entry to be delete not found with alias " + alias);
                }
            }

        } catch (KeyStoreException e) {
            System.err.println("ERROR: GFIPMKeystore.deleteEntry failed: ");
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;
    }  // end deleteEntry

    // ======================================================================
    /**
     * Deletes all Java key store certificates that are associated with the
     * GFIPM trust fabric. These are identified by the alias name prefix
     * "GFIPMcert" or other configured aliasPrefix. Writes error messages on
     * exceptions.
     *
     * @return true if successful; false otherwise
     *
     */
    public boolean deleteAllGFIPMEntries() {

        if ((aliasPrefix == null) || (aliasPrefix.trim().length() == 0)) {
            System.err.println("ERROR: GFIPMKeystore.deleteAllGFIPMEntries: Attempting to delete all key store entries. Aborted.");
            System.err.flush();
            return false;
        }

        try {
            String alias = null;
            int count = 0;

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                alias = aliases.nextElement();
                if (alias.startsWith(aliasPrefix)) {
                    if (verboseOut) {
                        System.out.println("Key store: delete entry " + alias);
                        System.out.flush();
                    }
                    keyStore.deleteEntry(alias);
                    count++;
                    modifiedFlag = true;
                }
            }
            if (verboseOut) {
                System.out.println("Key store: deleteall: # entries deleted: " + count);
            }
        } catch (KeyStoreException e) {
            System.err.println("ERROR: GFIPMKeystore.deleteAllGFIPMEntries failed: ");
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;
    }  // end deleteAllGFIPMEntitries

    // ======================================================================
    /**
     * Adds a new entry to the Java key store, using the GFIPM entity id as the
     * key store alias and using the filename for source of the trusted
     * certificate. Writes out an error messages on an exception.
     *
     * @param entityid The GFIPM entity to be added
     *
     * @param filename The file from where the trusted certificate should be
     * read.
     *
     * @return true on success, false otherwise.
     *
     */
    public boolean addNewEntryFromFile(String entityid, String filename) {
        String alias = makeEntityAliasName(entityid);
        if (alias == null) {
            System.err.println("ERROR: GFIPMKeystore.addNewEntryFromFile: No alias name. Aborted.");
            System.err.flush();
            return false;
        }

        try {

            // Source: http://download.oracle.com/javase/1.5.0/docs/api/java/security/cert/X509Certificate.html
            InputStream inStream = new FileInputStream(filename);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();

            if (verboseOut) {
                System.out.println("Key Store: add new entry " + alias);
                System.out.flush();
            }
            keyStore.setCertificateEntry(alias, cert);
            modifiedFlag = true;

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.addNewEntryFromFile failed: ");
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;
    }  // end addNewEntryFromFile

    // ======================================================================
    /**
     * Adds a new entry to the Java key store, using the GFIPM entity id as the
     * key store alias and using the certstr as the trusted certificate. Writes
     * out an error messages on an exception.
     *
     * @param entityid The GFIPM entity to be added
     *
     * @param certstr The trusted certificate in a string.
     *
     * @return true on success, false otherwise.
     */
    public boolean addNewEntryFromString(String entityid, String certstr) {
        String alias = makeEntityAliasName(entityid);
        if (alias == null) {
            System.err.println("ERROR: GFIPMKeystore.addNewEntryFromString: No alias name. Aborted.");
            System.err.flush();
            return false;
        }

        try {

            if (!certstr.contains("-----BEGIN CERTIFICATE-----")) {
                StringBuilder certbuf = new StringBuilder();
                certbuf.append("-----BEGIN CERTIFICATE-----\n");
                certbuf.append(certstr);
                char ch = certstr.charAt(certstr.length() - 1);
                if ((ch != '\n') && (ch != '\r')) {
                    certbuf.append("\n");
                }
                certbuf.append("-----END CERTIFICATE-----\n");
                certstr = certbuf.toString();
            }

            byte[] bytes = certstr.getBytes("UTF-8");   // or "ISO-8859-1"?
            InputStream inStream = new ByteArrayInputStream(bytes);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            inStream.close();

            if (verboseOut) {
                System.out.println("Key Store: add new entry " + alias);
                System.out.flush();
            }
            keyStore.setCertificateEntry(alias, cert);
            modifiedFlag = true;

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.addNewEntryFromString failed: ");
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;
    }  // end addNewEntryFromString

    // ======================================================================
    /**
     * Adds a new entry to the Java key store, using the GFIPMCertificate to
     * build the key store alias and extract the trusted certificate. Writes out
     * an error messages on an exception.
     *
     * @param cert A GFIPMCertificate from which the entity ID, type, key use,
     * and certificate is taken.
     *
     * @return true on success, false otherwise.
     */
    public boolean addNewEntryFromCertificate(GFIPMCertificate cert) {

        return addNewEntryFromString(makeEntityAliasName(cert), cert.getCertificate());

    }  // end addNewEntryFromCertificate

    // ======================================================================
    /**
     * Adds new entries to the Java key store, using the certlist list of
     * GFIPMCertificate as the source to build the key store aliases and extract
     * the trusted certificates. Writes out an error messages on an exception.
     *
     * @param certlist The list of GFIPMCertificate certificates to be added.
     *
     * @return Always returns true.
     */
    public boolean addEntriesFromCertificateList(List<GFIPMCertificate> certlist) {

        int count = 0;
        for (GFIPMCertificate cert : certlist) {
            if (addNewEntryFromCertificate(cert)) {
                count++;
            }
        }

        if (verboseOut) {
            System.out.println("Key Store: added " + count + " entries.");
        }

        return true;
    }

    // ======================================================================
    /**
     * Write the certificate String to a file. Opens the file, writes the
     * string, and then closes the file. Expects the outStr to be a Base64
     * encoded certificate, so that the file can be written according to the
     * Internet RFC 1421 standard. Returns true if the write operation was
     * successful, otherwise returns false and writes an error message.
     *
     * @param outfile The output File object. Must be a full pathname with
     * directory and file components.
     *
     * @param outStr The certificate (in Base64 encoding) to write to the file.
     * If str is null, this method writes "null" to the file. If str is 0
     * length, just writes one space to the file.
     *
     * @return Returns true if the write operation was successful, otherwise
     * writes an error message and returns false.
     *
     */
    public boolean writeCertToFile(File outfile, String outStr) {

        try {
            /*
             * if (!outfile.canWrite()) { System.err.println("ERROR:
             * GFIPMKeystore.writeCertToFile: Unable to write to file " +
             * outfile.toString()); System.err.flush(); return false; }
             *
             */
            FileWriter outWriter = new FileWriter(outfile, false);

            if (outStr == null) {
                outWriter.write("null");
            } else if (outStr.length() == 0) {
                outWriter.write(" ");
            } else {
                outWriter.write("-----BEGIN CERTIFICATE-----\n");
                outWriter.write(outStr);
                char ch = outStr.charAt(outStr.length() - 1);
                if ((ch != '\n') && (ch != '\r')) {
                    outWriter.write("\n");
                }
                outWriter.write("-----END CERTIFICATE-----\n");
            }
            outWriter.flush();
            outWriter.close();
            if (verboseOut) {
                System.out.print("Created certificate file: ");
                System.out.println(outfile.getCanonicalPath());
                System.out.flush();
            }

        } catch (IOException e) {
            System.err.println("ERROR: GFIPMKeystore.writeCertToFile failed: ");
            System.err.println(e.toString());
            System.err.flush();
            return false;
        }

        return true;

    }  // end writeCertToFile

    // ======================================================================
    /**
     * Write the certificate String to a file. Opens the file, writes the
     * string, and then closes the file. Expects the outStr to be a Base64
     * encoded certificate, so that the file can be written according to the
     * Internet RFC 1421 standard. Returns true if the write operation was
     * successful, otherwise returns false and writes an error message.
     *
     * @param filename The name of the file to write. Must be a full pathname
     * with directory and file and type components.
     *
     * @param outStr The certificate (in Base64 encoding) to write to the file.
     * If str is null, this method writes "null" to the file. If str is 0
     * length, just writes one space to the file.
     *
     * @return Returns true if the write operation was successful, otherwise
     * writes an error message to stderr and returns false.
     *
     */
    public boolean writeCertToFile(String filename, String outStr) {

        return writeCertToFile(new File(filename), outStr);

    }

    // ======================================================================
    /**
     * Writes a list of GFIPMCertificate certificates to a directory on disk.
     * The full path name for each certificate is built by concatenating dirName
     * and the alias name of each certificate and ".crt". Writes out error
     * messages on exceptions.
     *
     * @param certlist The list of GFIPMCertificate certificates to be added.
     *
     * @param dirName The name of the directory in which to put the certificate
     * files.
     *
     * @return Returns false if method cannot write to dirName; true otherwise.
     */
    public boolean writeCertificatesToDirectory(List<GFIPMCertificate> certlist,
            String dirName) {

        int count = 0;
        try {
            File dirObj = new File(dirName);
            if (!dirObj.isDirectory()) {
                if (dirObj.isFile()) {
                    System.err.println("ERROR: GFIPMKeystore.writeCertificatesToDirectory: not a directory: " + dirName);
                    return false;
                }
                if (!dirObj.mkdirs()) {
                    System.err.println("ERROR: GFIPMKeystore.writeCertificatesToDirectory: cannot create directory: " + dirName);
                    return false;
                }
            }
            File fileObj;

            for (GFIPMCertificate cert : certlist) {
                fileObj = new File(dirObj, makeEntityAliasName(cert) + ".crt");
                if (writeCertToFile(fileObj, cert.getCertificate())) {
                    count++;
                }
            }
            if (verboseOut) {
                System.out.println("GFIPMKeystore.writeCertificatesToDirectory: wrote " + count + " files.");
            }

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.writeCertificatesToDirectory failed: ");
            System.err.println(e.toString());
            System.err.flush();
            if (verboseOut) {
                System.out.println("GFIPMKeystore.writeCertificatesToDirectory: wrote " + count + " files.");
                System.out.flush();
            }

            return false;
        }
        return true;
    }  // end writeCertificatesToDirectory

    // ======================================================================
    /**
     * Writes out the alias names of all the key store entries. For debugging
     * purposes.
     *
     */
    public void printKeyStoreAliases() {
        try {
            String alias = null;

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                alias = aliases.nextElement();
                if (alias.startsWith(aliasPrefix)) {
                    System.out.print(" * ");
                } else {
                    System.out.print("   ");
                }
                System.out.println(alias);
            }

            System.out.println("");
            System.out.print("Number of entries in key store: ");
            System.out.println(keyStore.size());
            System.out.flush();

        } catch (KeyStoreException e) {
            System.err.println("ERROR: GFIPMKeystore.printKeyStoreAliases failed: ");
            System.err.println(e.toString());
            System.err.flush();
        }

    }  // end printKeyStoreAliases

    // ======================================================================
    /**
     * Writes out the certificates of all the key store entries. For debugging
     * purposes.
     *
     * @param certformat If "rawcert", writes out the text information (long)
     * about the certificates. If "enccert" [default], writes out the
     * certificates in base64 (short).
     *
     */
    public void printKeyStoreCertificates(String certformat) {
        try {
            String alias = null;
            Certificate cert;

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                alias = aliases.nextElement();
                System.out.println("");
                if (alias.startsWith(aliasPrefix)) {
                    System.out.print(" * ===== ");
                } else {
                    System.out.print("   ===== ");
                }
                System.out.println(alias);
                // entry = (TrustedCertificateEntry) keyStore.getEntry(alias, null);
                System.out.print("   Creation Date:    ");
                System.out.println(keyStore.getCreationDate(alias));
                System.out.print("   Certificate type: ");
                cert = keyStore.getCertificate(alias);
                System.out.print(cert.getType());
                if (keyStore.isKeyEntry(alias)) {
                    System.out.println("                          (details hidden)");
                    continue;
                } else {
                    System.out.println("");
                }

                if (keyStore.isCertificateEntry(alias)) {
                    if ((certformat != null) && (certformat.equals("rawcert"))) {
                        System.out.println(cert.toString());
                    } else // enccert, encoded certificate
                    {
                        //String encoded = javax.xml.bind.DatatypeConverter.printBase64Binary(data);
                        //byte[] decoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(encoded);                        
                        System.out.println(DatatypeConverter.printBase64Binary(cert.getEncoded()));
                    }
                }
                System.out.flush();
            }  // end for

            System.out.println("");
            System.out.print("Number of entries in key store: ");
            System.out.println(keyStore.size());
            System.out.flush();

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.printKeyStoreContents failed: ");
            System.err.println(e.toString());
            System.err.flush();
        }
    }  // end printKeyStoreCertificates

    // ======================================================================
    /**
     * Writes out the details of all the key store entries. This makes for a
     * long output. For debugging purposes.
     */
    public void printKeyStoreContents() {
        try {
            String alias = null;
            KeyStore.TrustedCertificateEntry entry = null;

            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                alias = aliases.nextElement();
                System.out.println("");
                if (alias.startsWith(aliasPrefix)) {
                    System.out.print(" * ===== ");
                } else {
                    System.out.print("   ===== ");
                }
                System.out.println(alias);
                if (keyStore.isKeyEntry(alias)) {
                    System.out.println("   is a KeyEntry                       (details hidden)");
                    continue;
                } else if (keyStore.isCertificateEntry(alias)) {
                    entry = (TrustedCertificateEntry) keyStore.getEntry(alias, null);
                    System.out.println(entry.toString());
                }
                System.out.flush();
            }  // end for

            System.out.println("");
            System.out.print("Number of entries in key store: ");
            System.out.println(keyStore.size());
            System.out.flush();

        } catch (Exception e) {
            System.err.println("ERROR: GFIPMKeystore.printKeyStoreContents failed: ");
            System.err.println(e.toString());
            System.err.flush();
        }
    }  // end printKeyStoreContents
}  // end class
