package util;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.decryption_verification.MessageMetadata;
import org.pgpainless.encryption_signing.*;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

import java.io.*;

/**
 * Wrapper Utility class for PgPainless library, in this utility we only focus on the below 4 implementation</br>
 * <ul>
 *     <li>decryptString</li>
 *     <li>decryptFile</li>
 *     <li>encryptString</li>
 *     <li>encryptFile</li>
 * </ul>
 *
 * exact implementation logic and document comments for the methods will be in the method documentation
 * @author marlan
 */
public class PgpPainlessUtil {


    /**
     * Encrypt the given string with the provided public and private key
     * @param plainText : message to be encrypted
     * @param privateKey : private key of the sender
     * @param publicKey : public key of the receiver
     * @return String : cypher text of the message
     * @throws PgpUtilException : For any exception will throw this with sufficient message detail
     */
    public static String encryptString( String plainText, byte[] privateKey, byte[] publicKey) throws  PgpUtilException{

        if (plainText == null || plainText.isEmpty()) throw new PgpUtilException("Message should be present to encrypt");
        InputStream inputStream = new ByteArrayInputStream(plainText.getBytes());
        OutputStream outputStream = new ByteArrayOutputStream();

        encryptFile(inputStream,outputStream, privateKey, publicKey);

        return outputStream.toString();
    }


    /**
     * Decrypt the string provided
     * @param cypherTextMessage : cypher text message
     * @param privateKey : private key
     * @param publicKey : public key of the sender
     * @return String :plain text
     * @throws PgpUtilException
     */
    public static String decryptstring (String cypherTextMessage, byte[] privateKey, byte[] publicKey) throws PgpUtilException {

        if (cypherTextMessage == null || cypherTextMessage.isEmpty()) throw new PgpUtilException("Message should be present to encrypt");

        InputStream inputStream = new ByteArrayInputStream(cypherTextMessage.getBytes());
        OutputStream outputStream = new ByteArrayOutputStream();

        decryptFile(inputStream,outputStream, privateKey, publicKey);

        return outputStream.toString();

    }

    /**
     * Encrypt provided input stream and return Output stream of the encrypted data
     * @param inputStream : plain file/text
     * @param privateKey : private key (our key)
     * @param publicKey : public key of the reciever
     * @return outputStream : stream of encrypted data
     * @throws PgpUtilException
     */
    public static void encryptFile(InputStream inputStream, OutputStream outputStream,  byte[] privateKey, byte[] publicKey)
            throws PgpUtilException {

        if (inputStream == null) throw new PgpUtilException("Input file is null");

        Keys keys = getKeys(privateKey, publicKey);

        EncryptionOptions encryptionOptions = EncryptionOptions.get().addRecipient(keys.receiverKey);
        ProducerOptions options = null;

        try {
            // Sign and encrypt
            options = ProducerOptions.signAndEncrypt( encryptionOptions,
                    SigningOptions.get().addDetachedSignature(new UnprotectedKeysProtector(), keys.secretKey));
        } catch (PGPException e) {
            throw new PgpUtilException(e.getMessage());
        }

        encrypt(options, inputStream, outputStream);
    }

    public static void decryptFile (InputStream inputStream, OutputStream outputStream,
                                            byte[] privateKey, byte[] publicKey) throws PgpUtilException {

        if (inputStream == null) throw new PgpUtilException("Encrypt file not provided");

        Keys keys = getKeys(privateKey, publicKey);

        ConsumerOptions options = ConsumerOptions.get()
                .addVerificationCert(keys.receiverKey) // add a verification cert for signature verification
                .addDecryptionKey(keys.secretKey);

        decrypt(inputStream, outputStream,  options);

    }



    private static void decrypt(InputStream inputStream, OutputStream outputStream,
                                        ConsumerOptions options) throws PgpUtilException {

        try {
            DecryptionStream consumerStream = PGPainless.decryptAndOrVerify()
                    .onInputStream(inputStream)
                    .withOptions(options);

            Streams.pipeAll(consumerStream, outputStream);
            consumerStream.close(); // important!

            // The result will contain metadata of the message
            MessageMetadata result = consumerStream.getMetadata();
        } catch (PGPException | IOException e) {
            throw new PgpUtilException(e.getMessage() + " on decrypting message");
        }
    }

    private static void encrypt(ProducerOptions options, InputStream inputStream, OutputStream outputStream)
            throws PgpUtilException {

        EncryptionStream encryptionStream = null;
        try {
            encryptionStream = PGPainless.encryptAndOrSign()
                    .onOutputStream(outputStream)
                    .withOptions(options);

            Streams.pipeAll(inputStream, encryptionStream);

        } catch (PGPException | IOException e) {
            throw new PgpUtilException(e.getMessage() + "In encrypting the message");
        } finally {
            try {
                if (encryptionStream != null)
                    encryptionStream.close();
            } catch (IOException e) {
                // failed to close the stream
            }
        }
    }


    private static Keys getKeys(byte[] privateKey, byte[] publicKey) throws PgpUtilException {

        validateKeysNotNull(privateKey, publicKey);

        PGPSecretKeyRing secretKey = null;
        PGPPublicKeyRing receiverKey = null;

        try {
            // get secret key
            secretKey = PGPainless.readKeyRing().secretKeyRing(privateKey);
            receiverKey = PGPainless.readKeyRing().publicKeyRing(publicKey);
        } catch (IOException e) {
            throw new PgpUtilException("Failed to get PgpKeys");
        }

        if (secretKey == null) throw new PgpUtilException("Invalid Private key");
        if (receiverKey == null) throw new PgpUtilException("Invalid Public key");

        return new Keys(secretKey, receiverKey);
    }

    private static void validateKeysNotNull(byte[] privateKey, byte[] publicKey) throws PgpUtilException {
        if (privateKey == null) throw new PgpUtilException("Private key should be present");
        if (publicKey == null) throw new PgpUtilException("Public key should be present");
    }

    private static class Keys {
        public final PGPSecretKeyRing secretKey;
        public final PGPPublicKeyRing receiverKey;

        public Keys(PGPSecretKeyRing secretKey, PGPPublicKeyRing receiverKey) {
            this.secretKey = secretKey;
            this.receiverKey = receiverKey;
        }
    }

}
