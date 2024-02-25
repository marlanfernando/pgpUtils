import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import util.PgpPainlessUtil;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileMainEncrypt {

    public static void main(String[] args) {

        String resourcePath = "TEST_FILE.pdf";
        String filePath = "src/main/resources/output.enc";
        String encFilePath = "output.enc";
        String decFilePath = "src/main/resources/decrypted_file.pdf";
        boolean isEncrypt = false;

        PGPSecretKeyRing secretKeys = null;
        PGPSecretKeyRing pk = null;

        try (InputStream ourKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("ourKey");
             InputStream theirKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("theirKey")) {

            assert ourKey != null;
            secretKeys = PGPainless.readKeyRing().secretKeyRing(ourKey);

            assert theirKey != null;
            pk = PGPainless.readKeyRing().secretKeyRing(theirKey);

            assert secretKeys != null;
            assert pk != null;

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (isEncrypt) {
            encrypt(resourcePath, filePath, secretKeys, pk);
        } else {
            decrypt(encFilePath, decFilePath, pk, secretKeys);
        }




    }

    private static void decrypt(String encFilePath, String decFilePath, PGPSecretKeyRing pk, PGPSecretKeyRing secretKeys) {
        // Obtaining an InputStream to the resource file
        try (InputStream inputStream = FileMainEncrypt.class.getClassLoader().getResourceAsStream(encFilePath);
             OutputStream os = Files.newOutputStream(Paths.get(decFilePath))) {

            if (inputStream != null) {
                PgpPainlessUtil.decryptFile(inputStream,os, pk.getEncoded(),
                        secretKeys.getPublicKey().getEncoded());

                byte[] buffer = new byte[1024];
                int length;
                // Read from the InputStream and write to the FileOutputStream
                while ((length = inputStream.read(buffer)) != -1) {
                    os.write(buffer, 0, length);
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encrypt(String resourcePath, String filePath, PGPSecretKeyRing secretKeys, PGPSecretKeyRing pk) {
        // Obtaining an InputStream to the resource file
        try (InputStream inputStream = FileMainEncrypt.class.getClassLoader().getResourceAsStream(resourcePath);
             OutputStream os = Files.newOutputStream(Paths.get(filePath))) {


            if (inputStream != null) {
                PgpPainlessUtil.encryptFile(inputStream,os, secretKeys.getEncoded(),
                        pk.getPublicKey().getEncoded());

                byte[] buffer = new byte[1024];
                int length;
                // Read from the InputStream and write to the FileOutputStream
                while ((length = inputStream.read(buffer)) != -1) {
                    os.write(buffer, 0, length);
                }
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
