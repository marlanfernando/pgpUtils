import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.type.rsa.RsaLength;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class CreateKeys {

    public static void main(String[] args) {
        try {
            PGPSecretKeyRing ourKey = PGPainless.generateKeyRing()
                    .simpleRsaKeyRing("Marlan <marlanfernando@outlook.com>", RsaLength._4096);

            PGPSecretKeyRing receiverKey = PGPainless.generateKeyRing().simpleRsaKeyRing("gio", RsaLength._4096);

            String filePath = "src/main/resources/ourKey";
            String theirKey = "src/main/resources/theirKey";

            try (OutputStream outputStream = Files.newOutputStream(Paths.get(filePath))) {

                ourKey.encode(outputStream);

                System.out.println("Data has been written to the file.");
            } catch (Exception e) {
                e.printStackTrace();
            }

            try (OutputStream outputStream = Files.newOutputStream(Paths.get(theirKey))) {

                receiverKey.encode(outputStream);

                System.out.println("Data has been written to the file.");
            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
