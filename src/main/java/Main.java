import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.pgpainless.PGPainless;
import org.pgpainless.key.generation.type.rsa.RsaLength;
import util.PgpPainlessUtil;

import java.io.InputStream;

public class Main {

    public static void main(String[] args) {

        try (InputStream ourKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("ourKey");
             InputStream theirKey = Thread.currentThread().getContextClassLoader().getResourceAsStream("theirKey")) {

            assert ourKey != null;
            PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(ourKey);

            assert theirKey != null;
            PGPSecretKeyRing pk = PGPainless.readKeyRing().secretKeyRing(theirKey);

            assert secretKeys != null;
            assert pk != null;
            String cypherText = PgpPainlessUtil.encryptString("this is plainText",
                    secretKeys.getEncoded(), pk.getPublicKey().getEncoded());

            System.out.println(cypherText);

            String plainText = PgpPainlessUtil.decryptstring(cypherText, pk.getEncoded(),
                    secretKeys.getPublicKey().getEncoded());

            System.out.println(plainText);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
