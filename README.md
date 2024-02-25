# PgpPainlessUtil

This utility class is a wrapper for PGPainless implementation. In this utility class I cover the bellow usecases

<ul>
    <li>encryptString</li>
    <li>decryptString</li>
    <li>encryptFile</li>
    <li>decryptFile</li>
</ul>

In the `PgpPainlessUtil` class you can find the method comments on how to use this utility class

# How to use

If you dont have keys generated, run the `CreateKeys` class. it will generate the keys for you and
can be found at the resources directory.

once you have the keys generated you can run any of the above-mentioned methods as in `Main` class or `FileMainEncrypt` 
class.

below is a snippet from `Main` class where encryption and decryption happen for a text.

```
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
```