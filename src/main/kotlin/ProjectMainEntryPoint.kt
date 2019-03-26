import java.io.Console
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement
import javax.xml.bind.DatatypeConverter

fun main(args: Array<String>) {
    try {
        /** Getting console unique instante */
        val console : Console = System.console()

        /** Using java security to create KeyPairGenerator instance */
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")

        /** Setting keySize 256 */
        keyPairGenerator.initialize(256)

        /** Generating the key pair from KeyPairGenerator instante */
        val keyPair = keyPairGenerator.generateKeyPair()

        /** Getting public key from the generated pair */
        val ourPublicKey = keyPair.public.encoded

        /** Printing in the console public key retrieved */
        console.printf("Public Key: %s%n", DatatypeConverter.printHexBinary(ourPublicKey))

        /** Getting other public key */
        val otherPublickey = DatatypeConverter.parseHexBinary(console.readLine("Other PK: "))

        /** Setting EC cryptography method to other public key */
        val keyFactory = KeyFactory.getInstance("EC")

        /** Setting spec for the other public key */
        val publicKeySpec = X509EncodedKeySpec(otherPublickey)

        /** Really generate the other public key according to spec */
        val otherPublicKey = keyFactory.generatePublic(publicKeySpec)

        /** Setting Diffie-Hellman as the key-agreement protocol */
        val keyAgreement  = KeyAgreement.getInstance("ECDH")

        /** Setting private key from generated key pair for the ECDH agreement */
        keyAgreement.init(keyPair.private)

        /** Key exchange performed */
        keyAgreement.doPhase(otherPublicKey, true)

        /** Getting shared secret after keys exchange */
        val sharedSecret = keyAgreement.generateSecret()

        /** Printing in the console shared secret */
        console.printf("Shared secret: %s%n", DatatypeConverter.printHexBinary(sharedSecret))

        /** Setting SHA-256 in Message Digest one-way hash function initialization */
        val hash = MessageDigest.getInstance("SHA-256")

        /** Update hash using shared secret generated from public key exchange */
        hash.update(sharedSecret)

        /** Creating keyList with our public key and the other one */
        val keys = Arrays.asList(ByteBuffer.wrap(ourPublicKey), ByteBuffer.wrap(otherPublickey))

        /** Randomizing order of the keys in the list */
        Collections.sort(keys)

        /** Updating hash with first key in the list */
        hash.update(keys.get(0))

        /** Updating hash with second key in the list */
        hash.update(keys.get(1))

        /** Getting derived key from the updated hash */
        val derivedKey = hash.digest()

        /** Printing in the console the final key */
        console.printf("Final key: %s%n", DatatypeConverter.printHexBinary(derivedKey))
    } catch (e : Exception) {
        e.printStackTrace()
    }
}