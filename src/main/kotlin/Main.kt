import java.io.File
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun main(args: Array<String>) {

    try {
        val privateKeyParamPosition = args.indexOf("-p")
        val encryptedAesKeyParamPosition = args.indexOf("-a")
        val encryptedAesDataParamPosition = args.indexOf("-d")
        if (privateKeyParamPosition == -1 || encryptedAesKeyParamPosition == -1 || encryptedAesDataParamPosition == -1) {
            printInputError()
            return
        }

        val privateKeyPatch: String = args[privateKeyParamPosition.inc()]
        val encryptedAesKeyPath: String = args[encryptedAesKeyParamPosition.inc()]
        val encryptedAesDataPath: String = args[encryptedAesDataParamPosition.inc()]

        Decryptor(privateKeyPatch, encryptedAesKeyPath, encryptedAesDataPath).decrypt()
    } catch (ex: ArrayIndexOutOfBoundsException) {
        printInputError()
    } catch (ex: Exception) {
        println("Something went wrong: $ex")
    }
}

fun printInputError() {
    println("We must have such parameters as:")
    println("-p - private RSA key")
    println("-a - encrypted AES key")
    println("-d - encrypted AES data")
    println("Command example: java -jar Decryptor.jar -p <private RSA key> -a <encrypted AES key> -d <encrypted AES data>")
}

internal class Decryptor(
    private val privateKeyPatch: String,
    private val encryptedAesKeyPath: String,
    private val encryptedAesDataPath: String,
) {

    fun decrypt() {
        val privateRSAKey = getPrivateRsaKey()
        val decryptedAESKey = decryptAESKey(privateRSAKey)
        val decryptedAESData = decryptAESData(decryptedAESKey)
        val decryptedData = File("YourFile.zip").apply {
            if (exists()) {
                deleteRecursively()
            }
            writeBytes(decryptedAESData)
        }
        println("Your data was decrypted: ${decryptedData.absolutePath}")
    }

    private fun cleanRSAHeaderAndDecodeToBase64(key: String): ByteArray {
        val publicKeyPEM = key
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace(System.lineSeparator().toRegex(), "")
            .replace("-----END PRIVATE KEY-----", "")
        return Base64.getDecoder().decode(publicKeyPEM)
    }

    private fun getPrivateRsaKey(): PrivateKey {
        val privateSpec = PKCS8EncodedKeySpec(cleanRSAHeaderAndDecodeToBase64(File(privateKeyPatch).readText()))
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(privateSpec)
    }

    private fun decryptAESKey(privateRSAKey: PrivateKey): SecretKey {
        val encryptedAesKey = File(encryptedAesKeyPath).readBytes()
        val cipher1: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher1.init(Cipher.DECRYPT_MODE, privateRSAKey)
        val secretKeyBytes: ByteArray = cipher1.doFinal(encryptedAesKey)
        return SecretKeySpec(secretKeyBytes, 0, secretKeyBytes.size, "AES")
    }

    private fun decryptAESData(aesKey: SecretKey): ByteArray {
        val encryptedAesData = File(encryptedAesDataPath).readBytes()
        val raw = aesKey.encoded
        val skeySpec = SecretKeySpec(raw, "AES")
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, IvParameterSpec(ByteArray(16)))
        return cipher.doFinal(encryptedAesData)
    }
}
