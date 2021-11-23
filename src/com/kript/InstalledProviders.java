package com.kript;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Provider;
import java.security.Security;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import org.bouncycastle.util.encoders.Hex;
public class InstalledProviders {
    static
        {
         Security.addProvider(new BouncyCastleProvider());
        }

    public static SecretKey generateSymmetricKey(String algo) throws NoSuchAlgorithmException
    {
        KeyGenerator kg = KeyGenerator.getInstance(algo); return kg.generateKey();
    }
    public static byte [] simpleSymmetricEncrype(Cipher cipher, SecretKey key, byte[] inputMas) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        cipher.init(Cipher.ENCRYPT_MODE, key); return cipher.doFinal(inputMas);
    }

    public static byte [] simpleSymmetricDecrypt(Cipher cipher, SecretKey key, byte[] encryptMas) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        cipher.init(Cipher.DECRYPT_MODE, key); return cipher.doFinal(encryptMas);
    }

    public static void main(String[] args) throws Exception {
        Scanner in=new Scanner(System.in);
        System.out.println("Введите сообщение");
        String vvod=in.nextLine();
        byte inputMessage[] = vvod.getBytes();
        String algo="GOST28147";
        System.out.println(vvod);
            Cipher cipher = Cipher.getInstance(algo, "BC");
            SecretKey key = generateSymmetricKey(algo);
            byte encMas[] = simpleSymmetricEncrype(cipher, key, inputMessage);
            byte decMas[] = simpleSymmetricDecrypt(cipher, key,encMas);
                    System.out.println("Алгоритм: " + algo);
            System.out.println("Секретный ключ: 0x" + new String(Hex.encode(key.getEncoded())));
            System.out.println("Зашифрованное сообщение - 0x" + new String(Hex.encode(encMas)));
            System.out.println("Расшифрованное сообщение - " + new String(decMas));

    }

}
