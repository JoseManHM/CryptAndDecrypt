import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class CryptAndDecrypt {
    String PASSWORD = "rcVhNGWW5gFmTMCc0p67PAUzveFcdug1m7M5Z5ukMEWpU5Cv2XyPgm1heQwrxuhMWa42x22JrXiiLX7aCDbHh2GnHLCWTaX2cm2ESMKRnCJ2HBxMHbGV8ZwipMiJP7QUtScbmmj7mn7UnizD61NXMmYMb39Xee0v0ZhX730eDruFVScnxYqUGd0ZytfR2cZN3SASRXUSYkeGuSQBW33g6cAG6RWH6NSCcSfhqkyuLrQwvwZGyY0ApwVcZbfTzLvx";
    String SALT = "S99PXf8qNGECgkWx";
    final int ITERATION_COUNT = 4000;
    final int KEY_LENGTH = 256;
    final int GCM_IV_LENGTH = 12;
    final int GCM_TAG_LENGTH = 16;

    CryptAndDecrypt(){
        CryptAndDecrypt main = new CryptAndDecrypt();
        //JOptionPane.showMessageDialog(null, main.Encrypt("Hola"));
        //JOptionPane.showMessageDialog(null, main.GetKeyString(main.password.toCharArray(),main.salt.getBytes("UTF-8"), main.ITERATION_COUNT, main.KEY_LENGTH));
        //JOptionPane.showMessageDialog(null, new String(main.generateSalt(), StandardCharsets.UTF_8));
        //JOptionPane.showMessageDialog(null, main.crypt("716e0834865c19e3025b054d045c86ef",main.SALT.getBytes("UTF-8")));
        //JOptionPane.showMessageDialog(null, main.decrypt("VStQK1BZUXR1a2ludkJMcDpVems1VUZobU9IRk9SMFZEWjJ0WGVBPT06Wkp1VVdHMFVLNHcrNWdKK2pidkxJYnZ2dVVlWVZMSDlxSC8rVjNTOVQzY24xTXJTcEVIZzlGeVF4SndlODcxWg=="));
    }

    //USANDO EJEMPLO QUE SE INDICA EN REMEDIACIONES DOCS
    //Generar Secret Key
    private SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }
    //Obtener la secret key que se genera en el método anterior como string
    private String GetKeyString(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("keyLength = " + keyLength);
        String res =  Base64.getEncoder().encodeToString(createSecretKey(password, salt, iterationCount, keyLength).getEncoded());
        System.out.println("res = " + res);
        return res;
    }
    //Generar salt
    private byte[] generateSalt(){
        byte[] salt = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        byte[] saltFinal =  Base64.getEncoder().encode(salt);
        System.out.println("saltFinal = " + new String(saltFinal, StandardCharsets.UTF_8));
        return saltFinal;
    }
    //Genera el valor IV aleatoriamente el cual se usa para el encriptado de la cadena
    private byte[] getIV(){
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        return IV;
    }

    private String base64Encode(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    private byte[] base64Decode(String property) throws IOException {
        return Base64.getDecoder().decode(property);
    }
    //Encriptar valores
    public String crypt(String cadena, byte[] salt) throws GeneralSecurityException, UnsupportedEncodingException {
        //Generar secret key
        SecretKeySpec secretKey = createSecretKey(PASSWORD.toCharArray(),salt,ITERATION_COUNT, KEY_LENGTH);
        Cipher pbeCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] IV = getIV();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        pbeCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cryptoText = pbeCipher.doFinal(cadena.getBytes("UTF-8"));
        String cryptText =  Base64.getEncoder().encodeToString((base64Encode(IV) + ":" + base64Encode(salt) + ":" + base64Encode(cryptoText)).getBytes());
        System.out.println("cryptText = " + cryptText);
        return cryptText;
    }
    //Desencriptar valores
    public String decrypt(String cadena) throws GeneralSecurityException, IOException {
        String decodeString = new String(Base64.getDecoder().decode(cadena));
        String[] parts = decodeString.split(":");
        String IV = parts[0];
        String salt = parts[1];
        String property = parts[2];
        //Generar secret key
        SecretKeySpec secretKey = createSecretKey(PASSWORD.toCharArray(), base64Decode(salt), ITERATION_COUNT, KEY_LENGTH);
        Cipher pbeCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, base64Decode(IV));
        pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] decryptoText = pbeCipher.doFinal(base64Decode(property));
        System.out.println("desencriptado = " + new String(decryptoText, "UTF-8"));
        return new String(decryptoText, "UTF-8");
    }
}
