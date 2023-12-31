import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.List;
import java.util.Timer;

public class Opciones extends javax.swing.JFrame {
    private JPanel form;
    private JButton encriptarButton;
    private JButton desencriptarButton;
    private JCheckBox tienesConfiguradaLaLlaveCheckBox;
    private JTextArea txtAreaLlave;
    private JTextArea textSalt;
    private JTextArea textAreaValor;
    private JTextArea textAreaResultado;
    private JButton copiarButton;
    private JButton salirButton;
    private JLabel txtKey;
    private JLabel txtSalt;
    private JLabel lblMessageCopy;
    private JButton btnClean;
    private JButton btnRandom;
    private JTextArea textSizeGenerate;
    private JTextArea textAreaGenerate;
    private JButton copiarButton2;

    //Cont use for crypt and decrypt
    final int ITERATION_COUNT = 4000;
    final int KEY_LENGTH = 256;
    final int GCM_IV_LENGTH = 12;
    final int GCM_TAG_LENGTH = 16;

    JFrame frame = new JFrame();

    Opciones(){
        System.out.println("Init program");
        OnInit();
    }

    public void OnInit(){
        frame.pack();
        //Configure the size of the UI
        frame.setSize(740, 555);
        frame.setVisible(true);
        frame.add(form);
        //Configure text format
        txtAreaLlave.setLineWrap(true);
        txtAreaLlave.setWrapStyleWord(true);
        textSalt.setLineWrap(true);
        textSalt.setWrapStyleWord(true);
        textAreaValor.setLineWrap(true);
        textAreaValor.setWrapStyleWord(true);
        textAreaResultado.setLineWrap(true);
        textAreaResultado.setWrapStyleWord(true);
        textAreaGenerate.setLineWrap(true);
        textAreaGenerate.setWrapStyleWord(true);
        //Listen when button is clicked to exit program
        salirButton.addActionListener(actionListenerExit);
        //Listen to checkBox changes to show or hide fields for key and salt
        tienesConfiguradaLaLlaveCheckBox.addActionListener(actionListenerCheckEnv);
        //Listen when crypt button is clicked
        encriptarButton.addActionListener(actionListenerEncriptarBtn);
        //Listen when button Copy is selected
        copiarButton.addActionListener(actionListenerCopy);
        //Listen when button Copy 2 is selected
        copiarButton2.addActionListener(actionListenerCopy2);
        //Listen when decrypt button is clicked
        desencriptarButton.addActionListener(actionListenerDesencriptarBtn);
        //Listen when clean button is clicked
        btnClean.addActionListener(actionListenerCleanBtn);
        //Listen when button Generate random value is clicked
        btnRandom.addActionListener(actionListenerGenerate);
        //Show or hide textArea for the key and salt for default
        if(tienesConfiguradaLaLlaveCheckBox.isSelected()){
            txtAreaLlave.setVisible(false);
            textSalt.setVisible(false);
            txtKey.setVisible(false);
            txtSalt.setVisible(false);
        }
    }
    //Exit
    ActionListener actionListenerExit = new ActionListener() {
        public void actionPerformed(ActionEvent actionEvent) {
            System.exit(0);
        }
    };
    //Checkbox env
    ActionListener actionListenerCheckEnv = new ActionListener() {
        public void actionPerformed(ActionEvent actionEvent) {
            if(tienesConfiguradaLaLlaveCheckBox.isSelected()){
                txtAreaLlave.setVisible(false);
                textSalt.setVisible(false);
                txtKey.setVisible(false);
                txtSalt.setVisible(false);
            }else{
                txtAreaLlave.setVisible(true);
                textSalt.setVisible(true);
                txtKey.setVisible(true);
                txtSalt.setVisible(true);
                frame.setSize(740, 650);
            }
        }
    };
    //Crypt
    ActionListener actionListenerEncriptarBtn = new ActionListener() {
        public void actionPerformed(ActionEvent e) {
            //From here init the crypt
            //Obtain key and salt
            List<String> keyAndSalt = getKeyAndSalt(tienesConfiguradaLaLlaveCheckBox.isSelected());
            String llave = keyAndSalt.get(0);
            String salt = keyAndSalt.get(1);
            String valueToCrypt = textAreaValor.getText().trim();
            if(!Objects.equals(llave, "") && llave != null && !Objects.equals(salt, "") && salt != null && !valueToCrypt.isEmpty()){
                try {
                    String cryptValue = crypt(valueToCrypt,salt.getBytes("UTF-8"),llave);
                    textAreaResultado.setText(cryptValue);
                    JOptionPane.showMessageDialog(null, "Valor encriptado correctamente.","Éxito",JOptionPane.INFORMATION_MESSAGE);
                } catch (GeneralSecurityException ex) {
                    System.out.println("Error: " + ex.getMessage());
                    throw new RuntimeException(ex);
                } catch (UnsupportedEncodingException ex) {
                    System.out.println("Error: " + ex.getMessage());
                    throw new RuntimeException(ex);
                }
            }else{
                JOptionPane.showMessageDialog(null,"Los campos no pueden ir vacíos, completar todos.","Error",JOptionPane.ERROR_MESSAGE);
            }
        }
    };
    //Copy clipboard
    ActionListener actionListenerCopy = new ActionListener() {
        public void actionPerformed(ActionEvent e) {
            if(!textAreaResultado.getText().isEmpty()){
                textAreaResultado.selectAll();
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection stringToCopy = new StringSelection(textAreaResultado.getSelectedText());
                clipboard.setContents(stringToCopy, null);
                new Timer().schedule(new TimerTask() {
                    public void run() {
                        lblMessageCopy.setText("");
                    }
                }, 5000);
                lblMessageCopy.setText("Texto copiado al portapapeles");
            }
        }
    };
    //Copy clipboard 2
    ActionListener actionListenerCopy2 = new ActionListener() {
        public void actionPerformed(ActionEvent e) {
            if(!textAreaGenerate.getText().isEmpty()){
                textAreaGenerate.selectAll();
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection stringToCopy = new StringSelection(textAreaGenerate.getSelectedText());
                clipboard.setContents(stringToCopy, null);
                new Timer().schedule(new TimerTask() {
                    public void run() {
                        lblMessageCopy.setText("");
                    }
                }, 5000);
                lblMessageCopy.setText("Texto copiado al portapapeles");
            }
        }
    };
    //Decrypt
    ActionListener actionListenerDesencriptarBtn = new ActionListener() {
        public void actionPerformed(ActionEvent e) {
            //Obtain key and salt
            List<String> keyAndSalt = getKeyAndSalt(tienesConfiguradaLaLlaveCheckBox.isSelected());
            String llave = keyAndSalt.get(0);
            String valueToDecrypt = textAreaValor.getText().trim();
            if(llave != "" && !llave.isEmpty() && valueToDecrypt != "" && !valueToDecrypt.isEmpty()){
                try {
                    String decryptValue = decrypt(valueToDecrypt, llave);
                    if(decryptValue != null){
                        textAreaResultado.setText(decryptValue);
                        JOptionPane.showMessageDialog(null, "Valor desencriptado correctamente.","Éxito",JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (GeneralSecurityException ex) {
                    System.out.println("Error: " + ex.getMessage());
                    throw new RuntimeException(ex);
                } catch (IOException ex) {
                    System.out.println("Error: " + ex.getMessage());
                    throw new RuntimeException(ex);
                }
            }else{
                JOptionPane.showMessageDialog(null,"Los campos no pueden ir vacíos, completar todos.","Error",JOptionPane.ERROR_MESSAGE);
            }
        }
    };
    //Clean Button
    ActionListener actionListenerCleanBtn = new ActionListener() {
        public void actionPerformed(ActionEvent e) {
            txtAreaLlave.setText("");
            textSalt.setText("");
            textAreaValor.setText("");
            textAreaResultado.setText("");
            textSizeGenerate.setText("");
            textAreaGenerate.setText("");
        }
    };
    //Get salt and key from enviroment or fields
    public List<String> getKeyAndSalt(boolean checked){
        List<String> valores = new ArrayList<>();
        if(checked){
            if(System.getenv("AES_256_PASS") != null && System.getenv("AES_256_SALT") != null){
                valores.add(System.getenv("AES_256_PASS"));
                valores.add(System.getenv("AES_256_SALT"));
            }else{
                valores.add(null);
                valores.add(null);
                JOptionPane.showMessageDialog(null, "No se cuentan con las variables de entorno configuradas", "Error", JOptionPane.ERROR_MESSAGE);
            }
        }else{
            valores.add(txtAreaLlave.getText().trim());
            valores.add(textSalt.getText().trim());
        }
        return valores;
    }

    //Create a Secret Key
    private SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey keyTmp = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(keyTmp.getEncoded(), "AES");
    }

    //Create salt
    private byte[] generateSalt(){
        byte[] salt = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        byte[] saltFinal =  Base64.getEncoder().encode(salt);
        return saltFinal;
    }

    //Create IV value random to crypt the string
    private byte[] getIV(){
        byte[] IV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        return IV;
    }

    private String base64Encode(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    private byte[] base64Decode(String property){
        return Base64.getDecoder().decode(property);
    }

    //Crypt values
    public String crypt(String cadena, byte[] salt, String password) throws GeneralSecurityException, UnsupportedEncodingException {
        //Generar secret key
        SecretKeySpec secretKey = createSecretKey(password.toCharArray(),salt,ITERATION_COUNT, KEY_LENGTH);
        Cipher pbeCipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] IV = getIV();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
        pbeCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] cryptoText = pbeCipher.doFinal(cadena.getBytes("UTF-8"));
        String cryptText =  Base64.getEncoder().encodeToString((base64Encode(IV) + ":" + base64Encode(salt) + ":" + base64Encode(cryptoText)).getBytes());
        return cryptText;
    }

    //Decrypt values
    public String decrypt(String cadena, String password) throws GeneralSecurityException, IOException {
        String response = null;
        try{
            String decodeString = new String(Base64.getDecoder().decode(cadena));
            String[] parts = decodeString.split(":");
            String IV = parts[0];
            String salt = parts[1];
            String property = parts[2];
            //Generar secret key
            SecretKeySpec secretKey = createSecretKey(password.toCharArray(), base64Decode(salt), ITERATION_COUNT, KEY_LENGTH);
            Cipher pbeCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, base64Decode(IV));
            pbeCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] decryptoText = pbeCipher.doFinal(base64Decode(property));
            response = new String(decryptoText, "UTF-8");
        }catch(Exception e){
            System.out.println("Error = " + e.getMessage());
            JOptionPane.showMessageDialog(null,"Ocurrió un error al realiza la desencriptación, verifique el valor a desencriptar","Error",JOptionPane.ERROR_MESSAGE);
        }
        return response;
    }

    //Action listen button generate
    ActionListener actionListenerGenerate = new ActionListener() {
       public void actionPerformed(ActionEvent e){
           try{
               Integer size = Integer.parseInt(textSizeGenerate.getText());
               if(size > 0){
                   String valorGenerado = generateRandomValue(size);
                   textAreaGenerate.setText(valorGenerado);
               }
           }catch(NumberFormatException ex){
               System.out.println("Error: " + ex.getMessage());
               JOptionPane.showMessageDialog(null, "Debes de ingresar solo números","Error",JOptionPane.ERROR_MESSAGE);
           }catch (Exception ex){
               System.out.println("Excepcion = " + ex);
               System.out.println("Error = " + ex.getMessage());
           }
       }
    };

    public String generateRandomValue(Integer size){
        String response = null;
        try{
            SecureRandom secureRandom = new SecureRandom();
            byte[] values = new byte[size];
            secureRandom.nextBytes(values);
            Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
            String value = encoder.encodeToString(values);
            response = value.replaceAll("[^A-Za-z0-9]+","").substring(0,size);
        }catch(Exception e){
            System.out.println("Error: " + e.getMessage());
        }
        return response;
    }
}
