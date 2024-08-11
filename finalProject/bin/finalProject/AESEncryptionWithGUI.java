package finalProject;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

public class AESEncryptionWithGUI {
    private JButton encryptButton;
    private JButton copyButton;
    private JButton decryptButton;
    private JTextField inputText;
    private JLabel encryptedLabel;
    private JLabel secretKeyField;

    private static final String ALGORITHM = "AES";

    public AESEncryptionWithGUI() {
        JFrame frame = new JFrame("AES Encryption with GUI");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        createGUI(frame);
        initListeners();
        frame.setVisible(true);
    }

    private void createGUI(JFrame frame) {
        encryptButton = new JButton("Encrypt");
        copyButton = new JButton("Copy");
        decryptButton = new JButton("Decrypt");
        inputText = new JTextField(20);
        encryptedLabel = new JLabel("Encrypted Text: ");
        secretKeyField = new JLabel("secretKey : ");
        JPanel panel = new JPanel();
        panel.setLayout(new FlowLayout());
        panel.add(inputText);
        panel.add(encryptButton);
        panel.add(copyButton);
        panel.add(decryptButton);
        panel.add(encryptedLabel);
        panel.add(secretKeyField);
        frame.add(panel);
        frame.pack();
    }

    private void initListeners() {
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
            	 System.out.println("actionPerformed :::::::::::::::::::::::::::::::::::::::: " );
            	 String secretKey = JOptionPane.showInputDialog("Enter the secret key (16, 24, or 32 characters):");
                String originalText = inputText.getText();

                // Generate a random 128-bit key if not provided
                if (secretKey.length() != 16 && secretKey.length() != 24 && secretKey.length() != 32) {
                    byte[] keyBytes = new byte[16];
                    new SecureRandom().nextBytes(keyBytes);
                    secretKey = Base64.getEncoder().encodeToString(keyBytes);
                }

                // Encrypt the text
                String encryptedText = encrypt(originalText, secretKey);
                encryptedLabel.setText("Encrypted Text: " + encryptedText);
                secretKeyField.setText("secretKeyField: " + secretKey);
                System.out.println("Original Text: " + originalText);
                System.out.println("Encrypted Text: " + encryptedText);              
                System.out.println("secretKey: " + secretKey);  
            }
        });

        copyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String encryptedText = encryptedLabel.getText().replace("Encrypted Text: ", "");
                StringSelection selection = new StringSelection(encryptedText);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                JOptionPane.showMessageDialog(null, "Encrypted text copied to clipboard!", "Copy Result", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) { 
                String secretKey = JOptionPane.showInputDialog("Enter the secret key for decryption:");
                String encryptedText = encryptedLabel.getText().replace("Encrypted Text: ", "");              
                // Decrypt the text
                String decryptedText = decrypt(encryptedText, secretKey);
                System.out.println("decryptedText Text: " + decryptedText);
                JOptionPane.showMessageDialog(null, "Decrypted Text:\n" + decryptedText, "Decryption Result", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        copyButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String secretKey = secretKeyField.getText().replace("Secret Key: ", "");
                StringSelection selection = new StringSelection(secretKey);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                JOptionPane.showMessageDialog(null, "Secret key copied to clipboard!", "Copy Result", JOptionPane.INFORMATION_MESSAGE);
            }});
    }

    public static String encrypt(String valueToEnc, String secretKey) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedBytes = cipher.doFinal(valueToEnc.getBytes());
            String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String encryptedValue, String secretKey) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedValue);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "Decryption failed. Invalid key or ciphertext.";
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new AESEncryptionWithGUI());
    }
}

