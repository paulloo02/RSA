package RSA_Algorithm.src;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;


public class gui implements ActionListener {
    JFrame f = new JFrame();//creating instance of JFrame
    JButton b1 = new JButton("Encrypt Message");
    JButton b2 = new JButton("Decrypt Message");
    TextArea encryptStatTextArea;
    TextArea decryptStatTextArea;
    TextField messageTextField;
    RSAEncrypt rsaEncrypt;
    RSADecrypt rsaDecrypt;

    gui() {
        rsaEncrypt = new RSAEncrypt(); //create instance of RSAEncrypt
        rsaDecrypt = new RSADecrypt(); //create instance of RSADecrypt
        gui1();
        button1();
    }

    public void gui1() {
        f.setTitle("RSA encryption");
        f.getContentPane().setBackground(Color.gray);
        JLabel q = new JLabel("Choose");
        f.add(q);
        q.setBounds(20, 30, 1000, 100);
        f.getContentPane().setLayout(null);
        f.setVisible(true);
        f.setBounds(100, 100, 600, 600);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    public void button1() {
        b1.setBounds(20, 100, 200, 40);
        b2.setBounds(250, 100, 200, 40);
        f.add(b1);
        f.add(b2);
        b1.addActionListener(this);
        b2.addActionListener(this);
    }


    public void encrypt() {
        JLabel title1 = new JLabel("Welcome to RSA Encryption");          //Welcome Text
        title1.setBounds(100, 30, 400, 50);
        title1.setFont(new Font("Arial", Font.PLAIN, 30));

        JLabel en = new JLabel("Enter Message");
        en.setBounds(150, 80, 400, 20);
        JButton e = new JButton("Key Generate");              //generate key button
        e.setBounds(20, 100, 120, 40);
        JButton k = new JButton("Encrypt");       //encrypt Button
        k.setBounds(20, 150, 120, 40);
        messageTextField = new TextField(50);          //enter message
        messageTextField.setBounds(150, 110, 300, 60);


        encryptStatTextArea = new TextArea();           //status box
        encryptStatTextArea.setText("Ready to generate key...");
        encryptStatTextArea.setEditable(false);

        encryptStatTextArea.setBounds(20, 400, 410, 150);


        JLabel kn = new JLabel("Status");
        kn.setBounds(20, 360, 100, 40);


        JButton bck = new JButton("Back");              //back button to main page
        bck.setBounds(450, 450, 100, 40);


        f.add(title1);
        f.add(e);
        f.add(encryptStatTextArea);
        f.add(en);
        f.add(bck);
        f.add(kn);
        f.add(k);
        f.add(messageTextField);


        e.addActionListener(this);
        bck.addActionListener(this);
        k.addActionListener(this);
        messageTextField.addActionListener(this);

    }


    public void decrypt() {
        JLabel title1 = new JLabel("Welcome to RSA Decryption");          //welcome text
        title1.setBounds(100, 30, 400, 50);
        title1.setForeground(Color.WHITE);
        title1.setFont(new Font("Arial", Font.PLAIN, 30));

        JButton e = new JButton("Load Private Key");              //load key button
        e.setBounds(20, 100, 150, 40);
        JButton k = new JButton("Load Ciphertext");       //load ciphertext button
        k.setBounds(20, 160, 150, 40);
        JButton d = new JButton("Decrypt");       //decrypt button
        d.setBounds(20, 220, 150, 40);


        decryptStatTextArea = new TextArea();           //status box
        decryptStatTextArea.setText("Ready to load key and ciphertext...");
        decryptStatTextArea.setEditable(false);

        decryptStatTextArea.setBounds(20, 400, 410, 150);


        JLabel kn = new JLabel("Status");
        kn.setBounds(20, 360, 100, 40);


        JButton bck = new JButton("Back");              //back button to main page
        bck.setBounds(450, 450, 100, 40);


        f.add(title1);
        f.add(e);
        f.add(decryptStatTextArea);
        f.add(bck);
        f.add(kn);
        f.add(k);
        f.add(d);


        e.addActionListener(this);
        bck.addActionListener(this);
        k.addActionListener(this);
        d.addActionListener(this);

    }


    public void actionPerformed(ActionEvent e) {
        String status;
        String str = e.getActionCommand();
        switch (str) {
            case "Encrypt Message":
                f.getContentPane().removeAll();
                f.getContentPane().setBackground(Color.lightGray);
                encrypt();
                break;

            case "Decrypt Message":
                f.getContentPane().removeAll();
                f.getContentPane().setBackground(Color.darkGray);
                decrypt();
                break;

            case "Back":
                f.getContentPane().removeAll();
                f.getContentPane().setBackground(Color.gray);
                gui1();
                button1();
                break;

            case "Key Generate":
                try {
                    rsaEncrypt.generate();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                status = encryptStatTextArea.getText();
                encryptStatTextArea.setText(status + "\nKeys is saved to publickey.txt and privatekey.txt\nUsing the public key");
                break;

            case "Encrypt":
                if (Objects.equals(messageTextField.getText(), "")) {
                    status = encryptStatTextArea.getText();
                    encryptStatTextArea.setText(status + "\nerror : Message cannot be empty!");
                } else{
                    try {
                        rsaEncrypt.encrypt(messageTextField.getText(), rsaEncrypt);
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                             InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException ex) {
                        throw new RuntimeException(ex);
                    }
                    status = encryptStatTextArea.getText();
                    encryptStatTextArea.setText(status + "\nCiphertext is saved to: ciphertext.txt");
                }
                break;

            case "Load Private Key":
                try {
                    rsaDecrypt.loadKey(rsaDecrypt);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                status = decryptStatTextArea.getText();
                decryptStatTextArea.setText(status + "\nPrivate key loaded from privatekey.txt!");
                break;

            case "Load Ciphertext":
                try {
                    rsaDecrypt.loadCiphertext();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                status = decryptStatTextArea.getText();
                decryptStatTextArea.setText(status + "\nCiphertext loaded from ciphertext.txt!");
                break;

            case "Decrypt":
                String message;
                try {
                     message = rsaDecrypt.decrypt(rsaDecrypt);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |
                         InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    throw new RuntimeException(ex);
                }

                if (message.equals("d_n_null")){
                    status = decryptStatTextArea.getText();
                    decryptStatTextArea.setText(status + "\nERROR: Private key not loaded!");
                } else if (message.equals("c_null")) {
                    status = decryptStatTextArea.getText();
                    decryptStatTextArea.setText(status + "\nERROR: Ciphertext not loaded!");
                }else {
                    status = decryptStatTextArea.getText();
                    decryptStatTextArea.setText(status + "\n" + message);
                }
                break;
        }
    }

}