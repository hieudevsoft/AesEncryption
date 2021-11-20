package util;

import core.AES;

import java.util.Base64;
import java.util.BitSet;
import java.util.Random;
import java.util.Scanner;

public class Encryption {
    private static AES aes;
    private static byte[] plaintext;
    private static byte[] cipherText;
    public static void ECBEncryptionWithKey(Scanner sc){
        while (true){
            try {
                System.out.print("Plain text: ");
                String plainText = sc.nextLine();
                System.out.print("Key: ");
                String keyInput = sc.nextLine();
                byte[] inputText = pushDataToBlock(plainText).getBytes();
                byte[] key;
                key = keyInput.getBytes();
                aes = new AES(key);
                double startTime = System.currentTimeMillis();
                System.out.println("Plain text: " + plainText);
                byte [] cipherBytes = aes.ECB_encrypt(inputText);
                String a = Base64.getEncoder().encodeToString(cipherBytes);
                System.out.println("Cipher text: " + a.trim());
                double endTime = System.currentTimeMillis();
                System.out.println("ECB Encryption | "+(float)(endTime-startTime)/1000.00 + " secs");
                startTime = System.currentTimeMillis();
                System.out.println("Cipher text: " + a.trim());
                plainText = new String(aes.ECB_decrypt(cipherBytes)).trim();
                System.out.println("Plain text: " + plainText);
                endTime = System.currentTimeMillis();
                System.out.println("ECB Decryption | "+(float)(endTime-startTime)/1000 + " secs");
                plaintext = inputText;
                cipherText = cipherBytes;
                break;
            }catch (Exception e){
                System.out.println("Vui lòng nhập lại: ");
                System.out.println(e.getMessage());
            }
        }
    }

    public static void ECBEncryptionWithRandomKey(Scanner sc){
        while (true){
            try {
                System.out.print("Plain text: ");
                String plainText = sc.nextLine();
                byte[] inputText = pushDataToBlock(plainText).getBytes();
                byte[] key;
                key = makeRandomKey();
                System.out.println("Random Key: " + new String(key));
                aes = new AES(key);
                double startTime = System.currentTimeMillis();
                System.out.println("Plain text: " + plainText);
                byte [] cipherBytes = aes.ECB_encrypt(inputText);
                String a = Base64.getEncoder().encodeToString(cipherBytes);
                System.out.println("Cipher text: " + a.trim());
                double endTime = System.currentTimeMillis();
                System.out.println("ECB Encryption | "+(float)(endTime-startTime)/1000.00 + " secs");
                startTime = System.currentTimeMillis();
                System.out.println("Cipher text: " + a.trim());
                plainText = new String(aes.ECB_decrypt(cipherBytes)).trim();
                System.out.println("Plain text: " + plainText);
                endTime = System.currentTimeMillis();
                System.out.println("ECB Decryption | "+(float)(endTime-startTime)/1000 + " secs");
                plaintext = inputText;
                cipherText = cipherBytes;
                break;
            }catch (Exception e){
                System.out.println("Vui lòng nhập lại: ");
                System.out.println(e.getMessage());
            }
        }
    }

    public static void CBCEncryptionWithKey(Scanner sc){
        while (true){
            try {
                System.out.print("Plain text: ");
                String plainText = sc.nextLine();
                System.out.print("Key: ");
                String keyInput = sc.nextLine();
                System.out.print("Initialisation vector: ");
                String ivInput = sc.nextLine();
                byte[] inputText = pushDataToBlock(plainText).getBytes();
                byte[] key;
                key = keyInput.getBytes();
                byte[] iv = ivInput.getBytes();
                aes = new AES(key,iv);
                double startTime = System.currentTimeMillis();
                System.out.println("Plain text: " + plainText);
                byte [] cipherBytes = aes.CBC_encrypt(inputText);
                String a = Base64.getEncoder().encodeToString(cipherBytes);
                System.out.println("Cipher text: " + a.trim());
                double endTime = System.currentTimeMillis();
                System.out.println("CBC Encryption | "+(float)(endTime-startTime)/1000.00 + " secs");
                startTime = System.currentTimeMillis();
                System.out.println("Cipher text: " + a.trim());
                plainText = new String(aes.CBC_decrypt(cipherBytes)).trim();
                System.out.println("Plain text: " + plainText);
                endTime = System.currentTimeMillis();
                System.out.println("CBC Decryption | "+(float)(endTime-startTime)/1000 + " secs");
                plaintext = inputText;
                cipherText = cipherBytes;
                break;
            }catch (Exception e){
                System.out.println("Vui lòng nhập lại: ");
                System.out.println(e.getMessage());
            }
        }
    }

    public static void CBCEncryptionWithRandomKey(Scanner sc){
        while (true){
            try {
                System.out.print("Plain text: ");
                String plainText = sc.nextLine();
                byte[] inputText = pushDataToBlock(plainText).getBytes();
                byte[] key;
                key = makeRandomKey();
                System.out.println("Random Key: " + new String(key));
                byte[] iv = makeRandomIv();
                aes = new AES(key,iv);
                double startTime = System.currentTimeMillis();
                System.out.println("Plain text: " + plainText);
                byte [] cipherBytes = aes.CBC_encrypt(inputText);
                String a = Base64.getEncoder().encodeToString(cipherBytes);
                System.out.println("Cipher text: " + a.trim());
                String b = Base64.getEncoder().encodeToString(iv);
                System.out.println("Iv: " + b.trim());
                double endTime = System.currentTimeMillis();
                System.out.println("CBC Encryption | "+(float)(endTime-startTime)/1000.00 + " secs");
                startTime = System.currentTimeMillis();
                System.out.println("Cipher text: " + a.trim());
                plainText = new String(aes.CBC_decrypt(cipherBytes)).trim();
                System.out.println("Plain text: " + plainText);
                endTime = System.currentTimeMillis();
                System.out.println("CBC Decryption | "+(float)(endTime-startTime)/1000 + " secs");
                plaintext = inputText;
                cipherText = cipherBytes;
                break;
            }catch (Exception e){
                System.out.println("Vui lòng nhập lại: ");
                System.out.println(e.getMessage());
            }
        }
    }

    public static void diffBit(){
        System.out.println("Plain text: " + new String(plaintext));
        System.out.println("Cipher text: " + Base64.getEncoder().encodeToString(cipherText));
        System.out.println("Số bits khác biệt: " + numBitDiff(plaintext,cipherText) );
    }

    private static String pushDataToBlock(String text) {
        int spaceNum = text.getBytes().length % 16 == 0 ? 0 : 16 - text.getBytes().length % 16;
        StringBuilder textBuilder = new StringBuilder(text);
        textBuilder.append(" ".repeat(spaceNum));
        text = textBuilder.toString();
        return text;
    }

    private static byte[] makeRandomKey() {
        String key = "";
        int length = 2+new Random().nextInt(2);
        for (int i = 0; i < length; i++) key += Long.toHexString(Double.doubleToLongBits(Math.random()));
        return key.getBytes();
    }

    private static byte[] makeRandomIv() {
        String key = "";
        for (int i = 0; i < 2; i++) key += Long.toHexString(Double.doubleToLongBits(Math.random()));
        return key.getBytes();
    }

    private static int numBitDiff(byte[] a, byte[] b) {
        int num = 0;
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int j = 0; j < result.length; j++) {
            int xor = a[j] ^ b[j];
            while(xor>0){
                int temp = xor%2;
                if(temp==1) num++;
                xor/=2;
            }
        }
        return num;
    }
}
