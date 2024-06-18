package com.example;

import org.apache.shiro.crypto.hash.Sha512Hash;
import org.apache.shiro.util.ByteSource;

import java.security.SecureRandom;
import java.util.Base64;

public class ShiroHashingExample {
    private static final int SALT_LENGTH = 16; // 16 bytes

    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String hashPassword(String password, String salt, int iterations, boolean isHex) {
        byte[] saltBytes;
        if (isHex) {
            saltBytes = hexStringToByteArray(salt);
        } else {
            saltBytes = Base64.getDecoder().decode(salt);
        }
        ByteSource saltByteSource = ByteSource.Util.bytes(saltBytes);
        Sha512Hash hash = new Sha512Hash(password, saltByteSource, iterations);
        return Base64.getEncoder().encodeToString(hash.getBytes());
    }

    public static void main(String[] args) {
        if (args.length < 2 || args.length > 3) {
            System.err.println("Usage: java -jar shiro-hash.jar <string-to-hash> <iterations> [hex-salt]");
            System.exit(1);
        }

        String password = args[0];
        int iterations;
        try {
            iterations = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            System.err.println("Invalid number of iterations: " + args[1]);
            System.exit(1);
            return;
        }

        String salt;
        String hashedPassword;
        if (args.length == 3) {
            salt = args[2];
	    byte[] saltBytes;
	    saltBytes = hexStringToByteArray(salt);
            hashedPassword = hashPassword(password, salt, iterations, true);
            System.out.println("$shiro1$SHA-512$" + iterations + "$" + Base64.getEncoder().encodeToString(saltBytes) + "$" + hashedPassword);
        } else {
            salt = generateSalt();
            hashedPassword = hashPassword(password, salt, iterations, false);
            System.out.println("$shiro1$SHA-512$" + iterations + "$" + salt + "$" + hashedPassword);
        }
    }
}

