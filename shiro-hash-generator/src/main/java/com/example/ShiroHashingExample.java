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

    public static String hashPassword(String password, String salt, int iterations) {
        ByteSource saltBytes = ByteSource.Util.bytes(Base64.getDecoder().decode(salt));
        Sha512Hash hash = new Sha512Hash(password, saltBytes, iterations);
        return Base64.getEncoder().encodeToString(hash.getBytes());
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java -jar shiro-hash.jar <string-to-hash> <iterations>");
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

        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt, iterations);
        System.out.println("$shiro1$SHA-512$" + iterations + "$" + salt + "$" + hashedPassword);
    }
}

