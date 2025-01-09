import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            PrintTitle();

            String algorithm = getAlgorithm(scanner);

            SecretKey secretKey = getKey(algorithm, scanner);

            validateKey(secretKey, algorithm);

            File file = getFile(scanner);

            if (file.isDirectory()) {
                decryptFilesRecursively(secretKey, file, algorithm);
            } else {
                decryptFile(secretKey, file, algorithm);
            }

            System.out.println("Decryption completed successfully.");
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid algorithm choice or secret key.");
        } catch (FileNotFoundException e) {
            System.out.println(e.getMessage());
        } catch (Exception e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }

    private static File getFile(Scanner scanner) throws Exception {
        System.out.println("Enter the path of the directory or file to encrypt: ");
        String filePath = scanner.nextLine().trim();

        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("Invalid file or directory path.");
        }
        return file;
    }

    private static String getAlgorithm(Scanner scanner) {
        System.out.println("1. AES");
        System.out.println("2. Blowfish");
        System.out.println("Choose an encryption algorithm: ");
        int algoChoice = scanner.nextInt();
        scanner.nextLine();

        return switch (algoChoice) {
            case 1 -> "AES";
            case 2 -> "Blowfish";
            default -> throw new IllegalArgumentException("Invalid choice for algorithm.");
        };
    }

    private static SecretKey getKey(String algorithm, Scanner scanner) {
        try {
            System.out.print("Enter the secret key (Base64 encoded): ");
            String secretKeyBase64 = scanner.nextLine();
            byte[] decodedKey = Base64.getDecoder().decode(secretKeyBase64);
            return new SecretKeySpec(decodedKey, algorithm);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 key.");
        }
    }

    private static void validateKey(SecretKey secretKey, String algorithm) throws InvalidKeyException {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] dummyData = "validate_key".getBytes();
            byte[] encryptedDummyData = cipher.doFinal(dummyData);

            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedDummyData = cipher.doFinal(encryptedDummyData);

            if (!new String(decryptedDummyData).equals("validate_key")) {
                throw new InvalidKeyException("Invalid secret key.");
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    private static void decryptFilesRecursively(SecretKey secretKey, File directory, String algorithm) throws Exception {
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }

        for (File file : files) {
            if (file.isDirectory()) {
                decryptFilesRecursively(secretKey, file, algorithm);
            } else {
                decryptFile(secretKey, file, algorithm);
            }
        }
    }

    private static void decryptFile(SecretKey secretKey, File file, String algorithm) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(fileBytes);
        Files.write(file.toPath(), decryptedBytes);
        System.out.println("(＾▽＾) Decrypted file: " + file.getAbsolutePath());
    }

    private static void PrintTitle(){
        System.out.println();
        System.out.println("""
                
                _____________________________  ________________________.___._____________________
                \\______   \\_   _____/\\______ \\ \\_   ___ \\______   \\__  |   |\\______   \\__    ___/
                 |       _/|    __)_  |    |  \\/    \\  \\/|       _//   |   | |     ___/ |    |  \s
                 |    |   \\|        \\ |    `   \\     \\___|    |   \\\\____   | |    |     |    |  \s
                 |____|_  /_______  //_______  /\\______  /____|_  // ______| |____|     |____|  \s
                        \\/        \\/         \\/        \\/       \\/ \\/                           \s
                
                """);
        System.out.println();
        System.out.println(" * Welcome to REDCRYPT - The file encryption / decryption tool.");
        System.out.println(" * This tool uses AES, DES, or Blowfish encryption algorithms to encrypt and decrypt files.");
        System.out.println(" * This tool is for educational purposes only. Do not use it for malicious purposes.");
        System.out.println(" > This tool was proudly developed by ENNACHAT Redwan.");
        System.out.println();
    }
}
