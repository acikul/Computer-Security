import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.SecureRandom;
//import java.security.MessageDigest;

import java.util.Arrays;

class MyCryptoFunctions {
	
	//AES-128 enkripcija
	//vraća IV konkateniran na enkriptirane podatke
	public static byte[] encrypt(byte[] data, SecretKey key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecureRandom secRandom = new SecureRandom();
		
		byte[] IV = new byte[cipher.getBlockSize()];
		secRandom.nextBytes(IV);
		IvParameterSpec ivParam = new IvParameterSpec(IV);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
		byte[] encrypted = cipher.doFinal(data);
		
		byte[] ivPlusEncrypted = PasswordManager.concat(IV, encrypted);
		return ivPlusEncrypted;
	}
	
	//AES-128 dekripcija
	public static byte[] decrypt(byte[] data, SecretKey key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		byte[] IV = new byte[cipher.getBlockSize()];
		IV = Arrays.copyOf(data, IV.length);
		IvParameterSpec ivParam = new IvParameterSpec(IV);
		
		byte[] encrypted = Arrays.copyOfRange(data, IV.length, data.length);
		cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
		byte[] decrypted = cipher.doFinal(encrypted);
		return decrypted;
	}
	
	//HmacSHA512 funkcija
	public static byte[] hmac(byte[] data, SecretKey key) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {		
		Mac MAC = Mac.getInstance("HmacSHA512");
		MAC.init(key);
		return MAC.doFinal(data);
	}
	
	//kriptografski siguran generator random brojeva
	public static byte[] RNG(int size) {
		SecureRandom secRand = new SecureRandom();
		byte[] rtrn = new byte[size];
		
		secRand.nextBytes(rtrn);
		return rtrn;
	}
	
	//funkcija za derivaciju ključa duljine 128 bitova iz zadanog izvornog passworda i salta
	public static SecretKey keyGen(String password, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
		
		SecretKey tmp = skf.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
		
		return key;
	}
}

public class PasswordManager {
	
	private static SecretKey encriptionKey;
	private static SecretKey macKey;
	private static byte[] encriptionSalt;
	private static byte[] macSalt;
	
	//pomocne funkcije za concat
	public static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		
		return c;
	}
	public static byte[] concat(byte[] a, byte[] b, byte[] d) {
		byte[] c = new byte[a.length + b.length+d.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		System.arraycopy(d, 0, c, a.length+b.length, d.length);
		
		return c;
	}
	public static byte[] concat(byte[] a, byte[] b, byte[] d, byte[] e) {
		byte[] c = new byte[a.length + b.length + d.length + e.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		System.arraycopy(d, 0, c, a.length+b.length, d.length);
		System.arraycopy(e, 0, c, a.length+b.length+d.length, e.length);
		
		return c;
	}
	
	//pomocna funkcija za provjeru postoji li vault datoteka
	private static boolean checkDir() {
		String vaultPath = System.getProperty("user.dir") + "/vault";
		
		File vault = new File(vaultPath);
		
		return vault.exists();
	}
	
	//funkcija za inicijalizaciju vault datoteke
	private static void init(String maspass) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		String vaultPathTmp = System.getProperty("user.dir") + "/vault";
		
		Path vaultPath = Paths.get(vaultPathTmp);
		
		File vault = new File(vaultPathTmp);
		
		Files.deleteIfExists(vaultPath);
		
		vault.createNewFile();
				
		encriptionSalt = MyCryptoFunctions.RNG(256);
		macSalt = MyCryptoFunctions.RNG(256);
		
		encriptionKey = MyCryptoFunctions.keyGen(maspass, encriptionSalt);
		macKey = MyCryptoFunctions.keyGen(maspass, macSalt);
		
		byte[] vaultData = Files.readAllBytes(vaultPath);
		byte[] encrypted = MyCryptoFunctions.encrypt(vaultData, encriptionKey);
		byte[] hmac = MyCryptoFunctions.hmac(encrypted, macKey);
		byte[] macSaltHmacEncEncSalt = concat(macSalt, hmac, encrypted, encriptionSalt);
		
		try (FileOutputStream out = new FileOutputStream(vault)) {
			out.write(macSaltHmacEncEncSalt);
			out.close();
		}
		System.out.println("Inicijalizacija obavljena!");
	}
	
	//funkcija koja se obavlja prije izvršavanja put i get akcija
	//provjerava postojanje vault datoteke te provodi integrity check ako postoji
	private static boolean entrance(String masterPasswordString) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
		if (!checkDir()) {
			System.out.println("Vault datotetka nedostaje, ponovno pokrenite inicijalizaciju!");
			System.exit(0);
		}
		
		String vaultPathTmp = System.getProperty("user.dir") + "/vault";
		
		Path vaultPath = Paths.get(vaultPathTmp);
		
		byte[] vaultData = Files.readAllBytes(vaultPath);
		
		macSalt = Arrays.copyOf(vaultData, 256);
		encriptionSalt = Arrays.copyOfRange(vaultData, vaultData.length-256, vaultData.length);

		encriptionKey = MyCryptoFunctions.keyGen(masterPasswordString, encriptionSalt);
		macKey = MyCryptoFunctions.keyGen(masterPasswordString, macSalt);

		byte[] hmacBefore = Arrays.copyOfRange(vaultData, 256, 320);
		byte[] encrypted = Arrays.copyOfRange(vaultData, 320, vaultData.length-256);
		byte[] hmacNow = MyCryptoFunctions.hmac(encrypted, macKey);

		if (!Arrays.equals(hmacBefore, hmacNow)) {
			System.out.println("Krivi master password ili integritet vault-a kompromitiran!!!");
			System.exit(0);
		}
		return true;
	}
	
	//pomoćna funkcija za traženje stavke sa zadanom adresom
	private static String search(String adresa, byte[] data) throws UnsupportedEncodingException {
		String ds = new String(data, "UTF-8");
		String[] stavke = ds.split("	");
		
		for (String i : stavke) {
			String adresaSplit = i.split(" ")[0];
			if (adresaSplit.equals(adresa)){
				return i;
			}
		}
		return null;
	}
	
	//funkcija za spremanje/azuriranje zaporke za zadanu adresu
	//dekriptira, sprema novu stavku ili pronalazi i ažurira postojeću i ponovno enkriptira
	private static void put(String masterPasswordString, String adresa, String zaporka) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		String vaultPath = System.getProperty("user.dir") + "/vault";
		Path path = Paths.get(vaultPath);
		byte[] data = Files.readAllBytes(path);
		
		byte[] encryptedTmp = Arrays.copyOfRange(data, 320, data.length-256);
		byte[] decrypted = MyCryptoFunctions.decrypt(encryptedTmp, encriptionKey);
		
		//generiranje novih saltova i ključeva za enkripciju
		macSalt = MyCryptoFunctions.RNG(256);
		encriptionSalt = MyCryptoFunctions.RNG(256);

		encriptionKey = MyCryptoFunctions.keyGen(masterPasswordString, encriptionSalt);
		macKey = MyCryptoFunctions.keyGen(masterPasswordString, macSalt);
		
		if (search(adresa, decrypted) == null) {
			String novaStavka = adresa + " " + zaporka + "	";
			byte[] novaStavkaByte = novaStavka.getBytes("UTF-8");
			
			byte[] novaStavkaNaSve = concat(decrypted, novaStavkaByte);
			byte[] encrypted = MyCryptoFunctions.encrypt(novaStavkaNaSve, encriptionKey);
			
			byte[] hmac = MyCryptoFunctions.hmac(encrypted, macKey);
			byte[] saltHmacEncryptedEncSalt = concat(macSalt, hmac, encrypted, encriptionSalt);
			
			try (FileOutputStream out = new FileOutputStream("vault")) {
				out.write(saltHmacEncryptedEncSalt);
				out.close();
				System.out.println("Spremljena zaporka za: " + adresa);
				System.exit(0);
			}
		} else {
			String izmjenjenaStavka = adresa + " " + zaporka + "	";
			String sveStavkeString = new String(decrypted, "UTF-8");
			String[] sveStavke = sveStavkeString.split("	");
			for (int i = 0; i < sveStavke.length; i++) {
				if (sveStavke[i].contains(adresa)) {
					sveStavke[i] = izmjenjenaStavka;
					break;
				}
			}
			String rebuild = "";
			for (String i : sveStavke) {
				rebuild += i + "	";
			}
			byte[] rebuildByte = rebuild.getBytes("UTF-8");
			
			byte[] encrypted = MyCryptoFunctions.encrypt(rebuildByte, encriptionKey);
			
			byte[] hmac = MyCryptoFunctions.hmac(encrypted, macKey);
			byte[] saltHmacEncryptedEncSalt = concat(macSalt, hmac, encrypted, encriptionSalt);
			
			try (FileOutputStream out = new FileOutputStream("vault")) {
				out.write(saltHmacEncryptedEncSalt);
				out.close();
				System.out.println("Izmijenjena zaporka za: " + adresa);
				System.exit(0);
			}
		}

	}
	
	//funckija za dohvaćanje zaporke za zadanu adresu
	private static void get(String adresa) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String vaultPath = System.getProperty("user.dir") + "/vault";
		Path path = Paths.get(vaultPath);
		byte[] data = Files.readAllBytes(path);
		
		byte[] encryptedTmp = Arrays.copyOfRange(data, 320, data.length-256);
		byte[] decrypted = MyCryptoFunctions.decrypt(encryptedTmp, encriptionKey);
		
		boolean found = false;
		String s = search(adresa, decrypted);
		if(!(s == null)) {
			found = true;
			System.out.println("Zaporka za " + adresa + ": " + s.split(" ")[1]);
		}

		if(!found) {
			System.out.println("Za tu adresu nije spremljena zaporka!");
		}
		System.exit(0);
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
		if (args.length==0) {
			System.out.println("Nije moguće pokretanje bez argumenata!");
			System.exit(0);
		}
		String naredba = args[0];
		
		switch(naredba) {
			case "init":
				init(args[1]);
				break;
				
			case "put":
				if (entrance(args[1])) {
					put(args[1], args[2], args[3]);
				}
				break;
				
			case "get":
				if (entrance(args[1])) {
					get(args[2]);
				}
				break;
			default:
				System.out.println("Neispravno upisana naredba!");
				System.exit(0);
				break;
		}
	}
}
