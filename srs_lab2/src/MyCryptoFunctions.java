import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MyCryptoFunctions {
	
	//kriptografski siguran generator random brojeva
	public static byte[] RNG(int size) {
		SecureRandom secRand = new SecureRandom();
		byte[] rtrn = new byte[size];
		
		secRand.nextBytes(rtrn);
		return rtrn;
	}
	
	//hash funkcija - PBKDF2WithHmacSHA256 (hash(odn. kljuc) duljine 128 byte-ova)
	public static byte[] hash(String password, byte [] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 2048);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		
		return skf.generateSecret(keySpec).getEncoded();

	}
}