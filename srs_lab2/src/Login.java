import java.io.Console;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Login {
	
	private static Console c = System.console();
	private static String userPassPathTmp = System.getProperty("user.dir") + "/userpass";
	private static File userPass = new File(userPassPathTmp);	
	private static byte[] salt;
	private static Map<String, HashSaltForced> userPassMap = new HashMap<String, HashSaltForced>();

	//pomocna funckija za unos sifre i ponovljeni unos sifre
	private static String unosPass(String user) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String retLozinka = null;
		boolean passwdMatch = false;
		
		while(!passwdMatch) {
			retLozinka = String.valueOf(c.readPassword("New password: "));

			while (retLozinka.length() < 8) {
				System.out.println("Password must have at least 8 characters!");
				retLozinka = String.valueOf(c.readPassword("New password: "));
			}
			String opetLozinka = String.valueOf(c.readPassword("Repeat new password: "));

			if (!retLozinka.equals(opetLozinka)) {
				System.out.println("New password mismatch!\n");
			} else {
				HashSaltForced userChunk = userPassMap.get(user);
				byte[] stariHash = userChunk.hashedSaltPass;
				byte[] stariSalt = userChunk.salt;
				byte[] noviHashStariSalt = MyCryptoFunctions.hash(retLozinka, stariSalt);
				if (Arrays.equals(stariHash, noviHashStariSalt)) {
					System.out.println("New password cannot be the same as old password!\n");
				} else {
					passwdMatch = true;
				}
			}
		}

		return retLozinka;
	}

	//pomocna funkcija za deserijaliziranje/ucitavanje mape iz datoteke
	@SuppressWarnings("unchecked")
	public static void loader() {
		try {
			FileInputStream fileIn = new FileInputStream("userpass");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			userPassMap = (Map<String, HashSaltForced>) in.readObject();
			in.close();
			fileIn.close();
		} catch (EOFException e) {
			//				e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	//pomocna funckija za serijalizaciju/zapisivanje mape u datoteku
	private static void zapis() throws FileNotFoundException, IOException {

		try {
			FileOutputStream fileOut = new FileOutputStream("userpass");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(userPassMap);
			out.close();
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (args.length==0) {
			System.out.println("Nije moguće pokretanje bez argumenata!\n");
			System.exit(0);
		}
		//ako nema userPass datoteke stvara novu
		if (!userPass.exists()) {
			userPass.createNewFile();
		}
		
		String user = args[0];
		loader();
		boolean loginSuccess = false;
		
		while(!loginSuccess) {
			String lozinka = String.valueOf(c.readPassword("Password: "));
			
			if (!userPassMap.containsKey(user)) {
				System.out.println("Username or password incorrect.\n");
				continue;
			} else {
				HashSaltForced userChunk = userPassMap.get(user);
				byte[] stariHash = userChunk.hashedSaltPass;
				byte[] stariSalt = userChunk.salt;
				
				byte[] noviHashStariSalt = MyCryptoFunctions.hash(lozinka, stariSalt);
				if (!Arrays.equals(stariHash, noviHashStariSalt)) {
					System.out.println("Username or password incorrect.\n");
					continue;
				}
				if (userChunk.forced) {
					String novaLozinka = unosPass(user);
					byte[] noviSalt = MyCryptoFunctions.RNG(256);
					byte[] noviHashNoviSalt = MyCryptoFunctions.hash(novaLozinka, noviSalt);

					HashSaltForced noviChunk= new HashSaltForced(noviHashNoviSalt, noviSalt, userChunk.forced);
					userPassMap.put(user, noviChunk);
				}
				System.out.println("Login successful.\n");
				loginSuccess = true;
			}
		}
		zapis();
	}

}
