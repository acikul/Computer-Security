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
import java.util.HashMap;
import java.util.Map;

public class UserMgmt {
	
	private static Console c = System.console();
	private static String userPassPathTmp = System.getProperty("user.dir") + "/userpass";
	private static File userPass = new File(userPassPathTmp);	
	private static byte[] salt;
	private static Map<String, HashSaltForced> userPassMap = new HashMap<String, HashSaltForced>();

	//dodavanje novog usera i lozinke
	private static void add(String user) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		loader();
		
		if (userPassMap.containsKey(user)) {
			System.out.println("User already exists!\n");
			System.exit(0);
		}
		
		String lozinka = unosPass("add");
		salt = MyCryptoFunctions.RNG(256);
		byte[] hashedSaltedPass = MyCryptoFunctions.hash(lozinka, salt);
		
		HashSaltForced userChunk = new HashSaltForced(hashedSaltedPass, salt, false);
		userPassMap.put(user, userChunk);
		
		zapis(user, "add");
	}
	
	//izmjena lozinke postojeceg korisnika
	private static void passwd(String user) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IOException {
		loader();
		
		//ako user ne postoji - izlaz
		if (!userPassMap.containsKey(user)) {
			System.out.println("No such user!\n");
			System.exit(0);
		} else {
			//nova lozinka i salt
			String novaLozinka = unosPass("passwd");
			salt = MyCryptoFunctions.RNG(256);
			byte[] hashedSaltedPass = MyCryptoFunctions.hash(novaLozinka, salt);

			HashSaltForced noviChunk= new HashSaltForced(hashedSaltedPass, salt, userPassMap.get(user).forced);
			userPassMap.put(user, noviChunk);
			
			zapis(user, "passwd");
		}
	}
	
	//forsiranje promjene lozinke za usera
	private static void forcepass(String user) throws FileNotFoundException, IOException {
		loader();
		
		//ako user ne postoji - izlaz
		if (!userPassMap.containsKey(user)) {
			System.out.println("No such user!\n");
			System.exit(0);
		} else {
			HashSaltForced zaIzmjenuForced = userPassMap.get(user);
			zaIzmjenuForced.forced = true;
			
			userPassMap.put(user, zaIzmjenuForced);
			
			zapis(user, "forcedpass");
		}
	}
	
	//uklanjanje usera i lozinke
	private static void del(String user) throws FileNotFoundException, IOException {
		loader();

		//ako user ne postoji - izlaz
		if (!userPassMap.containsKey(user)) {
			System.out.println("No such user!\n");
			System.exit(0);
		} else {
			userPassMap.remove(user);
			
			zapis(user, "del");
		}
	}
	
	//pomocna funckija za unos sifre i ponovljeni unos sifre
	private static String unosPass(String param) {
		boolean isMismatched = true;
		String retLozinka = null;

		while(isMismatched) {

			retLozinka = String.valueOf(c.readPassword("Password: "));

			while (retLozinka.length() < 8) {
				System.out.println("Password must have at least 8 characters!");
				retLozinka = String.valueOf(c.readPassword("Password: "));
			}
			String opetLozinka = String.valueOf(c.readPassword("Repeat password: "));

			if (!retLozinka.equals(opetLozinka)) {
				if (param.equals("add")) {
					System.out.println("User add failed. Password mismatch.\n");
				} else if (param.equals("passwd")) {
					System.out.println("Password change failed. Password mismatch.\n");
				}
			} else {
				isMismatched = false;
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
//			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	//pomocna funckija za serijalizaciju/zapisivanje mape u datoteku
	private static void zapis(String user, String param) throws FileNotFoundException, IOException {
		
		try {
			FileOutputStream fileOut = new FileOutputStream("userpass");
			ObjectOutputStream out = new ObjectOutputStream(fileOut);
			out.writeObject(userPassMap);
			out.close();
			
			if (param.equals("add")) {
				System.out.println("User " + user + " successfully added.\n");
			} else if (param.equals("passwd")) {
				System.out.println("Password change successful.\n");
			} else if (param.equals("forcedpass")) {
				System.out.println(user + " will be requested to change password on next login.\n");
			} else if (param.equals("del")) {
				System.out.println("User successfully removed.\n");
			}
			
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}
		
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		if (args.length==0) {
			System.out.println("Nije moguće pokretanje bez argumenata!\n");
			System.exit(0);
		}
		//ako nema userPass datoteke stvara novu
		if (!userPass.exists()) {
			userPass.createNewFile();
		}
		
		String naredba = args[0];
		String user = args[1];
		
		if (args[1].length()==0) {
			System.out.println("User must be specified!\n");
			System.exit(0);
		}
		
		switch(naredba) {
			case "add":
				add(user);
				break;
				
			case "passwd":
				passwd(user);
				break;
				
			case "forcepass":
				forcepass(user);
				break;
				
			case "del":
				del(user);
				break;
			default:
				System.out.println("Krivo zadani argumenti!\n");
				break;
		}
		
	}
}
