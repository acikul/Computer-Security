import java.io.Serializable;

public class HashSaltForced implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	byte[] hashedSaltPass;
	byte[] salt;
	boolean forced;
	
	public HashSaltForced(byte[] hashedSaltPass, byte[] salt, boolean forced) {
		this.hashedSaltPass = hashedSaltPass;
		this.salt = salt;
		this.forced = forced;
	}
}