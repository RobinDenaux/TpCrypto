package tpCrypto;

import javax.swing.JFrame;

import Affichage.Accueil;
import tpCrypto.denaux.SignatureManager;

public class Main {

	public static SignatureManager sigManager;
	public static String name = "Robin";
	public static String pass = "keypass";
	public static String kspass = "kspass";
	
	public static void main(String[] args) {
		sigManager = new SignatureManager("store.ks");
		
		byte[] tmp = sigManager.generateSignature("docTest.txt", name, pass, kspass);
		
		System.out.println(sigManager.verify("docTest2.txt", tmp, name, kspass));
	
		JFrame frame = new JFrame();
		Accueil accueil = new Accueil(frame, true);
		accueil.launch();
	}

}
