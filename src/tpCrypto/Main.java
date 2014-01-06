package tpCrypto;

import javax.swing.JFrame;

import Affichage.Accueil;
import tpCrypto.denaux.SignatureManager;

public class Main {

	public static SignatureManager sigManager;
	public static String name = "";
	public static String pass = "";
	public static String kspass = "";
	
	public static void main(String[] args) {
		sigManager = new SignatureManager("store.ks");
	
		JFrame frame = new JFrame();
		Accueil accueil = new Accueil(frame, true);
		accueil.launch();
	}

}
