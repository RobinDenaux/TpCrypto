package tpCrypto;

import javax.swing.JFrame;

import Affichage.Accueil;
import tpCrypto.denaux.SignatureManager;

public class Main {

	public static void main(String[] args) {
		SignatureManager sigManager = new SignatureManager("store.ks");
		
		byte[] tmp = sigManager.generateSignature("docTest.txt", "Robin", "keypass", "kspass");
		
		System.out.println(sigManager.verify("docTest2.txt", tmp, "Robin", "kspass"));
	
		JFrame frame = new JFrame();
		Accueil accueil = new Accueil(frame, true);
		accueil.launch();
	}

}
