package tpCrypto;

import tpCrypto.denaux.SignatureManager;

public class Main {

	public static void main(String[] args) {
		SignatureManager sigManager = new SignatureManager("store.ks");
		
		byte[] tmp = sigManager.generateSignature("docTest.txt", "Robin", "keypass", "kspass");
		
		System.out.println(sigManager.verify("docTest2.txt", tmp, "Robin", "keypass", "kspass"));
	}

}
