package tpCrypto.denaux;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import Affichage.Identifier;
import tpCrypto.Main;

public class SignatureManager {
	private String ksName;

	public SignatureManager(String ksName){
		this.ksName = ksName;
	}

	public byte[] generateSignature(String filePath, String name, String pass, String ksPass){
		return this.generateSignature(new File(filePath), name, pass, ksPass);
	}

	public byte[] generateSignature(File file, String name, String pass, String ksPass){
		BufferedInputStream bin;
		byte[] signature;
		Signature signer;
		PrivateKey priKey = getPriKey(name, pass, ksPass);
		try {
			signer = Signature.getInstance("SHA1withDSA");
			signer.initSign(priKey);
			bin = new BufferedInputStream(new FileInputStream(file));
			byte[] buffer = new byte[1024];
			int nr;
			while((nr = bin.read(buffer)) != -1)
				signer.update(buffer, 0, nr);
			signature = signer.sign();
			bin.close();
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		return signature;
	}

	private PrivateKey getPriKey(String name, String pass, String ksPass){
		PrivateKey pKUser;
		KeyStore ks;
		
		try {
			ks = KeyStore.getInstance("JCEKS");
			InputStream is = new BufferedInputStream(new FileInputStream(ksName));
			ks.load(is, ksPass.toCharArray());
			pKUser = (PrivateKey) ks.getKey(name, pass.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return pKUser;
	}
	
	private PublicKey getPubKey(String name, String ksPass){
		PublicKey pKUser;
		KeyStore ks;
		
		try {
			ks = KeyStore.getInstance("JCEKS");
			InputStream is = new BufferedInputStream(new FileInputStream(ksName));
			ks.load(is, ksPass.toCharArray());
			pKUser = ks.getCertificate(name).getPublicKey();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return pKUser;
	}
	
	private void addUser(String name, String pass, String ksPass){
		KeyPair kpUser = generateKeyPair();
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("JCEKS");
			InputStream is = new BufferedInputStream(new FileInputStream(ksName));
			ks.load(is, ksPass.toCharArray());
			//TODO remplacer par une PrivateKeyEntry
			ks.setKeyEntry(name, kpUser.getPrivate(), pass.toCharArray(), null);
			OutputStream os = new BufferedOutputStream(new FileOutputStream(ksName));
			ks.store(os, ksPass.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
	}

	public KeyPair generateKeyPair(){
		KeyPairGenerator kpg;
		KeyPair kp;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("probleme a la generation de la cle pair");
			e.printStackTrace();
			return null;
		}
		return kp;
	}

	public boolean verify(String filePath, byte[] sig, String name, String ksPass){
		Signature signer;
		try {
			signer = Signature.getInstance("SHA1withDSA");
			signer.initVerify(getPubKey(name, ksPass));
			   BufferedInputStream bin = new BufferedInputStream(new FileInputStream(filePath));
			   byte[] buffer = new byte[1024];
			   int nr;
			   while((nr = bin.read(buffer)) != -1)
			      signer.update(buffer, 0, nr);
			
			return signer.verify(sig);
		} catch (NoSuchAlgorithmException | SignatureException | IOException | InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	return false;
	}

	public void saveSignature(String absolutePath, String name, String pass, String kspass) {
		// TODO Loïc
		byte[] signature = generateSignature(absolutePath, name, pass, kspass);
		
		CharBuffer cbuf = CharBuffer.wrap(Main.name.toCharArray());
		ByteBuffer bbuf = Charset.defaultCharset().encode(cbuf);
		byte[] Bname = bbuf.array();
		
		byte[] result = new byte[Main.name.length()+signature.length+1];
		result[0] = (byte)Main.name.length();
		
		for(int i=0; i<Main.name.length(); i++)
			result[i+1] = Bname[i];
		
		for(int i=Main.name.length(); i<Main.name.length()+signature.length; i++)
			result[i+1] = signature[i-Main.name.length()];
		
		try {
			FileOutputStream fileOut = new FileOutputStream(new File(absolutePath+".sig"));
			fileOut.write(result);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void loadSignature(String absolutePath, Identifier identifier) throws IOException{
		File file = new File(absolutePath+".sig");
		FileInputStream fileIn = new FileInputStream(file);
		byte[] taille = new byte[1];
		fileIn.read(taille);
		byte[] Bname = new byte[taille[0]];
		fileIn.read(Bname);
		byte[] signature = new byte[fileIn.available()];
		fileIn.read(signature);
		identifier.signature = signature;
		identifier.Sname = new String(Bname);
	}

}
