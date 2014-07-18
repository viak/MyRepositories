package RSA;

import java.io.ByteArrayOutputStream;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * RSA 加密解密
 * @author zhuzhe
 */
public class RSAUtil extends Coder{
	
	public static final String KEY_ALGORITHM = "RSA";
	
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	private static final String RSA_PRIVATE_KEY = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBALfNuSqaGSS7LJIF" + "\r" +
												 "Yb3snVzfHFSUaL1FoOgUWI+ocbZoIeL6F0OVq+iEvREDtBaR85svksm/SCfa92D/" + "\r" +
												 "0q51G0cFIFUvNHKgXopOBXFVft1W8LSLvtknQrR+Vhim+yNM6jvoItZB4c/jObLa" + "\r" +
												 "ZZPSm9cIB+X92ReVMiz9/DFPh/EtAgMBAAECgYEAq8ZXhrj9Rpam0NC2yAiaCHF6" + "\r" +
												 "yJDqUfkAp+Rb3+ZMX2xyPu37T+5Q+r0S9RPA+lbsk9uiE2nwxU6eYsiy3NgU5HLi" + "\r" +
												 "JFDxL0Xii0lxwUU6WS7eLEhYzSLlLn2XIEUmXQdRvronFogYa6v2+6oEEbe5bNYF" + "\r" +
												 "nPwQVNtESxYOe5xIUwECQQDxXNgji6h14awXnlaeK9LjtWS2vTWlV/I/J1bCYKRz" + "\r" +
												 "d9g77rB7odaqV9T892xQLyOIZMIIkYWNoICQWAQlXoI3AkEAwvNGQvFIMnA5Pz4h" + "\r" +
												 "tXhdNCMfhUT1phZJ/ifx7N5MXjM7w9p25eLvCeyrK0ZQdHfIkRTiJT2aI9G2wDFY" + "\r" +
												 "DcpFuwJBAOz2MCVFudByDRjrFTMY52Uz83sNbBu2qliicKVJaGsM4DiG8LGQhEad" + "\r" +
												 "ELiC2c4nWYVRFsZ+yFXxnAcawodFsCUCQQCY2ZTlN7ibk1HPPC/B0LWDA2bbXs4b" + "\r" +
												 "gq5RD5CnX0QRN6pMTSWb6OnyphUuwNqj9qbS2cTV3g7UtsDKv+WCKm2xAkArbXOY" + "\r" +
												 "NN4FZILTRhW5ACvfGGmLr2nLVHhKN9cOrGPGJJevkQQ+u8l9APmhsYpKG5ANIWdm" + "\r" +
												 "GkzvAqWa2gpGgIi9";
	
	private static final String RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3zbkqmhkkuyySBWG97J1c3xxU" + "\r" +
												 "lGi9RaDoFFiPqHG2aCHi+hdDlavohL0RA7QWkfObL5LJv0gn2vdg/9KudRtHBSBV" + "\r" +
												 "LzRyoF6KTgVxVX7dVvC0i77ZJ0K0flYYpvsjTOo76CLWQeHP4zmy2mWT0pvXCAfl" + "\r" +
												 "/dkXlTIs/fwxT4fxLQIDAQAB";

	/**
	 * 用私钥对信息生成数字签名
	 * @param data 加密数据
	 * @throws Exception
	 */
	public static String sign(byte[] data) throws Exception {
		// 解密私钥
		byte[] keyBytes = decryptBASE64(RSA_PRIVATE_KEY);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPrivateKey priKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);
		return encryptBASE64(signature.sign());
	}

	/**
     * 校验数字签名
	 * @param data 加密数据
	 * @param sign 数字签名
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 */
	public static boolean verify(byte[] data , String sign)throws Exception {
		byte[] keyBytes = decryptBASE64(RSA_PUBLIC_KEY);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);
		
		// 验证签名是否正常
		return signature.verify(decryptBASE64(sign));
	}

	/**
	 * 用私钥解密
	 * @param data 加密数据
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data)throws Exception {
		byte[] keyBytes = decryptBASE64(RSA_PRIVATE_KEY);

		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);

		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM,new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		int blockSize = cipher.getBlockSize();
		
		ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
		int j = 0;
		while (data.length - j * blockSize > 0) {
			bout.write(cipher.doFinal(data, j * blockSize, blockSize));
			j++;
		}
		return bout.toByteArray();
	}

	/**
	 * 用公钥解密
	 * @param data 加密数据
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data)throws Exception {
		byte[] keyBytes = decryptBASE64(RSA_PUBLIC_KEY);

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);

		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM,new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		int blockSize = cipher.getBlockSize();
		
		ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
		int j = 0;
		while (data.length - j * blockSize > 0) {
			bout.write(cipher.doFinal(data, j * blockSize, blockSize));
			j++;
		}
		return bout.toByteArray();
	}

	/**
	 * 用公钥加密
	 * @param data 加密数据
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data)throws Exception {
		byte[] keyBytes = decryptBASE64(RSA_PUBLIC_KEY);

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);

		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM,new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		int blockSize = cipher.getBlockSize();
		int outputSize = cipher.getOutputSize(data.length);
		int leavedSize = data.length % blockSize;
		int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
		byte[] raw = new byte[outputSize * blocksSize];
		
		int i = 0;
		while (data.length - i * blockSize > 0) {
			if (data.length - i * blockSize > blockSize){
				cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
			}else{
				cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
			}
			i++;
		}
		return raw;
	}

	/**
	 * 用私钥加密
	 * @param data 加密数据
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data)throws Exception {
		byte[] keyBytes = decryptBASE64(RSA_PRIVATE_KEY);

		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);

		Cipher cipher = Cipher.getInstance(KEY_ALGORITHM,new org.bouncycastle.jce.provider.BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		
		int blockSize = cipher.getBlockSize();
		int outputSize = cipher.getOutputSize(data.length);
		int leavedSize = data.length % blockSize;
		int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
		byte[] raw = new byte[outputSize * blocksSize];
		
		int i = 0;
		while (data.length - i * blockSize > 0) {
			if (data.length - i * blockSize > blockSize){
				cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
			}else{
				cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
			}
			i++;
		}
		return raw;
	}
}
