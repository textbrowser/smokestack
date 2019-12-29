/*
** Copyright (c) Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from SmokeStack without specific prior written permission.
**
** SMOKESTACK IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SMOKESTACK, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package org.purple.smokestack;

import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

public class Cryptography
{
    static
    {
	Security.addProvider(new BouncyCastlePQCProvider());
    }

    private SecretKey m_encryptionKey = null;
    private SecretKey m_macKey = null;
    private final ReentrantReadWriteLock m_encryptionKeyMutex =
	new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_macKeyMutex =
	new ReentrantReadWriteLock();
    private final static String HASH_ALGORITHM = "SHA-512";
    private final static String HMAC_ALGORITHM = "HmacSHA512";
    private final static String PKI_ECDSA_SIGNATURE_ALGORITHM =
	"SHA512withECDSA";
    private final static String PKI_RSA_SIGNATURE_ALGORITHM =
	/*
	** SHA512withRSA/PSS requires API 23+.
	*/

	"SHA512withRSA";
    private final static String SYMMETRIC_ALGORITHM = "AES";
    private final static String SYMMETRIC_CIPHER_TRANSFORMATION =
	"AES/CBC/PKCS7Padding";
    private final static int OZONE_STREAM_CREATION_ITERATION_COUNT = 4096;
    private final static int SIPHASH_STREAM_CREATION_ITERATION_COUNT = 4096;
    private static Cryptography s_instance = null;
    private static SecureRandom s_secureRandom = null;
    public final static int SIPHASH_ID_LENGTH = 19; // 0000-0000-0000-0000

    private Cryptography()
    {
	prepareSecureRandom();
    }

    private static synchronized void prepareSecureRandom()
    {
	if(s_secureRandom != null)
	    return;

	try
	{
	    /*
	    ** Thread-safe?
	    */

	    s_secureRandom = SecureRandom.getInstance("SHA1PRNG");
	}
	catch(Exception exception)
	{
	    s_secureRandom = new SecureRandom(); // Thread-safe?
	}
    }

    public byte[] etm(byte data[]) // Encrypt-Then-MAC
    {
	/*
	** Encrypt-then-MAC.
	*/

	if(data == null)
	    return null;

	m_encryptionKeyMutex.readLock().lock();

	try
	{
	    if(m_encryptionKey == null)
		return null;
	}
	finally
	{
	    m_encryptionKeyMutex.readLock().unlock();
	}

	m_macKeyMutex.readLock().lock();

	try
	{
	    if(m_macKey == null)
		return null;
	}
	finally
	{
	    m_macKeyMutex.readLock().unlock();
	}

	byte bytes[] = null;

	m_encryptionKeyMutex.readLock().lock();

	try
	{
	    if(m_encryptionKey == null)
		return null;

	    byte iv[] = new byte[16];

	    s_secureRandom.nextBytes(iv);

	    Cipher cipher = Cipher.getInstance
		(SYMMETRIC_CIPHER_TRANSFORMATION);

	    cipher.init
		(Cipher.ENCRYPT_MODE, m_encryptionKey, new IvParameterSpec(iv));
	    bytes = cipher.doFinal(data);
	    bytes = Miscellaneous.joinByteArrays(iv, bytes);
	}
	catch(Exception exception)
	{
	    return null;
	}
	finally
	{
	    m_encryptionKeyMutex.readLock().unlock();
	}

	m_macKeyMutex.readLock().lock();

	try
	{
	    if(m_macKey == null)
		return null;

	    Mac mac = Mac.getInstance(HMAC_ALGORITHM);

	    mac.init(m_macKey);
	    return Miscellaneous.joinByteArrays(bytes, mac.doFinal(bytes));
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_macKeyMutex.readLock().unlock();
	}

	return null;
    }

    public byte[] hmac(byte data[])
    {
	if(data == null)
	    return null;

	m_macKeyMutex.readLock().lock();

	try
	{
	    if(m_macKey == null)
		return null;

	    Mac mac = Mac.getInstance(HMAC_ALGORITHM);

	    mac.init(m_macKey);
	    return mac.doFinal(data);
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_macKeyMutex.readLock().unlock();
	}

	return null;
    }

    public byte[] mtd(byte data[]) // MAC-Then-Decrypt
    {
	/*
	** MAC-then-decrypt.
	*/

	if(data == null)
	    return null;

	m_encryptionKeyMutex.readLock().lock();

	try
	{
	    if(m_encryptionKey == null)
		return null;
	}
	finally
	{
	    m_encryptionKeyMutex.readLock().unlock();
	}

	m_macKeyMutex.readLock().lock();

	try
	{
	    if(m_macKey == null)
		return null;
	}
	finally
	{
	    m_macKeyMutex.readLock().unlock();
	}

	try
	{
	    /*
	    ** Verify the computed digest with the provided digest.
	    */

	    byte digest1[] = null; // Provided digest.
	    byte digest2[] = null; // Computed digest.

	    digest1 = Arrays.copyOfRange
		(data, data.length - 512 / 8, data.length);
	    m_macKeyMutex.readLock().lock();

	    try
	    {
		if(m_macKey == null)
		    return null;

		Mac mac = Mac.getInstance(HMAC_ALGORITHM);

		mac.init(m_macKey);
		digest2 = mac.doFinal
		    (Arrays.copyOf(data, data.length - 512 / 8));
	    }
	    catch(Exception exception)
	    {
		return null;
	    }
	    finally
	    {
		m_macKeyMutex.readLock().unlock();
	    }

	    if(!memcmp(digest1, digest2))
		return null;
	}
	catch(Exception exception)
	{
	    return null;
	}

	m_encryptionKeyMutex.readLock().lock();

	try
	{
	    if(m_encryptionKey == null)
		return null;

	    Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_TRANSFORMATION);
	    byte iv[] = Arrays.copyOf(data, 16);

	    cipher.init
		(Cipher.DECRYPT_MODE, m_encryptionKey, new IvParameterSpec(iv));
	    return cipher.doFinal
		(Arrays.copyOfRange(data, 16, data.length - 512 / 8));
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_encryptionKeyMutex.readLock().unlock();
	}

	return null;
    }

    public static KeyPair generatePrivatePublicKeyPair
	(String algorithm, int keySize)
    {
	prepareSecureRandom();

	try
	{
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.
		getInstance(algorithm);

	    keyPairGenerator.initialize(keySize, s_secureRandom);
	    return keyPairGenerator.generateKeyPair();
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static KeyPair generatePrivatePublicKeyPair(String algorithm,
						       byte privateBytes[],
						       byte publicBytes[])
    {
	try
	{
	    EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec
		(privateBytes);
	    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
	    PrivateKey privateKey = null;
	    PublicKey publicKey = null;

	    privateKey = keyFactory.generatePrivate(privateKeySpec);
	    publicKey = keyFactory.generatePublic(publicKeySpec);
	    return new KeyPair(publicKey, privateKey);
	}
	catch(Exception exception)
	{
	    Database.getInstance().writeLog
		("Cryptography::generatePrivatePublicKeyPair(): " +
		 "exception raised.");
	}

	return null;
    }

    public static PublicKey publicKeyFromBytes(byte publicBytes[])
    {
	if(publicBytes == null)
	    return null;

	try
	{
	    EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicBytes);

	    for(int i = 0; i < 3; i++)
		try
		{
		    KeyFactory keyFactory = null;

		    switch(i)
		    {
		    case 0:
			keyFactory = KeyFactory.getInstance("EC");
			break;
		    case 1:
			keyFactory = KeyFactory.getInstance
			    (PQCObjectIdentifiers.mcElieceCca2.getId());
			break;
		    default:
			keyFactory = KeyFactory.getInstance("RSA");
			break;
		    }

		    return keyFactory.generatePublic(publicKeySpec);
		}
		catch(Exception exception)
		{
		}
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static SecretKey generateEncryptionKey(byte salt[],
						  char password[],
						  int iterations)
	throws InvalidKeySpecException, NoSuchAlgorithmException
    {
	if(salt == null)
	    return null;

	KeySpec keySpec = new PBEKeySpec(password, salt, iterations, 256);
	SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance
	    ("PBKDF2WithHmacSHA1");

	return secretKeyFactory.generateSecret(keySpec);
    }

    public static SecretKey generateMacKey(byte salt[],
					   char password[],
					   int iterations)
	throws InvalidKeySpecException, NoSuchAlgorithmException
    {
	if(salt == null)
	    return null;

	KeySpec keySpec = new PBEKeySpec(password, salt, iterations, 512);
	SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance
	    ("PBKDF2WithHmacSHA1");

	return secretKeyFactory.generateSecret(keySpec);
    }

    public static String fingerPrint(byte bytes[])
    {
	String fingerprint =
	    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc" +
	    "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd4" +
	    "7417a81a538327af927da3e";
	StringBuilder stringBuilder = new StringBuilder();

	if(bytes != null)
	{
	    bytes = sha512(bytes);

	    if(bytes != null)
		fingerprint = Miscellaneous.byteArrayAsHexString(bytes);
	}

	try
	{
	    int length = fingerprint.length();

	    for(int i = 0; i < length; i += 2)
		if(i < length - 2)
		    stringBuilder.append(fingerprint, i, i + 2).append(":");
		else
		    stringBuilder.append(fingerprint.substring(i));
	}
	catch(Exception exception)
	{
	}

	return stringBuilder.toString();
    }

    public static boolean memcmp(byte a[], byte b[])
    {
	if(a == null || b == null)
	    return false;

	int rc = 0;
	int size = java.lang.Math.max(a.length, b.length);

	for(int i = 0; i < size; i++)
	    rc |= (i < a.length ? a[i] : 0) ^ (i < b.length ? b[i] : 0);

	return rc == 0;
    }

    public static boolean verifySignature(PublicKey publicKey,
					  byte bytes[],
					  byte data[])
    {
	if(bytes == null || data == null || publicKey == null)
	    return false;

	try
	{
	    Signature signature = null;

	    if(publicKey.getAlgorithm().equals("EC"))
		signature = Signature.getInstance
		    (PKI_ECDSA_SIGNATURE_ALGORITHM);
	    else
		signature = Signature.getInstance(PKI_RSA_SIGNATURE_ALGORITHM);

	    signature.initVerify(publicKey);
	    signature.update(data);
	    return signature.verify(bytes);
	}
	catch(Exception exception)
	{
	}

	return false;
    }

    public static byte[] decrypt(byte data[], byte keyBytes[])
    {
	if(data == null || keyBytes == null)
	    return null;

	try
	{
	    Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_TRANSFORMATION);
	    SecretKey secretKey = new SecretKeySpec
		(keyBytes, SYMMETRIC_ALGORITHM);
	    byte iv[] = Arrays.copyOf(data, 16);

	    cipher.init
		(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
	    return cipher.doFinal
		(Arrays.copyOfRange(data, 16, data.length));
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] encrypt(byte data[], byte keyBytes[])
    {
	if(data == null || keyBytes == null)
	    return null;

	prepareSecureRandom();

	try
	{
	    SecretKey secretKey = new SecretKeySpec
		(keyBytes, SYMMETRIC_ALGORITHM);
	    byte bytes[] = null;
	    byte iv[] = new byte[16];

	    s_secureRandom.nextBytes(iv);

	    Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_TRANSFORMATION);

	    cipher.init
		(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
	    bytes = cipher.doFinal(data);
	    return Miscellaneous.joinByteArrays(iv, bytes);
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] generateOzone(String string)
    {
	if(string == null || string.trim().isEmpty())
	    return null;

	try
	{
	    byte bytes[] = null;
	    byte salt[] = sha512
		(string.trim().getBytes(StandardCharsets.UTF_8));

	    if(salt != null)
		bytes = pbkdf2
		    (salt,
		     string.trim().toCharArray(),
		     OZONE_STREAM_CREATION_ITERATION_COUNT,
		     160); // SHA-1

	    if(bytes != null)
		bytes = pbkdf2(salt,
			       Base64.encodeToString(bytes, Base64.NO_WRAP).
			       toCharArray(),
			       1,
			       768); // 8 * (32 + 64) bits.

	    return bytes;
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] keyForSipHash(byte data[])
    {
	if(data == null)
	    return null;

	return pbkdf2(sha512(data),
		      Miscellaneous.byteArrayAsHexString(data).toCharArray(),
		      SIPHASH_STREAM_CREATION_ITERATION_COUNT,
		      8 * SipHash.KEY_LENGTH);
    }

    public static byte[] hmac(byte data[], byte keyBytes[])
    {
	if(data == null || keyBytes == null)
	    return null;

	try
	{
	    Mac mac = Mac.getInstance(HMAC_ALGORITHM);
	    SecretKey key = new SecretKeySpec(keyBytes, HASH_ALGORITHM);

	    mac.init(key);
	    return mac.doFinal(data);
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] pbkdf2(byte salt[],
				char password[],
				int iterations,
				int length)
    {
	if(password == null || salt == null)
	    return null;

	try
	{
	    KeySpec keySpec = new PBEKeySpec
		(password, salt, iterations, length);
	    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance
		("PBKDF2WithHmacSHA1");

	    return secretKeyFactory.generateSecret(keySpec).getEncoded();
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] randomBytes(int length)
    {
	if(length <= 0)
	    return null;

	prepareSecureRandom();

	try
	{
	    byte bytes[] = new byte[length];

	    s_secureRandom.nextBytes(bytes);
	    return bytes;
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] sha512(byte[] ... data)
    {
	try
	{
	    MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");

	    for(byte b[] : data)
		if(b != null)
		    messageDigest.update(b);

	    return messageDigest.digest();
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] sipHashIdStream(String sipHashId)
    {
	try
	{
	    byte bytes[] = null;
	    byte salt[] = sha512(sipHashId.getBytes(StandardCharsets.UTF_8));
	    byte temporary[] = pbkdf2(salt,
				      sipHashId.toCharArray(),
				      SIPHASH_STREAM_CREATION_ITERATION_COUNT,
				      160); // SHA-1

	    if(temporary != null)
		bytes = pbkdf2
		    (salt,
		     Base64.encodeToString(temporary, Base64.NO_WRAP).
		     toCharArray(),
		     1,
		     768); // 8 * (32 + 64) bits.

	    return bytes;
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static synchronized Cryptography getInstance()
    {
	if(s_instance == null)
	    s_instance = new Cryptography();

	return s_instance;
    }

    public void reset()
    {
	m_encryptionKeyMutex.writeLock().lock();

	try
	{
	    m_encryptionKey = null;
	}
	finally
	{
	    m_encryptionKeyMutex.writeLock().unlock();
	}

	m_macKeyMutex.writeLock().lock();

	try
	{
	    m_macKey = null;
	}
	finally
	{
	    m_macKeyMutex.writeLock().unlock();
	}
    }

    public void setEncryptionKey(SecretKey key)
    {
	m_encryptionKeyMutex.writeLock().lock();

	try
	{
	    m_encryptionKey = key;
	}
	finally
	{
	    m_encryptionKeyMutex.writeLock().unlock();
	}
    }

    public void setMacKey(SecretKey key)
    {
	m_macKeyMutex.writeLock().lock();

	try
	{
	    m_macKey = key;
	}
	finally
	{
	    m_macKeyMutex.writeLock().unlock();
	}
    }
}
