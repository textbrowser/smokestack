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
import java.util.Arrays;

public class Messages
{
    public final static String EOM = "\r\n\r\n\r\n";
    public final static byte[] CHAT_KEY_TYPE = new byte[] {0x00};
    public final static byte[] CHAT_MESSAGE_READ = new byte[] {0x04};
    public final static byte[] CHAT_MESSAGE_RETRIEVAL = new byte[] {0x00};
    public final static byte[] PKP_MESSAGE_REQUEST = new byte[] {0x01};
    public final static byte[] SHARE_SIPHASH_ID = new byte[] {0x02};
    public final static byte[] SHARE_SIPHASH_IDENTITY_CONFIRIMATION =
	new byte[] {0x03};
    public final static int EPKS_GROUP_ONE_ELEMENT_COUNT = 7;
    private final static int ETAG_LENGTH = 32;

    public static String bytesToMessageString(byte[] bytes)
    {
	if(bytes == null || bytes.length == 0)
	    return "";

	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("\r\n");
	    results.append("ETag: ");
	    results.append
		(Miscellaneous.
		 byteArrayAsHexString(Cryptography.
				      randomBytes(ETAG_LENGTH / 2)));
	    results.append("\r\n\r\n");
	    results.append("content=%2");
	    results.append(EOM);

	    String base64 = Base64.encodeToString(bytes, Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = EOM.length() + base64.length() + "content=".length();

	    results = results.replace
		(indexOf, indexOf + 2, String.valueOf(length));
	    indexOf = results.indexOf("%2");
	    results = results.replace(indexOf, indexOf + 2, base64);
	    return results.toString();
	}
	catch(Exception exception)
	{
	}

	return "";
    }

    public static String identitiesMessage(byte[] bytes)
    {
	if(bytes == null || bytes.length == 0)
	    return "";

	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("\r\n");
	    results.append("type=0095b&content=%2");
	    results.append(EOM);

	    String base64 = Base64.encodeToString(bytes, Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = EOM.length() +
		base64.length() +
		"type=0095b&content=".length();

	    results = results.replace
		(indexOf, indexOf + 2, String.valueOf(length));
	    indexOf = results.indexOf("%2");
	    results = results.replace(indexOf, indexOf + 2, base64);
	    return results.toString();
	}
	catch(Exception exception)
	{
	}

	return "";
    }

    public static String requestAuthentication(StringBuffer stringBuffer)
    {
	if(stringBuffer == null || stringBuffer.length() == 0)
	    return "";

	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("\r\n");
	    results.append("type=0097a&content=%2");
	    results.append(EOM);

	    int indexOf = results.indexOf("%1");
	    int length = EOM.length() +
		stringBuffer.length() +
		"type=0097a&content=".length();

	    results = results.replace
		(indexOf, indexOf + 2, String.valueOf(length));
	    indexOf = results.indexOf("%2");
	    results = results.replace
		(indexOf, indexOf + 2, stringBuffer.toString());
	    return results.toString();
	}
	catch(Exception exception)
	{
	}

	return "";
    }

    public static String requestUnsolicited()
    {
	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("\r\n");
	    results.append("type=0096&content=%2");
	    results.append(EOM);

	    String base64 = Base64.encodeToString
		("true".getBytes(), Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = EOM.length() +
		base64.length() +
		"type=0096&content=".length();

	    results = results.replace
		(indexOf, indexOf + 2, String.valueOf(length));
	    indexOf = results.indexOf("%2");
	    results = results.replace(indexOf, indexOf + 2, base64);
	    return results.toString();
	}
	catch(Exception exception)
	{
	}

	return "";
    }

    public static String stripMessage(String message)
    {
	if(message == null)
	    return "";

	/*
	** Remove SmokeStack-specific leading and trailing data.
	*/

	int indexOf = message.indexOf("content=");

	if(indexOf >= 0)
	    message = message.substring(indexOf + 8);

	return message.trim();
    }

    public static byte[] epksMessage(String sipHashId, String[] strings)
    {
	if(strings == null ||
	   strings.length != EPKS_GROUP_ONE_ELEMENT_COUNT - 1)
	    return null;

	/*
	** keyStream
	** [0 ... 31] - Encryption Key
	** [32 ... 95] - HMAC Key
	*/

	try
	{
	    byte[] keyStream = Cryptography.sipHashIdStream(sipHashId);

	    if(keyStream == null)
		return null;

	    StringBuilder stringBuilder = new StringBuilder();

	    /*
	    ** [ A Timestamp ]
	    */

	    stringBuilder.append
		(Base64.encodeToString(Miscellaneous.
				       longToByteArray(System.
						       currentTimeMillis()),
				       Base64.NO_WRAP));
	    stringBuilder.append("\n");

	    /*
	    ** [ Key Type ]
	    */

	    stringBuilder.append(strings[0]);
	    stringBuilder.append("\n");

	    /*
	    ** [ Sender's Smoke Identity ]
	    */

	    stringBuilder.append(strings[5]);
	    stringBuilder.append("\n");

	    /*
	    ** [ Encryption Public Key ]
	    */

	    stringBuilder.append(strings[1]);
	    stringBuilder.append("\n");

	    /*
	    ** [ Encryption Public Key Signature ]
	    */

	    stringBuilder.append(strings[2]);
	    stringBuilder.append("\n");

	    /*
	    ** [ Signature Public Key ]
	    */

	    stringBuilder.append(strings[3]);
	    stringBuilder.append("\n");

	    /*
	    ** [ Signature Public Key Signature ]
	    */

	    stringBuilder.append(strings[4]);

	    byte[] ciphertext = Cryptography.encrypt
		(stringBuilder.toString().getBytes(),
		 Arrays.copyOfRange(keyStream,
				    0,
				    Cryptography.CIPHER_KEY_LENGTH));

	    stringBuilder.delete(0, stringBuilder.length());

	    if(ciphertext == null)
		return null;

	    /*
	    ** [ HMAC ]
	    */

	    byte[] hmac = Cryptography.hmac
		(ciphertext,
		 Arrays.copyOfRange(keyStream,
				    Cryptography.CIPHER_KEY_LENGTH,
				    keyStream.length));

	    if(hmac == null)
		return null;

	    /*
	    ** [ Destination ]
	    */

	    byte[] destination = Cryptography.hmac
		(Miscellaneous.joinByteArrays(ciphertext, hmac),
		 Cryptography.
		 shaX512(sipHashId.getBytes(StandardCharsets.UTF_8)));

	    return Miscellaneous.joinByteArrays(ciphertext, hmac, destination);
	}
	catch(Exception exception)
	{
	}

	return null;
    }

    public static byte[] shareSipHashIdMessageConfirmation
	(Cryptography cryptography,
	 String sipHashId,
	 byte[] identity,
	 byte[] keyStream)
    {
	if(cryptography == null)
	    return null;

	try
	{
	    byte[] bytes = Miscellaneous.joinByteArrays
		(
		 /*
		 ** [ A Byte ]
		 */

		 SHARE_SIPHASH_IDENTITY_CONFIRIMATION,

		 /*
		 ** [ A Timestamp ]
		 */

		 Miscellaneous.longToByteArray(System.currentTimeMillis()),

		 /*
		 ** [ SipHash Identity ]
		 */

		 sipHashId.getBytes(StandardCharsets.UTF_8),

		 /*
		 ** [ Temporary Identity ]
		 */

		 identity);

	    /*
	    ** [ Ciphertext ]
	    */

	    byte[] ciphertext = Cryptography.encrypt
		(bytes, Arrays.copyOfRange(keyStream,
					   0,
					   Cryptography.CIPHER_KEY_LENGTH));

	    if(ciphertext == null)
		return null;

	    /*
	    ** [ HMAC ]
	    */

	    byte[] hmac = Cryptography.hmac
		(ciphertext, Arrays.copyOfRange(keyStream,
					    Cryptography.CIPHER_KEY_LENGTH,
					    keyStream.length));

	    if(hmac == null)
		return null;

	    /*
	    ** [ Destination ]
	    */

	    byte[] destination = Cryptography.hmac
		(Miscellaneous.joinByteArrays(ciphertext, hmac),
		 Cryptography.
		 shaX512(sipHashId.getBytes(StandardCharsets.UTF_8)));

	    return Miscellaneous.joinByteArrays(ciphertext, hmac, destination);
	}
	catch(Exception exception)
	{
	}

	return null;
    }
}
