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
import java.util.Arrays;

public class Messages
{
    public final static String EOM = "\r\n\r\n\r\n";
    public final static byte CHAT_KEY_TYPE[] = new byte[] {0x00};
    public final static byte CHAT_MESSAGE_RETRIEVAL[] = new byte[] {0x00};
    public final static byte PK_MESSAGE_REQUEST[] = new byte[] {0x01};
    public final static int EPKS_GROUP_ONE_ELEMENT_COUNT = 6;

    public static String bytesToMessageString(byte bytes[])
    {
	if(bytes == null || bytes.length <= 0)
	    return "";

	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append("\r\n");
	    results.append("content=%2\r\n");
	    results.append("\r\n\r\n");

	    String base64 = Base64.encodeToString(bytes, Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = base64.length() + "content=\r\n\r\n\r\n".length();

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

    public static String identitiesMessage(byte bytes[])
    {
	if(bytes == null || bytes.length <= 0)
	    return "";

	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append("\r\n");
	    results.append("type=0095b&content=%2\r\n");
	    results.append("\r\n\r\n");

	    String base64 = Base64.encodeToString(bytes, Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = base64.length() +
		"type=0095b&content=\r\n\r\n\r\n".length();

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

    public static String requestUnsolicited()
    {
	try
	{
	    StringBuilder results = new StringBuilder();

	    results.append("POST HTTP/1.1\r\n");
	    results.append
		("Content-Type: application/x-www-form-urlencoded\r\n");
	    results.append("Content-Length: %1\r\n");
	    results.append("\r\n");
	    results.append("type=0096&content=%2\r\n");
	    results.append("\r\n\r\n");

	    String base64 = Base64.encodeToString
		("true".getBytes(), Base64.NO_WRAP);
	    int indexOf = results.indexOf("%1");
	    int length = base64.length() +
		"type=0096&content=\r\n\r\n\r\n".length();

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
	/*
	** Remove SmokeStack-specific leading and trailing data.
	*/

	int indexOf = message.indexOf("content=");

	if(indexOf >= 0)
	    message = message.substring(indexOf + 8);

	return message.trim();
    }

    public static byte[] epksMessage(String sipHashId,
				     String strings[])
    {
	if(strings == null ||
	   strings.length != EPKS_GROUP_ONE_ELEMENT_COUNT - 1)
	    return null;

	/*
	** keyStream
	** [0 ... 31] - AES-256 Encryption Key
	** [32 ... 95] - SHA-512 HMAC Key
	*/

	try
	{
	    byte keyStream[] = Cryptography.sipHashIdStream(sipHashId);

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

	    byte aes256[] = Cryptography.encrypt
		(stringBuilder.toString().getBytes(),
		 Arrays.copyOfRange(keyStream, 0, 32));

	    stringBuilder.setLength(0);
	    stringBuilder = null;

	    if(aes256 == null)
		return null;

	    /*
	    ** [ SHA-512 HMAC ]
	    */

	    byte sha512[] = Cryptography.hmac
		(aes256,
		 Arrays.copyOfRange(keyStream, 32, keyStream.length));

	    if(sha512 == null)
		return null;

	    /*
	    ** [ Destination ]
	    */

	    byte destination[] = Cryptography.hmac
		(Miscellaneous.joinByteArrays(aes256, sha512),
		 Cryptography.sha512(sipHashId.getBytes("UTF-8")));

	    return Miscellaneous.joinByteArrays(aes256, sha512, destination);
	}
	catch(Exception exception)
	{
	}

	return null;
    }
}
