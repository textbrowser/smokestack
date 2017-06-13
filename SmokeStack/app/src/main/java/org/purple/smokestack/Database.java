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

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteConstraintException;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Base64;
import android.util.Patterns;
import android.util.SparseArray;
import android.util.SparseIntArray;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.regex.Matcher;

public class Database extends SQLiteOpenHelper
{
    private SQLiteDatabase m_db = null;
    private final static Comparator<ListenerElement>
	s_readListenersComparator = new Comparator<ListenerElement> ()
	{
	    @Override
	    public int compare(ListenerElement e1, ListenerElement e2)
	    {
		/*
		** Sort by IP address, port, and scope ID.
		*/

		try
		{
		    byte bytes1[] = InetAddress.getByName(e1.m_localIpAddress).
		    getAddress();
		    byte bytes2[] = InetAddress.getByName(e2.m_localIpAddress).
		    getAddress();
		    int length = Math.max(bytes1.length, bytes2.length);

		    for(int i = 0; i < length; i++)
		    {
			byte b1 = (i >= length - bytes1.length) ?
			    bytes1[i - (length - bytes1.length)] : 0;
			byte b2 = (i >= length - bytes2.length) ?
			    bytes2[i - (length - bytes2.length)] : 0;

			if(b1 != b2)
			    return (0xff & b1) - (0xff & b2);
		    }
		}
		catch(Exception exception)
		{
		}

		int i = e1.m_localPort.compareTo(e2.m_localPort);

		if(i != 0)
		    return i;

		return e1.m_localScopeId.compareTo(e2.m_localScopeId);
	    }
	};
    private final static Comparator<NeighborElement>
	s_readNeighborsComparator = new Comparator<NeighborElement> ()
	{
	    @Override
	    public int compare(NeighborElement e1, NeighborElement e2)
	    {
		/*
		** Sort by IP address, port, and transport.
		*/

		try
		{
		    byte bytes1[] = InetAddress.getByName(e1.m_remoteIpAddress).
		    getAddress();
		    byte bytes2[] = InetAddress.getByName(e2.m_remoteIpAddress).
		    getAddress();
		    int length = Math.max(bytes1.length, bytes2.length);

		    for(int i = 0; i < length; i++)
		    {
			byte b1 = (i >= length - bytes1.length) ?
			    bytes1[i - (length - bytes1.length)] : 0;
			byte b2 = (i >= length - bytes2.length) ?
			    bytes2[i - (length - bytes2.length)] : 0;

			if(b1 != b2)
			    return (0xff & b1) - (0xff & b2);
		    }
		}
		catch(Exception exception)
		{
		}

		int i = e1.m_remotePort.compareTo(e2.m_remotePort);

		if(i != 0)
		    return i;

		return e1.m_transport.compareTo(e2.m_transport);
	    }
	};
    private final static Comparator<OzoneElement>
	s_readOzonesComparator = new Comparator<OzoneElement> ()
	{
	    @Override
	    public int compare(OzoneElement e1, OzoneElement e2)
	    {
		/*
		** Sort by address.
		*/

		return e1.m_address.compareTo(e2.m_address);
	    }
	};
    private final static Comparator<SipHashIdElement>
	s_readSipHashIdsComparator = new Comparator<SipHashIdElement> ()
	{
	    @Override
	    public int compare(SipHashIdElement e1, SipHashIdElement e2)
	    {
		/*
		** Sort by name and SipHash identity.
		*/

	    	int i = e1.m_name.compareTo(e2.m_name);

		if(i != 0)
		    return i;

		return e1.m_sipHashId.compareTo(e2.m_sipHashId);
	    }
	};
    private final static String DATABASE_NAME = "smokestack.db";
    private final static int DATABASE_VERSION = 1;
    private final static int ONE_WEEK = 604800000;
    private final static int SIPHASH_STREAM_CREATION_ITERATION_COUNT = 4096;
    private final static int WRITE_PARTICIPANT_TIME_DELTA = 60000; // 60 Seconds
    private static Database s_instance = null;

    private Database(Context context)
    {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    private void prepareDb()
    {
	if(m_db == null)
	    try
	    {
		m_db = getWritableDatabase();
	    }
	    catch(Exception exception)
	    {
	    }
    }

    public ArrayList<ListenerElement> readListeners(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	Cursor cursor = null;
	ArrayList<ListenerElement> arrayList = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT " +
		 "certificate, " +
		 "ip_version, " +
		 "last_error, " +
		 "local_ip_address, " +
		 "local_port, " +
		 "local_scope_id, " +
		 "peers_count, " +
		 "private_key, " +
		 "public_key, " +
		 "status, " +
		 "status_control, " +
		 "uptime, " +
		 "OID " +
		 "FROM listeners", null);

	    if(cursor != null && cursor.moveToFirst())
	    {
		arrayList = new ArrayList<> ();

		while(!cursor.isAfterLast())
		{
		    ListenerElement listenerElement = new ListenerElement();
		    boolean error = false;

		    for(int i = 0; i < cursor.getColumnCount(); i++)
		    {
			if(i == cursor.getColumnCount() - 1)
			{
			    listenerElement.m_oid = cursor.getInt(i);
			    continue;
			}

			byte bytes[] = null;

			if(i != 0)
			    bytes = cryptography.mtd
				(Base64.decode(cursor.getString(i).getBytes(),
					       Base64.DEFAULT));

			if(bytes == null && i != 0)
			{
			    error = true;

			    StringBuilder stringBuilder = new StringBuilder();

			    stringBuilder.append("Database::readListeners(): ");
			    stringBuilder.append("error on column ");
			    stringBuilder.append(cursor.getColumnName(i));
			    stringBuilder.append(".");
			    writeLog(stringBuilder.toString());
			    break;
			}

			switch(i)
			{
			case 0:
			    listenerElement.m_certificate = Miscellaneous.
				deepCopy(bytes);
			    break;
			case 1:
			    listenerElement.m_ipVersion = new String(bytes);
			    break;
			case 2:
			    listenerElement.m_error = new String(bytes);
			    break;
			case 3:
			    listenerElement.m_localIpAddress = new String
				(bytes);
			    break;
			case 4:
			    listenerElement.m_localPort = new String(bytes);
			    break;
			case 5:
			    listenerElement.m_localScopeId = new String
				(bytes);
			    break;
			case 6:
			    try
			    {
				listenerElement.m_peersCount =
				    Long.parseLong(new String(bytes));
			    }
			    catch(Exception exception)
			    {
				listenerElement.m_peersCount = 0;
			    }

			    break;
			case 7:
			    listenerElement.m_privateKey = Miscellaneous.
				deepCopy(bytes);
			    break;
			case 8:
			    listenerElement.m_publicKey = Miscellaneous.
				deepCopy(bytes);
			    break;
			case 9:
			    listenerElement.m_status = new String(bytes);
			    break;
			case 10:
			    listenerElement.m_statusControl = new String
				(bytes);
			    break;
			case 11:
			    listenerElement.m_uptime = new String(bytes);
			    break;
			}
		    }

		    if(!error)
			arrayList.add(listenerElement);

		    cursor.moveToNext();
		}

		if(arrayList.size() > 1)
		    Collections.sort(arrayList, s_readListenersComparator);
	    }
	}
	catch(Exception exception)
	{
	    if(arrayList != null)
		arrayList.clear();

	    arrayList = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return arrayList;
    }

    public ArrayList<NeighborElement> readNeighbors(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	Cursor cursor = null;
	ArrayList<NeighborElement> arrayList = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT " +
		 "(SELECT COUNT(*) FROM outbound_queue o WHERE " +
		 "o.neighbor_oid = n.OID), " +
		 "n.bytes_read, " +
		 "n.bytes_written, " +
		 "n.echo_queue_size, " +
		 "n.ip_version, " +
		 "n.last_error, " +
		 "n.local_ip_address, " +
		 "n.local_port, " +
		 "n.proxy_ip_address, " +
		 "n.proxy_port, " +
		 "n.proxy_type, " +
		 "n.remote_certificate, " +
		 "n.remote_ip_address, " +
		 "n.remote_port, " +
		 "n.remote_scope_id, " +
		 "n.session_cipher, " +
		 "n.status, " +
		 "n.status_control, " +
		 "n.transport, " +
		 "n.uptime, " +
		 "n.OID " +
		 "FROM neighbors n ORDER BY n.OID", null);

	    if(cursor != null && cursor.moveToFirst())
	    {
		arrayList = new ArrayList<> ();

		while(!cursor.isAfterLast())
		{
		    NeighborElement neighborElement = new NeighborElement();
		    boolean error = false;

		    for(int i = 0; i < cursor.getColumnCount(); i++)
		    {
			if(i == cursor.getColumnCount() - 1)
			{
			    neighborElement.m_oid = cursor.getInt(i);
			    continue;
			}

			byte bytes[] = null;

			if(i != 0)
			    bytes = cryptography.mtd
				(Base64.decode(cursor.getString(i).getBytes(),
					       Base64.DEFAULT));

			if(bytes == null && i != 0)
			{
			    error = true;

			    StringBuilder stringBuilder = new StringBuilder();

			    stringBuilder.append("Database::readNeighbors(): ");
			    stringBuilder.append("error on column ");
			    stringBuilder.append(cursor.getColumnName(i));
			    stringBuilder.append(".");
			    writeLog(stringBuilder.toString());
			    break;
			}

			switch(i)
			{
			case 0:
			    neighborElement.m_outboundQueued = cursor.
				getLong(1);
			    break;
			case 1:
			    neighborElement.m_bytesRead = new String(bytes);
			    break;
			case 2:
			    neighborElement.m_bytesWritten = new String(bytes);
			    break;
			case 3:
			    neighborElement.m_echoQueueSize = new String(bytes);
			    break;
			case 4:
			    neighborElement.m_ipVersion = new String(bytes);
			    break;
			case 5:
			    neighborElement.m_error = new String(bytes);
			    break;
			case 6:
			    neighborElement.m_localIpAddress =
				new String(bytes);
			    break;
			case 7:
			    neighborElement.m_localPort = new String(bytes);
			    break;
			case 8:
			    neighborElement.m_proxyIpAddress =
				new String(bytes);
			    break;
			case 9:
			    neighborElement.m_proxyPort = new String(bytes);
			    break;
			case 10:
			    neighborElement.m_proxyType = new String(bytes);
			    break;
			case 11:
			    neighborElement.m_remoteCertificate =
				Miscellaneous.deepCopy(bytes);
			    break;
			case 12:
			    neighborElement.m_remoteIpAddress =
				new String(bytes);
			    break;
			case 13:
			    neighborElement.m_remotePort = new String(bytes);
			    break;
			case 14:
			    neighborElement.m_remoteScopeId = new String(bytes);
			    break;
			case 15:
			    neighborElement.m_sessionCipher = new String(bytes);
			    break;
			case 16:
			    neighborElement.m_status = new String(bytes);
			    break;
			case 17:
			    neighborElement.m_statusControl = new String(bytes);
			    break;
			case 18:
			    neighborElement.m_transport = new String(bytes);
			    break;
			case 19:
			    neighborElement.m_uptime = new String(bytes);
			    break;
			}
		    }

		    if(!error)
			arrayList.add(neighborElement);

		    cursor.moveToNext();
		}

		if(arrayList.size() > 1)
		    Collections.sort(arrayList, s_readNeighborsComparator);
	    }
	}
	catch(Exception exception)
	{
	    if(arrayList != null)
		arrayList.clear();

	    arrayList = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return arrayList;
    }

    public ArrayList<OzoneElement> readOzones(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	ArrayList<OzoneElement> arrayList = null;
	Cursor cursor = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT " +
		 "ozone_address, " +
		 "ozone_address_stream, " +
		 "OID " +
		 "FROM ozones", null);

	    if(cursor != null && cursor.moveToFirst())
	    {
		arrayList = new ArrayList<> ();

		while(!cursor.isAfterLast())
		{
		    OzoneElement ozoneElement = new OzoneElement();
		    boolean error = false;

		    for(int i = 0; i < cursor.getColumnCount(); i++)
		    {
			if(i == cursor.getColumnCount() - 1)
			{
			    ozoneElement.m_oid = cursor.getInt(i);
			    continue;
			}

			byte bytes[] = cryptography.mtd
			    (Base64.decode(cursor.getString(i).getBytes(),
					   Base64.DEFAULT));

			if(bytes == null)
			{
			    error = true;

			    StringBuilder stringBuilder = new StringBuilder();

			    stringBuilder.append
				("Database::readOzones(): ");
			    stringBuilder.append("error on column ");
			    stringBuilder.append(cursor.getColumnName(i));
			    stringBuilder.append(".");
			    writeLog(stringBuilder.toString());
			    break;
			}

			switch(i)
			{
			case 0:
			    ozoneElement.m_address = new String(bytes);
			    break;
			case 1:
			    ozoneElement.m_addressStream = Miscellaneous.
				deepCopy(bytes);
			    break;
			}
		    }

		    if(!error)
			arrayList.add(ozoneElement);

		    cursor.moveToNext();
		}

		if(arrayList.size() > 1)
		    Collections.sort(arrayList, s_readOzonesComparator);
	    }
	}
	catch(Exception exception)
	{
	    if(arrayList != null)
		arrayList.clear();

	    arrayList = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return arrayList;
    }

    public ArrayList<SipHashIdElement> readSipHashIds(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	ArrayList<SipHashIdElement> arrayList = null;
	Cursor cursor = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT " +
		 "(SELECT p.encryption_public_key_digest || " +
		 "p.signature_public_key_digest FROM participants p " +
		 "WHERE p.siphash_id_digest = si.siphash_id_digest) AS a, " +
		 "(SELECT p.encryption_public_key_digest FROM participants p " +
		 "WHERE p.siphash_id_digest = si.siphash_id_digest) AS b, " +
		 "(SELECT COUNT(s.OID) FROM stack s WHERE " +
		 "s.siphash_id_digest = si.siphash_id_digest AND " +
		 "s.timestamp IS NULL) AS c, " +
		 "(SELECT COUNT(s.OID) FROM stack s WHERE " +
		 "s.siphash_id_digest = si.siphash_id_digest AND " +
		 "s.timestamp IS NOT NULL) AS d, " +
		 "si.accept_without_signatures, " +
		 "si.name, " +
		 "si.siphash_id, " +
		 "si.stream, " +
		 "si.OID " +
		 "FROM siphash_ids si ORDER BY si.OID", null);

	    if(cursor != null && cursor.moveToFirst())
	    {
		arrayList = new ArrayList<> ();

		while(!cursor.isAfterLast())
		{
		    SipHashIdElement sipHashIdElement = new SipHashIdElement();
		    boolean error = false;

		    for(int i = 0; i < cursor.getColumnCount(); i++)
		    {
			if(i == 0)
			{
			    if(cursor.isNull(i) ||
			       cursor.getString(i).isEmpty())
			    {
				sipHashIdElement.m_epksCompleted = false;
				continue;
			    }

			    String string_a = cursor.getString(i);
			    String string_b = Base64.encodeToString
				(Cryptography.sha512("".getBytes()),
				 Base64.DEFAULT);

			    string_b += string_b;
			    sipHashIdElement.m_epksCompleted =
				!string_a.equals(string_b);
			    continue;
			}
			else if(i == 1)
			{
			    if(cursor.isNull(i) ||
			       cursor.getString(i).isEmpty())
			    {
				sipHashIdElement.m_chatEncryptionKeyDigest =
				    null;
				continue;
			    }

			    sipHashIdElement.m_chatEncryptionKeyDigest =
				Base64.decode(cursor.getString(i),
					      Base64.DEFAULT);
			    continue;
			}
			else if(i == 2)
			{
			    sipHashIdElement.m_inMessages =
				cursor.getLong(i);
			    continue;
			}
			else if(i == 3)
			{
			    sipHashIdElement.m_outMessages =
				cursor.getLong(i);
			    sipHashIdElement.m_totalMessages =
				sipHashIdElement.m_inMessages +
				sipHashIdElement.m_outMessages;
			    continue;
			}
			else if(i == cursor.getColumnCount() - 1)
			{
			    sipHashIdElement.m_oid = cursor.getInt(i);
			    continue;
			}

			byte bytes[] = cryptography.mtd
			    (Base64.decode(cursor.getString(i).getBytes(),
					   Base64.DEFAULT));

			if(bytes == null)
			{
			    error = true;

			    StringBuilder stringBuilder = new StringBuilder();

			    stringBuilder.append
				("Database::readSipHashIds(): ");
			    stringBuilder.append("error on column ");
			    stringBuilder.append(cursor.getColumnName(i));
			    stringBuilder.append(".");
			    writeLog(stringBuilder.toString());
			    break;
			}

			switch(i)
			{
			case 0:
			    break;
			case 1:
			    break;
			case 2:
			    break;
			case 3:
			    break;
			case 4:
			    sipHashIdElement.m_acceptWithoutSignatures =
				new String(bytes).equals("true");
			    break;
			case 5:
			    sipHashIdElement.m_name = new String(bytes);
			    break;
			case 6:
			    sipHashIdElement.m_sipHashId = new String
				(bytes, "UTF-8");
			    break;
			case 7:
			    sipHashIdElement.m_stream = Miscellaneous.
				deepCopy(bytes);
			    break;
			}
		    }

		    if(!error)
			arrayList.add(sipHashIdElement);

		    cursor.moveToNext();
		}

		if(arrayList.size() > 1)
		    Collections.sort(arrayList, s_readSipHashIdsComparator);
	    }
	}
	catch(Exception exception)
	{
	    if(arrayList != null)
		arrayList.clear();

	    arrayList = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return arrayList;
    }

    public ArrayList<byte[]> readTaggedMessage(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	ArrayList<byte[]> arrayList = null;
	Cursor cursor = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT message, message_digest, siphash_id " +
		 "FROM stack WHERE timestamp IS NULL AND verified_digest = ?",
		 new String[] {Base64.
			       encodeToString(cryptography.
					      hmac("true".getBytes()),
					      Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
	    {
		arrayList = new ArrayList<> ();

		boolean error = false;

		for(int i = 0; i < 3; i++)
		{
		    byte bytes[] = null;

		    switch(i)
		    {
		    case 0:
			bytes = cryptography.mtd
			    (Base64.decode(cursor.getString(i).getBytes(),
					   Base64.DEFAULT));

			if(bytes != null)
			    arrayList.add(bytes);
			else
			    error = true;

			break;
		    case 1:
			arrayList.add(cursor.getString(i).getBytes());
			break;
		    case 2:
			bytes = cryptography.mtd
			    (Base64.decode(cursor.getString(i).getBytes(),
					   Base64.DEFAULT));

			if(bytes != null)
			    arrayList.add(bytes);
			else
			    error = true;

			break;
		    }

		    if(error)
			break;
		}

		if(error)
		{
		    arrayList.clear();
		    arrayList = null;
		}
	    }
	}
	catch(Exception exception)
	{
	    if(arrayList != null)
		arrayList.clear();

	    arrayList = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return arrayList;
    }

    public MessageTotals readMessageTotals(String oid)
    {
	prepareDb();

	if(m_db == null)
	    return null;

	Cursor cursor = null;
	MessageTotals messageTotals = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT (SELECT COUNT(s.OID) FROM stack s WHERE " +
		 "s.siphash_id_digest = si.siphash_id_digest AND " +
		 "s.timestamp IS NULL) AS a, " +
		 "(SELECT COUNT(s.OID) FROM stack s WHERE " +
		 "s.siphash_id_digest = si.siphash_id_digest AND " +
		 "s.timestamp IS NOT NULL) AS b, " +
		 "si.OID " +
		 "FROM siphash_ids si WHERE si.OID = ? ORDER BY si.OID",
		 new String[] {oid});

	    if(cursor != null && cursor.moveToFirst())
	    {
		messageTotals = new MessageTotals();
		messageTotals.m_inMessages = cursor.getLong(0);
		messageTotals.m_outMessages = cursor.getLong(1);
		messageTotals.m_totalMessages = messageTotals.m_inMessages +
		    messageTotals.m_outMessages;
	    }
	}
	catch(Exception exception)
	{
	    messageTotals = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return messageTotals;
    }

    public PublicKey signatureKeyForDigest(Cryptography cryptography,
					   byte digest[])
    {
	prepareDb();

	if(cryptography == null ||
	   digest == null ||
	   digest.length < 0 ||
	   m_db == null)
	    return null;

	Cursor cursor = null;
	PublicKey publicKey = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT " +
		 "signature_public_key " +
		 "FROM participants WHERE encryption_public_key_digest = ?",
		 new String[] {Base64.encodeToString(digest, Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
	    {
		byte bytes[] = cryptography.mtd
		    (Base64.decode(cursor.getString(0).getBytes(),
				   Base64.DEFAULT));

		if(bytes != null)
		    for(int i = 0; i < 2; i++)
			try
			{
			    if(i == 0)
				publicKey = KeyFactory.getInstance("EC").
				    generatePublic
				    (new X509EncodedKeySpec(bytes));
			    else
				publicKey = KeyFactory.getInstance("RSA").
				    generatePublic
				    (new X509EncodedKeySpec(bytes));

			    break;
			}
			catch(Exception exception)
			{
			}
	    }
	}
	catch(Exception exception)
	{
	    publicKey = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return publicKey;
    }

    public SparseIntArray readNeighborOids()
    {
	prepareDb();

	if(m_db == null)
	    return null;

	Cursor cursor = null;
	SparseIntArray sparseArray = null;

	try
	{
	    cursor = m_db.rawQuery("SELECT OID FROM neighbors", null);

	    if(cursor != null && cursor.moveToFirst())
	    {
		int index = -1;

		sparseArray = new SparseIntArray();

		while(!cursor.isAfterLast())
		{
		    index += 1;
		    sparseArray.append(index, cursor.getInt(0));
		    cursor.moveToNext();
		}
	    }
	}
	catch(Exception exception)
	{
	    if(sparseArray != null)
		sparseArray.clear();

	    sparseArray = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return sparseArray;
    }

    public String nameFromSipHashId(Cryptography cryptography, String sipHashId)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return "";

	Cursor cursor = null;
	String name = "";

	try
	{
	    cursor = m_db.rawQuery
		("SELECT name FROM siphash_ids WHERE siphash_id_digest = ?",
		 new String[] {Base64.
			       encodeToString(cryptography.
					      hmac(sipHashId.toLowerCase().
						   trim().getBytes("UTF-8")),
					      Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
	    {
		byte bytes[] = cryptography.mtd
		    (Base64.decode(cursor.getString(0).getBytes(),
				   Base64.DEFAULT));

		if(bytes != null)
		    name = new String(bytes);
	    }
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return name;
    }

    public String readListenerNeighborStatusControl
	(Cryptography cryptography, String table, int oid)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	Cursor cursor = null;
	String status = "";

	try
	{
	    cursor = m_db.rawQuery
		("SELECT status_control FROM " + table + " WHERE OID = ?",
		 new String[] {String.valueOf(oid)});

	    if(cursor != null && cursor.moveToFirst())
	    {
		byte bytes[] = cryptography.mtd
		    (Base64.decode(cursor.getString(0).getBytes(),
				   Base64.DEFAULT));

		if(bytes != null)
		    status = new String(bytes);
	    }
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return status;
    }

    public String readSetting(Cryptography cryptography, String name)
    {
	prepareDb();

	if(m_db == null)
	    return "";

	Cursor cursor = null;
	String str = "";

	try
	{
	    if(cryptography == null)
		cursor = m_db.rawQuery
		    ("SELECT value FROM settings WHERE name = ?",
		     new String[] {name});
	    else
	    {
		byte bytes[] = cryptography.hmac(name.getBytes());

		if(bytes != null)
		    cursor = m_db.rawQuery
			("SELECT value FROM settings WHERE name_digest = ?",
			 new String[] {Base64.encodeToString(bytes,
							     Base64.DEFAULT)});
	    }

	    if(cursor != null && cursor.moveToFirst())
		if(cryptography == null)
		    str = cursor.getString(0);
		else
		{
		    byte bytes[] = cryptography.mtd
			(Base64.decode(cursor.getString(0).getBytes(),
				       Base64.DEFAULT));

		    if(bytes != null)
			str = new String(bytes);
		}
	}
	catch(Exception exception)
	{
	    str = "";
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	/*
	** Default values.
	*/

	if(name.equals("show_chat_icons") && str.isEmpty())
	    return "true";

	return str;
    }

    public String sipHashIdDigestFromDigest(Cryptography cryptography,
					    byte digest[])
    {
	prepareDb();

	if(cryptography == null ||
	   digest == null ||
	   digest.length < 0 ||
	   m_db == null)
	    return null;

	Cursor cursor = null;
	String sipHashIdDigest = "";

	try
	{
	    cursor = m_db.rawQuery
		("SELECT siphash_id_digest " +
		 "FROM participants WHERE encryption_public_key_digest = ?",
		 new String[] {Base64.encodeToString(digest, Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
		sipHashIdDigest = cursor.getString(0);
	}
	catch(Exception exception)
	{
	    sipHashIdDigest = "";
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return sipHashIdDigest;
    }

    public String[] readOutboundMessage(int oid)
    {
	prepareDb();

	if(m_db == null)
	    return null;

	Cursor cursor = null;
	String array[] = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT message, OID FROM outbound_queue " +
		 "WHERE neighbor_oid = ? ORDER BY OID",
		 new String[] {String.valueOf(oid)});

	    if(cursor != null && cursor.moveToFirst())
	    {
		array = new String[2];
		array[0] = cursor.getString(0);
		array[1] = String.valueOf(cursor.getInt(1));
	    }
	}
	catch(Exception exception)
	{
	    array = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return array;
    }

    public boolean accountPrepared()
    {
	return !readSetting(null, "encryptionSalt").isEmpty() &&
	    !readSetting(null, "macSalt").isEmpty() &&
	    !readSetting(null, "saltedPassword").isEmpty();
    }

    public boolean containsCongestionDigest(long value)
    {
	prepareDb();

	if(m_db == null)
	    return false;

	Cursor cursor = null;
	boolean contains = false;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT EXISTS(SELECT 1 FROM " +
		 "congestion_control WHERE digest = ?)",
		 new String[] {Base64.
			       encodeToString(Miscellaneous.
					      longToByteArray(value),
					      Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
		contains = cursor.getInt(0) == 1;
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return contains;
    }

    public boolean deleteEntry(String oid, String table)
    {
	prepareDb();

	if(m_db == null)
	    return false;

	boolean ok = false;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ok = m_db.delete(table, "OID = ?", new String[] {oid}) > 0;
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean removeMessages(String oid)
    {
	prepareDb();

	if(m_db == null)
	    return false;

	boolean ok = false;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ok = m_db.delete
		("stack",
		 "siphash_id_digest = (SELECT siphash_id_digest " +
		 "FROM siphash_ids WHERE OID = ?)",
		 new String[] {oid}) > 0;
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean resetRetrievalState(Cryptography cryptography,
				       String oid)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return false;

	boolean ok = false;
	
	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("verified_digest",
		 Base64.encodeToString(cryptography.
				       hmac("false".getBytes()),
				       Base64.DEFAULT));
	    values.putNull("timestamp");
	    ok = m_db.update
		("stack",
		 values,
		 "siphash_id_digest = (SELECT siphash_id_digest " +
		 "FROM siphash_ids WHERE OID = ?)",
		 new String[] {oid}) > 0;
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean writeListener(Cryptography cryptography,
				 String ipAddress,
				 String ipPort,
				 String ipScopeId,
				 String version)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return false;

	ContentValues values = null;
	boolean ok = true;

	try
	{
	    values = new ContentValues();
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	if(!ok)
	    return ok;

	/*
	** Content values should prevent SQL injections.
	*/

	try
	{
	    SparseArray<String> sparseArray = new SparseArray<> ();
	    byte bytes[] = null;

	    sparseArray.append(0, "certificate");
	    sparseArray.append(1, "ip_version");
	    sparseArray.append(2, "last_error");
	    sparseArray.append(3, "local_ip_address");
	    sparseArray.append(4, "local_ip_address_digest");
	    sparseArray.append(5, "local_port");
	    sparseArray.append(6, "local_port_digest");
	    sparseArray.append(7, "local_scope_id");
	    sparseArray.append(8, "peers_count");
	    sparseArray.append(9, "private_key");
	    sparseArray.append(10, "public_key");
            sparseArray.append(11, "status");
            sparseArray.append(12, "status_control");
	    sparseArray.append(13, "uptime");

	    if(!ipAddress.toLowerCase().trim().matches(".*[a-z].*"))
	    {
		Matcher matcher = Patterns.IP_ADDRESS.matcher(ipAddress.trim());

		if(!matcher.matches())
		{
		    if(version.toLowerCase().equals("ipv4"))
			ipAddress = "0.0.0.0";
		    else
			ipAddress = "0:0:0:0:0:ffff:0:0";
		}
	    }

	    for(int i = 0; i < sparseArray.size(); i++)
	    {
		if(sparseArray.get(i).equals("ip_version"))
		    bytes = cryptography.etm(version.trim().getBytes());
		else if(sparseArray.get(i).equals("local_ip_address"))
		    bytes = cryptography.etm(ipAddress.trim().getBytes());
		else if(sparseArray.get(i).equals("local_ip_address_digest"))
		    bytes = cryptography.hmac(ipAddress.trim().getBytes());
		else if(sparseArray.get(i).equals("local_port"))
		    bytes = cryptography.etm(ipPort.trim().getBytes());
		else if(sparseArray.get(i).equals("local_port_digest"))
		    bytes = cryptography.hmac(ipPort.trim().getBytes());
		else if(sparseArray.get(i).equals("local_scope_id"))
		    bytes = cryptography.etm(ipScopeId.trim().getBytes());
		else if(sparseArray.get(i).equals("peers_count"))
		    bytes = cryptography.etm("0".getBytes());
		else if(sparseArray.get(i).equals("status"))
		    bytes = cryptography.etm("disconnected".getBytes());
		else if(sparseArray.get(i).equals("status_control"))
		    bytes = cryptography.etm("listen".getBytes());
		else
		    bytes = cryptography.etm("".getBytes());

		if(bytes == null)
		{
		    StringBuilder stringBuilder = new StringBuilder();

		    stringBuilder.append
			("Database::writeListener(): error with ");
		    stringBuilder.append(sparseArray.get(i));
		    stringBuilder.append(" field.");
		    writeLog(stringBuilder.toString());
		    throw new Exception();
		}

		String str = Base64.encodeToString(bytes, Base64.DEFAULT);

		values.put(sparseArray.get(i), str);
	    }
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	m_db.beginTransactionNonExclusive();

	try
	{
	    if(ok)
	    {
		m_db.insert("listeners", null, values);
		m_db.setTransactionSuccessful();
	    }
	}
	catch(SQLiteConstraintException exception)
	{
	    ok = exception.getMessage().toLowerCase().contains("unique");
	}
	catch(Exception exception)
        {
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean writeNeighbor(Cryptography cryptography,
				 String proxyIpAddress,
				 String proxyPort,
				 String proxyType,
				 String remoteIpAddress,
				 String remoteIpPort,
				 String remoteIpScopeId,
				 String transport,
				 String version)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return false;

	ContentValues values = null;
	boolean ok = true;

	try
	{
	    values = new ContentValues();
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	if(!ok)
	    return ok;

	/*
	** Content values should prevent SQL injections.
	*/

	try
	{
	    SparseArray<String> sparseArray = new SparseArray<> ();
	    byte bytes[] = null;

	    sparseArray.append(0, "bytes_read");
	    sparseArray.append(1, "bytes_written");
	    sparseArray.append(2, "echo_queue_size");
	    sparseArray.append(3, "ip_version");
	    sparseArray.append(4, "last_error");
	    sparseArray.append(5, "local_ip_address");
	    sparseArray.append(6, "local_ip_address_digest");
	    sparseArray.append(7, "local_port");
	    sparseArray.append(8, "local_port_digest");
	    sparseArray.append(9, "proxy_ip_address");
	    sparseArray.append(10, "proxy_port");
	    sparseArray.append(11, "proxy_type");
	    sparseArray.append(12, "remote_certificate");
	    sparseArray.append(13, "remote_ip_address");
	    sparseArray.append(14, "remote_ip_address_digest");
	    sparseArray.append(15, "remote_port");
            sparseArray.append(16, "remote_port_digest");
            sparseArray.append(17, "remote_scope_id");
            sparseArray.append(18, "session_cipher");
            sparseArray.append(19, "status");
            sparseArray.append(20, "status_control");
            sparseArray.append(21, "transport");
            sparseArray.append(22, "transport_digest");
            sparseArray.append(23, "uptime");
            sparseArray.append(24, "user_defined_digest");

	    /*
	    ** Proxy information.
	    */

	    proxyIpAddress = proxyIpAddress.trim();

	    if(proxyIpAddress.isEmpty())
		proxyPort = "";

	    if(!remoteIpAddress.toLowerCase().trim().matches(".*[a-z].*"))
	    {
		Matcher matcher = Patterns.IP_ADDRESS.matcher
		    (remoteIpAddress.trim());

		if(!matcher.matches())
		{
		    if(version.toLowerCase().equals("ipv4"))
			remoteIpAddress = "0.0.0.0";
		    else
			remoteIpAddress = "0:0:0:0:0:ffff:0:0";
		}
	    }

	    for(int i = 0; i < sparseArray.size(); i++)
	    {
		if(sparseArray.get(i).equals("echo_queue_size"))
		    bytes = cryptography.etm("0".getBytes());
		else if(sparseArray.get(i).equals("ip_version"))
		    bytes = cryptography.etm(version.trim().getBytes());
		else if(sparseArray.get(i).equals("last_error"))
		    bytes = cryptography.etm("".getBytes());
		else if(sparseArray.get(i).equals("local_ip_address_digest"))
		    bytes = cryptography.hmac("".getBytes());
		else if(sparseArray.get(i).equals("local_port_digest"))
		    bytes = cryptography.hmac("".getBytes());
		else if(sparseArray.get(i).equals("proxy_ip_address"))
		    bytes = cryptography.etm(proxyIpAddress.getBytes());
		else if(sparseArray.get(i).equals("proxy_port"))
		    bytes = cryptography.etm(proxyPort.getBytes());
		else if(sparseArray.get(i).equals("proxy_type"))
		    bytes = cryptography.etm(proxyType.getBytes());
		else if(sparseArray.get(i).equals("remote_ip_address"))
		    bytes = cryptography.etm(remoteIpAddress.trim().getBytes());
		else if(sparseArray.get(i).equals("remote_ip_address_digest"))
		    bytes = cryptography.hmac(remoteIpAddress.trim().
					      getBytes());
		else if(sparseArray.get(i).equals("remote_port"))
		    bytes = cryptography.etm(remoteIpPort.trim().getBytes());
		else if(sparseArray.get(i).equals("remote_port_digest"))
		    bytes = cryptography.hmac(remoteIpPort.trim().getBytes());
		else if(sparseArray.get(i).equals("remote_scope_id"))
		    bytes = cryptography.etm(remoteIpScopeId.trim().getBytes());
		else if(sparseArray.get(i).equals("status"))
		    bytes = cryptography.etm("disconnected".getBytes());
		else if(sparseArray.get(i).equals("status_control"))
		    bytes = cryptography.etm("connect".getBytes());
		else if(sparseArray.get(i).equals("transport"))
		    bytes = cryptography.etm(transport.trim().getBytes());
		else if(sparseArray.get(i).equals("transport_digest"))
		    bytes = cryptography.hmac(transport.trim().getBytes());
		else if(sparseArray.get(i).equals("user_defined_digest"))
		    bytes = cryptography.hmac("true".getBytes());
		else
		    bytes = cryptography.etm("".getBytes());

		if(bytes == null)
		{
		    StringBuilder stringBuilder = new StringBuilder();

		    stringBuilder.append
			("Database::writeNeighbor(): error with ");
		    stringBuilder.append(sparseArray.get(i));
		    stringBuilder.append(" field.");
		    writeLog(stringBuilder.toString());
		    throw new Exception();
		}

		String str = Base64.encodeToString(bytes, Base64.DEFAULT);

		values.put(sparseArray.get(i), str);
	    }
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	m_db.beginTransactionNonExclusive();

	try
	{
	    if(ok)
	    {
		m_db.insert("neighbors", null, values);
		m_db.setTransactionSuccessful();
	    }
	}
	catch(SQLiteConstraintException exception)
	{
	    ok = exception.getMessage().toLowerCase().contains("unique");
	}
	catch(Exception exception)
        {
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean writeOzone(Cryptography cryptography,
			      String address,
			      byte addressStream[])
    {
	prepareDb();

	if(addressStream == null ||
	   addressStream.length < 0 ||
	   cryptography == null ||
	   m_db == null)
	    return false;

	ContentValues values = null;
	boolean ok = true;

	try
	{
	    values = new ContentValues();
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	if(!ok)
	    return ok;

	/*
	** Content values should prevent SQL injections.
	*/

	try
	{
	    SparseArray<String> sparseArray = new SparseArray<> ();
	    byte bytes[] = null;

	    sparseArray.append(0, "ozone_address");
	    sparseArray.append(1, "ozone_address_digest");
	    sparseArray.append(2, "ozone_address_stream");

	    for(int i = 0; i < sparseArray.size(); i++)
	    {
		if(sparseArray.get(i).equals("ozone_address"))
		    bytes = cryptography.etm(address.getBytes("UTF-8"));
		else if(sparseArray.get(i).equals("ozone_address_digest"))
		    bytes = cryptography.hmac(address.getBytes("UTF-8"));
		else
		    bytes = cryptography.etm(addressStream);

		if(bytes == null)
		{
		    StringBuilder stringBuilder = new StringBuilder();

		    stringBuilder.append
			("Database::writeOzone(): error with ");
		    stringBuilder.append(sparseArray.get(i));
		    stringBuilder.append(" field.");
		    writeLog(stringBuilder.toString());
		    throw new Exception();
		}

		String str = Base64.encodeToString(bytes, Base64.DEFAULT);

		values.put(sparseArray.get(i), str);
	    }
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	m_db.beginTransactionNonExclusive();

	try
	{
	    if(ok)
	    {
		if(m_db.replace("ozones", null, values) == -1)
		    ok = false;

		m_db.setTransactionSuccessful();
	    }
	}
	catch(Exception exception)
        {
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public boolean writeParticipant(Cryptography cryptography,
				    boolean ignoreSignatures,
				    byte data[])
    {
	prepareDb();

	if(cryptography == null ||
	   data == null ||
	   data.length < 0 ||
	   m_db == null)
	    return false;

	m_db.beginTransactionNonExclusive();

	try
	{
	    String strings[] = new String(data).split("\\n");

	    if(strings.length != Messages.EPKS_GROUP_ONE_ELEMENT_COUNT)
		return false;

	    PublicKey publicKey = null;
	    PublicKey signatureKey = null;
	    byte keyType[] = null;
	    byte publicKeySignature[] = null;
	    byte signatureKeySignature[] = null;
	    int ii = 0;

	    for(String string : strings)
		switch(ii)
		{
		case 0:
		    long current = System.currentTimeMillis();
		    long timestamp = Miscellaneous.byteArrayToLong
			(Base64.decode(string.getBytes(), Base64.NO_WRAP));

		    if(current - timestamp < 0)
		    {
			if(timestamp - current > WRITE_PARTICIPANT_TIME_DELTA)
			    return false;
		    }
		    else if(current - timestamp > WRITE_PARTICIPANT_TIME_DELTA)
			return false;

		    ii += 1;
		    break;
		case 1:
		    keyType = Base64.decode
			(string.getBytes(), Base64.NO_WRAP);

		    if(keyType == null ||
		       keyType.length != 1 ||
		       keyType[0] != Messages.CHAT_KEY_TYPE[0])
			return false;

		    ii += 1;
		    break;
		case 2:
		    publicKey = Cryptography.publicKeyFromBytes
			(Base64.decode(string.getBytes(), Base64.NO_WRAP));

		    if(publicKey == null)
			return false;

		    ii += 1;
		    break;
		case 3:
		    if(!ignoreSignatures)
		    {
			publicKeySignature = Base64.decode
			    (string.getBytes(), Base64.NO_WRAP);

			if(!Cryptography.verifySignature(publicKey,
							 publicKeySignature,
							 publicKey.
							 getEncoded()))
			    return false;
		    }

		    ii += 1;
		    break;
		case 4:
		    signatureKey = Cryptography.publicKeyFromBytes
			(Base64.decode(string.getBytes(), Base64.NO_WRAP));

		    if(signatureKey == null)
			return false;

		    ii += 1;
		    break;
		case 5:
		    if(!ignoreSignatures)
		    {
			signatureKeySignature = Base64.decode
			    (string.getBytes(), Base64.NO_WRAP);

			if(!Cryptography.verifySignature(signatureKey,
							 signatureKeySignature,
							 signatureKey.
							 getEncoded()))
			    return false;
		    }

		    break;
		}

	    /*
	    ** We shall use the two public keys to generate the
	    ** provider's SipHash ID. If a SipHash ID is not defined,
	    ** we'll reject the data.
	    */

	    String name = "";
	    String sipHashId = Miscellaneous.
		sipHashIdFromData(Miscellaneous.
				  joinByteArrays(publicKey.getEncoded(),
						 signatureKey.getEncoded())).
		toLowerCase();

	    name = nameFromSipHashId(cryptography, sipHashId);

	    if(name.isEmpty())
		return false;

	    ContentValues values = new ContentValues();
	    SparseArray<String> sparseArray = new SparseArray<> ();

	    sparseArray.append(0, "encryption_public_key");
	    sparseArray.append(1, "encryption_public_key_digest");
	    sparseArray.append(2, "function_digest");
	    sparseArray.append(3, "signature_public_key");
	    sparseArray.append(4, "signature_public_key_digest");
	    sparseArray.append(5, "siphash_id");
	    sparseArray.append(6, "siphash_id_digest");

	    for(int i = 0; i < sparseArray.size(); i++)
	    {
		byte bytes[] = null;

		if(sparseArray.get(i).equals("encryption_public_key"))
		    bytes = cryptography.etm(publicKey.getEncoded());
		else if(sparseArray.get(i).
			equals("encryption_public_key_digest"))
		    bytes = Cryptography.sha512(publicKey.getEncoded());
		else if(sparseArray.get(i).equals("function_digest"))
		{
		    if(keyType != null &&
		       keyType.length == 1 &&
		       keyType[0] == Messages.CHAT_KEY_TYPE[0])
			bytes = cryptography.hmac("chat".getBytes());
		}
		else if(sparseArray.get(i).equals("signature_public_key"))
		    bytes = cryptography.etm(signatureKey.getEncoded());
		else if(sparseArray.get(i).
			equals("signature_public_key_digest"))
		    bytes = Cryptography.sha512(signatureKey.getEncoded());
		else if(sparseArray.get(i).equals("siphash_id"))
		    bytes = cryptography.etm(sipHashId.getBytes("UTF-8"));
		else if(sparseArray.get(i).equals("siphash_id_digest"))
		    bytes = cryptography.hmac(sipHashId.getBytes("UTF-8"));

		if(bytes == null)
		    return false;

		values.put(sparseArray.get(i),
			   Base64.encodeToString(bytes, Base64.DEFAULT));
	    }

	    m_db.insert("participants", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(SQLiteConstraintException exception)
	{
	    return exception.getMessage().toLowerCase().contains("unique");
	}
	catch(Exception exception)
	{
	    return false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return true;
    }

    public boolean writeSipHashParticipant(Cryptography cryptography,
					   String name,
					   String sipHashId,
					   boolean acceptWithoutSignatures)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return false;

	ContentValues values = null;
	boolean ok = true;

	try
	{
	    values = new ContentValues();
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	if(!ok)
	    return ok;

	/*
	** Content values should prevent SQL injections.
	*/

	try
	{
	    SparseArray<String> sparseArray = new SparseArray<> ();
	    byte bytes[] = null;

	    name = name.trim();

	    if(name.isEmpty())
		name = "unknown";

	    sipHashId = sipHashId.toLowerCase().trim();
	    sparseArray.append(0, "accept_without_signatures");
	    sparseArray.append(1, "name");
	    sparseArray.append(2, "siphash_id");
	    sparseArray.append(3, "siphash_id_digest");
	    sparseArray.append(4, "stream");

	    for(int i = 0; i < sparseArray.size(); i++)
	    {
		if(sparseArray.get(i).equals("accept_without_signatures"))
		    bytes = cryptography.etm
			(acceptWithoutSignatures ?
			 "true".getBytes() : "false".getBytes());
		else if(sparseArray.get(i).equals("name"))
		    bytes = cryptography.etm(name.getBytes());
		else if(sparseArray.get(i).equals("siphash_id"))
		    bytes = cryptography.etm
			(sipHashId.trim().getBytes("UTF-8"));
		else if(sparseArray.get(i).equals("siphash_id_digest"))
		    bytes = cryptography.hmac
			(sipHashId.trim().getBytes("UTF-8"));
		else
		{
		    byte salt[] = Cryptography.sha512
			(sipHashId.trim().getBytes("UTF-8"));
		    byte temporary[] = Cryptography.
			pbkdf2(salt,
			       sipHashId.toCharArray(),
			       SIPHASH_STREAM_CREATION_ITERATION_COUNT,
			       160); // SHA-1

		    if(temporary != null)
			bytes = cryptography.etm
			    (Cryptography.
			     pbkdf2(salt,
				    new String(temporary, "UTF-8").
				    toCharArray(),
				    1,
				    768)); // 8 * (32 + 64) Bits
		}

		if(bytes == null)
		{
		    StringBuilder stringBuilder = new StringBuilder();

		    stringBuilder.append
			("Database::writeSipHashParticipant(): error with ");
		    stringBuilder.append(sparseArray.get(i));
		    stringBuilder.append(" field.");
		    writeLog(stringBuilder.toString());
		    throw new Exception();
		}

		String str = Base64.encodeToString(bytes, Base64.DEFAULT);

		values.put(sparseArray.get(i), str);
	    }
	}
	catch(Exception exception)
	{
	    ok = false;
	}

	m_db.beginTransactionNonExclusive();

	try
	{
	    if(ok)
	    {
		if(m_db.replace("siphash_ids", null, values) == -1)
		    ok = false;

		m_db.setTransactionSuccessful();
	    }
	}
	catch(Exception exception)
        {
	    ok = false;
	}
	finally
	{
	    m_db.endTransaction();
	}

	return ok;
    }

    public byte[] neighborRemoteCertificate(Cryptography cryptography,
					    int oid)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return null;

	Cursor cursor = null;
	byte bytes[] = null;

	try
	{
	    cursor = m_db.rawQuery
		("SELECT remote_certificate FROM neighbors WHERE OID = ?",
		 new String[] {String.valueOf(oid)});

	    if(cursor != null && cursor.moveToFirst())
		bytes = cryptography.mtd
		    (Base64.decode(cursor.getString(0).getBytes(),
				   Base64.DEFAULT));
	}
	catch(Exception exception)
	{
	    bytes = null;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return bytes;
    }

    public long count(String table)
    {
	prepareDb();

	if(m_db == null)
	    return -1;

	Cursor cursor = null;
	long c = 0;

	try
	{
	    StringBuilder stringBuilder = new StringBuilder();

	    stringBuilder.append("SELECT COUNT(*) FROM ");
	    stringBuilder.append(table);
	    cursor = m_db.rawQuery(stringBuilder.toString(), null);

	    if(cursor != null && cursor.moveToFirst())
		c = cursor.getLong(0);
	}
	catch(Exception exception)
	{
	    c = -1;
	}
	finally
	{
	    if(cursor != null)
		cursor.close();
	}

	return c;
    }

    public static synchronized Database getInstance()
    {
	return s_instance; // Should never be null.
    }

    public static synchronized Database getInstance(Context context)
    {
	if(s_instance == null)
	    s_instance = new Database(context.getApplicationContext());

	return s_instance;
    }

    public void cleanDanglingMessages()
    {
	prepareDb();

	if(m_db == null)
	    return;

	Cursor cursor = null;

	m_db.beginTransactionNonExclusive();

	try
	{
	    cursor = m_db.rawQuery
		("DELETE FROM stack WHERE siphash_id_digest " +
		 "NOT IN (SELECT siphash_id_digest FROM siphash_ids)",
		 null);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    if(cursor != null)
		cursor.close();

	    m_db.endTransaction();
	}
    }

    public void cleanDanglingOutboundQueued()
    {
	prepareDb();

	if(m_db == null)
	    return;

	Cursor cursor = null;

	m_db.beginTransactionNonExclusive();

	try
	{
	    cursor = m_db.rawQuery
		("DELETE FROM outbound_queue WHERE neighbor_oid " +
		 "NOT IN (SELECT OID FROM neighbors)",
		 null);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    if(cursor != null)
		cursor.close();

	    m_db.endTransaction();
	}
    }

    public void cleanDanglingParticipants()
    {
	prepareDb();

	if(m_db == null)
	    return;

	Cursor cursor = null;

	m_db.beginTransactionNonExclusive();

	try
	{
	    cursor = m_db.rawQuery
		("DELETE FROM participants WHERE siphash_id_digest " +
		 "NOT IN (SELECT siphash_id_digest FROM siphash_ids)",
		 null);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    if(cursor != null)
		cursor.close();

	    m_db.endTransaction();
	}
    }

    public void clearTable(String table)
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    m_db.delete(table, null, null);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void enqueueOutboundMessage(String message, int oid)
    {
	prepareDb();

	if(message.trim().isEmpty() || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put("message", message);
	    values.put("neighbor_oid", oid);
	    m_db.insert("outbound_queue", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void listenerNeighborControlStatus(Cryptography cryptography,
					      String controlStatus,
					      String oid,
					      String table)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("status_control",
		 Base64.encodeToString(cryptography.
				       etm(controlStatus.trim().getBytes()),
				       Base64.DEFAULT));
	    m_db.update(table, values, "OID = ?", new String[] {oid});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void neighborRecordCertificate(Cryptography cryptography,
					  String oid,
					  byte certificate[])
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    if(certificate == null)
		values.put
		    ("remote_certificate",
		     Base64.encodeToString(cryptography.etm("".getBytes()),
					   Base64.DEFAULT));
	    else
		values.put
		    ("remote_certificate",
		     Base64.encodeToString(cryptography.etm(certificate),
					   Base64.DEFAULT));

	    m_db.update("neighbors", values, "OID = ?", new String[] {oid});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    @Override
    public void onConfigure(SQLiteDatabase db)
    {
	try
	{
	    db.enableWriteAheadLogging();
	}
	catch(Exception exception)
	{
	}

	try
	{
	    db.execSQL("PRAGMA secure_delete = True", null);
	}
	catch(Exception exception)
	{
	}

	try
	{
	    db.setForeignKeyConstraintsEnabled(true);
        }
	catch(Exception exception)
	{
	}
    }

    @Override
    public void onCreate(SQLiteDatabase db)
    {
	String str = "";

	/*
	** Order is critical.
	*/

	/*
	** Create the siphash_ids table.
	*/

	str = "CREATE TABLE IF NOT EXISTS siphash_ids (" +
	    "accept_without_signatures TEXT NOT NULL, " +
	    "name TEXT NOT NULL, " +
	    "siphash_id TEXT NOT NULL, " +
	    "siphash_id_digest TEXT NOT NULL PRIMARY KEY, " +
	    "stream TEXT NOT NULL)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the congestion_control table.
	*/

	str = "CREATE TABLE IF NOT EXISTS congestion_control (" +
	    "digest TEXT NOT NULL PRIMARY KEY, " +
	    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the listeners table.
	*/

	str = "CREATE TABLE IF NOT EXISTS listeners (" +
	    "certificate TEXT NOT NULL, " +
	    "ip_version TEXT NOT NULL, " +
	    "last_error TEXT NOT NULL, " +
	    "local_ip_address TEXT NOT NULL, " +
	    "local_ip_address_digest TEXT NOT NULL, " +
	    "local_port TEXT NOT NULL, " +
	    "local_port_digest TEXT NOT NULL, " +
	    "local_scope_id TEXT NOT NULL, " +
	    "peers_count TEXT NOT NULL, " +
	    "private_key TEXT NOT NULL, " +
	    "public_key TEXT NOT NULL, " +
	    "status TEXT NOT NULL, " +
	    "status_control TEXT NOT NULL, " +
	    "uptime TEXT NOT NULL, " +
	    "PRIMARY KEY (local_ip_address_digest, " +
	    "local_port_digest))";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the log table.
	*/

	str = "CREATE TABLE IF NOT EXISTS log (" +
	    "event TEXT NOT NULL, " +
	    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the neighbors table.
	*/

	str = "CREATE TABLE IF NOT EXISTS neighbors (" +
	    "bytes_read TEXT NOT NULL, " +
	    "bytes_written TEXT NOT NULL, " +
	    "echo_queue_size TEXT NOT NULL, " +
	    "ip_version TEXT NOT NULL, " +
	    "last_error TEXT NOT NULL, " +
	    "local_ip_address TEXT NOT NULL, " +
	    "local_ip_address_digest TEXT NOT NULL, " +
	    "local_port TEXT NOT NULL, " +
	    "local_port_digest TEXT NOT NULL, " +
	    "proxy_ip_address TEXT NOT NULL, " +
	    "proxy_port TEXT NOT NULL, " +
	    "proxy_type TEXT NOT NULL, " +
	    "remote_certificate TEXT NOT NULL, " +
	    "remote_ip_address TEXT NOT NULL, " +
	    "remote_ip_address_digest TEXT NOT NULL, " +
	    "remote_port TEXT NOT NULL, " +
	    "remote_port_digest TEXT NOT NULL, " +
	    "remote_scope_id TEXT NOT NULL, " +
	    "session_cipher TEXT NOT NULL, " +
	    "status TEXT NOT NULL, " +
	    "status_control TEXT NOT NULL, " +
	    "transport TEXT NOT NULL, " +
	    "transport_digest TEXT NOT NULL, " +
	    "uptime TEXT NOT NULL, " +
	    "user_defined_digest TEXT NOT NULL, " +
	    "PRIMARY KEY (remote_ip_address_digest, " +
	    "remote_port_digest, " +
	    "transport_digest))";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the outbound_queue table.
	*/

	str = "CREATE TABLE IF NOT EXISTS outbound_queue (" +
	    "message TEXT NOT NULL, " +
	    "neighbor_oid INTEGER NOT NULL, " +
	    "PRIMARY KEY (message, neighbor_oid))";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the ozones table.
	*/

	str = "CREATE TABLE IF NOT EXISTS ozones (" +
	    "ozone_address TEXT NOT NULL, " +
	    "ozone_address_digest TEXT NOT NULL PRIMARY KEY, " +
	    "ozone_address_stream TEXT NOT NULL)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the participants table.
	*/

	str = "CREATE TABLE IF NOT EXISTS participants (" +
	    "encryption_public_key TEXT NOT NULL, " +
	    "encryption_public_key_digest TEXT NOT NULL, " +
	    "function_digest NOT NULL, " + // chat, e-mail, etc.
	    "signature_public_key TEXT NOT NULL, " +
	    "signature_public_key_digest TEXT NOT NULL, " +
	    "siphash_id TEXT NOT NULL, " +
	    "siphash_id_digest TEXT NOT NULL, " +
	    "FOREIGN KEY (siphash_id_digest) REFERENCES " +
	    "siphash_ids(siphash_id_digest) ON DELETE CASCADE, " +
	    "PRIMARY KEY (encryption_public_key_digest, " +
	    "signature_public_key_digest))";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the settings table.
	*/

	str = "CREATE TABLE IF NOT EXISTS settings (" +
	    "name TEXT NOT NULL, " +
	    "name_digest TEXT NOT NULL PRIMARY KEY, " +
	    "value TEXT NOT NULL)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}

	/*
	** Create the stack table.
	*/

	str = "CREATE TABLE IF NOT EXISTS stack (" +
	    "message TEXT NOT NULL, " +
	    "message_digest TEXT NOT NULL PRIMARY KEY, " +
	    "siphash_id TEXT NOT NULL, " +
	    "siphash_id_digest TEXT NOT NULL, " +
	    "timestamp TEXT DEFAULT NULL, " +
	    "verified_digest TEXT NOT NULL, " +
	    "FOREIGN KEY (siphash_id_digest) REFERENCES " +
	    "siphash_ids(siphash_id_digest) ON DELETE CASCADE)";

	try
	{
	    db.execSQL(str);
	}
	catch(Exception exception)
	{
	}
    }

    @Override
    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion)
    {
        onUpgrade(db, oldVersion, newVersion);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion)
    {
        onCreate(db);
    }

    public void purgeCongestion(int lifetime)
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    /*
	    ** The bound string value must be cast to an integer.
	    */

	    m_db.delete
		("congestion_control",
		 "ABS(STRFTIME('%s', 'now') - STRFTIME('%s', timestamp)) > " +
		 "CAST(? AS INTEGER)",
		 new String[] {String.valueOf(lifetime)});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void purgeReleasedMessages(Cryptography cryptography)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	Cursor cursor = null;
	StringBuilder stringBuilder = new StringBuilder();

	try
	{
	    cursor = m_db.rawQuery
		("SELECT timestamp, OID " +
		 "FROM stack WHERE timestamp IS NOT NULL AND " +
		 "verified_digest = ?",
		 new String[] {Base64.
			       encodeToString(cryptography.
					      hmac("true".getBytes()),
					      Base64.DEFAULT)});

	    if(cursor != null && cursor.moveToFirst())
		while(!cursor.isAfterLast())
		{
		    byte bytes[] = cryptography.mtd
			(Base64.decode(cursor.getString(0).getBytes(),
				       Base64.DEFAULT));

		    if(bytes == null)
		    {
			if(stringBuilder.length() > 0)
			    stringBuilder.append(",");

			stringBuilder.append(cursor.getInt(1));
		    }
		    else
		    {
			long timestamp = Miscellaneous.byteArrayToLong(bytes);

			if(Math.abs(System.currentTimeMillis() - timestamp) >
			   ONE_WEEK)
			{
			    if(stringBuilder.length() > 0)
				stringBuilder.append(",");

			    stringBuilder.append(cursor.getInt(1));
			}
		    }

		    cursor.moveToNext();
		}
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    if(cursor != null)
		cursor.close();

	    cursor = null;
	}

	if(stringBuilder.length() > 0)
	{
	    m_db.beginTransactionNonExclusive();

	    try
	    {
		cursor = m_db.rawQuery
		    ("DELETE FROM stack WHERE OID IN (?)",
		     new String[] {stringBuilder.toString()});
		m_db.setTransactionSuccessful();
	    }
	    catch(Exception exception)
	    {
	    }
	    finally
	    {
		if(cursor != null)
		    cursor.close();

		m_db.endTransaction();
	    }
	}
    }

    public void reset()
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    m_db.delete("congestion_control", null, null);
	    m_db.delete("listeners", null, null);
	    m_db.delete("log", null, null);
	    m_db.delete("neighbors", null, null);
	    m_db.delete("outbound_queue", null, null);
	    m_db.delete("ozones", null, null);
	    m_db.delete("participants", null, null);
	    m_db.delete("settings", null, null);
	    m_db.delete("siphash_ids", null, null);
	    m_db.delete("stack", null, null);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void resetAndDrop()
    {
	reset();

	if(m_db == null)
	    return;

	String strings[] = new String[]
	    {"DROP TABLE IF EXISTS congestion_control",
	     "DROP TABLE IF EXISTS listeners",
	     "DROP TABLE IF EXISTS log",
	     "DROP TABLE IF EXISTS neighbors",
	     "DROP TABLE IF EXISTS outbound_queue",
	     "DROP TABLE IF EXISTS ozones",
	     "DROP TABLE IF EXISTS participants",
	     "DROP TABLE IF EXISTS settings",
	     "DROP TABLE IF EXISTS siphash_ids",
	     "DROP TABLE IF EXISTS stack"};

	for(String string : strings)
	    try
	    {
		m_db.execSQL(string);
	    }
	    catch(Exception exception)
	    {
	    }

	onCreate(m_db);
    }

    public void saveListenerInformation(Cryptography cryptography,
					String error,
					String peersCount,
					String status,
					String uptime,
					String oid)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    if(!status.equals("listening"))
	    {
		error = error.trim(); // Do not clear the error.
		peersCount = "";
		uptime = "";
	    }

	    values.put
		("last_error",
		 Base64.encodeToString(cryptography.etm(error.getBytes()),
				       Base64.DEFAULT));
	    values.put
		("peers_count",
		 Base64.encodeToString(cryptography.etm(peersCount.getBytes()),
				       Base64.DEFAULT));
	    values.put
		("status",
		 Base64.encodeToString(cryptography.
				       etm(status.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("uptime",
		 Base64.encodeToString(cryptography.
				       etm(uptime.trim().getBytes()),
				       Base64.DEFAULT));
	    m_db.update("listeners", values, "OID = ?", new String[] {oid});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void saveNeighborInformation(Cryptography cryptography,
					String bytesRead,
					String bytesWritten,
					String echoQueueSize,
					String error,
					String ipAddress,
					String ipPort,
					String sessionCipher,
					String status,
					String uptime,
					String oid)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    if(!status.equals("connected"))
	    {
		bytesRead = "";
		bytesWritten = "";
		echoQueueSize = "0";
		error = error.trim(); // Do not clear the error.
		ipAddress = "";
		ipPort = "";
		sessionCipher = "";
		uptime = "";
	    }

	    values.put
		("bytes_read",
		 Base64.encodeToString(cryptography.etm(bytesRead.getBytes()),
				       Base64.DEFAULT));
	    values.put
		("bytes_written",
		 Base64.encodeToString(cryptography.etm(bytesWritten.
							getBytes()),
				       Base64.DEFAULT));
	    values.put
		("echo_queue_size",
		 Base64.encodeToString(cryptography.etm(echoQueueSize.
							getBytes()),
				       Base64.DEFAULT));
	    values.put
		("last_error",
		 Base64.encodeToString(cryptography.etm(error.getBytes()),
				       Base64.DEFAULT));
	    values.put
		("local_ip_address",
		 Base64.encodeToString(cryptography.
				       etm(ipAddress.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("local_ip_address_digest",
		 Base64.encodeToString(cryptography.
				       hmac(ipAddress.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("local_port",
		 Base64.encodeToString(cryptography.
				       etm(ipPort.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("local_port_digest",
		 Base64.encodeToString(cryptography.
				       hmac(ipPort.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("session_cipher",
		 Base64.encodeToString(cryptography.etm(sessionCipher.
							getBytes()),
				       Base64.DEFAULT));
	    values.put
		("status",
		 Base64.encodeToString(cryptography.
				       etm(status.trim().getBytes()),
				       Base64.DEFAULT));
	    values.put
		("uptime",
		 Base64.encodeToString(cryptography.
				       etm(uptime.trim().getBytes()),
				       Base64.DEFAULT));
	    m_db.update("neighbors", values, "OID = ?", new String[] {oid});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void tagMessagesForRelease(Cryptography cryptography,
				      String sipHashIdDigest)
    {
	prepareDb();

	if(cryptography == null || m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("verified_digest",
		 Base64.encodeToString(cryptography.hmac("true".getBytes()),
				       Base64.DEFAULT));
	    m_db.update
		("stack", values, "siphash_id_digest = ? AND " +
		 "timestamp IS NULL AND verified_digest = ?",
		 new String[] {sipHashIdDigest,
			       Base64.encodeToString(cryptography.
						     hmac("false".getBytes()),
						     Base64.DEFAULT)});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void timestampReleasedMessage(Cryptography cryptography,
					 byte digest[])
    {
	prepareDb();

	if(cryptography == null ||
	   digest == null ||
	   digest.length < 0 ||
	   m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("timestamp",
		 Base64.
		 encodeToString(cryptography.
				etm(Miscellaneous.
				    longToByteArray(System.
						    currentTimeMillis())),
				Base64.DEFAULT));
	    m_db.update
		("stack", values, "message_digest = ? AND " +
		 "timestamp IS NULL AND verified_digest = ?",
		 new String[] {new String(digest),
			       Base64.encodeToString(cryptography.
						     hmac("true".getBytes()),
						     Base64.DEFAULT)});
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void writeCongestionDigest(long value)
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("digest",
		 Base64.encodeToString(Miscellaneous.
				       longToByteArray(value), Base64.DEFAULT));
	    m_db.insert("congestion_control", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void writeLog(String event)
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put("event", event.trim());
	    m_db.insert("log", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void writeMessage(Cryptography cryptography,
			     String sipHashId,
			     byte message[])
    {
	prepareDb();

	if(cryptography == null ||
	   m_db == null ||
	   message == null ||
	   message.length < 0)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    ContentValues values = new ContentValues();

	    values.put
		("message",
		 Base64.encodeToString(cryptography.etm(message),
				       Base64.DEFAULT));
	    values.put
		("message_digest",
		 Base64.encodeToString(cryptography.hmac(message),
				       Base64.DEFAULT));
	    values.put
		("siphash_id",
		 Base64.encodeToString(cryptography.etm(sipHashId.
							getBytes("UTF-8")),
				       Base64.DEFAULT));
	    values.put
		("siphash_id_digest",
		 Base64.encodeToString(cryptography.hmac(sipHashId.
							 getBytes("UTF-8")),
				       Base64.DEFAULT));
	    values.put
		("verified_digest",
		 Base64.encodeToString(cryptography.hmac("false".getBytes()),
				       Base64.DEFAULT));
	    m_db.insert("stack", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_db.endTransaction();
	}
    }

    public void writeSetting(Cryptography cryptography,
			     String name,
			     String value)
    {
	prepareDb();

	if(m_db == null)
	    return;

	m_db.beginTransactionNonExclusive();

	try
	{
	    String a = name.trim();
	    String b = name.trim();
	    String c = value; // Do not trim.

	    if(cryptography != null)
	    {
		byte bytes[] = null;

		bytes = cryptography.etm(a.getBytes());

		if(bytes != null)
		    a = Base64.encodeToString(bytes, Base64.DEFAULT);
		else
		    a = "";

		bytes = cryptography.hmac(b.getBytes());

		if(bytes != null)
		    b = Base64.encodeToString(bytes, Base64.DEFAULT);
		else
		    b = "";

		bytes = cryptography.etm(c.getBytes());

		if(bytes != null)
		    c = Base64.encodeToString(bytes, Base64.DEFAULT);
		else
		    c = "";

		if(a.isEmpty() || b.isEmpty() || c.isEmpty())
		    throw new Exception();
	    }

	    ContentValues values = new ContentValues();

	    values.put("name", a);
	    values.put("name_digest", b);
	    values.put("value", c);
	    m_db.replace("settings", null, values);
	    m_db.setTransactionSuccessful();
	}
	catch(Exception exception)
        {
	}
	finally
	{
	    m_db.endTransaction();
	}
    }
}
