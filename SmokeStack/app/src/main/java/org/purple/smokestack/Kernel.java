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

import android.content.Intent;
import android.util.Base64;
import android.util.SparseArray;
import android.util.SparseIntArray;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Kernel
{
    private ScheduledExecutorService m_congestionScheduler = null;
    private ScheduledExecutorService m_neighborsScheduler = null;
    private ScheduledExecutorService m_releaseMessagesScheduler = null;
    private final ReentrantReadWriteLock m_ozonesMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_sipHashIdsMutex = new
	ReentrantReadWriteLock();
    private final SparseArray<Neighbor> m_neighbors = new SparseArray<> ();
    private final static Database s_databaseHelper = Database.getInstance();
    private final static Cryptography s_cryptography =
	Cryptography.getInstance();
    private final static SipHash s_congestionSipHash = new SipHash
	(Cryptography.randomBytes(SipHash.KEY_LENGTH));
    private final static int CHAT_MESSAGE_RETRIEVAL_WINDOW = 30000; /*
								    ** 30
								    ** Seconds
								    */
    private final static int CONGESTION_INTERVAL = 15000; // 15 Seconds
    private final static int CONGESTION_LIFETIME = 30;
    private final static int NEIGHBORS_INTERVAL = 5000; // 5 Seconds
    private final static int RELEASE_MESSAGES_INTERVAL = 1500; // 1.5 Seconds
    private static Kernel s_instance = null;

    private Kernel()
    {
	populateOzones();
	populateSipHashIds();
	prepareSchedulers();
    }

    private void populateOzones()
    {
    }

    private void populateSipHashIds()
    {
    }

    private void prepareSchedulers()
    {
	if(m_congestionScheduler == null)
	{
	    m_congestionScheduler = Executors.
		newSingleThreadScheduledExecutor();
	    m_congestionScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    s_databaseHelper.purgeCongestion(CONGESTION_LIFETIME);
		}
	    }, 1500, CONGESTION_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_neighborsScheduler == null)
	{
	    m_neighborsScheduler = Executors.newSingleThreadScheduledExecutor();
	    m_neighborsScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    prepareNeighbors();
		}
	    }, 1500, NEIGHBORS_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_releaseMessagesScheduler == null)
	{
	    m_releaseMessagesScheduler = Executors.
		newSingleThreadScheduledExecutor();
	    m_releaseMessagesScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    releaseMessages();
		}
	    }, 1500, RELEASE_MESSAGES_INTERVAL, TimeUnit.MILLISECONDS);
	}
    }

    private void purge()
    {
	/*
	** Disconnect all existing sockets.
	*/

	synchronized(m_neighbors)
	{
	    for(int i = 0; i < m_neighbors.size(); i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null)
		    m_neighbors.get(j).abort();
	    }

	    m_neighbors.clear();
	}
    }

    private void releaseMessages()
    {
	ArrayList<byte[]> arrayList = s_databaseHelper.readTaggedMessage
	    (s_cryptography);

	if(arrayList == null || arrayList.size() != 3)
	    return;

	byte destination[] = Cryptography.hmac
	    (arrayList.get(0), Cryptography.sha512(arrayList.get(2)));

	if(destination == null)
	    return;

	enqueueMessage
	    (Messages.
	     bytesToMessageString(Miscellaneous.
				  joinByteArrays(arrayList.get(0),
						 destination)));
	s_databaseHelper.timestampReleasedMessage
	    (s_cryptography, arrayList.get(1));
    }

    public boolean ourMessage(String buffer)
    {
	if(s_databaseHelper.containsCongestionDigest(s_congestionSipHash.
						     hmac(buffer.getBytes())))
	    return true;

	s_databaseHelper.writeCongestionDigest
	    (s_congestionSipHash.hmac(buffer.getBytes()));

	try
	{
	    byte bytes[] =
		Base64.decode(Messages.stripMessage(buffer), Base64.DEFAULT);

	    if(bytes == null || bytes.length < 128)
		return false;

	    /*
	    ** EPKS
	    */

	    ArrayList<SipHashIdElement> arrayList1 = s_databaseHelper.
		readSipHashIds(s_cryptography);

	    if(arrayList1 == null || arrayList1.size() == 0)
		return false;

	    byte array1[] = Arrays.copyOfRange // Blocks #1, #2, etc.
		(bytes, 0, bytes.length - 128);
	    byte array2[] = Arrays.copyOfRange // Second to the last block.
		(bytes, bytes.length - 128, bytes.length - 64);

	    for(SipHashIdElement sipHashIdElement : arrayList1)
	    {
		if(sipHashIdElement == null)
		    continue;
		else if(sipHashIdElement.m_epksCompleted)
		    continue;

		if(!Cryptography.
		   memcmp(array2,
			  Cryptography.hmac(array1, Arrays.
					    copyOfRange(sipHashIdElement.
							m_stream,
							32,
							sipHashIdElement.
							m_stream.length))))
		    continue;

		byte aes256[] = Cryptography.decrypt
		    (array1,
		     Arrays.copyOfRange(sipHashIdElement.m_stream, 0, 32));

		if(s_databaseHelper.writeParticipant(s_cryptography, aes256))
		{
		    Intent intent = new Intent
			("org.purple.smokestack.populate_participants");

		    SmokeStack.getApplication().sendBroadcast(intent);
		}

		return true;
	    }

	    ArrayList<OzoneElement> arrayList2 = s_databaseHelper.readOzones
		(s_cryptography);

	    if(arrayList2 == null || arrayList2.size() == 0)
		return false;

	    byte a1[] = Arrays.copyOfRange(bytes,
					   0,
					   bytes.length - 64);
	    byte a2[] = Arrays.copyOfRange(bytes,
					   bytes.length - 64,
					   bytes.length);

	    for(OzoneElement ozoneElement : arrayList2)
	    {
		if(ozoneElement == null)
		    continue;

		if(Cryptography.
		   memcmp(a2,
			  Cryptography.
			  hmac(a1,
			       Arrays.copyOfRange(ozoneElement.m_addressStream,
						  32,
						  ozoneElement.m_addressStream.
						  length))))
		 {
		     /*
		     ** A message-retrieval request!
		     */

		     byte aes256[] = Cryptography.decrypt
			 (a1,
			  Arrays.copyOfRange(ozoneElement.m_addressStream,
					     0,
					     32));

		     if(aes256 == null)
			 return false;

		     long current = System.currentTimeMillis();
		     long timestamp = Miscellaneous.byteArrayToLong
			 (Arrays.copyOfRange(aes256, 1, 1 + 8));

		     if(current - timestamp < 0)
		     {
			 if(timestamp - current > CHAT_MESSAGE_RETRIEVAL_WINDOW)
			     return false;
		     }
		     else if(current - timestamp >
			     CHAT_MESSAGE_RETRIEVAL_WINDOW)
			 return false;

		     PublicKey signatureKey = s_databaseHelper.
			 signatureKeyForDigest
			 (s_cryptography,
			  Arrays.copyOfRange(aes256, 9, 9 + 64));

		     if(signatureKey == null)
			 return false;

		     if(!Cryptography.
			verifySignature(signatureKey,
					Arrays.copyOfRange(aes256,
							   73,
							   aes256.length),
					Arrays.
					copyOfRange(aes256,
						    0,
						    73)))
			 return false;

		     String sipHashIdDigest = s_databaseHelper.
			 sipHashIdDigestFromDigest
			 (s_cryptography,
			  Arrays.copyOfRange(aes256, 9, 9 + 64));

		     /*
		     ** Tag all messages for release.
		     */

		     s_databaseHelper.tagMessagesForRelease
			 (s_cryptography, sipHashIdDigest);
		     return true;
		 }

		for(SipHashIdElement sipHashIdElement : arrayList1)
		{
		    if(sipHashIdElement == null)
			continue;

		    long minutes = TimeUnit.MILLISECONDS.toMinutes
			(System.currentTimeMillis());

		    for(int i = 0; i < 2; i++)
			if(!Cryptography.
			   memcmp(a2,
				  Cryptography.
				  hmac(Miscellaneous.
				       joinByteArrays(a1,
						      sipHashIdElement.
						      m_sipHashId.
						      getBytes("UTF-8"),
						      Miscellaneous.
						      longToByteArray(i +
								      minutes)),
				       Arrays.copyOfRange(ozoneElement.
							  m_addressStream,
							  32,
							  ozoneElement.
							  m_addressStream.
							  length))))
			    continue;
			else
			{
			    /*
			    ** Discovered.
			    */

			    s_databaseHelper.writeMessage
				(s_cryptography,
				 sipHashIdElement.m_sipHashId,
				 a1);
			    return true;
			}
		}
	    }
	}
	catch(Exception exception)
	{
	    return false;
	}

	return false;
    }

    public static synchronized Kernel getInstance()
    {
	if(s_instance == null)
	    s_instance = new Kernel();

	return s_instance;
    }

    public static void writeCongestionDigest(String message)
    {
	s_databaseHelper.writeCongestionDigest
	    (s_congestionSipHash.hmac(message.getBytes()));
    }

    public static void writeCongestionDigest(byte data[])
    {
	s_databaseHelper.writeCongestionDigest
	    (s_congestionSipHash.hmac(data)); /*
					      ** Zero on hmac() failure.
					      ** Acceptable.
					      */
    }

    public void clearNeighborQueues()
    {
	synchronized(m_neighbors)
	{
	    for(int i = 0; i < m_neighbors.size(); i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null)
		    m_neighbors.get(j).clearQueue();
	    }
	}
    }

    public void echo(String message, int oid)
    {
	if(message.trim().isEmpty())
	    return;

	if(s_databaseHelper.
	   containsCongestionDigest(s_congestionSipHash.hmac(message.
							     getBytes())))
	    return;

	synchronized(m_neighbors)
	{
	    for(int i = 0; i < m_neighbors.size(); i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null &&
		   m_neighbors.get(j).getOid() != oid)
		    m_neighbors.get(j).scheduleSend(message);
	    }
	}
    }

    public void enqueueMessage(String message)
    {
	if(message.trim().isEmpty())
	    return;

	SparseIntArray neighbors = s_databaseHelper.readNeighborOids();

	if(neighbors == null || neighbors.size() == 0)
	    return;

	for(int i = 0; i < neighbors.size(); i++)
	    s_databaseHelper.enqueueOutboundMessage(message, neighbors.get(i));

	neighbors.clear();
    }

    public void prepareNeighbors()
    {
	ArrayList<NeighborElement> neighbors =
	    s_databaseHelper.readNeighbors(s_cryptography);

	if(neighbors == null || neighbors.size() == 0)
	{
	    purge();
	    return;
	}

	synchronized(m_neighbors)
	{
	    for(int i = m_neighbors.size() - 1; i >= 0; i--)
	    {
		/*
		** Remove neighbor objects which do not exist in the
		** database.
		*/

		boolean found = false;
		int oid = m_neighbors.keyAt(i);

		for(NeighborElement neighbor : neighbors)
		    if(neighbor != null && neighbor.m_oid == oid)
		    {
			found = true;
			break;
		    }

		if(!found)
		{
		    if(m_neighbors.get(oid) != null)
			m_neighbors.get(oid).abort();

		    m_neighbors.remove(oid);
		}
	    }
	}

	for(NeighborElement neighborElement : neighbors)
	{
	    if(neighborElement == null)
		continue;
	    else
	    {
		synchronized(m_neighbors)
		{
		    if(m_neighbors.get(neighborElement.m_oid) != null)
			continue;
		}

		if(neighborElement.m_statusControl.toLowerCase().
		   equals("delete") ||
		   neighborElement.m_statusControl.toLowerCase().
		   equals("disconnect"))
		{
		    if(neighborElement.m_statusControl.toLowerCase().
		       equals("disconnect"))
			s_databaseHelper.saveNeighborInformation
			    (s_cryptography,
			     "0",             // Bytes Read
			     "0",             // Bytes Written
			     "0",             // Queue Size
			     "",              // Error
			     "",              // IP Address
			     "0",             // Port
			     "",              // Session Cipher
			     "disconnected",  // Status
			     "0",             // Uptime
			     String.valueOf(neighborElement.m_oid));

		    continue;
		}
	    }

	    Neighbor neighbor = null;

	    if(neighborElement.m_transport.equals("TCP"))
		neighbor = new TcpNeighbor
		    (neighborElement.m_proxyIpAddress,
		     neighborElement.m_proxyPort,
		     neighborElement.m_proxyType,
		     neighborElement.m_remoteIpAddress,
		     neighborElement.m_remotePort,
		     neighborElement.m_remoteScopeId,
		     neighborElement.m_ipVersion,
		     neighborElement.m_oid);
	    else if(neighborElement.m_transport.equals("UDP"))
	    {
		try
		{
		    InetAddress inetAddress = InetAddress.getByName
			(neighborElement.m_remoteIpAddress);

		    if(inetAddress.isMulticastAddress())
			neighbor = new UdpMulticastNeighbor
			    (neighborElement.m_remoteIpAddress,
			     neighborElement.m_remotePort,
			     neighborElement.m_remoteScopeId,
			     neighborElement.m_ipVersion,
			     neighborElement.m_oid);
		    else
			neighbor = new UdpNeighbor
			    (neighborElement.m_remoteIpAddress,
			     neighborElement.m_remotePort,
			     neighborElement.m_remoteScopeId,
			     neighborElement.m_ipVersion,
			     neighborElement.m_oid);
		}
		catch(Exception exception)
		{
		}
	    }

	    if(neighbor == null)
		continue;

	    synchronized(m_neighbors)
	    {
		m_neighbors.append(neighborElement.m_oid, neighbor);
	    }
	}

	neighbors.clear();
    }
}
