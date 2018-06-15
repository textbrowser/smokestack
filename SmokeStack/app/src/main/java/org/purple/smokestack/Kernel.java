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

import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiManager.WifiLock;
import android.net.wifi.WifiManager;
import android.os.PowerManager.WakeLock;
import android.os.PowerManager;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Base64;
import android.util.SparseArray;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Kernel
{
    private ArrayList<OzoneElement> m_ozones = null;
    private ArrayList<SipHashIdElement> m_sipHashIds = null;
    private Hashtable<String, ScheduledFuture>
	m_releaseMessagesSchedulers = null;
    private ScheduledExecutorService m_congestionScheduler = null;
    private ScheduledExecutorService m_listenersScheduler = null;
    private ScheduledExecutorService m_neighborsScheduler = null;
    private ScheduledExecutorService m_purgeExpiredRoutingEntries = null;
    private ScheduledExecutorService m_purgeReleasedMessagesScheduler = null;
    private WakeLock m_wakeLock = null;
    private WifiLock m_wifiLock = null;
    private final ArrayList<TcpNeighbor> m_serverNeighbors = new ArrayList<> ();
    private final ReentrantReadWriteLock m_ozonesMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_releaseMessagesSchedulersMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_serverNeighborsMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_sipHashIdsMutex = new
	ReentrantReadWriteLock();
    private final SparseArray<Neighbor> m_neighbors = new SparseArray<> ();
    private final SparseArray<TcpListener> m_listeners = new SparseArray<> ();
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
    private final static int CONGESTION_LIFETIME = 60;
    private final static int LISTENERS_INTERVAL = 5000; // 5 Seconds
    private final static int NEIGHBORS_INTERVAL = 5000; // 5 Seconds
    private final static int PKP_MESSAGE_RETRIEVAL_WINDOW = 30000; // 30 Seconds
    private final static int PURGE_RELEASED_MESSAGES_INTERVAL =
	5000; // 5 Seconds
    private final static int ROUTING_ENTRY_LIFETIME = CONGESTION_LIFETIME;
    private final static int ROUTING_INTERVAL = 15000; // 15 Seconds
    private static Kernel s_instance = null;
    public final static int MAXIMUM_IDENTITIES = 512;

    private Kernel()
    {
	m_releaseMessagesSchedulers = new Hashtable<> ();

	/*
	** Never, ever sleep.
	*/

	try
	{
	    PowerManager powerManager = (PowerManager)
		SmokeStack.getApplication().getApplicationContext().
		getSystemService(Context.POWER_SERVICE);

	    if(powerManager != null)
		m_wakeLock = powerManager.newWakeLock
		    (PowerManager.PARTIAL_WAKE_LOCK, "SmokeStackWakeLockTag");

	    if(m_wakeLock != null)
	    {
		m_wakeLock.setReferenceCounted(false);
		m_wakeLock.acquire();
	    }
	}
	catch(Exception exception)
	{
	}

	try
	{
	    WifiManager wifiManager = (WifiManager)
		SmokeStack.getApplication().getApplicationContext().
		getSystemService(Context.WIFI_SERVICE);

	    if(wifiManager != null)
		m_wifiLock = wifiManager.createWifiLock
		    (WifiManager.WIFI_MODE_FULL_HIGH_PERF,
		     "SmokeStackWiFiLockTag");

	    if(m_wifiLock != null)
	    {
		m_wifiLock.setReferenceCounted(false);
		m_wifiLock.acquire();
	    }
	}
	catch(Exception exception)
	{
	}

	/*
	** Other tasks.
	*/

	populateOzones();
	populateSipHashIds();
	prepareSchedulers();
    }

    private void prepareNeighbors()
    {
	ArrayList<NeighborElement> neighbors = purgeDeletedNeighbors();

	if(neighbors == null)
	    return;

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

    private void prepareReleaseMessagesScheduler(final String sipHashIdDigest,
						 final byte identity[])
    {
	if(identity == null ||
	   identity.length <= 0 ||
	   sipHashIdDigest == null ||
	   sipHashIdDigest.isEmpty())
	    return;

	m_releaseMessagesSchedulersMutex.writeLock().lock();

	try
	{
	    if(m_releaseMessagesSchedulers.containsKey(sipHashIdDigest))
		return;

	    m_releaseMessagesSchedulers.put
		(sipHashIdDigest,
		 Executors.newSingleThreadScheduledExecutor().
		 schedule(new Runnable()
		{
		    @Override
		    public void run()
		    {
			try
			{
			    while(true)
			    {
				ArrayList<byte[]> arrayList = s_databaseHelper.
				    readTaggedMessage
				    (sipHashIdDigest, s_cryptography);

				if(arrayList == null || arrayList.size() != 2)
				    break;

				byte destination[] = Cryptography.hmac
				    (arrayList.get(0), identity);

				if(destination == null)
				    break;

				String message = Messages.bytesToMessageString
				    (Miscellaneous.
				     joinByteArrays(arrayList.get(0),
						    destination));

				enqueueMessage(message);
				s_databaseHelper.timestampReleasedMessage
				    (s_cryptography, arrayList.get(1));
				Thread.sleep(200);
			    }
			}
			catch(Exception exception)
			{
			    throw new RuntimeException(exception);
			}
		    }
		}, 1500, TimeUnit.MILLISECONDS));
	}
	finally
	{
	    m_releaseMessagesSchedulersMutex.writeLock().unlock();
	}
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
		    try
		    {
			s_databaseHelper.purgeCongestion(CONGESTION_LIFETIME);
		    }
		    catch(Exception exception)
		    {
			throw new RuntimeException(exception);
		    }
		}
	    }, 1500, CONGESTION_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_listenersScheduler == null)
	{
	    m_listenersScheduler = Executors.newSingleThreadScheduledExecutor();
	    m_listenersScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			prepareListeners();
		    }
		    catch(Exception exception)
		    {
			throw new RuntimeException(exception);
		    }
		}
	    }, 1500, LISTENERS_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_neighborsScheduler == null)
	{
	    m_neighborsScheduler = Executors.newSingleThreadScheduledExecutor();
	    m_neighborsScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			prepareNeighbors();
		    }
		    catch(Exception exception)
		    {
			throw new RuntimeException(exception);
		    }
		}
	    }, 1500, NEIGHBORS_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_purgeReleasedMessagesScheduler == null)
	{
	    m_purgeReleasedMessagesScheduler = Executors.
		newSingleThreadScheduledExecutor();
	    m_purgeReleasedMessagesScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			m_releaseMessagesSchedulersMutex.writeLock().lock();

			try
			{
			    if(!m_releaseMessagesSchedulers.isEmpty())
			    {
				/*
				** Remove completed schedules.
				*/

				Iterator<Hashtable.
				         Entry<String, ScheduledFuture> >
				    it = m_releaseMessagesSchedulers.entrySet().
				    iterator();

				while(it.hasNext())
				{
				    Hashtable.Entry<String, ScheduledFuture>
					entry = it.next();

				    if(entry.getValue() == null)
					it.remove();
				    else if(entry.getValue().isDone())
					it.remove();
				}
			    }
			}
			finally
			{
			    m_releaseMessagesSchedulersMutex.writeLock().
				unlock();
			}

			try
			{
			    s_databaseHelper.purgeReleasedMessages
				(s_cryptography);
			}
			catch(Exception exception)
			{
			}
		    }
		    catch(Exception exception)
		    {
			throw new RuntimeException(exception);
		    }
		}
	    }, 1500, PURGE_RELEASED_MESSAGES_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_purgeExpiredRoutingEntries == null)
	{
	    m_purgeExpiredRoutingEntries = Executors.
		newSingleThreadScheduledExecutor();
	    m_purgeExpiredRoutingEntries.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			s_databaseHelper.purgeExpiredRoutingEntries
			    (ROUTING_ENTRY_LIFETIME);
		    }
		    catch(Exception exception)
		    {
			throw new RuntimeException(exception);
		    }
		}
	    }, 1500, ROUTING_INTERVAL, TimeUnit.MILLISECONDS);
	}
    }

    private void purgeListeners()
    {
	/*
	** Disconnect all existing sockets.
	*/

	synchronized(m_listeners)
	{
	    for(int i = 0; i < m_listeners.size(); i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		    m_listeners.get(j).abort();
	    }

	    m_listeners.clear();
	}

	m_serverNeighborsMutex.writeLock().lock();

	try
	{
	    /*
	    ** TcpListener will disconnect its sockets.
	    */

	    for(int i = 0; i < m_serverNeighbors.size(); i++)
		if(m_serverNeighbors.get(i) != null)
		    m_serverNeighbors.get(i).abort();

	    m_serverNeighbors.clear();
	}
	finally
	{
	    m_serverNeighborsMutex.writeLock().unlock();
	}
    }

    private void purgeNeighbors()
    {
	/*
	** Disconnect all non-server sockets.
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

    public ArrayList<NeighborElement> purgeDeletedNeighbors()
    {
	ArrayList<NeighborElement> neighbors =
	    s_databaseHelper.readNeighbors(s_cryptography);

	if(neighbors == null || neighbors.size() == 0)
	{
	    purgeNeighbors();
	    return neighbors;
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

		for(NeighborElement neighborElement : neighbors)
		    if(neighborElement != null && neighborElement.m_oid == oid)
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

	return neighbors;
    }

    public boolean ourMessage(String buffer,
			      UUID clientIdentity,
			      boolean userDefined)
    {
	long value = s_congestionSipHash.hmac(buffer.getBytes());

	try
	{
	    if(!userDefined)
		/*
		** A server socket!
		*/

		if(buffer.contains("type=0095a&content"))
		{
		    s_databaseHelper.writeCongestionDigest(value);

		    /*
		    ** A client has shared an identity stream.
		    */

		    s_databaseHelper.writeIdentity
			(clientIdentity, Messages.stripMessage(buffer));

		    /*
		    ** Do not echo the identity stream to other neighbors
		    ** as a separate thread will distribute harvested
		    ** identities.
		    */

		    return true;
		}
		else if(buffer.contains("type=0095b&content"))
		{
		    /*
		    ** We've received identities.
		    */

		    s_databaseHelper.writeCongestionDigest(value);
		    s_databaseHelper.deleteRoutingEntry
			(clientIdentity.toString());

		    byte bytes[] = Base64.decode
			(Messages.stripMessage(buffer), Base64.DEFAULT);

		    s_databaseHelper.writeIdentities(clientIdentity, bytes);
		    return true;
		}
		else if(buffer.contains("type=0096&content"))
		    return true;

	    if(s_databaseHelper.containsCongestionDigest(value))
		return true;

	    byte bytes[] =
		Base64.decode(Messages.stripMessage(buffer), Base64.DEFAULT);

	    if(bytes == null || bytes.length < 128)
		return false;

	    /*
	    ** EPKS?
	    */

	    ArrayList<SipHashIdElement> arrayList1 = null;

	    m_sipHashIdsMutex.readLock().lock();

	    try
	    {
		arrayList1 = m_sipHashIds;
	    }
	    finally
	    {
		m_sipHashIdsMutex.readLock().unlock();
	    }

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

		s_databaseHelper.writeCongestionDigest(value);

		byte aes256[] = Cryptography.decrypt
		    (array1,
		     Arrays.copyOfRange(sipHashIdElement.m_stream, 0, 32));

		if(s_databaseHelper.
		   writeParticipant(s_cryptography,
				    sipHashIdElement.m_acceptWithoutSignatures,
				    aes256))
		{
		    Intent intent = new Intent
			("org.purple.smokestack.populate_participants");
		    LocalBroadcastManager localBroadcastManager =
			LocalBroadcastManager.getInstance
			(SmokeStack.getApplication());

		    localBroadcastManager.sendBroadcast(intent);
		}

		return true;
	    }

	    ArrayList<OzoneElement> arrayList2 = null;

	    m_ozonesMutex.readLock().lock();

	    try
	    {
		arrayList2 = m_ozones;
	    }
	    finally
	    {
		m_ozonesMutex.readLock().unlock();
	    }

	    if(arrayList2 == null || arrayList2.size() == 0)
		return false;

	    /*
	    ** Message retrieval and storage.
	    */

	    array1 = Arrays.copyOfRange(bytes, 0, bytes.length - 64);
	    array2 = Arrays.copyOfRange(bytes, bytes.length - 64, bytes.length);

	    for(OzoneElement ozoneElement : arrayList2)
	    {
		if(ozoneElement == null)
		    continue;

		if(Cryptography.
		   memcmp(array2,
			  Cryptography.
			  hmac(array1,
			       Arrays.copyOfRange(ozoneElement.m_addressStream,
						  32,
						  ozoneElement.m_addressStream.
						  length))))
		 {
		     /*
		     ** A message-retrieval request!
		     */

		     byte aes256[] = Cryptography.decrypt
			 (array1,
			  Arrays.copyOfRange(ozoneElement.m_addressStream,
					     0,
					     32));

		     if(aes256 == null || aes256.length < 25)
			 return true;

		     if(aes256[0] == Messages.CHAT_MESSAGE_RETRIEVAL[0])
		     {
			 long current = System.currentTimeMillis();
			 long timestamp = Miscellaneous.byteArrayToLong
			     (Arrays.copyOfRange(aes256, 1, 1 + 8));

			 if(current - timestamp < 0)
			 {
			     if(timestamp - current >
				CHAT_MESSAGE_RETRIEVAL_WINDOW)
				 return true;
			 }
			 else if(current - timestamp >
				 CHAT_MESSAGE_RETRIEVAL_WINDOW)
			     return true;

			 byte identity[] = Arrays.copyOfRange
			     (aes256, 9, 9 + 64);

			 if(identity == null || identity.length != 64)
			     return true;

			 PublicKey signatureKey = s_databaseHelper.
			     signatureKeyForDigest
			     (s_cryptography,
			      Arrays.copyOfRange(aes256, 73, 73 + 64));

			 if(signatureKey == null)
			     return true;

			 if(!Cryptography.
			    verifySignature(signatureKey,
					    Arrays.copyOfRange(aes256,
							       137,
							       aes256.length),
					    Arrays.
					    copyOfRange(aes256,
							0,
							137)))
			     return true;

			 s_databaseHelper.writeCongestionDigest(value);

			 String sipHashIdDigest = s_databaseHelper.
			     sipHashIdDigestFromDigest
			     (s_cryptography,
			      Arrays.copyOfRange(aes256, 73, 73 + 64));

			 /*
			 ** Tag all of sipHashIdDigest's messages for release.
			 */

			 s_databaseHelper.tagMessagesForRelease
			     (s_cryptography, sipHashIdDigest);
			 prepareReleaseMessagesScheduler
			     (sipHashIdDigest, identity);
			 return true;
		     }
		     else if(aes256[0] == Messages.PKP_MESSAGE_REQUEST[0])
		     {
			 /*
			 ** Request a public key pair.
			 */

			 long current = System.currentTimeMillis();
			 long timestamp = Miscellaneous.byteArrayToLong
			     (Arrays.copyOfRange(aes256, 1, 1 + 8));

			 if(current - timestamp < 0)
			 {
			     if(timestamp - current >
				PKP_MESSAGE_RETRIEVAL_WINDOW)
				 return true;
			 }
			 else if(current - timestamp >
				 PKP_MESSAGE_RETRIEVAL_WINDOW)
			     return true;

			 String sipHashId = new String
			     (Arrays.copyOfRange(aes256, 32, aes256.length),
			      "UTF-8");
			 String array[] = s_databaseHelper.readPublicKeyPair
			     (s_cryptography, sipHashId);

			 if(array == null)
			     return true;

			 sipHashId = new String
			     (Arrays.copyOfRange(aes256, 9, 9 + 23));

			 String message = Messages.bytesToMessageString
			     (Messages.epksMessage(sipHashId, array));

			 enqueueMessage(message);
			 return true;
		     }
		     else
			 return true;
		 }

		for(SipHashIdElement sipHashIdElement : arrayList1)
		{
		    if(sipHashIdElement == null)
			continue;

		    long minutes = TimeUnit.MILLISECONDS.toMinutes
			(System.currentTimeMillis());

		    for(int i = 0; i < 2; i++)
			if(Cryptography.
			   memcmp(array2,
				  Cryptography.
				  hmac(Miscellaneous.
				       joinByteArrays(array1,
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
			{
			    /*
			    ** Discovered.
			    */

			    s_databaseHelper.writeCongestionDigest(value);
			    s_databaseHelper.writeMessage
				(s_cryptography,
				 sipHashIdElement.m_sipHashId,
				 array1);
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
	    (s_congestionSipHash.hmac(data));
    }

    public void clearNeighborQueues()
    {
	synchronized(m_neighbors)
	{
	    for(int i = 0; i < m_neighbors.size(); i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null)
		    m_neighbors.get(j).clearEchoQueue();
	    }
	}
    }

    public void echo(String message, int oid)
    {
	if(message.trim().isEmpty())
	    return;

	synchronized(m_neighbors)
	{
	    for(int i = 0; i < m_neighbors.size(); i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null &&
		   m_neighbors.get(j).getOid() != oid)
		    m_neighbors.get(j).scheduleEchoSend(message);
	    }
	}

	m_serverNeighborsMutex.readLock().lock();

	try
	{
	    for(int i = 0; i < m_serverNeighbors.size(); i++)
		if(m_serverNeighbors.get(i) != null)
		    m_serverNeighbors.get(i).scheduleEchoSend(message);
	}
	finally
	{
	    m_serverNeighborsMutex.readLock().unlock();
	}
    }

    public void enqueueMessage(String message)
    {
	if(message.trim().isEmpty())
	    return;

	ArrayList<NeighborElement> arrayList =
	    s_databaseHelper.readNeighborOids(s_cryptography);

	if(arrayList != null && arrayList.size() > 0)
	{
	    for(int i = 0; i < arrayList.size(); i++)
		if(arrayList.get(i) != null &&
		   arrayList.get(i).m_statusControl.toLowerCase().
		   equals("connect"))
		    s_databaseHelper.enqueueOutboundMessage
			(message, arrayList.get(i).m_oid);

	    arrayList.clear();
	}

	m_serverNeighborsMutex.readLock().lock();

	try
	{
	    for(int i = 0; i < m_serverNeighbors.size(); i++)
		if(m_serverNeighbors.get(i) != null)
		    m_serverNeighbors.get(i).scheduleSend(message);
	}
	finally
	{
	    m_serverNeighborsMutex.readLock().unlock();
	}
    }

    public void populateOzones()
    {
	m_ozonesMutex.writeLock().lock();

	try
	{
	    m_ozones = s_databaseHelper.readOzones(s_cryptography);
	}
	finally
	{
	    m_ozonesMutex.writeLock().unlock();
	}
    }

    public void populateSipHashIds()
    {
	m_sipHashIdsMutex.writeLock().lock();

	try
	{
	    m_sipHashIds = s_databaseHelper.readSipHashIds(s_cryptography);
	}
	finally
	{
	    m_sipHashIdsMutex.writeLock().unlock();
	}
    }

    public void prepareListeners()
    {
	ArrayList<ListenerElement> listeners =
	    s_databaseHelper.readListeners(s_cryptography);

	if(listeners == null || listeners.size() == 0)
	{
	    purgeListeners();
	    return;
	}

	synchronized(m_listeners)
	{
	    for(int i = m_listeners.size() - 1; i >= 0; i--)
	    {
		/*
		** Remove listener objects which do not exist in the
		** database.
		*/

		boolean found = false;
		int oid = m_listeners.keyAt(i);

		for(ListenerElement listenerElement : listeners)
		    if(listenerElement != null && listenerElement.m_oid == oid)
		    {
			found = true;
			break;
		    }

		if(!found)
		{
		    if(m_listeners.get(oid) != null)
			m_listeners.get(oid).abort();

		    m_listeners.remove(oid);
		}
	    }
	}

	for(ListenerElement listenerElement : listeners)
	{
	    if(listenerElement == null)
		continue;
	    else
	    {
		synchronized(m_listeners)
		{
		    if(m_listeners.get(listenerElement.m_oid) != null)
			continue;
		}

		if(listenerElement.m_statusControl.toLowerCase().
		   equals("delete") ||
		   listenerElement.m_statusControl.toLowerCase().
		   equals("disconnect"))
		{
		    if(listenerElement.m_statusControl.toLowerCase().
		       equals("disconnect"))
			s_databaseHelper.saveListenerInformation
			    (s_cryptography,
			     "",              // Error
			     "0",             // Peers Count
			     "disconnected",  // Status
			     "0",             // Uptime
			     String.valueOf(listenerElement.m_oid));

		    continue;
		}
	    }

	    TcpListener listener = new TcpListener
		(listenerElement.m_localIpAddress,
		 listenerElement.m_localPort,
		 listenerElement.m_localScopeId,
		 listenerElement.m_ipVersion,
		 listenerElement.m_certificate,
		 listenerElement.m_privateKey,
		 listenerElement.m_publicKey,
		 listenerElement.m_oid);

	    synchronized(m_listeners)
	    {
		m_listeners.append(listenerElement.m_oid, listener);
	    }
	}

	listeners.clear();
    }

    public void recordNeighbor(TcpNeighbor neighbor)
    {
	if(neighbor == null)
	    return;

	m_serverNeighborsMutex.writeLock().lock();

	try
	{
	    m_serverNeighbors.add(neighbor);
	}
	finally
	{
	    m_serverNeighborsMutex.writeLock().unlock();
	}
    }

    public void removeNeighbor(TcpNeighbor neighbor)
    {
	if(neighbor == null)
	    return;

	m_serverNeighborsMutex.writeLock().lock();

	try
	{
	    m_serverNeighbors.remove(neighbor);

	    for(int i = m_serverNeighbors.size() - 1; i >= 0; i--)
		if(m_serverNeighbors.get(i) == null)
		    m_serverNeighbors.remove(i);
	}
	finally
	{
	    m_serverNeighborsMutex.writeLock().unlock();
	}
    }
}
