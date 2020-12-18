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
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager.WifiLock;
import android.net.wifi.WifiManager;
import android.os.PowerManager.WakeLock;
import android.os.PowerManager;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Base64;
import android.util.SparseArray;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Kernel
{
    private static class SipHashIdentityPair
    {
	public String m_sipHashIdDigest = "";
	public byte m_identity[] = null;

	public SipHashIdentityPair(String sipHashIdDigest, byte identity[])
	{
	    m_identity = identity;
	    m_sipHashIdDigest = sipHashIdDigest;
	}
    };

    private ArrayList<OzoneElement> m_ozones = null;
    private ArrayList<SipHashIdElement> m_sipHashIds = null;
    private LinkedList<SipHashIdentityPair> m_releaseMessagesQueue = null;
    private ScheduledExecutorService m_congestionScheduler = null;
    private ScheduledExecutorService m_listenersScheduler = null;
    private ScheduledExecutorService m_neighborsScheduler = null;
    private ScheduledExecutorService m_purgeExpiredRoutingEntriesScheduler =
	null;
    private ScheduledExecutorService m_releaseMessagesSchedulers[] = null;
    private WakeLock m_wakeLock = null;
    private WifiLock m_wifiLock = null;
    private final ReentrantReadWriteLock m_listenersMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_ozonesMutex = new
	ReentrantReadWriteLock();
    private final ReentrantReadWriteLock m_releaseMessagesQueueMutex = new
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
    private final static int CONGESTION_LIFETIME = 60;
    private final static int IDENTITY_LENGTH = 64; // Sender's Identity
    private final static int NUMBER_OF_CORES = Math.max
	(4, Runtime.getRuntime().availableProcessors());
    private final static int ROUTING_ENTRY_LIFETIME = CONGESTION_LIFETIME;
    private final static long CHAT_MESSAGE_RETRIEVAL_WINDOW = 30000L; /*
								      ** 30
								      ** Seconds
								      */
    private final static long CONGESTION_INTERVAL = 15000L; // 15 Seconds
    private final static long LISTENERS_INTERVAL = 5000L; // 5 Seconds
    private final static long NEIGHBORS_INTERVAL = 5000L; // 5 Seconds
    private final static long PKP_MESSAGE_RETRIEVAL_WINDOW =
	30000L; // 30 Seconds
    private final static long RELEASE_MESSAGES_INTERVAL = 500L; // 0.5 Seconds
    private final static long ROUTING_INTERVAL = 15000L; // 15 Seconds
    private final static long SHARE_SIPHASH_IDENTITY_WINDOW =
	30000L; // 30 Seconds
    private static Kernel s_instance = null;

    private Kernel()
    {
	m_releaseMessagesQueue = new LinkedList<> ();

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
		    (PowerManager.PARTIAL_WAKE_LOCK,
		     "SmokeStack:SmokeStackWakeLockTag");

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
		     "SmokeStack:SmokeStackWiFiLockTag");

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

    public boolean isNetworkAvailable()
    {
	try
	{
	    ConnectivityManager connectivityManager = (ConnectivityManager)
		SmokeStack.getApplication().getApplicationContext().
		getSystemService(Context.CONNECTIVITY_SERVICE);
	    NetworkInfo networkInfo = connectivityManager.
		getActiveNetworkInfo();

	    if(networkInfo.getState() !=
	       android.net.NetworkInfo.State.CONNECTED)
		return false;
	}
	catch(Exception exception)
	{
	    return false;
	}

	return true;
    }

    private void prepareListeners()
    {
	if(!isNetworkAvailable())
	{
	    purgeListeners();
	    return;
	}

	ArrayList<ListenerElement> listeners =
	    s_databaseHelper.readListeners(s_cryptography, -1);

	if(listeners == null || listeners.size() == 0)
	{
	    purgeListeners();
	    return;
	}

	m_listenersMutex.writeLock().lock();

	try
	{
	    for(int i = m_listeners.size() - 1; i >= 0; i--)
	    {
		/*
		** Remove listener objects which do not exist in the database.
		** Also removed will be listeners having disconnected statuses.
		*/

		boolean found = false;
		int oid = m_listeners.keyAt(i);

		for(ListenerElement listenerElement : listeners)
		    if(listenerElement != null && listenerElement.m_oid == oid)
		    {
			if(!listenerElement.m_statusControl.toLowerCase().
			   equals("disconnect"))
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
	finally
	{
	    m_listenersMutex.writeLock().unlock();
	}

	for(ListenerElement listenerElement : listeners)
	{
	    if(listenerElement == null)
		continue;
	    else
	    {
		m_listenersMutex.readLock().lock();

		try
		{
		    if(m_listeners.get(listenerElement.m_oid) != null)
			continue;
		}
		finally
		{
		    m_listenersMutex.readLock().unlock();
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
		 listenerElement.m_isPrivate,
		 listenerElement.m_certificate,
		 listenerElement.m_privateKey,
		 listenerElement.m_publicKey,
		 listenerElement.m_oid);

	    m_listenersMutex.writeLock().lock();

	    try
	    {
		m_listeners.append(listenerElement.m_oid, listener);
	    }
	    finally
	    {
		m_listenersMutex.writeLock().unlock();
	    }
	}

	listeners.clear();
    }

    private void prepareNeighbors()
    {
	if(!isNetworkAvailable())
	{
	    purgeNeighbors();
	    return;
	}

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
		    {
			s_databaseHelper.deleteEchoQueue
			    (neighborElement.m_oid);
			s_databaseHelper.saveNeighborInformation
			    (s_cryptography,
			     "0",             // Bytes Buffered
			     "0",             // Bytes Read
			     "0",             // Bytes Written
			     "",              // Error
			     "",              // IP Address
			     "0",             // Port
			     "0",             // Queue Size
			     "",              // Session Cipher
			     "disconnected",  // Status
			     "0",             // Uptime
			     String.valueOf(neighborElement.m_oid));
		    }

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

    private void prepareReleaseMessagesPair(final String sipHashIdDigest,
					    final byte identity[])
    {
	if(!isNetworkAvailable() ||
	   identity == null ||
	   identity.length == 0 ||
	   sipHashIdDigest == null ||
	   sipHashIdDigest.isEmpty())
	    return;

	m_releaseMessagesQueueMutex.writeLock().lock();

	try
	{
	    m_releaseMessagesQueue.add
		(new SipHashIdentityPair(sipHashIdDigest, identity));
	}
	finally
	{
	    m_releaseMessagesQueueMutex.writeLock().unlock();
	}

	synchronized(m_releaseMessagesQueueMutex)
	{
	    try
	    {
		m_releaseMessagesQueueMutex.notifyAll();
	    }
	    catch(Exception exception)
	    {
	    }
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
		    }
		}
	    }, 1500L, CONGESTION_INTERVAL, TimeUnit.MILLISECONDS);
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
		    }
		}
	    }, 1500L, LISTENERS_INTERVAL, TimeUnit.MILLISECONDS);
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
		    }
		}
	    }, 1500L, NEIGHBORS_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_purgeExpiredRoutingEntriesScheduler == null)
	{
	    m_purgeExpiredRoutingEntriesScheduler = Executors.
		newSingleThreadScheduledExecutor();
	    m_purgeExpiredRoutingEntriesScheduler.scheduleAtFixedRate
		(new Runnable()
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
		    }
		}
	    }, 1500L, ROUTING_INTERVAL, TimeUnit.MILLISECONDS);
	}

	if(m_releaseMessagesSchedulers == null)
	{
	    m_releaseMessagesSchedulers = new
		ScheduledExecutorService[NUMBER_OF_CORES];

	    for(int i = 0; i < m_releaseMessagesSchedulers.length; i++)
	    {
		m_releaseMessagesSchedulers[i] = Executors.
		    newSingleThreadScheduledExecutor();
	    
		m_releaseMessagesSchedulers[i].scheduleAtFixedRate
		    (new Runnable()
		{
		    private final AtomicInteger m_oid = new AtomicInteger(-1);

		    @Override
		    public void run()
			{
			try
			{
			    while(true)
			    {
				if(!isNetworkAvailable())
				{
				    Thread.sleep(250);
				    continue;
				}

				SipHashIdentityPair pair = null;

				m_releaseMessagesQueueMutex.writeLock().lock();

				try
				{
				    if(!m_releaseMessagesQueue.isEmpty())
					pair = m_releaseMessagesQueue.remove();
				}
				finally
				{
				    m_releaseMessagesQueueMutex.writeLock().
					unlock();
				}

				if(pair == null)
				{
				    synchronized(m_releaseMessagesQueueMutex)
				    {
					try
					{
					    m_releaseMessagesQueueMutex.wait();
					}
					catch(Exception exception)
					{
					}
				    }

				    continue;
				}

				do
				{
				    ArrayList<byte[]> arrayList =
					s_databaseHelper.readTaggedMessage
					(pair.m_sipHashIdDigest,
					 s_cryptography,
					 m_oid.get());

				    if(arrayList == null)
				    {
					m_oid.set(-1);
					break;
				    }

				    if(arrayList.size() != 3)
				    {
					arrayList.clear();
					continue;
				    }

				    byte destination[] = Cryptography.hmac
					(arrayList.get(0), pair.m_identity);

				    if(destination == null)
					continue;

				    String message = Messages.
					bytesToMessageString
					(Miscellaneous.
					 joinByteArrays(arrayList.get(0),
							destination));

				    enqueueMessage(message);
				    m_oid.set
					(Miscellaneous.
					 byteArrayToInt(arrayList.get(2)));
				    arrayList.clear();
				}
				while(true);
			    }
			}
			catch(Exception exception)
			{
			}
		    }
	        }, 1500L, RELEASE_MESSAGES_INTERVAL, TimeUnit.MILLISECONDS);
	    }
	}
    }

    private void purgeListeners()
    {
	/*
	** Disconnect all existing sockets.
	*/

	m_listenersMutex.writeLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		    m_listeners.get(j).abort();
	    }

	    m_listeners.clear();
	}
	finally
	{
	    m_listenersMutex.writeLock().unlock();
	}
    }

    private void purgeNeighbors()
    {
	/*
	** Disconnect all non-server sockets.
	*/

	synchronized(m_neighbors)
	{
	    int size = m_neighbors.size();

	    for(int i = 0; i < size; i++)
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
	    /*
	    ** Remove neighbor objects which do not exist in the database.
	    ** Also removed will be neighbors having disconnected statuses.
	    */

	    for(int i = m_neighbors.size() - 1; i >= 0; i--)
	    {
		boolean found = false;
		int oid = m_neighbors.keyAt(i);

		for(NeighborElement neighborElement : neighbors)
		    if(neighborElement != null && neighborElement.m_oid == oid)
		    {
			if(!neighborElement.m_statusControl.toLowerCase().
			   equals("disconnect"))
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

    public String remoteClientAddress(int position)
    {
	ArrayList<String> arrayList = new ArrayList<>();

	m_listenersMutex.readLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		{
		    ArrayList<String> addresses =
			m_listeners.get(j).clientsAddresses();

		    if(addresses != null)
		    {
			arrayList.addAll(addresses);
			addresses.clear();
		    }
		}
	    }
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}

	Collections.sort(arrayList);
	return arrayList.get(position);
    }

    public boolean ourMessage(String buffer,
			      UUID clientIdentity,
			      boolean userDefined)
    {
	/*
	** false - echo
	** true - do not echo
	*/

	if(buffer == null)
	    return true;

	try
	{
	    long value = s_congestionSipHash.hmac
		(buffer.getBytes(), Cryptography.SIPHASH_OUTPUT_LENGTH / 2)[0];

	    if(!userDefined)
		/*
		** A server socket!
		*/

		if(buffer.contains("type=0095a&content="))
		{
		    s_databaseHelper.writeCongestionDigest(value);

		    /*
		    ** A client has shared an identity stream.
		    */

		    s_databaseHelper.writeIdentity
			(clientIdentity, Messages.stripMessage(buffer));

		    /*
		    ** Do not echo the identity stream to other neighbors.
		    */

		    return true;
		}
		else if(buffer.contains("type=0095b&content="))
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
		else if(buffer.contains("type=0096&content="))
		    return true;
		else if(buffer.contains("type=0097a&content="))
		    return true;
		else if(buffer.contains("type=0097b&content="))
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

	    byte data[] = Arrays.copyOfRange // Blocks #1, #2, etc.
		(bytes, 0, bytes.length - 2 * Cryptography.HASH_KEY_LENGTH);
	    byte hmac[] = Arrays.copyOfRange // Second to the last block.
		(bytes,
		 bytes.length - 2 * Cryptography.HASH_KEY_LENGTH,
		 bytes.length - Cryptography.HASH_KEY_LENGTH);

	    if(arrayList1 != null && arrayList1.size() > 0)
	    {
		byte destination[] = Arrays.copyOfRange
		    (bytes,
		     bytes.length - Cryptography.HASH_KEY_LENGTH,
		     bytes.length);

		for(SipHashIdElement sipHashIdElement : arrayList1)
		{
		    if(sipHashIdElement == null)
			continue;
		    else if(sipHashIdElement.m_epksCompleted)
			continue;

		    if(!(Cryptography.
			 memcmp(hmac,
				Cryptography.hmac(data, Arrays.
						  copyOfRange(sipHashIdElement.
							      m_stream,
							      Cryptography.
							      CIPHER_KEY_LENGTH,
							      sipHashIdElement.
							      m_stream.
							      length))) &&
			 Cryptography.
			 memcmp(destination,
				Cryptography.
				hmac(Arrays.
				     copyOfRange(bytes,
						 0,
						 bytes.length -
						 Cryptography.HASH_KEY_LENGTH),
				     Cryptography.
				     shaX512(sipHashIdElement.
					     m_sipHashId.
					     getBytes(StandardCharsets.
						      UTF_8))))))
			continue;

		    s_databaseHelper.writeCongestionDigest(value);

		    byte ciphertext[] = Cryptography.decrypt
			(data,
			 Arrays.copyOfRange(sipHashIdElement.m_stream,
					    0,
					    Cryptography.CIPHER_KEY_LENGTH));

		    if(s_databaseHelper.
		       writeParticipant(s_cryptography,
					sipHashIdElement.
					m_acceptWithoutSignatures,
					ciphertext))
		    {
			Intent intent = new Intent
			    ("org.purple.smokestack.populate_participants");
			LocalBroadcastManager localBroadcastManager =
			    LocalBroadcastManager.getInstance
			    (SmokeStack.getApplication());

			localBroadcastManager.sendBroadcast(intent);
		    }

		    /*
		    ** Echo the key bundle.
		    */

		    return false;
		}
	    }

	    /*
	    ** Ozone-based messages.
	    */

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

	    data = Arrays.copyOfRange
		(bytes, 0, bytes.length - Cryptography.HASH_KEY_LENGTH);
	    hmac = Arrays.copyOfRange
		(bytes,
		 bytes.length - Cryptography.HASH_KEY_LENGTH,
		 bytes.length);

	    for(OzoneElement ozoneElement : arrayList2)
	    {
		if(ozoneElement == null)
		    continue;

		if(Cryptography.
		   memcmp(hmac,
			  Cryptography.
			  hmac(data,
			       Arrays.
			       copyOfRange(ozoneElement.m_addressStream,
					   Cryptography.CIPHER_KEY_LENGTH,
					   ozoneElement.m_addressStream.
					   length))))
		{
		    byte ciphertext[] = Cryptography.decrypt
			(data,
			 Arrays.copyOfRange(ozoneElement.m_addressStream,
					    0,
					    Cryptography.CIPHER_KEY_LENGTH));

		    if(ciphertext == null)
			return true;

		    if(ciphertext[0] == Messages.CHAT_MESSAGE_READ[0] ||
		       ciphertext[0] == Messages.CHAT_MESSAGE_RETRIEVAL[0])
		    {
			long current = System.currentTimeMillis();
			long timestamp = Miscellaneous.byteArrayToLong
			    (Arrays.copyOfRange(ciphertext, 1, 9));

			if(current - timestamp < 0L)
			{
			    if(timestamp - current >
			       CHAT_MESSAGE_RETRIEVAL_WINDOW)
				return true;
			}
			else if(current - timestamp >
				CHAT_MESSAGE_RETRIEVAL_WINDOW)
			    return true;

			byte identity[] = Arrays.copyOfRange
			    (ciphertext, 9, IDENTITY_LENGTH + 9);

			if(identity == null ||
			   identity.length != IDENTITY_LENGTH)
			    return true;

			PublicKey signatureKey = s_databaseHelper.
			    signatureKeyForDigest
			    (s_cryptography,
			     Arrays.
			     copyOfRange(ciphertext,
					 IDENTITY_LENGTH + 9,
					 Cryptography.HASH_KEY_LENGTH +
					 IDENTITY_LENGTH +
					 9));

			if(signatureKey == null)
			    return true;

			if(!Cryptography.
			   verifySignature(signatureKey,
					   Arrays.copyOfRange(ciphertext,
							      Cryptography.
							      HASH_KEY_LENGTH +
							      IDENTITY_LENGTH +
							      9,
							      ciphertext.
							      length),
					   Arrays.
					   copyOfRange(ciphertext,
						       0,
						       Cryptography.
						       HASH_KEY_LENGTH +
						       IDENTITY_LENGTH +
						       9)))
			    return true;

			s_databaseHelper.writeCongestionDigest(value);

			String sipHashIdDigest = s_databaseHelper.
			    sipHashIdDigestFromDigest
			    (s_cryptography,
			     Arrays.
			     copyOfRange(ciphertext,
					 IDENTITY_LENGTH + 9,
					 Cryptography.HASH_KEY_LENGTH +
					 IDENTITY_LENGTH +
					 9));

			if(ciphertext[0] == Messages.CHAT_MESSAGE_READ[0])
			    s_databaseHelper.timestampReleasedMessage
				(s_cryptography, identity);
			else
			{
			    /*
			    ** Tag all of sipHashIdDigest's
			    ** messages for release.
			    */

			    prepareReleaseMessagesPair
				(sipHashIdDigest, identity);
			    s_databaseHelper.tagMessagesForRelease
				(s_cryptography, sipHashIdDigest);
			}

			s_databaseHelper.updateSipHashIdTimestamp
			    (sipHashIdDigest.getBytes());
			return true;
		    }
		    else if(ciphertext[0] == Messages.PKP_MESSAGE_REQUEST[0])
		    {
			/*
			** Request a public key pair.
			*/

			long current = System.currentTimeMillis();
			long timestamp = Miscellaneous.byteArrayToLong
			    (Arrays.copyOfRange(ciphertext, 1, 9));

			if(current - timestamp < 0L)
			{
			    if(timestamp - current >
			       PKP_MESSAGE_RETRIEVAL_WINDOW)
				return true;
			}
			else if(current - timestamp >
				PKP_MESSAGE_RETRIEVAL_WINDOW)
			    return true;

			String sipHashId = new String
			    (Arrays.copyOfRange(ciphertext,
						9 +
						Cryptography.
						SIPHASH_IDENTITY_LENGTH,
						ciphertext.length),
			     StandardCharsets.UTF_8);
			String array[] = s_databaseHelper.readPublicKeyPair
			    (s_cryptography, sipHashId);

			if(array == null)
			    return true;

			sipHashId = new String
			    (Arrays.
			     copyOfRange(ciphertext,
					 9,
					 9 +
					 Cryptography.SIPHASH_IDENTITY_LENGTH));

			String message = Messages.bytesToMessageString
			    (Messages.epksMessage(sipHashId, array));

			enqueueMessage(message);
			return true;
		    }
		    else if(ciphertext[0] == Messages.SHARE_SIPHASH_ID[0])
		    {
			long current = System.currentTimeMillis();
			long timestamp = Miscellaneous.byteArrayToLong
			    (Arrays.copyOfRange(ciphertext, 1, 9));

			if(current - timestamp < 0L)
			{
			    if(timestamp - current >
			       SHARE_SIPHASH_IDENTITY_WINDOW)
				return true;
			}
			else if(current - timestamp >
				SHARE_SIPHASH_IDENTITY_WINDOW)
			    return true;

			String name = "";
			String sipHashId = new String
			    (Arrays.
			     copyOfRange(ciphertext,
					 9,
					 9 +
					 Cryptography.SIPHASH_IDENTITY_LENGTH),
			     StandardCharsets.UTF_8);

			name = sipHashId.toUpperCase().trim();

			if(s_databaseHelper.
			   writeSipHashParticipant(s_cryptography,
						   name,
						   sipHashId,
						   true))
			{
			    if((bytes = Cryptography.
				generateOzone(name)) != null)
				if(s_databaseHelper.
				   writeOzone(s_cryptography, name, bytes))
				    populateOzones();

			    populateSipHashIds();

			    Intent intent = new Intent
				("org.purple.smokestack." +
				 "populate_ozones_participants");
			    LocalBroadcastManager localBroadcastManager =
				LocalBroadcastManager.getInstance
				(SmokeStack.getApplication());

			    localBroadcastManager.sendBroadcast(intent);
			}

			byte identity[] = Arrays.copyOfRange
			    (ciphertext,
			     9 + Cryptography.SIPHASH_IDENTITY_LENGTH,
			     9 + Cryptography.SIPHASH_IDENTITY_LENGTH + 8);

			bytes = Messages.shareSipHashIdMessageConfirmation
			    (s_cryptography,
			     sipHashId,
			     identity,
			     ozoneElement.m_addressStream);
			enqueueMessage(Messages.bytesToMessageString(bytes));

			/*
			** Echo the shared Smoke identity.
			*/

			return false;
		    }
		    else
			return true;
		}

		if(arrayList1 != null && arrayList1.size() > 0)
		    for(SipHashIdElement sipHashIdElement : arrayList1)
		    {
			if(sipHashIdElement == null)
			    continue;

			long minutes = TimeUnit.MILLISECONDS.toMinutes
			    (System.currentTimeMillis());

			for(int i = 0; i < 2; i++)
			    if(Cryptography.
			       memcmp(hmac,
				      Cryptography.
				      hmac(Miscellaneous.
					   joinByteArrays
					   (data,
					    sipHashIdElement.
					    m_sipHashId.
					    getBytes(StandardCharsets.UTF_8),
					    Miscellaneous.
					    longToByteArray
					    (i + minutes)),
					   Arrays.copyOfRange(ozoneElement.
							      m_addressStream,
							      Cryptography.
							      CIPHER_KEY_LENGTH,
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
				     data);
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

    public int listenersCount()
    {
	m_listenersMutex.readLock().lock();

	try
	{
	    return m_listeners.size();
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}
    }

    public int neighborsCount()
    {
	synchronized(m_neighbors)
	{
	    return m_neighbors.size();
	}
    }

    public int remoteClientsCount()
    {
	int count = 0;

	m_listenersMutex.readLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		    count += m_listeners.get(j).clientsCount();
	    }
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}

	return count;
    }

    public static synchronized Kernel getInstance()
    {
	if(s_instance == null)
	    s_instance = new Kernel();

	return s_instance;
    }

    public static void writeCongestionDigest(String message)
    {
	if(message != null)
	    try
	    {
		s_databaseHelper.writeCongestionDigest
		    (s_congestionSipHash.
		     hmac(message.getBytes(),
			  Cryptography.SIPHASH_OUTPUT_LENGTH)[0]);
	    }
	    catch(Exception exception)
	    {
	    }
    }

    public static void writeCongestionDigest(byte data[])
    {
	if(data != null)
	    try
	    {
		s_databaseHelper.writeCongestionDigest
		    (s_congestionSipHash.
		     hmac(data, Cryptography.SIPHASH_OUTPUT_LENGTH)[0]);
	    }
	    catch(Exception exception)
	    {
	    }
    }

    public void clearNeighborQueues()
    {
	synchronized(m_neighbors)
	{
	    int size = m_neighbors.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null)
		{
		    m_neighbors.get(j).clearEchoQueue();
		    m_neighbors.get(j).clearQueue();
		}
	    }
	}
    }

    public void echo(String message, int oid)
    {
	if(message == null || message.trim().isEmpty())
	    return;

	m_listenersMutex.readLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		    m_listeners.get(j).scheduleEchoSend(message, oid);
	    }
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}

	synchronized(m_neighbors)
	{
	    int size = m_neighbors.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_neighbors.keyAt(i);

		if(m_neighbors.get(j) != null &&
		   m_neighbors.get(j).getOid() != oid)
		    m_neighbors.get(j).scheduleEchoSend(message);
	    }
	}
    }

    public void enqueueMessage(String message)
    {
	if(!isNetworkAvailable() || message == null || message.trim().isEmpty())
	    return;

	m_listenersMutex.readLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null)
		    m_listeners.get(j).scheduleSend(message);
	    }
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}

	ArrayList<NeighborElement> arrayList =
	    s_databaseHelper.readNeighborOids(s_cryptography);

	if(arrayList != null && arrayList.size() > 0)
	{
	    int size = arrayList.size();

	    for(int i = 0; i < size; i++)
		if(arrayList.get(i) != null &&
		   arrayList.get(i).m_statusControl.toLowerCase().
		   equals("connect"))
		    s_databaseHelper.enqueueOutboundMessage
			(s_cryptography,
			 message,
			 false,
			 arrayList.get(i).m_oid);

	    arrayList.clear();
	}
    }

    public void populateOzones()
    {
	m_ozonesMutex.writeLock().lock();

	try
	{
	    m_ozones = s_databaseHelper.readOzones(s_cryptography);
	}
	catch(Exception exception)
	{
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
	catch(Exception exception)
	{
	}
	finally
	{
	    m_sipHashIdsMutex.writeLock().unlock();
	}
    }

    public void toggleListenerPrivacy(int oid)
    {
	m_listenersMutex.readLock().lock();

	try
	{
	    int size = m_listeners.size();

	    for(int i = 0; i < size; i++)
	    {
		int j = m_listeners.keyAt(i);

		if(m_listeners.get(j) != null &&
		   m_listeners.get(j).oid() == oid)
		{
		    m_listeners.get(j).togglePrivacy();
		    break;
		}
	    }
	}
	finally
	{
	    m_listenersMutex.readLock().unlock();
	}
    }
}
