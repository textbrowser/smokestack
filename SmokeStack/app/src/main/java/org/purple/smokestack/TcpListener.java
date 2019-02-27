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
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TcpListener
{
    static
    {
	Security.addProvider(new BouncyCastleProvider());
    }

    private AtomicBoolean m_isPrivateServer = null;
    private AtomicInteger m_oid;
    private KeyStore m_keyStore = null;
    private SSLServerSocket m_socket = null;
    private final ScheduledExecutorService m_acceptScheduler =
	Executors.newSingleThreadScheduledExecutor();
    private final ScheduledExecutorService m_scheduler =
	Executors.newSingleThreadScheduledExecutor();
    private String m_ipAddress = "";
    private String m_ipPort = "";
    private final ArrayList<TcpNeighbor> m_neighbors = new ArrayList<> ();
    private final AtomicBoolean m_listen = new AtomicBoolean(false);
    private final AtomicInteger m_neighborCounter = new AtomicInteger(0);
    private final AtomicLong m_startTime = new AtomicLong(System.nanoTime());
    private final Cryptography m_cryptography = Cryptography.getInstance();
    private final Database m_databaseHelper = Database.getInstance();
    private final Object m_socketMutex = new Object();
    private final ReentrantReadWriteLock m_neighborsMutex =
	new ReentrantReadWriteLock();
    private final StringBuilder m_error = new StringBuilder();
    private final static int RSA_KEY_SIZE = 2048;
    private final static int SO_TIMEOUT = 500; // 0.5 Seconds
    private final static long ACCEPT_INTERVAL = 100; // Milliseconds
    private final static long TIMER_INTERVAL = 2500; // 2.5 Seconds

    public TcpListener(String ipAddress,
		       String ipPort,
		       String scopeId,
		       String version,
		       boolean isPrivateServer,
		       byte certificate[],
		       byte privateKey[],
		       byte publicKey[],
		       int oid)
    {
	m_oid = new AtomicInteger(oid);
	prepareCertificate(certificate, privateKey, publicKey);
	m_ipAddress = ipAddress;
	m_ipPort = ipPort;
	m_isPrivateServer = new AtomicBoolean(isPrivateServer);

	/*
	** Launch the schedulers.
	*/

	m_acceptScheduler.scheduleAtFixedRate(new Runnable()
	{
	    @Override
	    public void run()
	    {
		try
		{
		    saveStatistics();
		}
		catch(Exception exception)
		{
		}

		SSLSocket sslSocket = null;

		try
		{
		    if(!m_listen.get())
			return;

		    synchronized(m_socketMutex)
		    {
			if(m_socket == null)
			    return;

			sslSocket = (SSLSocket) m_socket.accept();
		    }

		    if(sslSocket == null)
			return;

		    TcpNeighbor neighbor = new TcpNeighbor
			(sslSocket,
			 m_isPrivateServer.get(),
			 -m_neighborCounter.incrementAndGet());

		    m_neighborsMutex.writeLock().lock();

		    try
		    {
			m_neighbors.add(neighbor);
		    }
		    catch(Exception exception)
		    {
			m_neighbors.remove(neighbor);
			neighbor.abort();
			neighbor = null;
		    }
		    finally
		    {
			m_neighborsMutex.writeLock().unlock();
		    }
		}
		catch(Exception exception1)
		{
		    try
		    {
			if(sslSocket != null)
			    sslSocket.close();
		    }
		    catch(Exception exception2)
		    {
		    }
		}
	    }
	}, 0, ACCEPT_INTERVAL, TimeUnit.MILLISECONDS);
	m_scheduler.scheduleAtFixedRate(new Runnable()
	{
	    @Override
	    public void run()
	    {
		try
		{
		    String statusControl = m_databaseHelper.
			readListenerNeighborStatusControl
			(m_cryptography, "listeners", m_oid.get());

		    switch(statusControl)
		    {
		    case "disconnect":
			disconnect();
			break;
		    case "listen":
			if(isNetworkConnected())
			    listen();
			else
			    disconnect();

			break;
		    default:
			/*
			** Abort!
			*/

			disconnect();
			return;
		    }

		    m_neighborsMutex.writeLock().lock();

		    try
		    {
			for(int i = m_neighbors.size() - 1; i >= 0; i--)
			{
			    TcpNeighbor neighbor = m_neighbors.get(i);

			    if(neighbor == null)
				m_neighbors.remove(i);
			    else if(!neighbor.connected())
			    {
				m_neighbors.remove(i);
				neighbor.abort();
				neighbor = null;
			    }
			}
		    }
		    catch(Exception exception)
		    {
		    }
		    finally
		    {
			m_neighborsMutex.writeLock().unlock();
		    }

		    saveStatistics();
		}
		catch(Exception exception)
		{
		}
	    }
	}, 0, TIMER_INTERVAL, TimeUnit.MILLISECONDS);
    }

    protected boolean isNetworkConnected()
    {
	try
	{
	    ConnectivityManager connectivityManager = (ConnectivityManager)
		SmokeStack.getApplication().getApplicationContext().
		getSystemService(Context.CONNECTIVITY_SERVICE);
	    NetworkInfo networkInfo = connectivityManager.
		getActiveNetworkInfo();

	    return networkInfo.getState() ==
		android.net.NetworkInfo.State.CONNECTED;
	}
	catch(Exception exception)
	{
	}

	return false;
    }

    private boolean listening()
    {
	synchronized(m_socketMutex)
	{
	    try
	    {
		return m_socket != null && m_socket.isBound();
	    }
	    catch(Exception exception)
	    {
	    }
	}

	return false;
    }

    private void prepareCertificate(byte certificateBytes[],
				    byte privateKey[],
				    byte publicKey[])
    {
	if(m_keyStore != null)
	    return;

	KeyPair keyPair = null;

	try
	{
	    if(certificateBytes == null ||
	       certificateBytes.length == 0 ||
	       privateKey == null ||
	       privateKey.length == 0 ||
	       publicKey == null ||
	       publicKey.length == 0)
		keyPair = Cryptography.generatePrivatePublicKeyPair
		    ("RSA", RSA_KEY_SIZE);
	    else
	    {
		keyPair = Cryptography.generatePrivatePublicKeyPair
		    ("RSA", privateKey, publicKey);

		if(keyPair != null)
		{
		    ByteArrayInputStream byteArrayInputStream = new
			ByteArrayInputStream(certificateBytes);
		    CertificateFactory certificateFactory =
			CertificateFactory.getInstance("X.509");
		    X509Certificate certificate = (X509Certificate)
			certificateFactory.generateCertificate
			(byteArrayInputStream);

		    m_keyStore = KeyStore.getInstance
			(KeyStore.getDefaultType());
		    m_keyStore.load(null, null);
		    m_keyStore.deleteEntry(m_ipAddress);
		    m_keyStore.setKeyEntry(m_ipAddress,
					   keyPair.getPrivate(),
					   null,
					   new X509Certificate[] {certificate});
		    return;
		}
	    }
	}
	catch(Exception exception)
	{
	    setError("An error (" +
		     exception.getMessage() +
		     ") occurred while preparing the key pair.");
	    return;
	}

	try
	{
	    Date endDate = new Date
		(System.currentTimeMillis() + 24L * 60L * 60L * 365L * 1000L);
	    Date startDate = new Date
		(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);
	    X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

	    /*
	    ** Prepare self-signing.
	    */

	    ContentSigner contentSigner = null;
	    Random random = new Random();
	    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.
		getInstance(keyPair.getPublic().getEncoded());
	    X500Name name = nameBuilder.build();
	    X509v3CertificateBuilder v3CertificateBuilder =
		new X509v3CertificateBuilder
		(name,
		 BigInteger.valueOf(random.nextLong()),
		 startDate,
		 endDate,
		 name,
		 subjectPublicKeyInfo);

	    contentSigner = new JcaContentSignerBuilder
		("SHA512WithRSAEncryption").setProvider("BC").build
		(keyPair.getPrivate());

	    X509Certificate certificate = null;
	    X509CertificateHolder certificateHolder = v3CertificateBuilder.
		build(contentSigner);

	    certificate = new JcaX509CertificateConverter().setProvider("BC").
		getCertificate(certificateHolder);
	    m_keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
	    m_keyStore.load(null, null);
	    m_keyStore.deleteEntry(m_ipAddress);
	    m_keyStore.setKeyEntry(m_ipAddress,
				   keyPair.getPrivate(),
				   null,
				   new X509Certificate[] {certificate});
	    m_databaseHelper.writeListenerCertificateDetails
		(m_cryptography,
		 certificate.getEncoded(),
		 keyPair.getPrivate().getEncoded(),
		 keyPair.getPublic().getEncoded(),
		 m_oid.get());
	}
	catch(Exception exception)
	{
	    m_keyStore = null;
	    setError("An error (" + exception.getMessage() +
		     ") occurred while preparing the key store.");
	}
    }

    private void saveStatistics()
    {
	String error = "";
	String peersCount = "";
	long uptime = System.nanoTime() - m_startTime.get();

	synchronized(m_error)
	{
	    error = m_error.toString();
	}

	m_neighborsMutex.readLock().lock();

	try
	{
	    peersCount = String.valueOf(m_neighbors.size());
	}
	finally
	{
	    m_neighborsMutex.readLock().unlock();
	}

	m_databaseHelper.saveListenerInformation
	    (m_cryptography,
	     error,
	     peersCount,
	     listening() ? "listening" : "disconnected",
	     String.valueOf(uptime),
	     String.valueOf(m_oid.get()));
    }

    private void setError(String error)
    {
	synchronized(m_error)
	{
	    m_error.setLength(0);
	    m_error.append(error);
	}
    }

    public void abort()
    {
	disconnect();

	synchronized(m_acceptScheduler)
	{
	    try
	    {
		m_acceptScheduler.shutdown();
	    }
	    catch(Exception exception)
	    {
	    }

	    try
	    {
		if(!m_acceptScheduler.awaitTermination(60, TimeUnit.SECONDS))
		    m_acceptScheduler.shutdownNow();
	    }
	    catch(Exception exception)
	    {
	    }
	}

	synchronized(m_scheduler)
	{
	    try
	    {
		m_scheduler.shutdown();
	    }
	    catch(Exception exception)
	    {
	    }

	    try
	    {
		if(!m_scheduler.awaitTermination(60, TimeUnit.SECONDS))
		    m_scheduler.shutdownNow();
	    }
	    catch(Exception exception)
	    {
	    }
	}
    }

    public void disconnect()
    {
	m_listen.set(false);

	synchronized(m_socketMutex)
	{
	    try
	    {
		if(m_socket != null)
		    m_socket.close();
	    }
	    catch(Exception exception)
	    {
	    }
	    finally
	    {
		m_socket = null;
	    }
	}

	m_neighborsMutex.writeLock().lock();

	try
	{
	    for(int i = m_neighbors.size() - 1; i >= 0; i--)
	    {
		TcpNeighbor neighbor = m_neighbors.remove(i);

		if(neighbor != null)
		    neighbor.abort();

		neighbor = null;
	    }
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_neighborsMutex.writeLock().unlock();
	}

	m_startTime.set(System.nanoTime());
    }

    public void listen()
    {
	if(listening())
	    return;

	m_listen.set(true);

	try
	{
	    SSLContext sslContext = null;

	    if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		sslContext = SSLContext.getInstance("TLS");
	    else
		sslContext = SSLContext.getInstance("SSL");

	    KeyManagerFactory keyManagerFactory = KeyManagerFactory.
		getInstance("X509");

	    keyManagerFactory.init(m_keyStore, null);
	    sslContext.init(keyManagerFactory.getKeyManagers(),
			    null,
			    null);

	    synchronized(m_socketMutex)
	    {
		m_socket = (SSLServerSocket)
		    sslContext.getServerSocketFactory().createServerSocket();
		m_socket.setReceiveBufferSize(TcpNeighbor.SO_RCVBUF_SIZE);
		m_socket.setReuseAddress(true);
		m_socket.bind
		    (new InetSocketAddress(InetAddress.getByName(m_ipAddress),
					   Integer.parseInt(m_ipPort)),
		     0);

		if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		    m_socket.setEnabledProtocols
			(new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
		else
		    m_socket.setEnabledProtocols
			(new String[] {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"});

		m_socket.setNeedClientAuth(false);
		m_socket.setSoTimeout(SO_TIMEOUT);
	    }

	    m_startTime.set(System.nanoTime());
	}
	catch(Exception exception)
	{
	    setError("An error (" +
		     exception.getMessage() +
		     ") occurred while attempting to listen.");
	    disconnect();
	}
    }

    public void scheduleEchoSend(String message, int oid)
    {
	m_neighborsMutex.readLock().lock();

	try
	{
	    int size = m_neighbors.size();

	    for(int i = 0; i < size; i++)
		if(m_neighbors.get(i) != null)
		    if(m_neighbors.get(i).getOid() != oid)
			m_neighbors.get(i).scheduleEchoSend(message);
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_neighborsMutex.readLock().unlock();
	}
    }

    public void scheduleSend(String message)
    {
	m_neighborsMutex.readLock().lock();

	try
	{
	    int size = m_neighbors.size();

	    for(int i = 0; i < size; i++)
		if(m_neighbors.get(i) != null)
		    m_neighbors.get(i).scheduleSend(message);
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_neighborsMutex.readLock().unlock();
	}
    }
}
