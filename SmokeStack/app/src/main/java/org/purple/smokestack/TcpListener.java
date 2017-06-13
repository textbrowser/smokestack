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

import android.os.Build;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameBuilder;
import org.spongycastle.asn1.x500.style.BCStyle;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v1CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

public class TcpListener
{
    private AtomicInteger m_oid;
    private Cryptography m_cryptography = Cryptography.getInstance();
    private Database m_databaseHelper = Database.getInstance();
    private KeyStore m_keyStore = null;
    private SSLServerSocket m_socket = null;
    private ScheduledExecutorService m_acceptScheduler = null;
    private ScheduledExecutorService m_scheduler = null;
    private String m_ipAddress = "";
    private String m_ipPort = "";
    private String m_scopeId = "";
    private String m_version = "";
    private final ArrayList<SSLSocket> m_sockets = new ArrayList<> ();
    private final AtomicInteger m_listen = new AtomicInteger(0);
    private final AtomicLong m_startTime = new AtomicLong(System.nanoTime());
    private final ReentrantReadWriteLock m_socketsMutex =
	new ReentrantReadWriteLock();
    private final StringBuilder m_error = new StringBuilder();
    private final static int ACCEPT_INTERVAL = 100; // Milliseconds
    private final static int TIMER_INTERVAL = 2500; // 2.5 Seconds

    public TcpListener(String ipAddress,
		       String ipPort,
		       String scopeId,
		       String version,
		       int oid)
    {
	m_acceptScheduler = Executors.newSingleThreadScheduledExecutor();
	m_acceptScheduler.scheduleAtFixedRate(new Runnable()
	{
	    @Override
	    public void run()
	    {
		try
		{
		    if(Thread.currentThread().isInterrupted())
			return;
		    else
			Thread.sleep(5);
		}
		catch(InterruptedException exception)
		{
		    Thread.currentThread().interrupt();
		}
		catch(Exception exception)
		{
		}

		if(m_listen.get() == 0)
		    return;

		try
		{
		    if(m_socket == null)
			return;

		    SSLSocket sslSocket = (SSLSocket) m_socket.accept();

		    if(sslSocket != null)
		    {
			m_socketsMutex.writeLock().lock();

			try
			{
			    m_sockets.add(sslSocket);
			}
			finally
			{
			    m_socketsMutex.writeLock().unlock();
			}
		    }
		}
		catch(Exception exception)
		{
		}
	    }
	}, 0, ACCEPT_INTERVAL, TimeUnit.MILLISECONDS);
	m_ipAddress = ipAddress;
	m_ipPort = ipPort;
	m_oid = new AtomicInteger(oid);
	m_scheduler = Executors.newSingleThreadScheduledExecutor();
	m_scheduler.scheduleAtFixedRate(new Runnable()
	{
	    @Override
	    public void run()
	    {
		try
		{
		    if(Thread.currentThread().isInterrupted())
			return;
		    else
			Thread.sleep(5);
		}
		catch(InterruptedException exception)
		{
		    Thread.currentThread().interrupt();
		}
		catch(Exception exception)
		{
		}

		String statusControl = m_databaseHelper.
		    readListenerNeighborStatusControl
		    (m_cryptography, "listeners", m_oid.get());

		switch(statusControl)
		{
		case "disconnect":
		    disconnect();
		    break;
		case "listen":
		    listen();
		    break;
		default:
		    /*
		    ** Abort!
		    */

		    disconnect();
		    return;
		}

		saveStatistics();
	    }
	}, 0, TIMER_INTERVAL, TimeUnit.MILLISECONDS);
	m_scopeId = scopeId;
	m_version = version;
	prepareCertificate();
    }

    private boolean listening()
    {
	try
	{
	    return m_socket != null && m_socket.isBound();
	}
	catch(Exception exception)
	{
	}

	return false;
    }

    private void prepareCertificate()
    {
	try
	{
	    if(m_keyStore != null)
		return;
	}
	catch(Exception exception)
	{
	    return;
	}

	KeyPair keyPair = null;

	try
	{
	    keyPair = Cryptography.generatePrivatePublicKeyPair
		("RSA", 2048);
	}
	catch(Exception exception)
	{
	    keyPair = null;
	}

	if(keyPair == null)
	    return;

	try
	{
	    Date endDate = new Date
		(System.currentTimeMillis() + 24 * 60 * 60 * 365 * 1000);
	    Date startDate = new Date
		(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	    X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

	    nameBuilder.addRDN(BCStyle.L, "SmokeStack");
	    nameBuilder.addRDN(BCStyle.O, "SmokeStack");
	    nameBuilder.addRDN(BCStyle.OU, "SmokeStack");

	    ContentSigner contentSigner = null;
	    Random random = new Random();
	    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.
		getInstance(keyPair.getPublic().getEncoded());
	    X500Name name = nameBuilder.build();
	    X509v1CertificateBuilder v1CertificateBuilder =
		new X509v1CertificateBuilder
		(name,
		 BigInteger.valueOf(random.nextLong()),
		 startDate,
		 endDate,
		 name,
		 subjectPublicKeyInfo);

	    Security.addProvider(new BouncyCastleProvider());
	    contentSigner = new JcaContentSignerBuilder
		("SHA512WithRSAEncryption").setProvider("SC").build
		(keyPair.getPrivate());

	    X509Certificate certificate = null;
	    X509CertificateHolder certificateHolder = v1CertificateBuilder.
		build(contentSigner);

	    certificate = new JcaX509CertificateConverter().setProvider("SC").
		getCertificate(certificateHolder);
	    m_keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
	    m_keyStore.load(null, null);
	    m_keyStore.setKeyEntry("certificate",
				   keyPair.getPrivate(), 
				   null,
				   new X509Certificate[] {certificate}); 
	}
	catch(Exception exception)
	{
	    m_keyStore = null;
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

	m_socketsMutex.readLock().lock();

	try
	{
	    peersCount = String.valueOf(m_sockets.size());
	}
	finally
	{
	    m_socketsMutex.readLock().unlock();
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
	m_acceptScheduler.shutdown();

	try
	{
	    m_acceptScheduler.awaitTermination(60, TimeUnit.SECONDS);
	}
	catch(Exception exception)
	{
	}

	m_scheduler.shutdown();

	try
	{
	    m_scheduler.awaitTermination(60, TimeUnit.SECONDS);
	}
	catch(Exception exception)
	{
	}
    }

    public void disconnect()
    {
	m_listen.set(0);

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
	    m_startTime.set(System.nanoTime());
	}

	m_socketsMutex.writeLock().lock();

	try
	{
	    for(int i = m_sockets.size() - 1; i >= 0; i--)
	    {
		SSLSocket sslSocket = m_sockets.remove(i);

		if(sslSocket != null)
		    try
		    {
			sslSocket.getInputStream().close();
			sslSocket.getOutputStream().close();
			sslSocket.close();
		    }
		    catch(Exception exception)
		    {
		    }
	    }
	}
	finally
	{
	    m_socketsMutex.writeLock().unlock();
	}
    }

    public void listen()
    {
	m_listen.set(1);

	try
	{
	    if(m_keyStore == null || m_socket != null)
		return;

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
			    SecureRandom.getInstance("SHA1PRNG"));
	    m_socket = (SSLServerSocket)
		sslContext.getServerSocketFactory().createServerSocket
		(Integer.parseInt(m_ipPort),
		 0,
		 InetAddress.getByName(m_ipAddress));

	    if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		m_socket.setEnabledProtocols
		    (new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"});
	    else
		m_socket.setEnabledProtocols
		    (new String[] {"SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"});

	    m_socket.setNeedClientAuth(false);
	    m_socket.setReuseAddress(true);
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
}
