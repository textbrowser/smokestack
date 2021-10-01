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
import android.util.Base64;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class TcpNeighbor extends Neighbor
{
    private AtomicBoolean m_handshakeCompleted = null;
    private AtomicBoolean m_isValidCertificate = null;
    private InetSocketAddress m_proxyInetSocketAddress = null;
    private SSLSocket m_socket = null;
    private ScheduledExecutorService m_requestAuthenticationScheduler = null;
    private String m_protocols[] = null;
    private String m_proxyIpAddress = "";
    private String m_proxyType = "";
    private TrustManager m_trustManagers[] = null;
    private final static int CONNECTION_TIMEOUT = 10000; // 10 Seconds
    private final static int HANDSHAKE_TIMEOUT = 10000; // 10 Seconds
    private final static long REQUEST_AUTHENTICATION_INTERVAL =
	10000L; // 10 Seconds
    private int m_proxyPort = -1;

    private void prepareMRandom()
    {
	m_randomBuffer.delete(0, m_randomBuffer.length());
	m_randomBuffer.trimToSize();

	try
	{
	    byte bytes[] = Miscellaneous.joinByteArrays
		(Cryptography.randomBytes(64),
		 Miscellaneous.longToByteArray(System.currentTimeMillis()));

	    m_randomBuffer.append
		(Base64.encodeToString(Cryptography.shaX512(bytes),
				       Base64.NO_WRAP));
	}
	catch(Exception exception)
	{
	    m_randomBuffer.delete(0, m_randomBuffer.length());
	    m_randomBuffer.trimToSize();
	}
    }

    protected String getLocalIp()
    {
	try
	{
	    if(m_socket != null && m_socket.getLocalAddress() != null)
		return m_socket.getLocalAddress().getHostAddress();
	}
	catch(Exception exception)
	{
	}

	if(m_version.equals("IPv4"))
	    return "0.0.0.0";
	else
	    return "::";
    }

    protected String getRemoteIp()
    {
	try
	{
	    if(m_socket != null && m_socket.getInetAddress() != null)
		return m_socket.getInetAddress().getHostAddress();
	}
	catch(Exception exception)
	{
	}

	if(m_version.equals("IPv4"))
	    return "0.0.0.0";
	else
	    return "::";
    }

    protected String getSessionCipher()
    {
	try
	{
	    if(m_socket != null &&
	       m_socket.getSession() != null &&
	       m_socket.getSession().isValid())
		return m_socket.getSession().getCipherSuite() +
		    "_" +
		    m_socket.getSession().getProtocol();
	}
	catch(Exception exception)
	{
	}

	return "";
    }

    protected boolean connected()
    {
	try
	{
	    return isNetworkConnected() &&
		m_handshakeCompleted.get() &&
		m_isValidCertificate.get() &&
		m_socket != null &&
		!m_socket.isClosed();
	}
	catch(Exception exception)
	{
	    return false;
	}
    }

    protected boolean send(String message)
    {
	if(!connected() || message == null || message.isEmpty())
	    return false;

	try
	{
	    if(m_isPrivateServer.get())
		if(!m_remoteUserAuthenticated.get())
		    if(!message.contains("type=0097a&content="))
			return false;

	    m_socket.getOutputStream().write(message.getBytes());
	    Kernel.writeCongestionDigest(message);
	    m_bytesWritten.getAndAdd(message.length());
	}
	catch(Exception exception)
	{
	    setError("A socket error occurred on send().");
	    disconnect();
	    return false;
	}

	return true;
    }

    protected int getLocalPort()
    {
	try
	{
	    if(m_socket != null && !m_socket.isClosed())
		return m_socket.getLocalPort();
	}
	catch(Exception exception)
	{
	}

	return 0;
    }

    protected int getRemotePort()
    {
	try
	{
	    if(m_socket != null)
		return m_socket.getPort();
	}
	catch(Exception exception)
	{
	}

	return 0;
    }

    protected void disconnect()
    {
	super.disconnect();
	m_databaseHelper.deleteRoutingEntry(m_uuid.toString());

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
	    m_handshakeCompleted.set(false);

	    if(m_oid.get() >= 0)
		m_isValidCertificate.set(false);

	    m_randomBuffer.delete(0, m_randomBuffer.length());
	    m_randomBuffer.trimToSize();
	    m_socket = null;
	    reset();
	}
    }

    public TcpNeighbor(SSLSocket socket, boolean isPrivateServer, int oid)
    {
	/*
	** We're a server socket.
	*/

	super("", "", "", "TCP", "", isPrivateServer, false, oid);
	m_handshakeCompleted = new AtomicBoolean(true);
	m_isValidCertificate = new AtomicBoolean(true);
	m_socket = socket;
	m_userDefined.set(false);

	if(m_socket != null)
	    try
	    {
		if(m_isPrivateServer.get())
		    m_socket.addHandshakeCompletedListener
			(new HandshakeCompletedListener()
		        {
			    @Override
			    public void handshakeCompleted
				(HandshakeCompletedEvent event)
			    {
				m_handshakeCompleted.set(true);
				prepareMRandom();
				scheduleSend
				    (Messages.
				     requestAuthentication(m_randomBuffer));

				synchronized(m_mutex)
				{
				    m_mutex.notifyAll();
				}
			    }
			});

		m_socket.setKeepAlive(false);
		m_socket.setSoLinger(true, 0);
		m_socket.setSoTimeout(HANDSHAKE_TIMEOUT);
		m_socket.setTcpNoDelay(true);
	    }
	    catch(Exception exception)
	    {
	    }

	/*
	** Launch the schedulers.
	*/

	if(isPrivateServer)
	{
	    m_requestAuthenticationScheduler = Executors.
		newSingleThreadScheduledExecutor();
	    m_requestAuthenticationScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			if(!connected() && !m_disconnected.get())
			    synchronized(m_mutex)
			    {
				try
				{
				    m_mutex.wait(WAIT_TIMEOUT);
				}
				catch(Exception exception)
				{
				}
			    }

			if(connected() && !m_remoteUserAuthenticated.get())
			{
			    prepareMRandom();
			    scheduleSend
				(Messages.
				 requestAuthentication(m_randomBuffer));
			}
		    }
		    catch(Exception exception)
		    {
		    }
		}
	    }, REQUEST_AUTHENTICATION_INTERVAL,
		REQUEST_AUTHENTICATION_INTERVAL,
		TimeUnit.MILLISECONDS);
	}

	m_readSocketScheduler.scheduleAtFixedRate(new Runnable()
	{
	    private boolean m_error = false;

	    @Override
	    public void run()
	    {
		try
		{
		    if(!connected() && !m_disconnected.get())
			synchronized(m_mutex)
			{
			    try
			    {
				m_mutex.wait(WAIT_TIMEOUT);
			    }
			    catch(Exception exception)
			    {
			    }
			}

		    if(!connected())
			return;
		    else if(m_error)
		    {
			if(connected())
			    m_error = false;
			else
			    return;
		    }
		    else if(m_socket == null ||
			    m_socket.getInputStream() == null)
			return;
		    else if(m_socket.getSoTimeout() == HANDSHAKE_TIMEOUT)
			/*
			** Reset SO_TIMEOUT from HANDSHAKE_TIMEOUT.
			*/

			m_socket.setSoTimeout(SO_TIMEOUT);

		    byte bytes[] = new byte[BYTES_PER_READ];
		    int i = 0;

		    try
		    {
			i = m_socket.getInputStream().read(bytes);
		    }
		    catch(Exception exception)
		    {
			i = -1;
			m_error = true;
		    }

		    long bytesRead = 0L;

		    if(i < 0)
			bytesRead = -1L;
		    else if(i > 0)
			bytesRead += (long) i;

		    if(bytesRead < 0L)
		    {
			m_error = true;
			setError("A socket read() error occurred.");
			disconnect();
			return;
		    }
		    else if(bytesRead == 0L)
			return;

		    m_bytesRead.getAndAdd(bytesRead);
		    m_lastTimeRead.set(System.nanoTime());

		    if(m_stringBuffer.length() < MAXIMUM_BYTES)
			m_stringBuffer.append
			    (new String(bytes, 0, (int) bytesRead));

		    synchronized(m_parsingSchedulerObject)
		    {
			m_parsingSchedulerObject.notify();
		    }
		}
		catch(java.net.SocketException exception)
		{
		    m_error = true;
		    setError("A socket error occurred while reading data.");
		    disconnect();
		}
		catch(Exception exception)
		{
		}
	    }
	}, 0L, READ_SOCKET_INTERVAL, TimeUnit.MILLISECONDS);
    }

    public TcpNeighbor(String proxyIpAddress,
		       String proxyPort,
		       String proxyType,
		       String ipAddress,
		       String ipPort,
		       String scopeId,
		       String version,
		       int oid)
    {
	super(ipAddress, ipPort, scopeId, "TCP", version, false, true, oid);
	m_handshakeCompleted = new AtomicBoolean(false);
	m_isValidCertificate = new AtomicBoolean(false);

	if(Build.VERSION.RELEASE.startsWith("10"))
	    m_protocols = TcpListener.TLS_NEW;
	else if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
	    m_protocols = TcpListener.TLS_V1_V2;
	else
	    m_protocols = TcpListener.TLS_LEGACY;

	m_proxyIpAddress = proxyIpAddress;

	try
	{
	    m_proxyPort = Integer.parseInt(proxyPort);
	}
	catch(Exception exception)
	{
	    m_proxyPort = -1;
	}

	m_proxyType = proxyType;

	if(!m_proxyIpAddress.isEmpty() && m_proxyPort != -1 &&
	   !m_proxyType.isEmpty())
	    try
	    {
		m_proxyInetSocketAddress = new InetSocketAddress
		    (m_proxyIpAddress, m_proxyPort);
	    }
	    catch(Exception exception)
	    {
		m_proxyInetSocketAddress = null;
	    }

	m_readSocketScheduler.scheduleAtFixedRate(new Runnable()
	{
	    private boolean m_error = false;

	    @Override
	    public void run()
	    {
		try
		{
		    if(!connected() && !m_disconnected.get())
			synchronized(m_mutex)
			{
			    try
			    {
				m_mutex.wait(WAIT_TIMEOUT);
			    }
			    catch(Exception exception)
			    {
			    }
			}

		    if(!connected())
			return;
		    else if(m_error)
		    {
			if(connected())
			    m_error = false;
			else
			    return;
		    }
		    else if(m_socket == null ||
			    m_socket.getInputStream() == null)
			return;
		    else if(m_socket.getSoTimeout() == HANDSHAKE_TIMEOUT)
			/*
			** Reset SO_TIMEOUT from HANDSHAKE_TIMEOUT.
			*/

			m_socket.setSoTimeout(SO_TIMEOUT);

		    byte bytes[] = new byte[BYTES_PER_READ];
		    int i = 0;

		    try
		    {
			i = m_socket.getInputStream().read(bytes);
		    }
		    catch(Exception exception)
		    {
			i = -1;
			m_error = true;
		    }

		    long bytesRead = 0L;

		    if(i < 0)
			bytesRead = -1L;
		    else if(i > 0)
			bytesRead += (long) i;

		    if(bytesRead < 0L)
		    {
			m_error = true;
			setError("A socket read() error occurred.");
			disconnect();
			return;
		    }
		    else if(bytesRead == 0L)
			return;

		    m_bytesRead.getAndAdd(bytesRead);
		    m_lastTimeRead.set(System.nanoTime());

		    if(m_stringBuffer.length() < MAXIMUM_BYTES)
			m_stringBuffer.append
			    (new String(bytes, 0, (int) bytesRead));

		    synchronized(m_parsingSchedulerObject)
		    {
			m_parsingSchedulerObject.notify();
		    }
		}
		catch(java.net.SocketException exception)
		{
		    m_error = true;
		    setError("A socket error occurred while reading data.");
		    disconnect();
		}
		catch(Exception exception)
		{
		}
	    }
	}, 0L, READ_SOCKET_INTERVAL, TimeUnit.MILLISECONDS);

	m_trustManagers = new TrustManager[]
	{
	    new X509TrustManager()
	    {
		public X509Certificate[] getAcceptedIssuers()
		{
		    return new X509Certificate[0];
		}

		public void checkClientTrusted
		    (X509Certificate chain[], String authType)
		{
		}

		public void checkServerTrusted
		    (X509Certificate chain[], String authType)
		{
		    if(authType == null || authType.length() == 0)
			m_isValidCertificate.set(false);
		    else if(chain == null || chain.length == 0)
			m_isValidCertificate.set(false);
		    else
		    {
			try
			{
			    chain[0].checkValidity();

			    byte bytes[] = m_databaseHelper.
				neighborRemoteCertificate
				(m_cryptography, m_oid.get());

			    if(bytes == null || bytes.length == 0)
			    {
				m_databaseHelper.neighborRecordCertificate
				    (m_cryptography,
				     String.valueOf(m_oid.get()),
				     chain[0].getEncoded());
				m_isValidCertificate.set(true);
			    }
			    else if(!Cryptography.memcmp(bytes,
							 chain[0].getEncoded()))
			    {
				setError("The stored server's " +
					 "certificate does not match the " +
					 "certificate that was provided by " +
					 "the server.");
				m_isValidCertificate.set(false);
			    }
			    else
				m_isValidCertificate.set(true);
			}
			catch(Exception exception)
			{
			    setError("The server's certificate has expired.");
			    m_isValidCertificate.set(false);
			}
		    }

		    if(!m_isValidCertificate.get())
			if(m_error.length() == 0)
			    m_error.append
				("A generic certificate error occurred.");
		}
	    }
	};
    }

    public void abort()
    {
	disconnect();
	super.abort();
	m_handshakeCompleted.set(false);

	if(m_oid.get() >= 0)
	    m_isValidCertificate.set(false);

	if(m_requestAuthenticationScheduler != null)
	    synchronized(m_requestAuthenticationScheduler)
	    {
		try
		{
		    m_requestAuthenticationScheduler.shutdown();
		}
		catch(Exception exception)
		{
		}

		try
		{
		    if(!m_requestAuthenticationScheduler.
		       awaitTermination(AWAIT_TERMINATION, TimeUnit.SECONDS))
			m_requestAuthenticationScheduler.shutdownNow();
		}
		catch(Exception exception)
		{
		}
	    }

	synchronized(m_readSocketScheduler)
	{
	    try
	    {
		m_readSocketScheduler.shutdown();
	    }
	    catch(Exception exception)
	    {
	    }

	    try
	    {
		if(!m_readSocketScheduler.
		   awaitTermination(AWAIT_TERMINATION, TimeUnit.SECONDS))
		    m_readSocketScheduler.shutdownNow();
	    }
	    catch(Exception exception)
	    {
	    }
	}
    }

    public void connect()
    {
	if(connected())
	    return;
	else if(m_oid.get() < 0)
	    return;

	try
	{
	    m_bytesRead.set(0);
	    m_bytesWritten.set(0);
	    m_handshakeCompleted.set(false);
	    m_lastParsed.set(System.currentTimeMillis());
	    m_lastTimeRead.set(System.nanoTime());

	    InetSocketAddress inetSocketAddress =
		new InetSocketAddress(m_ipAddress, Integer.parseInt(m_ipPort));
	    SSLContext sslContext = null;

	    if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
		sslContext = SSLContext.getInstance("TLS");
	    else
		sslContext = SSLContext.getInstance("SSL");

	    sslContext.init
		(null, m_trustManagers, new SecureRandom());

	    if(m_proxyInetSocketAddress == null)
	    {
		m_socket = (SSLSocket) sslContext.getSocketFactory().
		    createSocket();
		m_socket.setReceiveBufferSize(SO_RCVBUF);
		m_socket.setSendBufferSize(SO_SNDBUF);
		m_socket.connect(inetSocketAddress, CONNECTION_TIMEOUT);
	    }
	    else
	    {
		Socket socket = null;

		if(m_proxyType.equals("HTTP"))
		    socket = new Socket
			(new Proxy(Proxy.Type.HTTP, m_proxyInetSocketAddress));
		else
		    socket = new Socket
			(new Proxy(Proxy.Type.SOCKS, m_proxyInetSocketAddress));

		socket.setReceiveBufferSize(SO_RCVBUF);
		socket.setSendBufferSize(SO_SNDBUF);
		socket.connect(inetSocketAddress, CONNECTION_TIMEOUT);
		m_socket = (SSLSocket) sslContext.getSocketFactory().
		    createSocket(socket, m_proxyIpAddress, m_proxyPort, true);
	    }

	    m_socket.addHandshakeCompletedListener
		(new HandshakeCompletedListener()
		{
		    @Override
		    public void handshakeCompleted
			(HandshakeCompletedEvent event)
		    {
			m_handshakeCompleted.set(true);

			synchronized(m_mutex)
			{
			    m_mutex.notifyAll();
			}
		    }
		});
	    m_socket.setEnabledProtocols(m_protocols);
	    m_socket.setKeepAlive(false);
	    m_socket.setSoLinger(true, 0);
	    m_socket.setSoTimeout(HANDSHAKE_TIMEOUT); // SSL/TLS process.
	    m_socket.setTcpNoDelay(true);
	    m_startTime.set(System.nanoTime());
	    setError("");

	    synchronized(m_mutex)
	    {
		m_mutex.notifyAll();
	    }
	}
	catch(Exception exception)
	{
	    setError("An error (" +
		     exception.getMessage() +
		     ") occurred while attempting a connection.");
	    disconnect();
	}
    }

    public void startHandshake()
    {
	try
	{
	    if(m_socket != null)
		m_socket.startHandshake();
	}
	catch(Exception exception)
	{
	}
    }
}
