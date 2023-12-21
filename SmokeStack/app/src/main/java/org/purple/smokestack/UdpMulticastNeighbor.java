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

import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.util.concurrent.TimeUnit;

public class UdpMulticastNeighbor extends Neighbor
{
    private MulticastSocket m_socket = null;
    private final static int TTL = 255;

    protected String getLocalIp()
    {
	return m_ipAddress;
    }

    protected String getRemoteIp()
    {
	return m_ipAddress;
    }

    protected boolean connected()
    {
	try
	{
	    return isNetworkConnected() &&
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
	    StringBuilder stringBuilder = new StringBuilder(message);

	    while(stringBuilder.length() > 0)
	    {
		if(m_disconnected.get())
		    return false;

		byte[] bytes = stringBuilder.substring
		    (0, Math.min(576, stringBuilder.length())).getBytes();

		m_socket.send
		    (new DatagramPacket(bytes,
					bytes.length,
					InetAddress.getByName(m_ipAddress),
					Integer.parseInt(m_ipPort)));
		stringBuilder.delete(0, bytes.length);
	    }

	    Kernel.writeCongestionDigest(message);
	    m_bytesWritten.getAndAdd(message.length());
	    setError("");
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
	return getLocalPort();
    }

    protected void disconnect()
    {
	super.disconnect();
	m_databaseHelper.deleteRoutingEntry(m_uuid.toString());

	try
	{
	    if(m_socket != null)
	    {
		m_socket.leaveGroup(InetAddress.getByName(m_ipAddress));
		m_socket.close();
	    }
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_socket = null;
	    reset();
	}
    }

    public UdpMulticastNeighbor(String ipAddress,
				String ipPort,
				String scopeId,
				String version,
				int oid)
    {
	super(ipAddress, ipPort, scopeId, "UDP", version, false, true, oid);
	m_readSocketScheduler.scheduleAtFixedRate(new Runnable()
	{
	    private boolean m_error = false;

	    @Override
	    public void run()
	    {
		ByteArrayOutputStream byteArrayOutputStream = null;

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

		    DatagramPacket datagramPacket = null;
		    byte[] bytes = new byte[BYTES_PER_READ];

		    datagramPacket = new DatagramPacket(bytes, bytes.length);

		    try
		    {
			m_socket.receive(datagramPacket);
		    }
		    catch(Exception exception)
		    {
			m_error = true;
			setError("A socket receive() error occurred.");
			disconnect();
			return;
		    }

		    if(datagramPacket.getLength() > 0)
		    {
			byteArrayOutputStream = new ByteArrayOutputStream();
			byteArrayOutputStream.write
			    (datagramPacket.getData(),
			     0,
			     datagramPacket.getLength());
		    }

		    int bytesRead = datagramPacket.getLength();

		    if(bytesRead < 0)
		    {
			m_error = true;
			setError("A socket receive() error occurred.");
			disconnect();
			return;
		    }
		    else if(bytesRead == 0)
			return;

		    m_bytesRead.getAndAdd(bytesRead);
		    m_lastTimeRead.set(System.nanoTime());

		    if(byteArrayOutputStream != null &&
		       m_stringBuffer.length() < MAXIMUM_BYTES)
			m_stringBuffer.append
			    (byteArrayOutputStream);
		}
		catch(Exception exception)
		{
		}
		finally
		{
		    try
		    {
			if(byteArrayOutputStream != null)
			    byteArrayOutputStream.close();
		    }
		    catch(Exception exception)
		    {
		    }
		}
	    }
	}, 0L, READ_SOCKET_INTERVAL, TimeUnit.MILLISECONDS);
    }

    public void abort()
    {
	disconnect();
	super.abort();

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

	try
	{
	    m_bytesRead.set(0);
	    m_bytesWritten.set(0);
	    m_disconnected.set(false);
	    m_lastParsed.set(System.currentTimeMillis());
	    m_lastTimeRead.set(System.nanoTime());
	    m_socket = new MulticastSocket(Integer.parseInt(m_ipPort));
	    m_socket.joinGroup(InetAddress.getByName(m_ipAddress));
	    m_socket.setLoopbackMode(true);
	    m_socket.setSoTimeout(SO_TIMEOUT);
	    m_socket.setTimeToLive(TTL);
	    m_startTime.set(System.nanoTime());
	    setError("");

	    synchronized(m_mutex)
	    {
		m_mutex.notifyAll();
	    }
	}
	catch(Exception exception)
	{
	    setError("An error occurred while attempting a connection.");
	    disconnect();
	}
    }
}
