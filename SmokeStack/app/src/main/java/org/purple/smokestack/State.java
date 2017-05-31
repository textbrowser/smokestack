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

import android.os.Bundle;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class State
{
    private Bundle m_bundle = null;
    private final ReentrantReadWriteLock m_bundleMutex =
	new ReentrantReadWriteLock();
    private static State s_instance = null;

    private State()
    {
	m_bundle = new Bundle();
	setAuthenticated(false);
    }

    public static synchronized State getInstance()
    {
	if(s_instance == null)
	    s_instance = new State();

	return s_instance;
    }

    public CharSequence getCharSequence(String key)
    {
	m_bundleMutex.readLock().lock();

	try
	{
	    return m_bundle.getCharSequence(key, "");
	}
	finally
	{
	    m_bundleMutex.readLock().unlock();
	}
    }

    public String getString(String key)
    {
	m_bundleMutex.readLock().lock();

	try
	{
	    return m_bundle.getString(key, "");
	}
	finally
	{
	    m_bundleMutex.readLock().unlock();
	}
    }

    public boolean isAuthenticated()
    {
	m_bundleMutex.readLock().lock();

	try
	{
	    return m_bundle.getChar("is_authenticated", '0') == '1';
	}
	finally
	{
	    m_bundleMutex.readLock().unlock();
	}
    }

    public void removeKey(String key)
    {
	m_bundleMutex.writeLock().lock();

	try
	{
	    m_bundle.remove(key);
	}
	finally
	{
	    m_bundleMutex.writeLock().unlock();
	}
    }

    public void reset()
    {
	m_bundleMutex.writeLock().lock();

	try
	{
	    m_bundle.clear();
	}
	finally
	{
	    m_bundleMutex.writeLock().unlock();
	}
    }

    public void setAuthenticated(boolean state)
    {
	m_bundleMutex.writeLock().lock();

	try
	{
	    m_bundle.putChar("is_authenticated", state ? '1' : '0');
	}
	finally
	{
	    m_bundleMutex.writeLock().unlock();
	}
    }

    public void setString(String key, String value)
    {
	m_bundleMutex.writeLock().lock();

	try
	{
	    m_bundle.putString(key, value);
	}
	finally
	{
	    m_bundleMutex.writeLock().unlock();
	}
    }

    public void writeCharSequence(String key, CharSequence text)
    {
	m_bundleMutex.writeLock().lock();

	try
	{
	    m_bundle.putCharSequence(key, text);
	}
	finally
	{
	    m_bundleMutex.writeLock().unlock();
	}
    }
}
