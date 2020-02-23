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
**    derived from Smoke without specific prior written permission.
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

import android.support.v7.widget.RecyclerView;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnCreateContextMenuListener;
import android.view.ViewGroup;

public class ListenersAdapter extends RecyclerView.Adapter
				      <ListenersAdapter.ViewHolder>
{
    private Settings m_settings = null;

    public class ViewHolder extends RecyclerView.ViewHolder
	implements OnCreateContextMenuListener
    {
	ClientBubble m_clientBubble = null;
	int m_position = -1;

        public ViewHolder(ClientBubble clientBubble)
	{
	    super(clientBubble.view());
	    clientBubble.view().setOnCreateContextMenuListener(this);
	    m_clientBubble = clientBubble;
        }

	public void onCreateContextMenu(ContextMenu menu,
					View view,
					ContextMenuInfo menuInfo)
	{
	    if(menu == null || view == null)
		return;
	}

	public void setData(ClientElement clientElement, int position)
	{
	    if(clientElement == null)
	    {
		m_position = position;
	    }
	    else if(m_clientBubble == null)
		return;
	}
    }

    public ListenersAdapter(Settings settings)
    {
	m_settings = settings;
    }

    @Override
    public ListenersAdapter.ViewHolder onCreateViewHolder
	(ViewGroup parent, int viewType)
    {
	return null;
    }

    @Override
    public int getItemCount()
    {
	return 0;
    }

    @Override
    public void onBindViewHolder(ViewHolder viewHolder, int position)
    {
	if(viewHolder == null)
	    return;
    }
}
