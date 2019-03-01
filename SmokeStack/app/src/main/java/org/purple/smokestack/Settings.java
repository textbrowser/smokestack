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

import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AppCompatActivity;
import android.text.InputFilter;
import android.text.InputType;
import android.text.Spanned;
import android.util.Base64;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.ContextMenu;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout.LayoutParams;
import android.widget.PopupWindow;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

public class Settings extends AppCompatActivity
{
    private abstract class ContextMenuEnumerator
    {
	public final static int DELETE_ALL_MESSAGES = 0;
	public final static int DELETE_LISTENER = 1;
	public final static int DELETE_MESSAGES = 2;
	public final static int DELETE_OZONE = 3;
	public final static int DELETE_PARTICIPANT = 4;
	public final static int NEW_NAME = 5;
	public final static int RESET_RETRIEVAL_STATE = 6;
    }

    private class PopulateListeners implements Runnable
    {
	private ArrayList<ListenerElement> m_arrayList = null;

	public PopulateListeners(ArrayList<ListenerElement> arrayList)
	{
	    m_arrayList = arrayList;
	}

	@Override
	public void run()
	{
	    try
	    {
		populateListeners(m_arrayList);
	    }
	    catch(Exception exception)
	    {
	    }

	    if(m_arrayList != null)
		m_arrayList.clear();
	}
    }

    private class PopulateNeighbors implements Runnable
    {
	private ArrayList<NeighborElement> m_arrayList = null;

	public PopulateNeighbors(ArrayList<NeighborElement> arrayList)
	{
	    m_arrayList = arrayList;
	}

	@Override
	public void run()
	{
	    try
	    {
		populateNeighbors(m_arrayList);
	    }
	    catch(Exception exception)
	    {
	    }

	    if(m_arrayList != null)
		m_arrayList.clear();
	}
    }

    private class SettingsBroadcastReceiver extends BroadcastReceiver
    {
	public SettingsBroadcastReceiver()
	{
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
	    if(intent == null || intent.getAction() == null)
		return;

	    if(intent.getAction().
	       equals("org.purple.smokestack.populate_participants"))
		populateParticipants();
	    else if(intent.getAction().
		    equals("org.purple.smokestack.populate_" +
			   "ozones_participants"))
	    {
		populateOzoneAddresses();
		populateParticipants();
	    }
	}
    }

    private Database m_databaseHelper = null;
    private ScheduledExecutorService m_generalScheduler = null;
    private ScheduledExecutorService m_listenersScheduler = null;
    private ScheduledExecutorService m_neighborsScheduler = null;
    private SettingsBroadcastReceiver m_receiver = null;
    private boolean m_receiverRegistered = false;
    private final static Cryptography s_cryptography =
	Cryptography.getInstance();
    private final static InputFilter s_portFilter = new InputFilter()
    {
	public CharSequence filter(CharSequence source,
				   int start,
				   int end,
				   Spanned dest,
				   int dstart,
				   int dend)
	{
	    try
	    {
		int port = Integer.parseInt
		    (dest.toString() + source.toString());

		if(port >= 0 && port <= 65535)
		    return null;
	    }
	    catch(Exception exception)
	    {
	    }

	    return "";
	}
    };
    private final static InputFilter s_sipHashInputFilter = new InputFilter()
    {
	public CharSequence filter(CharSequence source,
				   int start,
				   int end,
				   Spanned dest,
				   int dstart,
				   int dend)
	{
	    for(int i = start; i < end; i++)
		/*
		** Allow hexadecimal characters only.
		*/

		if(!((source.charAt(i) == ' ' || source.charAt(i) == '-') ||
		     (source.charAt(i) >= '0' && source.charAt(i) <= '9') ||
		     (source.charAt(i) >= 'A' && source.charAt(i) <= 'F') ||
		     (source.charAt(i) >= 'a' && source.charAt(i) <= 'f')))
		    return source.subSequence(start, i);

	    return null;
	}
    };
    private final static String MINIMUM_PASSWORD_LENGTH_TEXT = "three";
    private final static int CHECKBOX_TEXT_SIZE = 13;
    private final static int CHECKBOX_WIDTH = 500;
    private final static int MINIMUM_PASSWORD_LENGTH = 3;
    private final static int TEXTVIEW_TEXT_SIZE = 13;
    private final static int TEXTVIEW_WIDTH = 500;
    private final static long TIMER_INTERVAL = 2500; // 2.5 Seconds

    private boolean generateOzone(String string)
    {
	byte bytes[] = Cryptography.generateOzone(string);

	if(bytes != null)
	    return m_databaseHelper.writeOzone
		(s_cryptography, string.trim(), bytes);
	else
	    return false;
    }

    private void addListener()
    {
	if(Settings.this.isFinishing())
	    return;

	CheckBox checkBox1 = (CheckBox) findViewById
	    (R.id.automatic_refresh_listeners);
	CheckBox checkBox2 = (CheckBox) findViewById(R.id.private_server);
	RadioGroup radioGroup1 = (RadioGroup) findViewById
	    (R.id.listeners_ipv_radio_group);
	String ipVersion = "";
	TextView textView1 = (TextView) findViewById(R.id.listeners_ip_address);
	TextView textView2 = (TextView) findViewById(R.id.listeners_port);
	TextView textView3 = (TextView) findViewById(R.id.listeners_scope_id);

	if(radioGroup1.getCheckedRadioButtonId() == R.id.listeners_ipv4)
	    ipVersion = "IPv4";
	else
	    ipVersion = "IPv6";

	if(textView1.getText().toString().trim().isEmpty())
	    Miscellaneous.showErrorDialog
		(Settings.this, "Please provide a listener IP address.");
	else if(!m_databaseHelper.
		writeListener(s_cryptography,
			      textView1.getText().toString(),
			      textView2.getText().toString(),
			      textView3.getText().toString(),
			      ipVersion,
			      checkBox2.isChecked()))
	    Miscellaneous.showErrorDialog
		(Settings.this,
		 "An error occurred while saving the listener information.");
	else if(!checkBox1.isChecked())
	    populateListeners(null);
    }

    private void addNeighbor()
    {
	if(Settings.this.isFinishing())
	    return;

	CheckBox checkBox1 = (CheckBox) findViewById
	    (R.id.automatic_refresh_neighbors);
	RadioGroup radioGroup1 = (RadioGroup) findViewById
	    (R.id.neighbors_ipv_radio_group);
	Spinner spinner1 = (Spinner) findViewById(R.id.neighbors_transport);
	Spinner spinner2 = (Spinner) findViewById(R.id.proxy_type);
	String ipVersion = "";
	TextView proxyIpAddress = (TextView) findViewById
	    (R.id.proxy_ip_address);
	TextView proxyPort = (TextView) findViewById(R.id.proxy_port);
	TextView textView1 = (TextView) findViewById(R.id.neighbors_ip_address);
	TextView textView2 = (TextView) findViewById(R.id.neighbors_port);
	TextView textView3 = (TextView) findViewById(R.id.neighbors_scope_id);

	if(radioGroup1.getCheckedRadioButtonId() == R.id.neighbors_ipv4)
	    ipVersion = "IPv4";
	else
	    ipVersion = "IPv6";

	if(textView1.getText().toString().trim().isEmpty())
	    Miscellaneous.showErrorDialog
		(Settings.this, "Please provide a neighbor IP address.");
	else if(!m_databaseHelper.
		writeNeighbor(s_cryptography,
			      proxyIpAddress.getText().toString(),
			      proxyPort.getText().toString(),
			      spinner2.getSelectedItem().toString(),
			      textView1.getText().toString(),
			      textView2.getText().toString(),
			      textView3.getText().toString(),
			      spinner1.getSelectedItem().toString(),
			      ipVersion))
	    Miscellaneous.showErrorDialog
		(Settings.this,
		 "An error occurred while saving the neighbor information.");
	else if(!checkBox1.isChecked())
	    populateNeighbors(null);
    }

    private void addParticipant()
    {
	if(Settings.this.isFinishing())
	    return;

	String string = "";
	StringBuilder stringBuilder = new StringBuilder();
	TextView textView1 = (TextView) findViewById
	    (R.id.participant_siphash_id);

	string = Miscellaneous.delimitString
	    (textView1.getText().toString().
	     replace(" ", "").replace("-", "").replace(":", "").trim(),
	     '-', 4);

	if(string.length() != Cryptography.SIPHASH_ID_LENGTH)
	{
	    Miscellaneous.showErrorDialog
		(Settings.this,
		 "A Smoke ID must be of the form 0102-0304-0506-0708.");
	    return;
	}

	final ProgressDialog dialog = new ProgressDialog(Settings.this);

	dialog.setCancelable(false);
	dialog.setIndeterminate(true);
	dialog.setMessage("Generating key material. Please be patient and " +
			  "do not rotate the device while the process " +
			  "executes.");
	dialog.show();

	class SingleShot implements Runnable
	{
	    private String m_name = "";
	    private String m_sipHashId = "";
	    private boolean m_acceptWithoutSignatures = false;
	    private boolean m_error = false;

	    SingleShot(String name,
		       String sipHashId,
		       boolean acceptWithoutSignatures)
	    {
		m_acceptWithoutSignatures = acceptWithoutSignatures;
		m_name = name;
		m_sipHashId = sipHashId.toUpperCase();
	    }

	    @Override
	    public void run()
	    {
		try
		{
		    if(!m_databaseHelper.
		       writeSipHashParticipant(s_cryptography,
					       m_name,
					       m_sipHashId,
					       m_acceptWithoutSignatures))
			m_error = true;
		    else
			generateOzone(m_sipHashId);

		    Settings.this.runOnUiThread(new Runnable()
		    {
			@Override
			public void run()
			{
			    dialog.dismiss();

			    if(m_error)
				Miscellaneous.showErrorDialog
				    (Settings.this,
				     "An error occurred while attempting " +
				     "to save the specified Smoke ID.");
			    else
			    {
				Kernel.getInstance().populateOzones();
				Kernel.getInstance().populateSipHashIds();
				populateOzoneAddresses();
				populateParticipants();
			    }
			}
		    });
		}
		catch(Exception exception)
		{
		}
	    }
	}

	Thread thread = new Thread
	    (new
	     SingleShot(((TextView) findViewById(R.id.participant_name)).
			getText().toString(), string,
			((CheckBox) findViewById(R.id.
						 accept_without_signatures)).
			isChecked()));

	thread.start();
    }

    private void enableWidgets(boolean state)
    {
	Button button1 = null;

	button1 = (Button) findViewById(R.id.add_listener);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.add_neighbor);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.add_participant);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.refresh_listeners);
	button1.setEnabled(state);
        button1 = (Button) findViewById(R.id.refresh_neighbors);
        button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.refresh_ozones);
        button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.refresh_participants);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.reset_listener_fields);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.reset_neighbor_fields);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.reset_participants_fields);
	button1.setEnabled(state);
	button1 = (Button) findViewById(R.id.save_ozone);
	button1.setEnabled(state);

	CheckBox checkBox1 = null;

	checkBox1 = (CheckBox) findViewById(R.id.accept_without_signatures);
	checkBox1.setChecked(!state);
	checkBox1.setEnabled(state);
	checkBox1 = (CheckBox) findViewById(R.id.overwrite);
	checkBox1.setChecked(!state);
	checkBox1.setEnabled(state);
	button1 = (Button) findViewById(R.id.set_password);
	button1.setEnabled(checkBox1.isChecked());
	checkBox1 = (CheckBox) findViewById(R.id.private_server);
	checkBox1.setChecked(!state);
	checkBox1.setEnabled(state);

	RadioButton radioButton1 = null;

	radioButton1 = (RadioButton) findViewById(R.id.listeners_ipv4);
	radioButton1.setEnabled(state);
	radioButton1 = (RadioButton) findViewById(R.id.listeners_ipv6);
	radioButton1.setEnabled(state);
	radioButton1 = (RadioButton) findViewById(R.id.neighbors_ipv4);
	radioButton1.setEnabled(state);
	radioButton1 = (RadioButton) findViewById(R.id.neighbors_ipv6);
	radioButton1.setEnabled(state);

	Spinner spinner1 = null;

	spinner1 = (Spinner) findViewById(R.id.neighbors_transport);
	spinner1.setEnabled(state);
	spinner1 = (Spinner) findViewById(R.id.proxy_type);
	spinner1.setEnabled(state);

	TextView textView1 = null;

	textView1 = (TextView) findViewById(R.id.listeners_ip_address);
	textView1.setEnabled(state);
        textView1 = (TextView) findViewById(R.id.listeners_port);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.listeners_scope_id);
        textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.neighbors_ip_address);
	textView1.setEnabled(state);
        textView1 = (TextView) findViewById(R.id.neighbors_port);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.neighbors_scope_id);
        textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.ozone);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.participant_name);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.participant_siphash_id);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.proxy_ip_address);
	textView1.setEnabled(state);
	textView1 = (TextView) findViewById(R.id.proxy_port);
	textView1.setEnabled(state);
    }

    private void populateListeners(ArrayList<ListenerElement> arrayList)
    {
	if(arrayList == null)
	    arrayList = m_databaseHelper.readListeners(s_cryptography);

	final TableLayout tableLayout = (TableLayout)
	    findViewById(R.id.listeners);

	if(arrayList == null || arrayList.size() == 0)
	{
	    tableLayout.removeAllViews();
	    return;
	}

	StringBuilder stringBuilder = new StringBuilder();
	int i = 0;

	/*
	** Remove table entries which do not exist in smokestack.db.
	*/

	for(i = tableLayout.getChildCount() - 1; i >= 0; i--)
	{
	    TableRow row = (TableRow) tableLayout.getChildAt(i);

	    if(row == null)
		continue;

	    CheckBox checkBox = (CheckBox) row.getChildAt(0);

	    if(checkBox == null)
	    {
		tableLayout.removeView(row);
		continue;
	    }

	    boolean found = false;

	    for(ListenerElement listenerElement : arrayList)
	    {
		stringBuilder.delete(0, stringBuilder.length());
		stringBuilder.append(listenerElement.m_localIpAddress);

		if(listenerElement.m_ipVersion.equals("IPv6"))
		    if(!listenerElement.m_localScopeId.isEmpty())
		    {
			stringBuilder.append("-");
			stringBuilder.append(listenerElement.m_localScopeId);
		    }

		stringBuilder.append(":");
		stringBuilder.append(listenerElement.m_localPort);

		if(checkBox.getText().toString().
		   contains(stringBuilder.toString()))
		{
		    found = true;
		    break;
		}
	    }

	    if(!found)
		tableLayout.removeView(row);
	}

	i = 0;

	for(ListenerElement listenerElement : arrayList)
	{
	    if(listenerElement == null)
		continue;

	    CheckBox checkBox = null;
	    TableRow row = null;
	    int count = tableLayout.getChildCount();

	    for(int j = 0; j < count; j++)
	    {
		TableRow r = (TableRow) tableLayout.getChildAt(j);

		if(r == null)
		    continue;

		CheckBox c = (CheckBox) r.getChildAt(0);

		if(c == null)
		    continue;

		stringBuilder.delete(0, stringBuilder.length());
		stringBuilder.append(listenerElement.m_localIpAddress);

		if(listenerElement.m_ipVersion.equals("IPv6"))
		    if(!listenerElement.m_localScopeId.isEmpty())
		    {
			stringBuilder.append("-");
			stringBuilder.append(listenerElement.m_localScopeId);
		    }

		stringBuilder.append(":");
		stringBuilder.append(listenerElement.m_localPort);

		if(c.getText().toString().contains(stringBuilder.toString()))
		{
		    checkBox = c;
		    break;
		}
	    }

	    if(checkBox == null)
	    {
		TableRow.LayoutParams layoutParams = new
		    TableRow.LayoutParams(TableRow.LayoutParams.WRAP_CONTENT);
		final String oid = String.valueOf(listenerElement.m_oid);

		row = new TableRow(Settings.this);
		row.setId(listenerElement.m_oid);
		row.setLayoutParams(layoutParams);
		checkBox = new CheckBox(Settings.this);
		checkBox.setOnCheckedChangeListener
		    (new CompoundButton.OnCheckedChangeListener()
		    {
			@Override
			public void onCheckedChanged
			    (CompoundButton buttonView, boolean isChecked)
			{
			    m_databaseHelper.listenerNeighborControlStatus
				(s_cryptography,
				 isChecked ? "listen" : "disconnect",
				 oid,
				 "listeners");
			}
		    });
	    }

	    registerForContextMenu(checkBox);

	    if(listenerElement.m_status.equals("listening"))
		checkBox.setTextColor(Color.rgb(27, 94, 32)); // Dark Green
	    else
		checkBox.setTextColor(Color.rgb(183, 28, 28)); // Dark Red

	    stringBuilder.delete(0, stringBuilder.length());
	    stringBuilder.append("Control: ");

	    try
	    {
		stringBuilder.append
		    (listenerElement.m_statusControl.substring(0, 1).
		     toUpperCase());
		stringBuilder.append
		    (listenerElement.m_statusControl.substring(1));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("Disconnect");
	    }

	    stringBuilder.append("\n");
	    stringBuilder.append("Status: ");

	    try
	    {
		stringBuilder.append
		    (listenerElement.m_status.substring(0, 1).toUpperCase());
		stringBuilder.append(listenerElement.m_status.substring(1));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("Disconnected");
	    }

	    stringBuilder.append("\n");

	    if(!listenerElement.m_error.isEmpty())
	    {
		stringBuilder.append("Error: ");
		stringBuilder.append(listenerElement.m_error);
		stringBuilder.append("\n");
	    }

	    stringBuilder.append(listenerElement.m_localIpAddress);

	    if(listenerElement.m_ipVersion.equals("IPv6"))
		if(!listenerElement.m_localScopeId.isEmpty())
		{
		    stringBuilder.append("-");
		    stringBuilder.append(listenerElement.m_localScopeId);
		}

	    stringBuilder.append(":");
	    stringBuilder.append(listenerElement.m_localPort);

	    if(listenerElement.m_certificate != null)
	    {
		/*
		** In PEM format.
		*/

		stringBuilder.append("\nCertificate Fingerprint: ");
		stringBuilder.append
		    (Cryptography.
		     fingerPrint(Miscellaneous.
				 pemFormat(listenerElement.m_certificate).
				 getBytes()));
	    }

	    stringBuilder.append("\nPeers Count: ");
	    stringBuilder.append(listenerElement.m_peersCount);
	    stringBuilder.append("\nPrivate: ");
	    stringBuilder.append(listenerElement.m_isPrivate ? "Yes" : "No");
	    stringBuilder.append("\nUptime: ");

	    try
	    {
		long uptime = Long.parseLong(listenerElement.m_uptime);

		stringBuilder.append
		    (String.
		     format(Locale.getDefault(),
			    "%d:%02d",
			    TimeUnit.NANOSECONDS.toMinutes(uptime),
			    TimeUnit.NANOSECONDS.toSeconds(uptime) -
			    TimeUnit.MINUTES.
			    toSeconds(TimeUnit.NANOSECONDS.
				      toMinutes(uptime))));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("0:00");
	    }

	    stringBuilder.append(" Min.\n");
	    checkBox.setChecked
		(listenerElement.m_statusControl.toLowerCase().
		 equals("listen"));
	    checkBox.setGravity(Gravity.CENTER_VERTICAL);
	    checkBox.setId(listenerElement.m_oid);
	    checkBox.setLayoutParams
		(new TableRow.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1));
	    checkBox.setTag
		(listenerElement.m_localIpAddress + ":" +
		 listenerElement.m_localPort);
	    checkBox.setText(stringBuilder);
	    checkBox.setTextSize(CHECKBOX_TEXT_SIZE);
	    checkBox.setWidth(CHECKBOX_WIDTH);

	    if(row != null)
	    {
		row.addView(checkBox);
		tableLayout.addView(row, i);
	    }

	    i += 1;
	}

	arrayList.clear();
    }

    private void populateNeighbors(ArrayList<NeighborElement> arrayList)
    {
	((TextView) findViewById(R.id.internal_neighbors)).setText
	    ("Internal Neighbors Container Size: " +
	     Kernel.getInstance().neighborsCount());

	if(arrayList == null)
	    arrayList = m_databaseHelper.readNeighbors(s_cryptography);

	final TableLayout tableLayout = (TableLayout)
	    findViewById(R.id.neighbors);

	if(arrayList == null || arrayList.size() == 0)
	{
	    tableLayout.removeAllViews();
	    return;
	}

	StringBuilder stringBuilder = new StringBuilder();
	int i = 0;

	/*
	** Remove table entries which do not exist in smokestack.db.
	*/

	for(i = tableLayout.getChildCount() - 1; i >= 0; i--)
	{
	    TableRow row = (TableRow) tableLayout.getChildAt(i);

	    if(row == null)
		continue;

	    TextView textView = (TextView) row.getChildAt(1);

	    if(textView == null)
	    {
		tableLayout.removeView(row);
		continue;
	    }

	    boolean found = false;

	    for(NeighborElement neighborElement : arrayList)
	    {
		stringBuilder.delete(0, stringBuilder.length());
		stringBuilder.append(neighborElement.m_remoteIpAddress);

		if(neighborElement.m_ipVersion.equals("IPv6"))
		    if(!neighborElement.m_remoteScopeId.isEmpty())
		    {
			stringBuilder.append("-");
			stringBuilder.append(neighborElement.m_remoteScopeId);
		    }

		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_remotePort);
		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_transport);

		if(textView.getText().toString().
		   contains(stringBuilder.toString()))
		{
		    found = true;
		    break;
		}
	    }

	    if(!found)
		tableLayout.removeView(row);
	}

	CheckBox checkBox = (CheckBox) findViewById(R.id.neighbor_details);

	i = 0;

	for(NeighborElement neighborElement : arrayList)
	{
	    if(neighborElement == null)
		continue;

	    Spinner spinner = null;
	    TableRow row = null;
	    TextView textView = null;
	    int count = tableLayout.getChildCount();

	    for(int j = 0; j < count; j++)
	    {
		TableRow r = (TableRow) tableLayout.getChildAt(j);

		if(r == null)
		    continue;

		TextView t = (TextView) r.getChildAt(1);

		if(t == null)
		    continue;

		stringBuilder.delete(0, stringBuilder.length());
		stringBuilder.append(neighborElement.m_remoteIpAddress);

		if(neighborElement.m_ipVersion.equals("IPv6"))
		    if(!neighborElement.m_remoteScopeId.isEmpty())
		    {
			stringBuilder.append("-");
			stringBuilder.append(neighborElement.m_remoteScopeId);
		    }

		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_remotePort);
		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_transport);

		if(t.getText().toString().contains(stringBuilder.toString()))
		{
		    textView = t;
		    break;
		}
	    }

	    if(textView == null)
	    {
		TableRow.LayoutParams layoutParams = new
		    TableRow.LayoutParams(TableRow.LayoutParams.WRAP_CONTENT);

		row = new TableRow(Settings.this);
		row.setId(neighborElement.m_oid);
		row.setLayoutParams(layoutParams);
		spinner = new Spinner(Settings.this);

		ArrayAdapter<String> arrayAdapter = null;
		String array[] = null;

		if(neighborElement.m_transport.equals("TCP"))
		    array = new String[]
		    {
			"Action",
			"Connect", "Delete", "Disconnect",
			"Reset SSL/TLS Credentials"
		    };
		else
		    array = new String[]
		    {
			"Action",
			"Connect", "Delete", "Disconnect"
		    };

		arrayAdapter = new ArrayAdapter<>
		    (Settings.this,
		     android.R.layout.simple_spinner_item,
		     array);
		spinner.setAdapter(arrayAdapter);
		spinner.setId(neighborElement.m_oid);
		spinner.setOnItemSelectedListener
		    (new OnItemSelectedListener()
		    {
			@Override
			public void onItemSelected(AdapterView<?> parent,
						   View view,
						   int position,
						   long id)
			{
			    if(position == 1) // Connect
				m_databaseHelper.listenerNeighborControlStatus
				    (s_cryptography,
				     "connect",
				     String.valueOf(parent.getId()),
				     "neighbors");
			    else if(position == 2 && // Delete
				    m_databaseHelper.
				    deleteEntry(String.valueOf(parent.getId()),
						"neighbors"))
			    {
				/*
				** Prepare the kernel's neighbors container
				** if a neighbor was deleted as the OID
				** field may represent a recycled value.
				*/

				Kernel.getInstance().purgeDeletedNeighbors();

				TableRow row = (TableRow) findViewById
				    (parent.getId());

				tableLayout.removeView(row);
			    }
			    else if(position == 3) // Disconnect
				m_databaseHelper.listenerNeighborControlStatus
				    (s_cryptography,
				     "disconnect",
				     String.valueOf(parent.getId()),
				     "neighbors");
			    else if(position == 4) // Reset SSL/TLS Credentials
			    {
				m_databaseHelper.neighborRecordCertificate
				    (s_cryptography,
				     String.valueOf(parent.getId()),
				     null);
				m_databaseHelper.listenerNeighborControlStatus
				    (s_cryptography,
				     "disconnect",
				     String.valueOf(parent.getId()),
				     "neighbors");
			    }

			    parent.setSelection(0);
			}

			@Override
			public void onNothingSelected(AdapterView<?> parent)
			{
			}
		    });

		textView = new TextView(Settings.this);
	    }

	    switch(neighborElement.m_status)
	    {
	    case "connected":
                textView.setTextColor(Color.rgb(27, 94, 32)); // Dark Green
                break;
            case "connecting":
                textView.setTextColor(Color.rgb(255, 111, 0)); // Dark Orange
                break;
            default:
                textView.setTextColor(Color.rgb(183, 28, 28)); // Dark Red
                break;
	    }

	    stringBuilder.delete(0, stringBuilder.length());
	    stringBuilder.append("Control: ");

	    try
	    {
		stringBuilder.append
		    (neighborElement.m_statusControl.substring(0, 1).
		     toUpperCase());
		stringBuilder.append
		    (neighborElement.m_statusControl.substring(1));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("Disconnect");
	    }

	    stringBuilder.append("\n");
	    stringBuilder.append("Status: ");

	    try
	    {
		stringBuilder.append
		    (neighborElement.m_status.substring(0, 1).toUpperCase());
		stringBuilder.append(neighborElement.m_status.substring(1));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("Disconnected");
	    }

	    stringBuilder.append("\n");

	    if(!neighborElement.m_error.isEmpty())
	    {
		stringBuilder.append("Error: ");
		stringBuilder.append(neighborElement.m_error);
		stringBuilder.append("\n");
	    }

	    stringBuilder.append(neighborElement.m_remoteIpAddress);

	    if(neighborElement.m_ipVersion.equals("IPv6"))
		if(!neighborElement.m_remoteScopeId.isEmpty())
		{
		    stringBuilder.append("-");
		    stringBuilder.append(neighborElement.m_remoteScopeId);
		}

	    stringBuilder.append(":");
	    stringBuilder.append(neighborElement.m_remotePort);
	    stringBuilder.append(":");
	    stringBuilder.append(neighborElement.m_transport);

	    if(!neighborElement.m_localIpAddress.isEmpty() &&
	       !neighborElement.m_localPort.isEmpty())
	    {
		stringBuilder.append("\n");
		stringBuilder.append(neighborElement.m_localIpAddress);
		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_localPort);
	    }

	    stringBuilder.append("\nProxy: ");

	    if(!neighborElement.m_proxyIpAddress.isEmpty() &&
	       !neighborElement.m_proxyPort.isEmpty())
	    {
		stringBuilder.append(neighborElement.m_proxyIpAddress);
		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_proxyPort);
		stringBuilder.append(":");
		stringBuilder.append(neighborElement.m_proxyType);
	    }

	    if(checkBox.isChecked())
	    {
		if(neighborElement.m_remoteCertificate != null &&
		   neighborElement.m_remoteCertificate.length > 0)
		{
		    stringBuilder.append("\n");
		    stringBuilder.append
			("Remote Certificate's Fingerprint: ");
		    stringBuilder.append
			(Cryptography.
			 fingerPrint(Miscellaneous.
				     pemFormat(neighborElement.
					       m_remoteCertificate).
				     getBytes()));
		}

		if(!neighborElement.m_sessionCipher.isEmpty())
		{
		    stringBuilder.append("\n");
		    stringBuilder.append("Session Cipher: ");
		    stringBuilder.append(neighborElement.m_sessionCipher);
		}
	    }

	    stringBuilder.append("\n");
	    stringBuilder.append("Echo Queue Size: ");
	    stringBuilder.append(neighborElement.m_outboundEchoQueued);
	    stringBuilder.append("\n");
	    stringBuilder.append("Queue Size: ");
	    stringBuilder.append(neighborElement.m_queueSize);
	    stringBuilder.append("\n");
	    stringBuilder.append("Buffered: ");
	    stringBuilder.append
		(Miscellaneous.
		 formattedDigitalInformation(neighborElement.m_bytesBuffered));
	    stringBuilder.append("\n");
	    stringBuilder.append("In: ");
	    stringBuilder.append
		(Miscellaneous.
		 formattedDigitalInformation(neighborElement.m_bytesRead));
	    stringBuilder.append("\n");
	    stringBuilder.append("Out: ");
	    stringBuilder.append
		(Miscellaneous.
		 formattedDigitalInformation(neighborElement.m_bytesWritten));
	    stringBuilder.append("\n");
	    stringBuilder.append("Outbound Queued: ");
	    stringBuilder.append(neighborElement.m_outboundQueued);
	    stringBuilder.append("\n");
	    stringBuilder.append("Uptime: ");

	    try
	    {
		long uptime = Long.parseLong(neighborElement.m_uptime);

		stringBuilder.append
		    (String.
		     format(Locale.getDefault(),
			    "%d:%02d",
			    TimeUnit.NANOSECONDS.toMinutes(uptime),
			    TimeUnit.NANOSECONDS.toSeconds(uptime) -
			    TimeUnit.MINUTES.
			    toSeconds(TimeUnit.NANOSECONDS.
				      toMinutes(uptime))));
	    }
	    catch(Exception exception)
	    {
		stringBuilder.append("0:00");
	    }

	    stringBuilder.append(" Min.\n");
	    textView.setGravity(Gravity.CENTER_VERTICAL);
	    textView.setLayoutParams
		(new TableRow.LayoutParams(0, LayoutParams.WRAP_CONTENT, 1));
	    textView.setText(stringBuilder);
	    textView.setTextSize(TEXTVIEW_TEXT_SIZE);
	    textView.setWidth(TEXTVIEW_WIDTH);

	    if(row != null)
	    {
		row.addView(spinner);
		row.addView(textView);
		tableLayout.addView(row, i);
	    }

	    i += 1;
	}

	arrayList.clear();
    }

    private void populateOzoneAddresses()
    {
	ArrayList<OzoneElement> arrayList =
	    m_databaseHelper.readOzones(s_cryptography);
	TableLayout tableLayout = (TableLayout) findViewById
	    (R.id.ozones);

	tableLayout.removeAllViews();

	if(arrayList == null || arrayList.size() == 0)
	    return;

	int i = 0;

	for(OzoneElement ozoneElement : arrayList)
	{
	    if(ozoneElement == null)
		continue;

	    TableRow.LayoutParams layoutParams = new
		TableRow.LayoutParams(TableRow.LayoutParams.WRAP_CONTENT);
	    TableRow row = new TableRow(Settings.this);

	    row.setLayoutParams(layoutParams);

	    TextView textView = new TextView(Settings.this);

	    textView.setGravity(Gravity.CENTER_VERTICAL);
	    textView.setId(ozoneElement.m_oid);
	    textView.setLayoutParams
		(new TableRow.LayoutParams(0,
					   LayoutParams.WRAP_CONTENT,
					   1));
	    textView.setTag(ozoneElement.m_address);
	    textView.setText(ozoneElement.m_address);
	    textView.setTextSize(TEXTVIEW_TEXT_SIZE);
	    registerForContextMenu(textView);
	    row.addView(textView);
	    tableLayout.addView(row, i);
	    i += 1;
	}

	arrayList.clear();
    }

    private void populateParticipants()
    {
	ArrayList<SipHashIdElement> arrayList =
	    m_databaseHelper.readSipHashIds(s_cryptography);
	TableLayout tableLayout = (TableLayout) findViewById
	    (R.id.participants);

	tableLayout.removeAllViews();

	if(arrayList == null || arrayList.size() == 0)
	    return;

	int i = 0;

	for(SipHashIdElement sipHashIdElement : arrayList)
	{
	    if(sipHashIdElement == null)
		continue;

	    TableRow row = new TableRow(Settings.this);
	    TableRow.LayoutParams layoutParams = new
		TableRow.LayoutParams(TableRow.LayoutParams.WRAP_CONTENT);

	    row.setLayoutParams(layoutParams);

	    for(int j = 0; j < 4; j++)
	    {
		TextView textView = new TextView(Settings.this);

		textView.setId(sipHashIdElement.m_oid);

		switch(j)
		{
                case 0:
		    textView.setGravity(Gravity.CENTER_VERTICAL);
		    textView.setLayoutParams
			(new TableRow.LayoutParams(0,
						   LayoutParams.MATCH_PARENT,
						   1));
                    textView.setText(sipHashIdElement.m_name);
                    break;
                case 1:
                    if(sipHashIdElement.m_epksCompleted &&
		       sipHashIdElement.m_keysSigned)
                        textView.setCompoundDrawablesWithIntrinsicBounds
			    (R.drawable.keys_signed, 0, 0, 0);
                    else if(sipHashIdElement.m_epksCompleted)
                        textView.setCompoundDrawablesWithIntrinsicBounds
			    (R.drawable.keys_not_signed, 0, 0, 0);
                    else
                        textView.setCompoundDrawablesWithIntrinsicBounds
			    (R.drawable.warning, 0, 0, 0);

                    textView.setCompoundDrawablePadding(5);
		    textView.setGravity(Gravity.CENTER_VERTICAL);
                    textView.setText(sipHashIdElement.m_sipHashId);
                    break;
                case 2:
                    textView.append
			(String.valueOf(sipHashIdElement.m_outMessages));
                    textView.append(" / ");
                    textView.append
			(String.valueOf(sipHashIdElement.m_inMessages));
                    textView.append(" / ");
                    textView.append
			(String.valueOf(sipHashIdElement.m_totalMessages));
		    textView.setGravity(Gravity.CENTER);
		    textView.setLayoutParams
			(new TableRow.LayoutParams(0,
						   LayoutParams.MATCH_PARENT,
						   1));
                    break;
		default:
		    textView.setGravity(Gravity.CENTER_VERTICAL);
		    textView.setLayoutParams
			(new TableRow.LayoutParams(0,
						   LayoutParams.MATCH_PARENT,
						   1));
		    textView.setText(sipHashIdElement.m_timestamp);
		    break;
		}

		if(j == 0 || j == 1)
		    textView.setTag(textView.getText());
		else
		    textView.setTag(sipHashIdElement.m_name);

		textView.setTextSize(TEXTVIEW_TEXT_SIZE);
		registerForContextMenu(textView);
		row.addView(textView);
	    }

	    tableLayout.addView(row, i);
	    i += 1;
	}

	arrayList.clear();
    }

    private void prepareCredentials()
    {
	if(Settings.this.isFinishing())
	    return;

	final ProgressDialog dialog = new ProgressDialog(Settings.this);
	final Spinner spinner1 = (Spinner) findViewById(R.id.iteration_count);
	final TextView textView1 = (TextView) findViewById
	    (R.id.password1);
	final TextView textView2 = (TextView) findViewById
	    (R.id.password2);
	int iterationCount = 1000;

	try
	{
	    iterationCount = Integer.parseInt
		(spinner1.getSelectedItem().toString());
	}
	catch(Exception exception)
	{
	    iterationCount = 1000;
	}

	dialog.setCancelable(false);
	dialog.setIndeterminate(true);
	dialog.setMessage
	    ("Generating confidential material. Please be patient and " +
	     "do not rotate the device while the process executes.");
	dialog.show();

	class SingleShot implements Runnable
	{
	    private String m_error = "";
	    private String m_password = "";
	    private int m_iterationCount = 1000;

	    SingleShot(String password,
		       int iterationCount)
	    {
		m_iterationCount = iterationCount;
		m_password = password;
	    }

	    @Override
	    public void run()
	    {
		SecretKey encryptionKey = null;
		SecretKey macKey = null;
		byte encryptionSalt[] = null;
		byte macSalt[] = null;

		try
		{
		    encryptionSalt = Cryptography.randomBytes(32);
		    encryptionKey = Cryptography.
			generateEncryptionKey
			(encryptionSalt,
			 m_password.toCharArray(),
			 m_iterationCount);

		    if(encryptionSalt == null)
		    {
			m_error = "generateEncryptionKey() failure";
			s_cryptography.reset();
			return;
		    }

		    macSalt = Cryptography.randomBytes(64);
		    macKey = Cryptography.generateMacKey
			(macSalt,
			 m_password.toCharArray(),
			 m_iterationCount);

		    if(macKey == null)
		    {
			m_error = "generateMacKey() failure";
			s_cryptography.reset();
			return;
		    }

		    /*
		    ** Prepare the Cryptography object's data.
		    */

		    s_cryptography.setEncryptionKey
			(encryptionKey);
		    s_cryptography.setMacKey(macKey);

		    /*
		    ** Record the data.
		    */

		    m_databaseHelper.writeSetting
			(null,
			 "encryptionSalt",
			 Base64.encodeToString(encryptionSalt,
					       Base64.DEFAULT));
		    m_databaseHelper.writeSetting
			(null,
			 "iterationCount",
			 String.valueOf(m_iterationCount));
		    m_databaseHelper.writeSetting
			(null,
			 "macSalt",
			 Base64.encodeToString(macSalt,
					       Base64.DEFAULT));

		    byte saltedPassword[] = Cryptography.
			sha512(m_password.getBytes(),
			       encryptionSalt,
			       macSalt);

		    if(saltedPassword != null)
			m_databaseHelper.writeSetting
			    (null,
			     "saltedPassword",
			     Base64.encodeToString(saltedPassword,
						   Base64.DEFAULT));
		    else
		    {
			m_error = "sha512() failure";
			s_cryptography.reset();
		    }
		}
		catch(Exception exception)
		{
		    m_error = exception.getMessage().toLowerCase().trim();
		    s_cryptography.reset();
		}

		Settings.this.runOnUiThread(new Runnable()
		{
		    @Override
		    public void run()
		    {
			try
			{
			    dialog.dismiss();

			    if(!m_error.isEmpty())
				Miscellaneous.showErrorDialog
				    (Settings.this,
				     "An error (" + m_error +
				     ") occurred while " +
				     "generating the confidential " +
				     "data.");
			    else
			    {
				Settings.this.enableWidgets(true);
				State.getInstance().setAuthenticated(true);
				textView1.requestFocus();
				textView1.setText("");
				textView2.setText("");
				populateOzoneAddresses();
				populateParticipants();
				startKernel();

				if(m_databaseHelper.
				   readSetting(null,
					       "automatic_listeners_refresh").
				   equals("true"))
				    startListenersTimers();
				else
				    populateListeners(null);

				if(m_databaseHelper.
				   readSetting(null,
					       "automatic_neighbors_refresh").
				   equals("true"))
				    startNeighborsTimers();
				else
				    populateNeighbors(null);
			    }
			}
			catch(Exception exception)
			{
			}
		    }
		});

		m_password = "";
	    }
	}

	Thread thread = new Thread
	    (new SingleShot(textView1.getText().toString(),
			    iterationCount));

	thread.start();
    }

    private void prepareListenerIpAddress()
    {
	RadioGroup radioGroup1 = (RadioGroup) findViewById
	    (R.id.listeners_ipv_radio_group);
	TextView textView1 = (TextView) findViewById(R.id.listeners_ip_address);

	try
	{
	    boolean found = false;

	    for(Enumeration<NetworkInterface> enumeration1 = NetworkInterface.
		    getNetworkInterfaces(); enumeration1.hasMoreElements();)
	    {
		if(found)
		    break;

		NetworkInterface networkInterface = enumeration1.nextElement();

		for(Enumeration<InetAddress> enumeration2 = networkInterface.
			getInetAddresses(); enumeration2.hasMoreElements();)
		{
		    InetAddress inetAddress = enumeration2.nextElement();

		    if(!inetAddress.isLoopbackAddress())
		    {
			if(radioGroup1.getCheckedRadioButtonId() ==
			   R.id.listeners_ipv4)
			{
			    if(inetAddress instanceof Inet4Address)
			    {
				found = true;
				textView1.setText
				    (inetAddress.getHostAddress());
				break;
			    }
			}
			else
			{
			    if(inetAddress instanceof Inet6Address)
			    {
				found = true;
				textView1.setText
				    (inetAddress.getHostAddress());
				break;
			    }
			}
		    }
		}
	    }
	}
	catch(Exception exception)
	{
	    textView1.setText("");
	}
    }

    private void prepareListeners()
    {
	if(Settings.this.isFinishing())
	    return;

	Button button1 = null;
	Spinner spinner1 = (Spinner) findViewById(R.id.neighbors_transport);

	button1 = (Button) findViewById(R.id.add_listener);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		addListener();
	    }
        });

	button1 = (Button) findViewById(R.id.add_neighbor);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		addNeighbor();
	    }
        });

	button1 = (Button) findViewById(R.id.add_participant);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		addParticipant();
	    }
        });

	button1 = (Button) findViewById(R.id.clear_log);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		m_databaseHelper.clearTable("log");
	    }
	});

	button1 = (Button) findViewById(R.id.refresh_listeners);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		populateListeners(null);
	    }
        });

	button1 = (Button) findViewById(R.id.refresh_neighbors);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		populateNeighbors(null);
	    }
        });

	button1 = (Button) findViewById(R.id.refresh_ozones);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		populateOzoneAddresses();
	    }
        });

	button1 = (Button) findViewById(R.id.refresh_participants);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		populateParticipants();
	    }
        });

	final DialogInterface.OnCancelListener listener1 =
	    new DialogInterface.OnCancelListener()
	{
	    public void onCancel(DialogInterface dialog)
	    {
		if(State.getInstance().getString("dialog_accepted").
		   equals("true"))
		{
		    State.getInstance().reset();
		    m_databaseHelper.resetAndDrop();
		    s_cryptography.reset();

		    Intent intent = getIntent();

		    startActivity(intent);
		    finish();
		}
	    }
	};

	button1 = (Button) findViewById(R.id.reset);
        button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		Miscellaneous.showPromptDialog
		    (Settings.this,
		     listener1,
		     "Are you sure that you " +
		     "wish to reset SmokeStack? All " +
		     "of the data will be removed.");
	    }
	});

	button1 = (Button) findViewById(R.id.reset_listener_fields);
        button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		CheckBox checkBox1 = (CheckBox) findViewById
		    (R.id.private_server);
		RadioButton radioButton1 = (RadioButton) findViewById
		    (R.id.listeners_ipv4);
		TextView textView1 = (TextView) findViewById
		    (R.id.listeners_ip_address);
		TextView textView2 = (TextView) findViewById
		    (R.id.listeners_port);
		TextView textView3 = (TextView) findViewById
		    (R.id.listeners_scope_id);

		checkBox1.setChecked(false);
		radioButton1.setChecked(true);
		textView1.setText("");
		textView2.setText("4710");
		textView3.setText("");
		textView1.requestFocus();
		prepareListenerIpAddress();
	    }
	});

	button1 = (Button) findViewById(R.id.reset_neighbor_fields);
        button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		RadioButton radioButton1 = (RadioButton) findViewById
		    (R.id.neighbors_ipv4);
		Spinner spinner1 = (Spinner) findViewById
		    (R.id.neighbors_transport);
		Spinner spinner2 = (Spinner) findViewById
		    (R.id.proxy_type);
		TextView proxyIpAddress = (TextView) findViewById
		    (R.id.proxy_ip_address);
		TextView proxyPort = (TextView) findViewById
		    (R.id.proxy_port);
		TextView textView1 = (TextView) findViewById
		    (R.id.neighbors_ip_address);
		TextView textView2 = (TextView) findViewById
		    (R.id.neighbors_port);
		TextView textView3 = (TextView) findViewById
		    (R.id.neighbors_scope_id);

		proxyIpAddress.setText("");
		proxyPort.setText("");
		radioButton1.setChecked(true);
		spinner1.setSelection(0);
		spinner2.setSelection(0);
		textView1.setText("");
		textView2.setText("4710");
		textView3.setText("");
		textView1.requestFocus();
	    }
	});

	button1 = (Button) findViewById(R.id.reset_participants_fields);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		CheckBox checkBox1 = (CheckBox) findViewById
		    (R.id.accept_without_signatures);
		TextView textView1 = (TextView) findViewById
		    (R.id.participant_name);
		TextView textView2 = (TextView) findViewById
		    (R.id.participant_siphash_id);

		checkBox1.setChecked(false);
		textView1.setText("");
		textView2.setText("");
		textView1.requestFocus();
	    }
	});

	button1 = (Button) findViewById(R.id.save_ozone);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		TextView textView = (TextView) findViewById(R.id.ozone);

		if(!generateOzone(textView.getText().toString()))
		{
		    Miscellaneous.showErrorDialog
			(Settings.this,
			 "An error occurred while processing the " +
			 "Ozone data. Perhaps a value should be provided.");
		    textView.requestFocus();
		}
		else
		{
		    Kernel.getInstance().populateOzones();
		    populateOzoneAddresses();
		}
	    }
	});

	final DialogInterface.OnCancelListener listener2 =
	    new DialogInterface.OnCancelListener()
	{
	    public void onCancel(DialogInterface dialog)
	    {
		if(State.getInstance().getString("dialog_accepted").
		   equals("true"))
		{
		    m_databaseHelper.reset();
		    Kernel.getInstance().populateOzones();
		    Kernel.getInstance().populateSipHashIds();
		    populateListeners(null);
		    populateNeighbors(null);
		    populateOzoneAddresses();
		    populateParticipants();
		    prepareCredentials();
		}
	    }
	};

	button1 = (Button) findViewById(R.id.set_password);
        button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		TextView textView1 = (TextView) findViewById(R.id.password1);
		TextView textView2 = (TextView) findViewById(R.id.password2);

		textView1.setSelectAllOnFocus(true);
		textView2.setSelectAllOnFocus(true);

		if(textView1.getText().length() < MINIMUM_PASSWORD_LENGTH ||
		   !textView1.getText().toString().
		   equals(textView2.getText().toString()))
		{
		    String error = "";

		    if(textView1.getText().length() < MINIMUM_PASSWORD_LENGTH)
			error = "Each password must contain " +
			    "at least " +
			    MINIMUM_PASSWORD_LENGTH_TEXT +
			    " characters.";
		    else
			error = "The provided passwords are not identical.";

		    Miscellaneous.showErrorDialog(Settings.this, error);
		    textView1.requestFocus();
		    return;
		}

		int iterationCount = 1000;

		try
		{
		    final Spinner spinner1 = (Spinner) findViewById
			(R.id.iteration_count);

		    iterationCount = Integer.parseInt
			(spinner1.getSelectedItem().toString());
		}
		catch(Exception exception)
		{
		    iterationCount = 1000;
		}

		if(iterationCount > 7500)
		    Miscellaneous.showPromptDialog
			(Settings.this,
			 listener2,
			 "You have selected an elevated iteration count. " +
			 "If you proceed, the initialization process may " +
			 "require a significant amount of time to complete. " +
			 "Continue?");
		else
		    prepareCredentials();
	    }
	});

	button1 = (Button) findViewById(R.id.siphash_help);
	button1.setOnClickListener(new View.OnClickListener()
	{
	    public void onClick(View view)
	    {
		if(Settings.this.isFinishing())
		    return;

		PopupWindow popupWindow = new PopupWindow(Settings.this);
		TextView textView = new TextView(Settings.this);
		float density = getApplicationContext().getResources().
		    getDisplayMetrics().density;

		textView.setBackgroundColor(Color.rgb(232, 234, 246));
		textView.setPaddingRelative
		    ((int) (10 * density),
		     (int) (10 * density),
		     (int) (10 * density),
		     (int) (10 * density));
		textView.setText
		    ("A Smoke ID is a sequence of digits and " +
		     "letters assigned to a specific subscriber " +
		     "(public key pair). " +
		     "The tokens allow participants to exchange public " +
		     "key pairs via the EPKS protocol. " +
		     "An example Smoke ID is ABAB-0101-CDCD-0202.");
		textView.setTextSize(16);
		popupWindow.setContentView(textView);
		popupWindow.setOutsideTouchable(true);

		if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
		{
		    popupWindow.setHeight(450);
		    popupWindow.setWidth(700);
		}

		popupWindow.showAsDropDown(view);
	    }
	});

	CheckBox checkBox1 = null;

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_listeners);
	checkBox1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    if(isChecked)
		    {
			m_databaseHelper.writeSetting
			    (null, "automatic_listeners_refresh", "true");
			startListenersTimers();
		    }
		    else
		    {
			m_databaseHelper.writeSetting
			    (null, "automatic_listeners_refresh", "false");
			stopListenersTimers();
		    }
		}
	    });

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_neighbors);
	checkBox1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    if(isChecked)
		    {
			m_databaseHelper.writeSetting
			    (null, "automatic_neighbors_refresh", "true");
			startNeighborsTimers();
		    }
		    else
		    {
			m_databaseHelper.writeSetting
			    (null, "automatic_neighbors_refresh", "false");
			stopNeighborsTimers();
		    }
		}
	    });

	checkBox1 = (CheckBox) findViewById(R.id.neighbor_details);
	checkBox1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    if(isChecked)
			m_databaseHelper.writeSetting
			    (null, "neighbors_details", "true");
		    else
			m_databaseHelper.writeSetting
			    (null, "neighbors_details", "false");

		    CheckBox checkBox = (CheckBox) findViewById
			(R.id.automatic_refresh_neighbors);

		    if(!checkBox.isChecked())
			populateNeighbors(null);
		}
	    });

	checkBox1 = (CheckBox) findViewById(R.id.overwrite);
	checkBox1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    Button button = (Button) findViewById
			(R.id.set_password);

		    button.setEnabled(isChecked);
		}
	    });

	checkBox1 = (CheckBox) findViewById(R.id.prefer_active_screen);
	checkBox1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    if(isChecked)
		    {
			getWindow().addFlags
			    (WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
			m_databaseHelper.writeSetting
			    (null, "prefer_active_screen", "true");
		    }
		    else
		    {
			getWindow().clearFlags
			    (WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
			m_databaseHelper.writeSetting
			    (null, "prefer_active_screen", "false");
		    }
		}
	    });

	spinner1.setOnItemSelectedListener
	    (new OnItemSelectedListener()
	    {
		@Override
		public void onItemSelected(AdapterView<?> parent,
					   View view,
					   int position,
					   long id)
		{
		    Spinner proxyType = (Spinner)
			findViewById(R.id.proxy_type);
		    TextView proxyIpAddress =
			(TextView) findViewById(R.id.proxy_ip_address);
		    TextView proxyPort = (TextView) findViewById
			(R.id.proxy_port);

		    if(position == 0)
		    {
			/*
			** Events may occur prematurely.
			*/

			boolean isAuthenticated = State.getInstance().
			    isAuthenticated();

			proxyIpAddress.setEnabled(isAuthenticated);
			proxyPort.setEnabled(isAuthenticated);
			proxyType.setEnabled(isAuthenticated);
		    }
		    else
		    {
			proxyIpAddress.setEnabled(false);
			proxyIpAddress.setText("");
			proxyPort.setEnabled(false);
			proxyPort.setText("");
			proxyType.setEnabled(false);
		    }
		}

		@Override
		public void onNothingSelected(AdapterView<?> parent)
		{
		}
	    });
    }

    private void showAuthenticateActivity()
    {
	Intent intent = new Intent(Settings.this, Authenticate.class);

	startActivity(intent);
	finish();
    }

    private void showSteamActivity()
    {
	Intent intent = new Intent(Settings.this, Steam.class);

	startActivity(intent);
	finish();
    }

    private void startGeneralTimer()
    {
	if(m_generalScheduler == null)
	{
	    m_generalScheduler = Executors.newSingleThreadScheduledExecutor();
	    m_generalScheduler.scheduleAtFixedRate(new Runnable()
	    {
		@Override
		public void run()
		{
		    try
		    {
			m_databaseHelper.cleanDanglingMessages();
			m_databaseHelper.cleanDanglingOutboundQueued();
			m_databaseHelper.cleanDanglingParticipants();
			Settings.this.runOnUiThread(new Runnable()
			{
			    @Override
			    public void run()
			    {
				Runtime runtime = Runtime.getRuntime();
				long memory = (runtime.totalMemory() -
					       runtime.freeMemory()) / 1048576L;

				((TextView) findViewById
				 (R.id.database_cursors_closed)).setText
				    (m_databaseHelper.cursorsClosed() +
				     " Database Cursors Closed");
				((TextView) findViewById
				 (R.id.database_cursors_opened)).setText
				    (m_databaseHelper.cursorsOpened() +
				     " Database Cursors Opened");
				((TextView) findViewById(R.id.memory)).setText
				    (memory + " MiB Consumed (JVM)");
			    }
			});
		    }
		    catch(Exception exception)
		    {
		    }
		}
	    }, 0, TIMER_INTERVAL, TimeUnit.MILLISECONDS);
        }
    }

    private void startKernel()
    {
	Kernel.getInstance().populateOzones();
	Kernel.getInstance().populateSipHashIds();
    }

    private void startListenersTimers()
    {
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
			Settings.this.runOnUiThread
			    (new
			     PopulateListeners(m_databaseHelper.
					       readListeners(s_cryptography)));
		    }
		    catch(Exception exception)
		    {
		    }
		}
	    }, 0, TIMER_INTERVAL, TimeUnit.MILLISECONDS);
        }
    }

    private void startNeighborsTimers()
    {
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
			Settings.this.runOnUiThread
			    (new
			     PopulateNeighbors(m_databaseHelper.
					       readNeighbors(s_cryptography)));
		    }
		    catch(Exception exception)
		    {
		    }
		}
	    }, 0, TIMER_INTERVAL, TimeUnit.MILLISECONDS);
        }
    }

    private void stopListenersTimers()
    {
	if(m_listenersScheduler == null)
	    return;

	try
	{
	    m_listenersScheduler.shutdown();
	}
	catch(Exception exception)
	{
	}

	try
	{
	    if(!m_listenersScheduler.awaitTermination(60, TimeUnit.SECONDS))
		m_listenersScheduler.shutdownNow();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_listenersScheduler = null;
	}
    }

    private void stopNeighborsTimers()
    {
	if(m_neighborsScheduler == null)
	    return;

	try
	{
	    m_neighborsScheduler.shutdown();
	}
	catch(Exception exception)
	{
	}

	try
	{
	    if(!m_neighborsScheduler.awaitTermination(60, TimeUnit.SECONDS))
		m_neighborsScheduler.shutdownNow();
	}
	catch(Exception exception)
	{
	}
	finally
	{
	    m_neighborsScheduler = null;
	}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
	super.onCreate(savedInstanceState);
	SmokeStackService.startForegroundTask(getApplicationContext());
	m_databaseHelper = Database.getInstance(getApplicationContext());
	m_receiver = new SettingsBroadcastReceiver();
        setContentView(R.layout.activity_settings);

	boolean isAuthenticated = State.getInstance().isAuthenticated();
        Button button1 = null;

	button1 = (Button) findViewById(R.id.add_listener);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.add_neighbor);
        button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.add_participant);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.refresh_listeners);
	button1.setEnabled(isAuthenticated);
        button1 = (Button) findViewById(R.id.refresh_neighbors);
        button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.refresh_ozones);
        button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.refresh_participants);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.reset_listener_fields);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.reset_neighbor_fields);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.reset_participants_fields);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.save_ozone);
	button1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.siphash_help);
	button1.setCompoundDrawablesWithIntrinsicBounds
	    (R.drawable.help, 0, 0, 0);

	CheckBox checkBox1 = null;

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_listeners);

	if(m_databaseHelper.
	   readSetting(null, "automatic_listeners_refresh").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_neighbors);

	if(m_databaseHelper.
	   readSetting(null, "automatic_neighbors_refresh").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.neighbor_details);

	if(m_databaseHelper.
	   readSetting(null, "neighbors_details").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.prefer_active_screen);

	if(m_databaseHelper.
	   readSetting(null, "prefer_active_screen").equals("true"))
	{
	    checkBox1.setChecked(true);
	    getWindow().addFlags
	    (WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
	}
	else
	{
	    checkBox1.setChecked(false);
	    getWindow().clearFlags
		(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
	}

        RadioButton radioButton1 = null;

	radioButton1 = (RadioButton) findViewById(R.id.listeners_ipv4);
	radioButton1.setEnabled(isAuthenticated);
	radioButton1 = (RadioButton) findViewById(R.id.listeners_ipv6);
	radioButton1.setEnabled(isAuthenticated);
	radioButton1 = (RadioButton) findViewById(R.id.neighbors_ipv4);
        radioButton1.setEnabled(isAuthenticated);
        radioButton1 = (RadioButton) findViewById(R.id.neighbors_ipv6);
        radioButton1.setEnabled(isAuthenticated);

	Spinner spinner1 = (Spinner) findViewById(R.id.proxy_type);
        String array[] = new String[]
	{
	    "HTTP", "SOCKS"
	};

	spinner1.setEnabled(isAuthenticated);

	ArrayAdapter<String> arrayAdapter = new ArrayAdapter<>
	    (Settings.this, android.R.layout.simple_spinner_item, array);

        spinner1.setAdapter(arrayAdapter);
        spinner1 = (Spinner) findViewById(R.id.neighbors_transport);
        array = new String[]
	{
	    "TCP", "UDP"
	};
        spinner1.setEnabled(isAuthenticated);
        arrayAdapter = new ArrayAdapter<>
	    (Settings.this, android.R.layout.simple_spinner_item, array);
        spinner1.setAdapter(arrayAdapter);
	array = new String[]
	{
	    "1000", "2500", "5000", "7500", "10000", "12500",
	    "15000", "17500", "20000", "25000", "30000", "35000",
	    "40000", "45000", "50000", "55000", "60000", "65000",
	    "70000", "75000", "85000", "100000", "150000", "250000",
	    "500000", "1000000"
	};
	arrayAdapter = new ArrayAdapter<>
	    (Settings.this, android.R.layout.simple_spinner_item, array);

	int index = arrayAdapter.getPosition
	    (m_databaseHelper.readSetting(null, "iterationCount"));

	spinner1 = (Spinner) findViewById(R.id.iteration_count);
	spinner1.setAdapter(arrayAdapter);

        RadioGroup radioGroup1 = null;

	radioGroup1 = (RadioGroup) findViewById(R.id.listeners_ipv_radio_group);
        radioGroup1.setOnCheckedChangeListener
	    (new RadioGroup.OnCheckedChangeListener()
	{
	    public void onCheckedChanged(RadioGroup group,
					 int checkedId)
	    {
		TextView textView1 = (TextView) findViewById
		    (R.id.listeners_scope_id);

		if(checkedId == R.id.listeners_ipv4)
		{
		    textView1.setEnabled(false);
		    textView1.setText("");
		    textView1 = (TextView) findViewById(R.id.listeners_port);
		    textView1.setNextFocusDownId(R.id.neighbors_ip_address);
		}
		else
		{
		    textView1.setEnabled(true);
		    textView1 = (TextView) findViewById(R.id.listeners_port);
		    textView1.setNextFocusDownId(R.id.listeners_scope_id);
		}

		prepareListenerIpAddress();
	    }
	});

	radioGroup1 = (RadioGroup) findViewById(R.id.neighbors_ipv_radio_group);
        radioGroup1.setOnCheckedChangeListener
	    (new RadioGroup.OnCheckedChangeListener()
	{
	    public void onCheckedChanged(RadioGroup group,
					 int checkedId)
	    {
		TextView textView1 = (TextView) findViewById
		    (R.id.neighbors_scope_id);

		if(checkedId == R.id.neighbors_ipv4)
		{
		    textView1.setEnabled(false);
		    textView1.setText("");
		    textView1 = (TextView) findViewById(R.id.neighbors_port);
		    textView1.setNextFocusDownId(R.id.proxy_ip_address);
		}
		else
		{
		    textView1.setEnabled(true);
		    textView1 = (TextView) findViewById(R.id.neighbors_port);
		    textView1.setNextFocusDownId(R.id.neighbors_scope_id);
		}
	    }
	});

	/*
	** Enable widgets.
	*/

	checkBox1 = (CheckBox) findViewById(R.id.accept_without_signatures);
	checkBox1.setEnabled(isAuthenticated);
	checkBox1 = (CheckBox) findViewById(R.id.overwrite);
	checkBox1.setChecked(!isAuthenticated);
	checkBox1.setEnabled(isAuthenticated);
	button1 = (Button) findViewById(R.id.set_password);
	button1.setEnabled(checkBox1.isChecked());
	checkBox1 = (CheckBox) findViewById(R.id.private_server);
	checkBox1.setEnabled(isAuthenticated);

	TextView textView1 = null;

	textView1 = (TextView) findViewById(R.id.about);
	textView1.setText(About.about());
	textView1 = (TextView) findViewById(R.id.listeners_scope_id);
        textView1.setEnabled(false);
	textView1 = (TextView) findViewById(R.id.neighbors_scope_id);
        textView1.setEnabled(false);
        textView1 = (TextView) findViewById(R.id.listeners_port);
        textView1.setEnabled(isAuthenticated);
	textView1.setFilters(new InputFilter[] { s_portFilter });
        textView1.setText("4710");
        textView1 = (TextView) findViewById(R.id.neighbors_port);
	textView1.setNextFocusDownId(R.id.proxy_ip_address);
        textView1.setEnabled(isAuthenticated);
	textView1.setFilters(new InputFilter[] { s_portFilter });
        textView1.setText("4710");
        textView1 = (TextView) findViewById(R.id.listeners_ip_address);

	if(isAuthenticated)
	    textView1.requestFocus();

	textView1.setEnabled(isAuthenticated);
	textView1 = (TextView) findViewById(R.id.ozone);
	textView1.setEnabled(isAuthenticated);
	textView1 = (TextView) findViewById(R.id.participant_name);
	textView1.setEnabled(isAuthenticated);
	textView1 = (TextView) findViewById(R.id.participant_siphash_id);
	textView1.setEnabled(isAuthenticated);
	textView1.setFilters(new InputFilter[] { new InputFilter.AllCaps(),
						 s_sipHashInputFilter });
	textView1.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS |
			       InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
	textView1 = (TextView) findViewById(R.id.password1);

	if(!isAuthenticated)
	    textView1.requestFocus();

	textView1.setText("");
        textView1 = (TextView) findViewById(R.id.password2);
        textView1.setText("");
	textView1 = (TextView) findViewById(R.id.proxy_ip_address);
	textView1.setEnabled(isAuthenticated);
	textView1 = (TextView) findViewById(R.id.proxy_port);
	textView1.setEnabled(isAuthenticated);
	textView1.setFilters(new InputFilter[] { s_portFilter });
	prepareListeners();

	/*
	** Restore some settings.
	*/

	spinner1 = (Spinner) findViewById(R.id.iteration_count);

	if(index >= 0)
	    spinner1.setSelection(index);
	else
	    spinner1.setSelection(0);

	m_databaseHelper.deleteEchoQueue();
	prepareListenerIpAddress();
	startGeneralTimer();

	if(isAuthenticated)
	{
	    checkBox1 = (CheckBox) findViewById
		(R.id.automatic_refresh_listeners);

	    if(checkBox1.isChecked())
		startListenersTimers();

	    checkBox1 = (CheckBox) findViewById
		(R.id.automatic_refresh_neighbors);

	    if(checkBox1.isChecked())
		startNeighborsTimers();

	    populateListeners(null);
	    populateNeighbors(null);
	    populateOzoneAddresses();
	    populateParticipants();
	    startKernel();
	}
	else
	    ((TextView) findViewById(R.id.internal_neighbors)).setText
		("Internal Neighbors Container Size: 0");

	/*
	** Show the Authenticate activity if an account is present.
	*/

	if(!State.getInstance().isAuthenticated())
	    if(m_databaseHelper.accountPrepared())
		showAuthenticateActivity();
    }

    @Override
    protected void onDestroy()
    {
	super.onDestroy();
	stopListenersTimers();
	stopNeighborsTimers();
    }

    @Override
    public boolean onContextItemSelected(MenuItem menuItem)
    {
	if(menuItem == null)
	    return false;

	final int groupId = menuItem.getGroupId();
	final int itemId = menuItem.getItemId();

	/*
	** Prepare a listener.
	*/

	final DialogInterface.OnCancelListener listener =
	    new DialogInterface.OnCancelListener()
	{
	    public void onCancel(DialogInterface dialog)
	    {
		switch(groupId)
	        {
		case ContextMenuEnumerator.DELETE_OZONE:
		    if(State.getInstance().getString("dialog_accepted").
		       equals("true"))
			if(m_databaseHelper.
			   deleteEntry(String.valueOf(itemId), "ozones"))
			{
			    Kernel.getInstance().populateOzones();
			    populateOzoneAddresses();
			}

		    break;
		case ContextMenuEnumerator.DELETE_ALL_MESSAGES:
		    if(State.getInstance().getString("dialog_accepted").
		       equals("true"))
			if(m_databaseHelper.removeMessages())
			    populateParticipants();

		    break;
		case ContextMenuEnumerator.DELETE_MESSAGES:
		    if(State.getInstance().getString("dialog_accepted").
		       equals("true"))
			if(m_databaseHelper.
			   removeMessages(String.valueOf(itemId)))
			{
			    TableLayout tableLayout = (TableLayout)
				findViewById(R.id.participants);
			    int count = tableLayout.getChildCount();

			    for(int i = 0; i < count; i++)
			    {
				TableRow row = (TableRow) tableLayout.
				    getChildAt(i);

				if(row == null)
				    continue;

				TextView textView = (TextView)
				    row.getChildAt(2);

				if(textView == null)
				    continue;

				if(itemId != textView.getId())
				    continue;

				textView.setText("0 / 0 / 0");
				break;
			    }
			}

		    break;
		case ContextMenuEnumerator.DELETE_PARTICIPANT:
		    if(State.getInstance().getString("dialog_accepted").
		       equals("true"))
			if(m_databaseHelper.
			   deleteOzoneAndSipHashId(String.valueOf(itemId)))
			{
			    Kernel.getInstance().populateOzones();
			    Kernel.getInstance().populateSipHashIds();
			    populateOzoneAddresses();
			    populateParticipants();
			}

		    break;
		case ContextMenuEnumerator.NEW_NAME:
		    String string = State.getInstance().
			getString("settings_participant_name_input");

		    if(m_databaseHelper.
		       writeParticipantName(s_cryptography,
					    string,
					    itemId))
			populateParticipants();

		    State.getInstance().removeKey
			("settings_participant_name_input");
		    break;
		case ContextMenuEnumerator.RESET_RETRIEVAL_STATE:
		    if(State.getInstance().getString("dialog_accepted").
		       equals("true"))
			if(m_databaseHelper.
			   resetRetrievalState(s_cryptography,
					       String.valueOf(itemId)))
			{
			    MessageTotals messageTotals = m_databaseHelper.
				readMessageTotals(String.valueOf(itemId));

			    if(messageTotals != null)
			    {
				TableLayout tableLayout = (TableLayout)
				    findViewById(R.id.participants);
				int count = tableLayout.getChildCount();

				for(int i = 0; i < count; i++)
				{
				    TableRow row = (TableRow) tableLayout.
					getChildAt(i);

				    if(row == null)
					continue;

				    TextView textView = (TextView) row.
					getChildAt(2);

				    if(textView == null)
					continue;

				    if(itemId != textView.getId())
					continue;

				    textView.setText
					(messageTotals.m_outMessages + " / " +
					 messageTotals.m_inMessages + " / " +
					 messageTotals.m_totalMessages);
				    break;
				}
			    }
			}

		    break;
		}
	    }
	};

	/*
	** Regular expression?
	*/

	switch(groupId)
	{
	case ContextMenuEnumerator.DELETE_OZONE:
	    Miscellaneous.showPromptDialog
		(Settings.this,
		 listener,
		 "Are you sure that you " +
		 "wish to delete the Ozone " +
		 menuItem.getTitle().toString().replace("Delete Ozone (", "").
		 replace(")", "") + "?");
	    break;
	case ContextMenuEnumerator.DELETE_ALL_MESSAGES:
	    Miscellaneous.showPromptDialog
		(Settings.this,
		 listener,
		 "Are you sure that you wish to delete all messages?");
	    break;
	case ContextMenuEnumerator.DELETE_MESSAGES:
	    Miscellaneous.showPromptDialog
		(Settings.this,
		 listener,
		 "Are you sure that you " +
		 "wish to delete the messages of participant " +
		 menuItem.getTitle().toString().
		 replace("Delete Messages (", "").
		 replace(")", "") + "?");
	    break;
	case ContextMenuEnumerator.DELETE_PARTICIPANT:
	    Miscellaneous.showPromptDialog
		(Settings.this,
		 listener,
		 "Are you sure that you " +
		 "wish to delete the participant " +
		 menuItem.getTitle().toString().
		 replace("Delete Participant (", "").
		 replace(")", "") + "? If confirmed, the associated Ozone " +
		 "will also be deleted.");
	    break;
	case ContextMenuEnumerator.NEW_NAME:
	    Miscellaneous.showTextInputDialog
		(Settings.this,
		 listener,
		 "Please provide a new name for " +
		 menuItem.getTitle().toString().
		 replace("New Name (", "").
		 replace(")", "") + ".",
		 "Name");
	    break;
	case ContextMenuEnumerator.RESET_RETRIEVAL_STATE:
	    Miscellaneous.showPromptDialog
		(Settings.this,
		 listener,
		 "Are you sure that you " +
		 "wish to reset the messages retrieval state for " +
		 menuItem.getTitle().toString().
		 replace("Reset Retrieval State (", "").
		 replace(")", "") + "?");
	    break;
	case ContextMenuEnumerator.DELETE_LISTENER:
	    if(m_databaseHelper.
	       deleteEntry(String.valueOf(itemId), "listeners"))
	    {
		/*
		** Prepare the kernel's listeners container
		** if a listener was deleted as the OID
		** field may represent a recycled value.
		*/

		Kernel.getInstance().prepareListeners();

		TableLayout tableLayout = (TableLayout)
		    findViewById(R.id.listeners);
		TableRow row = (TableRow) findViewById(itemId);

		tableLayout.removeView(row);
	    }

	    break;
	}

	return true;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        getMenuInflater().inflate(R.menu.settings_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem menuItem)
    {
	int id = menuItem.getItemId();

	if(id == R.id.action_steam)
	{
	    showSteamActivity();
	    return true;
	}

        return super.onOptionsItemSelected(menuItem);
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu)
    {
	boolean isAuthenticated = State.getInstance().isAuthenticated();

	if(!m_databaseHelper.accountPrepared())
	    /*
	    ** The database may have been modified or removed.
	    */

	    isAuthenticated = true;

	menu.findItem(R.id.action_authenticate).setEnabled(!isAuthenticated);
	menu.findItem(R.id.action_steam).setVisible(false);
	return true;
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu,
				    View v,
				    ContextMenuInfo menuInfo)
    {
	if(v == null)
	    return;

	Object tag = v.getTag();

	if(tag != null)
	{
	    super.onCreateContextMenu(menu, v, menuInfo);

	    try
	    {
		if(v.getParent().getParent() == findViewById(R.id.listeners))
		    menu.add(ContextMenuEnumerator.DELETE_LISTENER,
			     v.getId(),
			     0,
			     "Delete Listener (" + tag + ")");
		else if(v.getParent().getParent() == findViewById(R.id.ozones))
		    menu.add(ContextMenuEnumerator.DELETE_OZONE,
			     v.getId(),
			     0,
			     "Delete Ozone (" + tag + ")");
		else
		{
		    menu.add(ContextMenuEnumerator.DELETE_ALL_MESSAGES,
			     v.getId(),
			     0,
			     "Delete All Messages");
		    menu.add(ContextMenuEnumerator.DELETE_MESSAGES,
			     v.getId(),
			     0,
			     "Delete Messages (" + tag + ")");
		    menu.add(ContextMenuEnumerator.DELETE_PARTICIPANT,
			     v.getId(),
			     0,
			     "Delete Participant (" + tag + ")");
		    menu.add(ContextMenuEnumerator.NEW_NAME,
			     v.getId(),
			     0,
			     "New Name (" + tag + ")");
		    menu.add(ContextMenuEnumerator.RESET_RETRIEVAL_STATE,
			     v.getId(),
			     0,
			     "Reset Retrieval State (" + tag + ")");
		}
	    }
	    catch(Exception exception)
	    {
	    }
	}
    }

    @Override
    public void onPause()
    {
	super.onPause();

	if(m_receiverRegistered)
	{
	    LocalBroadcastManager.getInstance(this).unregisterReceiver
		(m_receiver);
	    m_receiverRegistered = false;
	}
    }

    @Override
    public void onRestoreInstanceState(Bundle savedInstanceState)
    {
	/*
	** Empty.
	*/
    }

    @Override
    public void onResume()
    {
	super.onResume();

	CheckBox checkBox1 = null;

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_listeners);

	if(m_databaseHelper.
	   readSetting(null, "automatic_listeners_refresh").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.automatic_refresh_neighbors);

	if(m_databaseHelper.
	   readSetting(null, "automatic_neighbors_refresh").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.neighbor_details);

	if(m_databaseHelper.
	   readSetting(null, "neighbors_details").equals("true"))
	    checkBox1.setChecked(true);
	else
	    checkBox1.setChecked(false);

	checkBox1 = (CheckBox) findViewById(R.id.prefer_active_screen);

	if(m_databaseHelper.
	   readSetting(null, "prefer_active_screen").equals("true"))
	{
	    checkBox1.setChecked(true);
	    getWindow().addFlags
	    (WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
	}
	else
	{
	    checkBox1.setChecked(false);
	    getWindow().clearFlags
		(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
	}

	if(!m_receiverRegistered)
	{
	    IntentFilter intentFilter = new IntentFilter();

	    intentFilter.addAction
		("org.purple.smokestack.populate_ozones_participants");
	    intentFilter.addAction
		("org.purple.smokestack.populate_participants");
	    LocalBroadcastManager.getInstance(this).registerReceiver
		(m_receiver, intentFilter);
	    m_receiverRegistered = true;
	}
    }

    @Override
    public void onStop()
    {
	super.onStop();

	if(m_receiverRegistered)
	{
	    LocalBroadcastManager.getInstance(this).unregisterReceiver
		(m_receiver);
	    m_receiverRegistered = false;
	}
    }
}
