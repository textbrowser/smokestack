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

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.text.InputType;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Switch;
import java.nio.ByteBuffer;
import java.text.DecimalFormat;

public abstract class Miscellaneous
{
    public static final int INTEGER_BYTES = 4;
    public static final int LONG_BYTES = 8;
    public static final long LONG_LONG_BYTES = 8L;

    public static String byteArrayAsHexString(byte[] bytes)
    {
	if(bytes == null || bytes.length == 0)
	    return "";

	try
	{
	    StringBuilder stringBuilder = new StringBuilder();

	    for(byte b : bytes)
		stringBuilder.append(String.format("%02x", b));

	    return stringBuilder.toString();
	}
	catch(Exception exception)
	{
	    return "";
	}
    }

    public static String byteArrayAsHexStringDelimited(byte[] bytes,
						       char delimiter,
						       int offset)
    {
	if(bytes == null || bytes.length == 0 || offset < 0)
	    return "";

	String string = byteArrayAsHexString(bytes);

	try
	{
	    StringBuilder stringBuilder = new StringBuilder();
	    int length = string.length();

	    for(int i = 0; i < length; i += offset)
	    {
		if(i < length - offset)
		    stringBuilder.append(string, i, i + offset);
		else
		    stringBuilder.append(string.substring(i));

		stringBuilder.append(delimiter);
	    }

	    if(stringBuilder.length() > 0 &&
	       stringBuilder.charAt(stringBuilder.length() - 1) == delimiter)
		return stringBuilder.substring(0, stringBuilder.length() - 1);
	    else
		return stringBuilder.toString();
	}
	catch(Exception exception)
	{
	    return "";
	}
    }

    public static String delimitString(String string,
				       char delimiter,
				       int offset)
    {
	if(offset < 0)
	    return "";

	try
	{
	    StringBuilder stringBuilder = new StringBuilder();
	    int length = string.length();

	    for(int i = 0; i < length; i += offset)
	    {
		if(i < length - offset)
		    stringBuilder.append(string, i, i + offset);
		else
		    stringBuilder.append(string.substring(i));

		stringBuilder.append(delimiter);
	    }

	    if(stringBuilder.length() > 0 &&
	       stringBuilder.charAt(stringBuilder.length() - 1) == delimiter)
		return stringBuilder.substring(0, stringBuilder.length() - 1);
	    else
		return stringBuilder.toString();
	}
	catch(Exception exception)
	{
	    return "";
	}
    }

    public static String formattedDigitalInformation(String bytes)
    {
	try
	{
	    DecimalFormat decimalFormat = new DecimalFormat("0.00");
	    StringBuilder stringBuilder = new StringBuilder();
	    long v = Integer.decode(bytes).longValue();

	    if(v < 1024L)
	    {
		stringBuilder.append(decimalFormat.format(v));
		stringBuilder.append(" B");
	    }
	    else if(v < 1048576L)
	    {
		stringBuilder.append(decimalFormat.format(v / 1024.0));
		stringBuilder.append(" KiB");
	    }
	    else if(v < 1073741824L)
	    {
		stringBuilder.append(decimalFormat.format(v / 1048576.0));
		stringBuilder.append(" MiB");
	    }
	    else
	    {
		stringBuilder.append(decimalFormat.format(v / 1073741824.0));
		stringBuilder.append(" GiB");
	    }

	    return stringBuilder.toString();
	}
	catch(Exception exception)
	{
	    return "";
	}
    }

    public static String pemFormat(byte[] bytes)
    {
	if(bytes == null || bytes.length == 0)
	    return "";

	try
	{
	    String string = Base64.encodeToString(bytes, Base64.NO_WRAP);
	    StringBuilder stringBuilder = new StringBuilder();

	    stringBuilder.append("-----BEGIN CERTIFICATE-----\n");

	    int length = string.length();

	    for(int i = 0; i < length; i += 64)
		if(i < length - 64)
		{
		    stringBuilder.append(string, i, i + 64);
		    stringBuilder.append("\n");
		}
		else
		{
		    stringBuilder.append(string.substring(i));
		    stringBuilder.append("\n");
		    break;
		}

	    stringBuilder.append("-----END CERTIFICATE-----\n");
	    return stringBuilder.toString();
	}
	catch(Exception exception)
	{
	    return "";
	}
    }

    public static String sipHashIdFromData(byte[] bytes)
    {
	SipHash sipHash = new SipHash();

	return byteArrayAsHexStringDelimited
	    (longArrayToByteArray(sipHash.
				  hmac(bytes,
				       Cryptography.keyForSipHash(bytes),
				       Cryptography.SIPHASH_OUTPUT_LENGTH)),
	     '-', 4);
    }

    public static byte[] intToByteArray(int value)
    {
	try
	{
	    return ByteBuffer.allocate(INTEGER_BYTES).putInt(value).array();
	}
	catch(Exception exception)
	{
	    return null;
	}
    }

    public static byte[] joinByteArrays(byte[] ... data)
    {
	if(data == null)
	    return null;

	try
	{
	    int length = 0;

	    for(byte[] b : data)
		if(b != null && b.length > 0)
		    length += b.length;

	    if(length == 0)
		return null;

	    byte[] bytes = new byte[length];
	    int i = 0;

	    for(byte[] b : data)
		if(b != null && b.length > 0)
		{
		    System.arraycopy(b, 0, bytes, i, b.length);
		    i += b.length;
		}

	    return bytes; // data[0] + data[1] + ... + data[n - 1]
	}
	catch(Exception exception)
	{
	    return null;
	}
    }

    public static byte[] longArrayToByteArray(long[] value)
    {
	try
	{
	    ByteBuffer byteBuffer = ByteBuffer.allocate
		(LONG_BYTES * value.length);

	    for(long l : value)
		byteBuffer.putLong(l);

	    return byteBuffer.array();
	}
	catch(Exception exception)
	{
	    return null;
	}
    }

    public static byte[] longToByteArray(long value)
    {
	try
	{
	    return ByteBuffer.allocate(LONG_BYTES).putLong(value).array();
	}
	catch(Exception exception)
	{
	    return null;
	}
    }

    public static int countOf(StringBuilder stringBuilder, char character)
    {
	if(stringBuilder == null || stringBuilder.length() == 0)
	    return 0;

	int count = 0;
	int length = stringBuilder.length();

	for(int i = 0; i < length; i++)
	    if(character == stringBuilder.charAt(i))
		count += 1;

	return count;
    }

    public static int byteArrayToInt(byte[] bytes)
    {
	if(bytes == null || bytes.length != INTEGER_BYTES)
	    return 0;

	try
	{
	    ByteBuffer byteBuffer = ByteBuffer.allocate(INTEGER_BYTES);

	    byteBuffer.put(bytes);
	    byteBuffer.flip();
	    return byteBuffer.getInt();
	}
	catch(Exception exception)
	{
	    return 0;
	}
    }

    public static long byteArrayToLong(byte[] bytes)
    {
	if(bytes == null || bytes.length != LONG_BYTES)
	    return 0L;

	try
	{
	    ByteBuffer byteBuffer = ByteBuffer.allocate(LONG_BYTES);

	    byteBuffer.put(bytes);
	    byteBuffer.flip();
	    return byteBuffer.getLong();
	}
	catch(Exception exception)
	{
	    return 0L;
	}
    }

    public static void showErrorDialog(Context context, String error)
    {
	if(((Activity) context).isFinishing())
	    return;

	AlertDialog alertDialog = new AlertDialog.Builder(context).create();

	alertDialog.setButton
	    (AlertDialog.BUTTON_NEUTRAL, "Dismiss",
	     new DialogInterface.OnClickListener()
	     {
		 public void onClick(DialogInterface dialog, int which)
		 {
		     dialog.dismiss();
		 }
	     });
	alertDialog.setMessage(error);
	alertDialog.setTitle("Error");
	alertDialog.show();
    }

    public static void showPromptDialog
	(Context context,
	 DialogInterface.OnCancelListener cancelListener,
	 String prompt)
    {
	if(((Activity) context).isFinishing())
	    return;

	AlertDialog alertDialog = new AlertDialog.Builder(context).create();
	Switch switch1 = new Switch(context);

	State.getInstance().removeKey("dialog_accepted");
	alertDialog.setButton
	    (AlertDialog.BUTTON_NEGATIVE, "No",
	     new DialogInterface.OnClickListener()
	     {
		 public void onClick(DialogInterface dialog, int which)
		 {
		     State.getInstance().removeKey("dialog_accepted");
		     dialog.dismiss();
		 }
	     });
	alertDialog.setButton
	    (AlertDialog.BUTTON_POSITIVE, "Yes",
	     new DialogInterface.OnClickListener()
	     {
		 public void onClick(DialogInterface dialog, int which)
		 {
		     State.getInstance().setString("dialog_accepted", "true");
		     dialog.cancel();
		 }
	     });
	alertDialog.setMessage(prompt);
	alertDialog.setOnCancelListener(cancelListener); /*
							 ** We cannot wait
							 ** for a response.
							 */
	alertDialog.setTitle("Confirmation");
	alertDialog.setView(switch1);
	alertDialog.show();

	final Button button = alertDialog.getButton
	    (AlertDialog.BUTTON_POSITIVE);

	button.setEnabled(false);
	switch1.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
	switch1.setOnCheckedChangeListener
	    (new CompoundButton.OnCheckedChangeListener()
	    {
		@Override
		public void onCheckedChanged
		    (CompoundButton buttonView, boolean isChecked)
		{
		    button.setEnabled(isChecked);
		}
	    });
	switch1.setText("Confirm");
    }

    public static void showTextInputDialog
	(Context context,
	 DialogInterface.OnCancelListener cancelListener,
	 String prompt,
	 String title)
    {
	if(((Activity) context).isFinishing())
	    return;

	AlertDialog alertDialog = new AlertDialog.Builder(context).create();
	final EditText editText = new EditText(context);
	final boolean contextIsSettings = context instanceof Settings;

	alertDialog.setButton
	    (AlertDialog.BUTTON_NEGATIVE, "Cancel",
	     new DialogInterface.OnClickListener()
	     {
		 public void onClick(DialogInterface dialog, int which)
		 {
		     if(contextIsSettings)
			 State.getInstance().removeKey
			     ("settings_participant_name_input");

		     dialog.dismiss();
		 }
	     });
	alertDialog.setButton
	    (AlertDialog.BUTTON_POSITIVE, "Accept",
	     new DialogInterface.OnClickListener()
	     {
		 public void onClick(DialogInterface dialog, int which)
		 {
		     if(contextIsSettings)
			 State.getInstance().setString
			     ("settings_participant_name_input",
			      editText.getText().toString());

		     dialog.cancel();
		 }
	     });
	alertDialog.setMessage(prompt);
	alertDialog.setOnCancelListener(cancelListener); /*
							 ** We cannot wait
							 ** for a response.
							 */
	alertDialog.setTitle(title);
	editText.setInputType(InputType.TYPE_CLASS_TEXT);
	alertDialog.setView(editText);
	alertDialog.show();
    }
}
