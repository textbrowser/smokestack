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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class About
{
    private static String s_about = "";

    private About()
    {
    }

    public static synchronized String about()
    {
	// The versions must agree with SmokeStack/app/build.gradle.

	try
	{
	    if(s_about.isEmpty())
	    {
		SimpleDateFormat simpleDateFormat = new
		    SimpleDateFormat("yyyy-MM-dd h:mm:ss", Locale.getDefault());

		simpleDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		s_about = "Bouncy Castle Version " +
		    new BouncyCastleProvider().getVersion() +
		    "\nSmokeStack Version 2022.04.01 Stack Smash (Final) " +
		    (BuildConfig.DEBUG ? "(Debug) " : "(Release)") +
		    "\nBuild Date " +
		    simpleDateFormat.format(new Date(BuildConfig.BUILD_TIME)) +
		    " UTC\nAndroid " + Build.VERSION.RELEASE +
		    (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP ?
		     "\nAndroid version not supported." : "");
	    }
	}
	catch(Exception exception)
	{
	    if(s_about.isEmpty())
		s_about = "SmokeStack Version 2022.04.01 Stack Smash (Final)";
	}

	return s_about;
    }
}
