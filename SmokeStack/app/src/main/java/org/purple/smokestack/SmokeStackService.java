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

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.os.IBinder;

public class SmokeStackService extends Service
{
    private final static int NOTIFICATION_ID = 796325177;

    @Override
    public IBinder onBind(Intent intent)
    {
	return null;
    }

    private void prepareNotification()
    {
	Intent notificationIntent = new Intent(this, Settings.class);
	Notification.Builder builder = new Notification.Builder(this);
	PendingIntent pendingIntent = PendingIntent.getActivity
	    (this, 0, notificationIntent, 0);

	builder.setContentIntent(pendingIntent);
	builder.setContentText("SmokeStack Activity");
	builder.setContentTitle("SmokeStack Activity");
	builder.setSmallIcon(R.drawable.smokestack);
	builder.setTicker("SmokeStack Activity");

	/*
	** Stop!
	*/

	Intent stopIntent = new Intent(this, SmokeStackService.class);

        stopIntent.setAction("stop");

	PendingIntent pendingStopIntent = PendingIntent.getService
	    (this, 0, stopIntent, 0);

	builder.addAction
	    (new Notification.Action.
	     Builder(Icon.createWithResource(this, R.drawable.smokestack),
		     "Stop SmokeStack Foreground Service",
		     pendingStopIntent).build());
	startForeground(NOTIFICATION_ID, builder.build());
    }

    private void start()
    {
	prepareNotification();
    }

    private void stop()
    {
	stopForeground(true);
	stopSelf();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
	if(intent != null && intent.getAction() != null)
	    switch(intent.getAction())
	    {
	    case "start":
		start();
		break;
	    case "stop":
		stop();
		break;
	    default:
		break;
	    }

	return START_STICKY;
    }

    public static void startForegroundTask(Context context)
    {
	if(context == null)
	    return;

	Intent intent = new Intent(context, SmokeStackService.class);

	intent.setAction("start");
	context.startService(intent);
    }

    public static void stopForegroundTask(Context context)
    {
	if(context == null)
	    return;

	Intent intent = new Intent(context, SmokeStackService.class);

	intent.setAction("stop");
	context.startService(intent);
    }

    @Override
    public void onCreate()
    {
	super.onCreate();
    }
}
