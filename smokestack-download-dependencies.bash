#!/bin/bash

# Must be executed in the top-level source directory.

# Bouncy Castle

bouncycastle1=bcpkix-jdk15on-165.jar
bouncycastle2=bcprov-ext-jdk15on-165.jar

wget --progress=bar https://bouncycastle.org/download/$bouncycastle1
wget --progress=bar https://bouncycastle.org/download/$bouncycastle2
mv $bouncycastle1 SmokeStack/app/libs/.
mv $bouncycastle2 SmokeStack/app/libs/.
