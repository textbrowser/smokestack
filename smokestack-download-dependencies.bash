#!/bin/bash

# Must be executed in the top-level source directory.

# Bouncy Castle

bouncycastle1=bcpkix-jdk15on-165.jar
bouncycastle2=bcpkix-jdk15on-165.tar.gz
bouncycastle3=bcprov-ext-jdk15on-165.jar
bouncycastle4=bcprov-jdk15on-165.tar.gz

wget --progress=bar https://bouncycastle.org/download/$bouncycastle1
wget --progress=bar https://bouncycastle.org/download/$bouncycastle2
wget --progress=bar https://bouncycastle.org/download/$bouncycastle3
wget --progress=bar https://bouncycastle.org/download/$bouncycastle4
mv $bouncycastle1 SmokeStack/app/libs/.
mv $bouncycastle2 SmokeStack/app/libs/.
mv $bouncycastle3 SmokeStack/app/libs/.
mv $bouncycastle4 SmokeStack/app/libs/.
echo "Please review SmokeStack/app/build.gradle!" 
