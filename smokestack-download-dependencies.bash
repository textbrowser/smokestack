#!/bin/bash

# Must be executed in the top-level source directory.

# Bouncy Castle

bouncycastle1=bcpkix-jdk15on-165.jar
bouncycastle2=bcpkix-jdk15on-165.tar.gz
bouncycastle3=bcprov-ext-jdk15on-165.jar
bouncycastle4=bcprov-jdk15on-165.tar.gz

rm -f $bouncycastle1
rm -f $bouncycastle2
rm -f $bouncycastle3
rm -f $bouncycastle4
wget --progress=bar https://bouncycastle.org/download/$bouncycastle1
wget --progress=bar https://bouncycastle.org/download/$bouncycastle2
wget --progress=bar https://bouncycastle.org/download/$bouncycastle3
wget --progress=bar https://bouncycastle.org/download/$bouncycastle4

if [ -r "$bouncycastle1" ]; then
    mv $bouncycastle1 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle1."
fi

if [ -r "$bouncycastle2" ]; then
    mv $bouncycastle2 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle2."
fi

if [ -r "$bouncycastle3" ]; then
    mv $bouncycastle3 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle3."
fi

if [ -r "$bouncycastle4" ]; then
    mv $bouncycastle4 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle4."
fi

echo "Please review SmokeStack/app/build.gradle!" 
