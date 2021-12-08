#!/bin/bash
# Alexis Megas.

# Must be executed in the top-level source directory.

# Bouncy Castle

bouncycastle1=bcpkix-jdk15on-168.jar
bouncycastle2=bcprov-ext-jdk15on-168.jar

rm -f $bouncycastle1
rm -f $bouncycastle2
wget --progress=bar https://bouncycastle.org/download/$bouncycastle1
wget --progress=bar https://bouncycastle.org/download/$bouncycastle2

if [ -r "$bouncycastle1" ]; then
    mkdir -p SmokeStack/app/libs
    mv $bouncycastle1 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle1."
fi

if [ -r "$bouncycastle2" ]; then
    mkdir -p SmokeStack/app/libs
    mv $bouncycastle2 SmokeStack/app/libs/.
else
    echo "Cannot read $bouncycastle2."
fi

echo "Please review SmokeStack/app/build.gradle and SmokeStack/app/libs!"
