#!/bin/sh
javac VulnerableApp.java

echo
echo Testing safely
echo --------------
echo

java -cp /usr/share/java/hsqldb2.0-2.0.0.jar:. VulnerableApp admin 0

echo
echo Testing with SQL injection
echo --------------------------
echo
java -cp /usr/share/java/hsqldb2.0-2.0.0.jar:. VulnerableApp "admin';insert into appusers values('mallory',1,'mwa ha ha');select 1 from Appusers;--" 0

echo
echo Patching
echo --------
echo

java -jar SQLInject/dist/SQLInject.jar VulnerableApp.class
cp VulnerableApp.class VulnerableApp.class.old
cp VulnerableApp.class.new VulnerableApp.class

echo
echo Testing safely
echo --------------
echo

java -cp /usr/share/java/hsqldb2.0-2.0.0.jar:. VulnerableApp admin 0


echo
echo Testing with SQL injection
echo --------------------------
echo
java -cp /usr/share/java/hsqldb2.0-2.0.0.jar:. VulnerableApp "admin';insert into appusers values('jim',1,'password');select 1 from Appusers;--" 0
