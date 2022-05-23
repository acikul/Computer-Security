#!/bin/bash

#Compiling
javac UserMgmt.java
javac Login.java

#Dodavanje novog korisničkog imena
echo "add user1 - hint: isprobati mismatched lozinke"
java UserMgmt add user1
echo "add user2"
java UserMgmt add user2
echo "add user3"
java UserMgmt add user3

#Forsiranje promjene lozinke
echo "forcepass user2"
java UserMgmt forcepass user2

#Brisanje korisničkog imena
echo "del user3"
java UserMgmt del user3

#Brisanje nepostojećeg korisničkog imena
echo "del user3"
java UserMgmt del user3

#Login korisnika bez forsiranja
echo "login user1 - hint: prvo pokušati unijeti krivu lozinku"
java Login user1

#Login korisnika s forsiranjem
echo "login user2 - hint: za novu lozinku probati unijeti staru"
java Login user2

#Admin promjena lozinke postojećeg korisnika
echo "passwd change user1"
java UserMgmt passwd user1

#Login korisnika nakon adminove promjene lozinke
echo "login user1"
java Login user1
