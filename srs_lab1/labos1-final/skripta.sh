#!/bin/bash

#Compiling
javac PasswordManager.java

#Inicijalizacija password managera
java PasswordManager init masterPass

#Spremanje zaporke za www.fer.hr
java PasswordManager put masterPass www.fer.hr ferSifra

#Spremanje zaporke za www.google.hr
java PasswordManager put masterPass www.google.hr googleSifra

#Dohvaćanje zaporke za www.fer.hr
java PasswordManager get masterPass www.fer.hr

#Dohvaćanje zaporke za www.google.hr
java PasswordManager get masterPass www.google.hr

#Ažuriranje zaporke za www.fer.hr
java PasswordManager put masterPass www.fer.hr novaFerSifra

#Dohvaćanje nove zaporke za www.fer.hr
java PasswordManager get masterPass www.fer.hr

#Dohvaćanje s krivim master passwordom
java PasswordManager get kriviMasterPass www.fer.hr

#Dohvaćanje za nepostojeću adresu
java PasswordManager get masterPass krivaAdresa