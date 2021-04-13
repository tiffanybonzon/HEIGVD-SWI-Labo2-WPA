#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - Those two aren't picked from the .cap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# Below here are the seven values that we're about to dynamicaly extract from the capture file
# Ref : https://gist.github.com/securitytube/5291959 
for p in wpa:
    handshake = []
    if p.haslayer(Dot11): 
        # SSID and the MAC of both the client and the AP
        if p.type == 0 and p.subtype == 0 :
            ssid        = p.info.decode('ascii')
            APmac       = a2b_hex(p.addr1.replace(':', ''))
            Clientmac   = a2b_hex(p.addr2.replace(':', ''))
    elif p.haslayer(WPA_key):
        print("New packet was added !")
        handshake.append(p)

print("The length is : " + len(handshake))

if len(handshake) != 4:
    print("The .cap is missing some handshake parts ! :(")
else:
    # Authenticator and Supplicant Nonces 
    ANonce = handshake[0].nonce
    SNonce = handshake[1].nonce

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    mic_to_test = handshake[3].wpa_key_mic
    handshake[3].wpa_key_mic = 0x00 # Set to 0 based on the "Quelques éléments à considérer" :D

    data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

    # Nothing to change regarding how B is computed -- No changes overall below
    B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    print ("\n\nValues used to derivate keys")
    print ("============================")
    print ("Passphrase: ",passPhrase,"\n")
    print ("SSID: ",ssid,"\n")
    print ("AP Mac: ",b2a_hex(APmac),"\n")
    print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
    print ("AP Nonce: ",b2a_hex(ANonce),"\n")
    print ("Client Nonce: ",b2a_hex(SNonce),"\n")

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    ssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    print ("\nResults of the key expansion")
    print ("=============================")
    print ("PMK:\t\t",pmk.hex(),"\n")
    print ("PTK:\t\t",ptk.hex(),"\n")
    print ("KCK:\t\t",ptk[0:16].hex(),"\n")
    print ("KEK:\t\t",ptk[16:32].hex(),"\n")
    print ("TK:\t\t",ptk[32:48].hex(),"\n")
    print ("MICK:\t\t",ptk[48:64].hex(),"\n")
    print ("MIC:\t\t",mic.hexdigest(),"\n")
