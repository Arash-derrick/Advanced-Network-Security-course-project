import socket
import time




IP ="0.0.0.0"
PORT =53

sock =socket .socket (socket .AF_INET ,socket .SOCK_DGRAM )
sock .bind ((IP ,PORT ))

print ("Slow Upstream DNS listening...")

while True :
    data ,addr =sock .recvfrom (512 )

    time .sleep (0.2 )



    trans_id =data [:2 ]


    flags =b'\x81\x80'
    qdcount =data [4 :6 ]
    ancount =b'\x00\x01'
    nscount =b'\x00\x00'
    arcount =b'\x00\x00'

















    response =trans_id +flags +qdcount +ancount +nscount +arcount



    idx =12
    while data [idx ]!=0 :
        idx +=1
    q_section =data [12 :idx +5 ]

    response +=q_section



    answer =b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x01\x02\x03\x04'

    response +=answer

    sock .sendto (response ,addr )
