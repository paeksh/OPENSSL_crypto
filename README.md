Computer Security hw3 - cryptography with OPENSSL
===============

part A. symmetric cryptography
-----------------

openssl enc -aes256 -in part_a.txt -out part_a.ctxt

    - part_a.txt를 openssl의 -aes256으로 암호화하여 part_a.ctxt를 생성한다 
    - AES에서는 128비트 데이터를 10개의 라운드를 거쳐 암호화함
        1. subbytes : 각 비트를 s-box으로 대체
        2. shift rows : 2번째 행을 <, 3번째 행을 <<, 4번째 행을 <<<
        3. mix columns : 각 열을 c(x)와 xor 연산
        4. AddRoundKey : 내가 정한 키와 XOR 연산
    - 내가 입력한 password + salt (랜덤 8바이트) -> KDF(변형을 통해 256비트의 키를 만듦) -> 256 bit AES key

part B. asymmetric cryptography
----------------

    - 2048 비트 RSA 키 쌍을 생성한다.
    - RSA는 임의의 소수 p, q를 설정하여 소인수 분해 문제를 기반으로 하여 공개키, 개인키를 생성한다.
    - 개인키는 -aes256으로 암호화해 보관한다.
    - 생성된 part_b.pem은 공개키이다. 

part C. generate sign
----------------
    