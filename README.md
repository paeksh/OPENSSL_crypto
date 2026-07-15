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

    - part_c.txt를 part B의 개인키 + sha-256으로 서명한다

part D. authorize sign
------------------

    - 학생마다 주어진 sigs/안의 파일 안의 file1.sig, file2.sig, file3.sig을 검증 ->  INVALID/VALID

part E. encryption + HMAC implementation
----------------

    - E에서는 enc와 dec 두개의 mode를 두고 enc에서는 입력 파일 암호화 + HMAC 태그 생성, dec에서는 HMAC 무결성 검증 + 복호화 or 실패 처리를 한다.
    - HMAC : 비밀키, 해시 함수 (sha-256)을 합쳐서 만드는 태그
    - 송신자는 tag = HMAC(key, message)을 계산해 (message, tag) 쌍을 보냄 (enc 에서 구현)
    - 수신자는 받은 message로 HMAC(key, message)를 계산해보고, 결과가 tag와 같으면 변조가 없었다고 판단 (dec 에서 구현)

<코드 설명>

parse_args()

    - 인자가 10개 들어왔는지 검사한다 (여기서 인자의 중복을 방지할수 있다. 하나라도 중복되면 구조체가 다 채워지지 않아서 마지막에 구조체 다 채워졌는지만 검사하면됨)
    - enc, dec 모드를 검사하고 mode에 저장한다
    - 각 파일이름 (-key, -in, -out, -tag)을 검사하고 그 뒤에 오는 파일 이름을 구조체의 각 부분에 저장한다.
    - 파일 이름들은 순서가 상관 없으므로 명령줄 인자의 2, 4, 6, 8번째만 검사하고 저장한다.


read_file()

    - 함수의 인자는 두개 : 읽어들일 파일 이름과 메인에서 미리 정의할 파일의 길이
    - 파일의 크기를 fseek로 구한다. 여기서 fseek는 파일의 끝 (seek_end)로 이동해서 ftell로 사이즈를 저장한다음 다시 파일의 맨 처음으로 돌아온다
    - 그리고 힙에 구한 파일의 크기만큼 메모리를 할당해서 파일의 내용을 fread로 저장함
    - 파일의 길이도 별도로 저장

write_file()

    - 함수의 인자는 세개 : 내용을 쓸 파일 이름과 내용, 그리고 파일의 길이
    - 파일은 wb, 바이너리 쓰기 모드로 연다 (파일을 덮어씀)
    - fwrite로 1바이트를 len개 만큼 쓴다. 
    - 다 쎴다면 1을 반환, 안 썼으면 0을 반환(?????)


main()

    enc 모드
        - key_buf, infile_buf로 키와 입력파일을 읽음
        - 키가 32바이트인지 검증
        - RAND_bytes로 16바이트 랜덤 iv todtjd
        - 암호화 3단계 수행 (AES-256-CBC)
        - HMAC 인증 태그 생성
        - memcpy로 파일 버퍼에 iv 16바이트와 암호문 합쳐서 입력
        - 태그는 별도 파일에 저장

    dec 모드 
        - key_buf와 in_buf로 암호문과 키 파일을 읽음
        - 입력파일 앞의 16비트는 iv, 나머지는 암호문으로 분리
        - 복호화 3단계 수행
        - 복호화된 평문과 키로 HMAC 태그 계산
        - CRYPTO_memcmp 로 계산한 태그와 받은 태그 비교 (타이밍 공격을 방지)
        - 태그 불일치 시 종료, 일치 시 평문을 출력파일에 저장

    
