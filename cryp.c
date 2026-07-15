#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define EXIT_OK         0   //성공 : stdout에 아무것도 출력 x
#define EXIT_VERIFY     1   //인증실패
#define EXIT_ERROR      2   //기타 에러

typedef enum{
    MODE_ENC = 1,
    MODE_DEC = 2,
} cryp_mode_t;

typedef struct{
    cryp_mode_t mode; //mode_t 가 먼저 정의되어야 함
    const char *key_file;
    const char *in_file;
    const char *out_file;
    const char *tag_file;
} args_t; 

static void die(void){
    printf("ERROR\n");
    exit(EXIT_ERROR);
}

static void parse_args(int argc, char* argv[], args_t *args){

    if (argc!= 10) die();

    if (strcmp(argv[1], "enc") ==0){
        args->mode = 1;
    } else if (strcmp(argv[1], "dec") == 0){
        args->mode = 0;
    } else{
        die();
    }

    for (int i=0;i<4;i++){
        if (strcmp(argv[2*i+2], "-key")==0){
            args->key_file = argv[2*i+3];
        } 
        else if (strcmp(argv[2*i+2], "-in")==0){
            args->in_file = argv[2*i+3];
        }
        else if(strcmp(argv[2*i+2], "-out")==0 ){
            args->out_file = argv[2*i+3];
        }
        else if (strcmp(argv[2*i+2], "-tag")==0){
            args->tag_file = argv[2*i+3];
        }
    }
    if (!args->key_file || !args->in_file ||
        !args->out_file || !args->tag_file){
            die();
    }
}

unsigned char* read_file(const char* filename, size_t *file_len){
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;

    //파일 크기 구하기
    //끝 (seek_end)로 이동해서 위치를 ftell로 읽으면 그게 총 바이트 수
    fseek(file, 0, SEEK_END); 
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (size<0){
        fclose(file);
        return NULL; //사이즈가 0보다 작을 경우 null 반환
    }

    //힙에 파일 크기만큼 할당
    unsigned char*buf = malloc(size);
    if (!buf){
        fclose(file);
        return NULL;
    }

    fread(buf, 1, size, file);
    fclose(file);

    *file_len = size;
    return buf;
}

static int write_file(const char* filename, const char* data, size_t len){
    FILE* file = fopen(filename, "wb"); // 바이너리 쓰기 모드, 파일을 덮어씀
    if (file==NULL) return 0;

    size_t written = fwrite(data, 1, len, file); //1바이트짜리를 len 개 쓰기
    fclose(file);

    return (written==len); //다 썼으면 1, 아니면 0
}

int main(int argc, char *argv[]){
    args_t args; // 여기서 args는 구조체

    parse_args(argc, argv, &args);

    if (args.mode == MODE_ENC){
        // 암호화 작업 상태를 담을 컨텍스트 구조체를 만들어 포인트를 돌려줌 -> 실패시 null 반환
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
        if(!ctx) die();

        size_t key_len, in_len;
        const char *key_buf = read_file(args.key_file, &key_len);
        const char *infile_buf = read_file(args.in_file, &in_len);
        if (!key_buf||!infile_buf) die();
        if (key_len!=32) die(); //AES-256 키는 32바이트여야 함

        unsigned char iv[16];
        if (!RAND_bytes(iv, sizeof(iv))) die();

        int out_len, final_len; //EncryptUpdate가 자동으로 채워주는 값
        char* out_buf = malloc(in_len+EVP_MAX_BLOCK_LENGTH);
        
        // 암호, 키, IV 설정 (암호화에 쓰일 요소 초기화)
        if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_buf, iv)) die();
        //데이터 조각 암호화 
        if(!EVP_EncryptUpdate(ctx, out_buf, &out_len, infile_buf, in_len)) die();
        if(!EVP_EncryptFinal_ex(ctx, out_buf + out_len, &final_len)) die();

        //전체 암호문 길이
        int message_len = out_len+final_len;
        
        //HMAC 태그 생성
        unsigned char tag[32];
        unsigned int tag_len;
        if(!HMAC(EVP_sha256(), key_buf, key_len, infile_buf, in_len, tag, &tag_len)) die(); //평문으로 hmac

        //out_file, tag_file 에 쓰기
        unsigned char *file_buf = malloc(16 + message_len); //16바이트 iv + 암호문을 쓰기 위한 버퍼
        if (!file_buf) die();
        
        //인자 : (목적지, 출처, 길이)
        memcpy(file_buf, iv, 16); //iv를 앞 16바이트에 쓰기
        memcpy(file_buf+16, out_buf, message_len); //뒤에 암호문 쓰기

        if (!write_file(args.out_file, file_buf, 16+message_len)) die();
        if (!write_file(args.tag_file, tag, tag_len)) die();

    } else{
        // HMAC 검증 -> 통과시 복호화
        unsigned char md[32];
        unsigned int md_len;
        size_t key_len;
        size_t in_len;
        unsigned char* in_buf = read_file(args.in_file, &in_len);
        unsigned char* key_buf = read_file(args.key_file, &key_len);

        //복호화
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
        if (!ctx) die();

        unsigned char *iv = in_buf; //앞의 16바이트가 iv
        size_t message_len = (int)in_len-16; //맨처음부터 16바이트 건너뛴 부분부터 암호문 길이
        int out_len;
        int final_len;
        unsigned char *out_buf = malloc(message_len + EVP_MAX_BLOCK_LENGTH);

        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_buf, iv)) die();
        if(!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf+16, (int)message_len)) die();
        if(!EVP_DecryptFinal_ex(ctx, out_buf+out_len, &final_len)) die();

        //HMAC 계산
        unsigned char *test_tag = HMAC(EVP_sha256(), key_buf, (int)key_len, out_buf, out_len+final_len, md, &md_len);
        //HMAC(EVP_sha256(), key_buf, key_len, infile_buf, in_len, tag, &tag_len)
        if (!test_tag) die();

        size_t tag_len;
        const char *tag_buf = read_file(args.tag_file, &tag_len);
        
        //계산한 HMAC 과 태그 비교
        if (CRYPTO_memcmp(test_tag, tag_buf, md_len)!=0) {
            printf("ERROR\n");
            exit(EXIT_VERIFY);
        }

        //파일에 쓰기
        if(!write_file(args.out_file, out_buf, out_len+final_len)) die();
    }

    return EXIT_OK;
}