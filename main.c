#include "mongoose.h"
#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <string.h>
#include <stdint.h>
#include <memory.h>

typedef struct
{
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];   
}MD5_CTX;
 
                         
#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) \
          { \
          a += F(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define GG(a,b,c,d,x,s,ac) \
          { \
          a += G(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define HH(a,b,c,d,x,s,ac) \
          { \
          a += H(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
#define II(a,b,c,d,x,s,ac) \
          { \
          a += I(b,c,d) + x + ac; \
          a = ROTATE_LEFT(a,s); \
          a += b; \
          }
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
                         
void MD5Init(MD5_CTX *context)
{
     context->count[0] = 0;
     context->count[1] = 0;
     context->state[0] = 0x67452301;
     context->state[1] = 0xEFCDAB89;
     context->state[2] = 0x98BADCFE;
     context->state[3] = 0x10325476;
}
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
         output[j] = input[i] & 0xFF;  
         output[j+1] = (input[i] >> 8) & 0xFF;
         output[j+2] = (input[i] >> 16) & 0xFF;
         output[j+3] = (input[i] >> 24) & 0xFF;
         i++;
         j+=4;
    }
}
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
     unsigned int i = 0,j = 0;
     while(j < len)
     {
           output[i] = (input[j]) |
                       (input[j+1] << 8) |
                       (input[j+2] << 16) |
                       (input[j+3] << 24);
           i++;
           j+=4; 
     }
}
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
     unsigned int a = state[0];
     unsigned int b = state[1];
     unsigned int c = state[2];
     unsigned int d = state[3];
     unsigned int x[64];
     MD5Decode(x,block,64);
     FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
 FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
 FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
 FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
 FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
 FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
 FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
 FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
 FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
 FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
 FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
 FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
 FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
 FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
 FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
 FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */
 
 /* Round 2 */
 GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
 GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
 GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
 GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
 GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
 GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
 GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
 GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
 GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
 GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
 GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
 GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
 GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
 GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
 GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
 GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */
 
 /* Round 3 */
 HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
 HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
 HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
 HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
 HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
 HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
 HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
 HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
 HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
 HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
 HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
 HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
 HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
 HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
 HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
 HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */
 
 /* Round 4 */
 II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
 II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
 II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
 II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
 II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
 II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
 II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
 II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
 II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
 II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
 II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
 II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
 II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
 II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
 II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
 II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
     state[0] += a;
     state[1] += b;
     state[2] += c;
     state[3] += d;
}
void MD5Update(MD5_CTX *context,unsigned char *input,unsigned int inputlen)
{
    unsigned int i = 0,index = 0,partlen = 0;
    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;
    if(context->count[0] < (inputlen << 3))
       context->count[1]++;
    context->count[1] += inputlen >> 29;
    
    if(inputlen >= partlen)
    {
       memcpy(&context->buffer[index],input,partlen);
       MD5Transform(context->state,context->buffer);
       for(i = partlen;i+64 <= inputlen;i+=64)
           MD5Transform(context->state,&input[i]);
       index = 0;        
    }  
    else
    {
        i = 0;
    }
    memcpy(&context->buffer[index],&input[i],inputlen-i);
}
void MD5Final(MD5_CTX *context,unsigned char digest[16])
{
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];
    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56)?(56-index):(120-index);
    MD5Encode(bits,context->count,8);
    MD5Update(context,PADDING,padlen);
    MD5Update(context,bits,8);
    MD5Encode(digest,context->state,16);
}

static const char *s_http_addr = "http://0.0.0.0:58001";    // HTTP port
static const char *s_root_dir = "./html";
static int is_reg = 0;
char *sn;
static char pwd[17]={};
GDBusConnection *con;
int isNum(char *str)
{
    int i;
    int a=strlen(str);
    for(i=0;i<a;i++){
        if (str[i]>'9' || str[i]<'0')
        {
            return 0;
        }
    }
    return 1;
}
char* trim(char *str) {
	int first = -1; //第一个空白字符的下标
	int last = -1; //最后一个空白字符的下标
	//找到第一个非空白字符
	for (int i = 0; str[i] != '\0'; i++) {
		if (str[i] != ' '
			&& str[i] != '\t'
			&& str[i] != '\n'
			&& str[i] != '\r') {
			first = i;
			break;
		}
	}
	if (first == -1) { //全是空白字符
		str[0] = '\0';
		return str;
	}
 
	//保存最后一个非空白字符的指针
	for (int i = first; str[i] != '\0'; i++) {
		if (str[i] != ' '
			&& str[i] != '\t'
			&& str[i] != '\n'
			&& str[i] != '\r') {
			last = i;
		}
	}
 
	//在最后一个非空白字符的后面赋值'\0'
	str[last + 1] = '\0';
	return str + first;
}
static char *adapter_at(GDBusConnection *conn,char *name)
{
        GError *error = NULL;
        
        GVariant *parameters = g_variant_new("(s)", name);
        GVariant *v = g_dbus_connection_call_sync(conn,
                                                                "org.ofono",
                                                                "/ril_0",
                                                                "org.ofono.Modem",
                                                                "SendAtcmd",
                                                                parameters,
                                                                NULL,
                                                                G_DBUS_CALL_FLAGS_NONE,
                                                                -1,
                                                                NULL,
                                                                &error);
        if(error) {
                g_error_free (error);
                return NULL;
        }
        if(!v){
            return NULL;
        }
        char* result;
        g_variant_get(v, "(s)", &result);
        return result; 
}

static void adapter_sms_changed(GDBusConnection *conn,
          const gchar *sender,
          const gchar *path,
          const gchar *interface,
          const gchar *signal,
          GVariant *params,
          void *userdata)
{
  (void)conn;
  (void)sender;
  (void)path;
  (void)interface;

  GVariantIter *properties = NULL;
  const char *sms;
  const char *key;
  GVariant *value = NULL;
  const gchar *signature = g_variant_get_type_string(params);

  if(strcmp(signature, "(sa{sv})") != 0) {
    g_print("Invalid signature for %s: %s != %s", signal, signature, "(sa{sv})");
    //goto done;
  }
FILE *fptr;
                fptr = fopen("/home/root/html/sms.txt", "a");
 g_variant_get(params, "(&sa{sv})",&sms, &properties);
if(fptr) fprintf(fptr,"Content:%s\n",sms);

  while(g_variant_iter_next(properties, "{&sv}", &key, &value)) {
        if(fptr) fprintf(fptr,"%s:%s\n", key,g_variant_get_string(value,NULL));
}
if(fptr){
fprintf(fptr,"\n");
fclose(fptr);
}
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_http_match_uri(hm, "/api/at")) {
      struct mg_str json = hm->body;
      char *cmd;

      if(is_reg==1){
        if ((cmd = mg_json_get_str(json, "$.cmd")) != NULL) {
          char* res = adapter_at(con,cmd);
          if(res){
          }else{
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "error\n");
          }
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "%s\n", res);
        }else{
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n","error\n");
        }
      }else{
        if ((cmd = mg_json_get_str(json, "$.cmd")) != NULL) {
            if (strncmp(cmd, pwd,16) == 0) {
                mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n","reg ok\n");
                FILE *fptr;
                fptr = fopen("/home/root/.sn", "w");
                fprintf(fptr,"%s", cmd);
                fclose(fptr);
                is_reg=1;
            }else{
                mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n","not reg\nsn:%s\n",sn);
            }
        }else{
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n","not reg\nsn:%s\n",sn);
        }
      }
      
    } else if (mg_http_match_uri(hm, "/api/lockr")) {
        FILE *fptr;
        if ((fptr = fopen("/home/root/.lock", "r")) == NULL)
        {
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "{\"lock\": \"\"}\n");
        }else{
          char buff[255]={};
          fscanf(fptr,"%[^\n]", buff);
          fclose(fptr);
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "{\"lock\": \"%s\"}\n",buff);
        }
              
    } else if (mg_http_match_uri(hm, "/api/lockw")) {
        struct mg_str json = hm->body;
        char *lock;
        if(is_reg==1){
        if ((lock = mg_json_get_str(json, "$.lock")) != NULL) {
            //printf("lock:%s\n",lock);
            adapter_at(con,"AT+SFUN=5");
            adapter_at(con,"AT+SPFORCEFRQ=16,0");
            adapter_at(con,"AT+SPFORCEFRQ=12,0");
            if(strlen(lock)){
                char atcmd[32]="AT+SPFORCEFRQ=";
                strcat(atcmd, lock);
                adapter_at(con,atcmd);
            }
            adapter_at(con,"AT+SFUN=4");
            FILE *fptr;
            fptr = fopen("/home/root/.lock", "w");
            fprintf(fptr,"%s", lock);
            fclose(fptr);
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "{\"state\": 1}\n");
        }else{
          mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "{\"state\": 0}\n");
        }
        }else{
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept\n", "{\"state\": 4}\n");
        }

              
    } else {
      struct mg_http_serve_opts opts = {.root_dir = s_root_dir};
      mg_http_serve_dir(c, ev_data, &opts);
    }
  }
  (void) fn_data;
}

void *signal_subscribe(){
GMainLoop *loop;
guint sub;
loop = g_main_loop_new(NULL, FALSE);
sub = g_dbus_connection_signal_subscribe(con,
            NULL,
            "org.ofono.MessageManager",
            "IncomingMessage",
            NULL,
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            adapter_sms_changed,
            NULL,
            NULL);
g_main_loop_run(loop);
g_dbus_connection_signal_unsubscribe(con, sub);
}

int main(void) {
int fd = -1;
    char *databuf = (char*)malloc(20 * sizeof(char));
    int data_len=20;
fd = open("/dev/ubi0_miscdata", O_RDONLY);
  if (fd >= 0) {
    int len = read(fd, databuf, data_len);
    //printf("sn is %s\n",databuf);
    if (len <= 0) {
      printf("read fail sn\n");
    }
    close(fd);
  } else {
    printf("read fail sn2\n");
  }
  con = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
  if(con == NULL) {
    g_print("bus error\n");
    return 1;
  }
sn=  (char*)malloc(16 * sizeof(char));
sn = databuf+4;
    printf("sn is %s\n", sn);
	unsigned char encrypt[32] ="test";//21232f297a57a5a743894a0e4a801fc3
	unsigned char decrypt[16];
strncat(encrypt, sn , 16);
	MD5_CTX md5;
	MD5Init(&md5);         		
	MD5Update(&md5,encrypt,strlen((char *)encrypt));
	MD5Final(&md5,decrypt);
        sprintf(pwd,"%02x%02x%02x%02x%02x%02x%02x%02x",decrypt[0],decrypt[1],decrypt[2],decrypt[3],decrypt[4],decrypt[5],decrypt[6],decrypt[7]);
  FILE *fptr;
FILE *fptr2;
  if ((fptr = fopen("/home/root/.sn", "r")) == NULL)
  {
    printf("unreg\n");
  }else{
    char buff[255];
    fscanf(fptr,"%[^\n]", buff);
    fclose(fptr);
    if (strcmp(buff, pwd) == 0) {
        printf("reg\n");
        is_reg = 1;
    }else{
        printf("unreg\n");
    }
  }
printf("reg:%d\n",is_reg);
  if ((fptr2 = fopen("/home/root/.lock", "r")) == NULL)
  {
    //printf("no lock\n");
  }else{
    char buff2[255]={};
    fscanf(fptr2,"%[^\n]", buff2);
    fclose(fptr2);
    //printf("lock:%s\n",buff2);
    if(strlen(buff2)){
        adapter_at(con,"AT+SFUN=5");
        adapter_at(con,"AT+SPFORCEFRQ=16,0");
        adapter_at(con,"AT+SPFORCEFRQ=12,0");
        char atcmd[32]="AT+SPFORCEFRQ=";
        strcat(atcmd, buff2);
        adapter_at(con,atcmd);
        adapter_at(con,"AT+SFUN=4");
    }else{
        //printf("no lock\n");
    }
  }
pthread_t thread;
pthread_create(&thread,NULL,signal_subscribe,NULL);

  struct mg_mgr mgr;                            // Event manager
  mg_log_set(MG_LL_NONE);                      // Set log level
  mg_mgr_init(&mgr);                            // Initialise event manager
  mg_http_listen(&mgr, s_http_addr, fn, NULL);  // Create HTTP listener
  for (;;) mg_mgr_poll(&mgr, 1000);                    // Infinite event loop
  mg_mgr_free(&mgr);
  return 0;
}
