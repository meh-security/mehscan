typedef unsigned long size_t;
typedef unsigned int uint32_t;
typedef struct sqlite3 sqlite3;
typedef struct CURL CURL;

char *getenv(const char *name);
int system(const char *command);
int execv(const char *command, char *const arguments[]);
int printf(const char *format, ...);
char *strcpy(char *destination, const char *source);
void *memcpy(void *destination, const void *source, size_t size);
void *fopen(const char *path, const char *mode);
char *realpath(const char *path, char *resolved);
const void *EVP_get_digestbyname(const char *algorithm);
int sqlite3_exec(sqlite3 *database, const char *query, void *callback, void *context, char **error);
int curl_easy_setopt(CURL *handle, int option, ...);

#define CURLOPT_URL 10002

void review_native_inputs(sqlite3 *database, CURL *client) {
    char destination[16];
    char resolved[256];
    char *arguments[] = { "/bin/tool", "--fixed", 0 };
    char *input = getenv("MEHSCAN_TEST_INPUT");

    system(input);
    execv("/bin/tool", arguments);
    printf(input);
    strcpy(destination, input);
    memcpy(destination, input, 64);
    fopen(input, "r");
    fopen(input, "w");
    realpath(input, resolved);
    EVP_get_digestbyname(input);
    sqlite3_exec(database, input, 0, 0, 0);
    curl_easy_setopt(client, CURLOPT_URL, input);
}

unsigned long review_narrowed_divisor(size_t wide_value) {
    size_t wide_local = wide_value;
    size_t narrowed_divisor = (uint32_t)wide_local;
    return 100 / narrowed_divisor;
}
