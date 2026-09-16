using size_t = unsigned long;
using uint32_t = unsigned int;
struct sqlite3;
struct CURL;

extern "C" char *getenv(const char *name);
extern "C" int system(const char *command);
extern "C" int execv(const char *command, char *const arguments[]);
extern "C" int printf(const char *format, ...);
extern "C" char *strcpy(char *destination, const char *source);
extern "C" void *memcpy(void *destination, const void *source, size_t size);
extern "C" void *fopen(const char *path, const char *mode);
extern "C" char *realpath(const char *path, char *resolved);
extern "C" const void *EVP_get_digestbyname(const char *algorithm);
extern "C" int sqlite3_exec(sqlite3 *database, const char *query, void *callback, void *context, char **error);
extern "C" int curl_easy_setopt(CURL *handle, int option, ...);

#define CURLOPT_URL 10002

void review_cpp_inputs(sqlite3 *database, CURL *client) {
    char destination[16];
    char resolved[256];
    char *arguments[] = { const_cast<char *>("/bin/tool"), const_cast<char *>("--fixed"), nullptr };
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
    sqlite3_exec(database, input, nullptr, nullptr, nullptr);
    curl_easy_setopt(client, CURLOPT_URL, input);
}

unsigned long review_cpp_narrowed_divisor(size_t wide_value) {
    size_t wide_local = wide_value;
    size_t narrowed_divisor = (uint32_t)wide_local;
    return 100 / narrowed_divisor;
}
