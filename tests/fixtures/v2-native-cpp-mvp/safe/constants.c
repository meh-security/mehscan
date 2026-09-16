typedef struct sqlite3 sqlite3;
typedef unsigned long size_t;
typedef unsigned int uint32_t;

int printf(const char *format, ...);
char *getenv(const char *name);
char *strcpy(char *destination, const char *source);
void *memcpy(void *destination, const void *source, size_t size);
int sqlite3_exec(sqlite3 *database, const char *query, void *callback, void *context, char **error);

void fixed_values(sqlite3 *database) {
    char destination[64];
    char *input = getenv("MEHSCAN_SAFE_INPUT");
    printf("%s", "fixed");
    strcpy(destination, "fixed");
    memcpy(destination, input, 16);
    sqlite3_exec(database, "select name from products", 0, 0, 0);
}

unsigned long guarded_narrowed_divisor(size_t wide_value) {
    size_t wide_local = wide_value;
    size_t narrowed_divisor = (uint32_t)wide_local;
    if (narrowed_divisor == 0)
        return 0;
    return 100 / narrowed_divisor;
}
