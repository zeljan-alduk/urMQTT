/* Minimal freestanding <string.h> for the vendored SQLite (ADR-030).
 * The mem* functions come from compiler_builtins, the str* functions from
 * urmqtt-store's Rust shims (src/libc.rs). */
#ifndef URMQTT_STRING_H
#define URMQTT_STRING_H
#include <stddef.h>
void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int strcmp(const char *a, const char *b);
int strncmp(const char *a, const char *b, size_t n);
size_t strcspn(const char *s, const char *reject);
char *strrchr(const char *s, int c);
char *strchr(const char *s, int c);
size_t strspn(const char *s, const char *accept);
#endif
