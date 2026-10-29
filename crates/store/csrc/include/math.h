/* Minimal freestanding <math.h> for the vendored SQLite (ADR-030). */
#ifndef URMQTT_MATH_H
#define URMQTT_MATH_H
#define INFINITY __builtin_inff()
#define NAN __builtin_nanf("")
#define HUGE_VAL __builtin_huge_val()
#define isnan(x) __builtin_isnan(x)
#define isinf(x) __builtin_isinf(x)
#define fabs(x) __builtin_fabs(x)
#endif
