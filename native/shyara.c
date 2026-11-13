/*
   shyara - small flat API over libyara for Symbol Hunter (P/Invoke friendly).
   Built together with libyara into one library: shyara-x64.dll (Windows) / libshyara.so (tests).
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#if defined(_WIN32)
#include <windows.h>
#define SH_API __declspec(dllexport)
#else
#define SH_API __attribute__((visibility("default")))
#endif

typedef void (*sh_error_cb)(int is_warning, const char* file, int line, const char* message);
typedef void (*sh_match_cb)(const char* ns, const char* rule, const char* tags, const char* metas, const char* strings);

typedef struct
{
  const char* base_dir;      /* directory of the top-level rule file, UTF-8 */
  const char* display_name;  /* name used in messages for the top-level file */
  sh_error_cb on_error;
} compile_ctx;

static char* read_whole_file(const char* path)
{
  FILE* f = NULL;
#if defined(_WIN32)
  wchar_t wpath[4096];
  if (MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 4096) == 0) return NULL;
  f = _wfopen(wpath, L"rb");
#else
  f = fopen(path, "rb");
#endif
  if (f == NULL) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0 || n > 64 * 1024 * 1024) { fclose(f); return NULL; }
  char* buf = (char*) malloc((size_t) n + 1);
  if (buf == NULL) { fclose(f); return NULL; }
  size_t got = fread(buf, 1, (size_t) n, f);
  fclose(f);
  buf[got] = 0;
  return buf;
}

static int is_absolute(const char* p)
{
  return p[0] == '/' || p[0] == '\\' || (p[0] != 0 && p[1] == ':');
}

static void dir_of(const char* path, char* out, size_t outlen)
{
  snprintf(out, outlen, "%s", path);
  char* s1 = strrchr(out, '/');
  char* s2 = strrchr(out, '\\');
  char* s = s1 > s2 ? s1 : s2;
  if (s != NULL) *s = 0; else out[0] = 0;
}

static const char* include_cb(const char* include_name, const char* calling_file, const char* calling_ns, void* user_data)
{
  compile_ctx* ctx = (compile_ctx*) user_data;
  char path[8192], dir[4096];
  (void) calling_ns;
  if (is_absolute(include_name))
    snprintf(path, sizeof(path), "%s", include_name);
  else
  {
    if (calling_file != NULL && calling_file[0] != 0)
    {
      char caller[8192];
      if (is_absolute(calling_file)) snprintf(caller, sizeof(caller), "%s", calling_file);
      else snprintf(caller, sizeof(caller), "%s/%s", ctx->base_dir, calling_file);
      dir_of(caller, dir, sizeof(dir));
    }
    else
      snprintf(dir, sizeof(dir), "%s", ctx->base_dir);
    snprintf(path, sizeof(path), "%s/%s", dir, include_name);
  }
  return read_whole_file(path);
}

static void include_free(const char* p, void* user_data)
{
  (void) user_data;
  free((void*) p);
}

static void compiler_cb(int level, const char* file, int line, const YR_RULE* rule, const char* message, void* user_data)
{
  compile_ctx* ctx = (compile_ctx*) user_data;
  (void) rule;
  if (ctx->on_error != NULL)
    ctx->on_error(level == YARA_ERROR_LEVEL_WARNING, file != NULL ? file : ctx->display_name, line, message);
}

SH_API int sh_init(void) { return yr_initialize(); }

SH_API const char* sh_version(void) { return YR_VERSION; }

SH_API void* sh_compiler_new(void)
{
  YR_COMPILER* c = NULL;
  if (yr_compiler_create(&c) != ERROR_SUCCESS) return NULL;
  return c;
}

/* Adds rule text; returns the number of errors (0 = ok). */
SH_API int sh_compiler_add(void* compiler, const char* source, const char* ns, const char* base_dir, const char* display_name, sh_error_cb cb)
{
  compile_ctx ctx;
  ctx.base_dir = base_dir != NULL ? base_dir : ".";
  ctx.display_name = display_name != NULL ? display_name : "rules";
  ctx.on_error = cb;
  YR_COMPILER* c = (YR_COMPILER*) compiler;
  yr_compiler_set_callback(c, compiler_cb, &ctx);
  yr_compiler_set_include_callback(c, include_cb, include_free, &ctx);
  int errors = yr_compiler_add_string(c, source, ns);
  yr_compiler_set_callback(c, NULL, NULL);
  return errors;
}

SH_API void* sh_compiler_rules(void* compiler)
{
  YR_RULES* rules = NULL;
  if (yr_compiler_get_rules((YR_COMPILER*) compiler, &rules) != ERROR_SUCCESS) return NULL;
  return rules;
}

SH_API void sh_compiler_free(void* compiler) { if (compiler != NULL) yr_compiler_destroy((YR_COMPILER*) compiler); }

SH_API void sh_rules_free(void* rules) { if (rules != NULL) yr_rules_destroy((YR_RULES*) rules); }

SH_API int sh_rules_count(void* rules)
{
  YR_RULES* r = (YR_RULES*) rules;
  YR_RULE* rule;
  int n = 0;
  yr_rules_foreach(r, rule) n++;
  return n;
}

typedef struct { char* p; size_t len, cap; } sbuf;

static void sb_add(sbuf* b, const char* s, size_t n)
{
  if (b->len + n + 1 > b->cap)
  {
    size_t cap = b->cap * 2 + n + 256;
    char* q = (char*) realloc(b->p, cap);
    if (q == NULL) return;
    b->p = q; b->cap = cap;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = 0;
}

static void sb_str(sbuf* b, const char* s) { sb_add(b, s, strlen(s)); }

static int scan_cb(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
  YR_RULE* rule = (YR_RULE*) message_data;
  sh_match_cb cb = (sh_match_cb) user_data;
  sbuf tags = {0}, metas = {0}, strs = {0};
  sb_str(&tags, ""); sb_str(&metas, ""); sb_str(&strs, "");
  const char* tag;
  yr_rule_tags_foreach(rule, tag) { if (tags.len > 0) sb_str(&tags, " "); sb_str(&tags, tag); }
  YR_META* meta;
  char num[64];
  yr_rule_metas_foreach(rule, meta)
  {
    sb_str(&metas, meta->identifier);
    sb_str(&metas, "=");
    if (meta->type == META_TYPE_STRING) sb_str(&metas, meta->string);
    else if (meta->type == META_TYPE_BOOLEAN) sb_str(&metas, meta->integer ? "true" : "false");
    else { snprintf(num, sizeof(num), "%lld", (long long) meta->integer); sb_str(&metas, num); }
    sb_str(&metas, "\n");
  }
  YR_STRING* string;
  int total = 0;
  yr_rule_strings_foreach(rule, string)
  {
    YR_MATCH* match;
    int per = 0;
    yr_string_matches_foreach(context, string, match)
    {
      if (per >= 4 || total >= 40) break;
      char line[256];
      snprintf(line, sizeof(line), "%s\t%lld\t%d\t", string->identifier, (long long) (match->base + match->offset), (int) match->match_length);
      sb_str(&strs, line);
      int n = match->data_length < 48 ? match->data_length : 48;
      for (int i = 0; i < n; i++) { snprintf(line, sizeof(line), "%02x", match->data[i]); sb_str(&strs, line); }
      sb_str(&strs, "\n");
      per++; total++;
    }
  }
  if (cb != NULL)
    cb(rule->ns != NULL ? rule->ns->name : "", rule->identifier, tags.p ? tags.p : "", metas.p ? metas.p : "", strs.p ? strs.p : "");
  free(tags.p); free(metas.p); free(strs.p);
  return CALLBACK_CONTINUE;
}

/* Scans a buffer; returns 0 or a YARA error code (e.g. timeout). */
SH_API int sh_scan(void* rules, const unsigned char* buffer, long long length, int timeout_seconds, sh_match_cb cb)
{
  return yr_rules_scan_mem((YR_RULES*) rules, buffer, (size_t) length, 0, scan_cb, (void*) cb, timeout_seconds);
}
