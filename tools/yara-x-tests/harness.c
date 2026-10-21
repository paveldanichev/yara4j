#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>
/* harness RULES_FILE DATA_FILE: prints "ERROR: ..." lines for compiler errors, else
   "RESULT <matching rules> <hex of the first match of the first matching rule or ->". */
static int errors = 0;
static void cb_err(int level, const char* file, int line, const YR_RULE* rule, const char* msg, void* ud) {
  if (level == YARA_ERROR_LEVEL_ERROR) { errors++; printf("ERROR: line %d: %s\n", line, msg); }
  else if (getenv("WARNINGS")) printf("WARNING: line %d: %s%s%s\n", line, rule ? rule->identifier : "", rule ? ": " : "", msg);
}
static int count = 0; static char first[1 << 16] = "-"; static int have_first = 0;
static int cb(YR_SCAN_CONTEXT* ctx, int msg, void* data, void* ud) {
  if (msg == CALLBACK_MSG_RULE_MATCHING) {
    YR_RULE* rule = (YR_RULE*) data; YR_STRING* s; YR_MATCH* m;
    count++;
    if (!have_first) {
      yr_rule_strings_foreach(rule, s) {
        yr_string_matches_foreach(ctx, s, m) {
          if (!have_first) {
            have_first = 1; first[0] = 0;
            for (int i = 0; i < m->data_length && i < 30000; i++) sprintf(first + 2 * i, "%02x", m->data[i]);
            if (m->data_length == 0) strcpy(first, "");
          }
        }
        if (have_first) break;
      }
    }
  }
  return CALLBACK_CONTINUE;
}
static char* slurp(const char* path, long* len) {
  FILE* f = fopen(path, "rb"); fseek(f, 0, SEEK_END); *len = ftell(f); fseek(f, 0, SEEK_SET);
  char* b = malloc(*len + 1); if (*len) fread(b, 1, *len, f); b[*len] = 0; fclose(f); return b;
}
int main(int argc, char** argv) {
  long rlen, dlen; char* rules_src = slurp(argv[1], &rlen); char* data = slurp(argv[2], &dlen);
  YR_COMPILER* c; YR_RULES* rules;
  yr_initialize(); yr_compiler_create(&c); yr_compiler_set_callback(c, cb_err, NULL);
  yr_compiler_add_string(c, rules_src, NULL);
  if (errors) return 0;
  if (yr_compiler_get_rules(c, &rules) != ERROR_SUCCESS) { printf("ERROR: get_rules\n"); return 0; }
  int r = yr_rules_scan_mem(rules, (uint8_t*) data, dlen, 0, cb, NULL, 0);
  if (r != ERROR_SUCCESS) { printf("SCANERROR %d\n", r); return 0; }
  printf("RESULT %d %s\n", count, first);
  return 0;
}
