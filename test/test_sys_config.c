/*
 *  The config interpreter (test/expect/system-config.md CF-1 to CF-6, the
 *  five grammars; finding-kinds.md, config_*). Files are written, captured
 *  with the real capture and compared with the real diff, so the second
 *  claim -- text, or systemd for a unit file, explaining the same path --
 *  is seen as a user's diff shows it. The fixtures are shaped from the
 *  grammar rows; none has yet been run against its tool (every grammar row
 *  is owed). Every expectation is written by hand from the pin; the two
 *  sha256 values of opaque blocks were computed with sha256sum.
 */
#include "sys_test.h"

#define EV(kind, fields, text, path) \
    "{\"event\":\"" kind "\",\"interp\":\"config\"," fields ",\"text\":\"" text "\",\"paths\":[\"" path "\"]}\n"
/* ct is the context as the text shows it, with a space before it when it is not empty */
#define ARROW " \xe2\x80\xba "
#define KV(word, path, g, cj, ct, key, value) \
    EV("config_key_" word, "\"path\":\"" path "\",\"grammar\":\"" g "\",\"context\":[" cj "],\"key\":\"" key \
       "\",\"value\":\"" value "\"", path ":" ct ARROW key " " word ": " value, path)
#define ADDED(path, g, cj, ct, key, value)   KV("added", path, g, cj, ct, key, value)
#define REMOVED(path, g, cj, ct, key, value) KV("removed", path, g, cj, ct, key, value)
#define CHANGED(path, g, cj, ct, key, from, to) \
    EV("config_key_changed", "\"path\":\"" path "\",\"grammar\":\"" g "\",\"context\":[" cj "],\"key\":\"" key \
       "\",\"from\":\"" from "\",\"to\":\"" to "\"", path ":" ct ARROW key " " from " -> " to, path)
#define NOT_KEYED(path, g, why) \
    EV("config_not_keyed", "\"path\":\"" path "\",\"grammar\":\"" g "\",\"why\":\"" why "\"", \
       path ": shown as lines (" why ")", path)
#define CNI(path) "{\"event\":\"could_not_interpret\",\"interp\":\"config\",\"text\":\"could not interpret\",\"paths\":[\"" path "\"]}\n"
#define INVALID(path) "{\"event\":\"invalid_finding\",\"interp\":\"config\",\"text\":\"invalid finding\",\"paths\":[\"" path "\"]}\n"
#define UNIQ "a block header is not unique"

/* CF-6: the text interpreter's line findings for the path stand. */
static bool has_text_finding(int a, int b, const char *path) {
    const char *rec = t_record(t_diff(a, b), path);
    return strstr(rec, "\"kind\":\"text_") != NULL;
}

/* ---- CF-L: namevalue ---- */

#define LD "etc/login.defs"

/* CF-1, CF-2, CF-5: a key with one value each side is changed; a repeated
 * one is a set; events by key, comments and blank lines nothing. */
TEST(namevalue_login_defs_by_key) {
    t_reset();
    t_file(LD, "# login.defs\nUID_MIN 1000\nUID_MAX\t60000\n\nUMASK 022\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(LD, "UID_MIN   500\n  UID_MAX 60000\nUMASK 022\nUMASK 027\nENCRYPT_METHOD SHA512   x\n"
               "   # UID_MIN 1\nMAIL_DIR\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(ADDED(LD, "namevalue", "", "", "ENCRYPT_METHOD", "SHA512 x")
                  ADDED(LD, "namevalue", "", "", "MAIL_DIR", "")
                  CHANGED(LD, "namevalue", "", "", "UID_MIN", "1000", "500")
                  ADDED(LD, "namevalue", "", "", "UMASK", "027"),
                  t_events(1, 2));
    ASSERT_EQ_STR(REMOVED(LD, "namevalue", "", "", "ENCRYPT_METHOD", "SHA512 x")
                  REMOVED(LD, "namevalue", "", "", "MAIL_DIR", "")
                  CHANGED(LD, "namevalue", "", "", "UID_MIN", "500", "1000")
                  REMOVED(LD, "namevalue", "", "", "UMASK", "027"),
                  t_events(2, 1));
    ASSERT_TRUE(has_text_finding(1, 2, LD));
}

/* CF-4 by the capture: a file past the store threshold (64 KiB) and within
 * 1 MiB is kept to be keyed; past 1 MiB it is not kept, and too large. */
TEST(a_file_past_the_store_threshold_is_kept_and_keyed) {
    t_reset();
    static char big[1100000];
    size_t w = 0;
    for (int i = 0; w < 100000; i++) w += (size_t)snprintf(big + w, sizeof big - w, "K%06d 1\n", i);
    t_bytes(LD, big, w, 0644);
    REQUIRE(t_snap(1) == 0);
    memcpy(big, "K000000 2", 9);
    t_bytes(LD, big, w, 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(CHANGED(LD, "namevalue", "", "", "K000000", "1", "2"), t_events(1, 2));
    memset(big + w, '#', 1024 * 1024 + 1 - w);
    t_bytes(LD, big, 1024 * 1024 + 1, 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(NOT_KEYED(LD, "namevalue", "too large"), t_events(2, 3));
}

/* ---- CF-K: keyvalue ---- */

#define SC "etc/sysctl.conf"
#define SD "etc/sysctl.d/99-site.conf"

TEST(keyvalue_sysctl_by_key) {
    t_reset();
    t_file(SC, "net.ipv4.ip_forward = 0\n; a comment\n# another\n-kernel.x=1\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(SC, "net.ipv4.ip_forward=1\n-kernel.x = 1\nvm.swappiness =   10   \nkernel.x = 1\n", 0644);
    t_file(SD, "a.b = c = d\n", 0644);
    REQUIRE(t_snap(2) == 0);
    /* `-` is part of the key as written: `kernel.x` is another key. */
    ASSERT_EQ_STR(ADDED(SC, "keyvalue", "", "", "kernel.x", "1")
                  CHANGED(SC, "keyvalue", "", "", "net.ipv4.ip_forward", "0", "1")
                  ADDED(SC, "keyvalue", "", "", "vm.swappiness", "10")
                  ADDED(SD, "keyvalue", "", "", "a.b", "c = d"),
                  t_events(1, 2));
    ASSERT_TRUE(has_text_finding(1, 2, SC));
    /* CF-4: a line that is no assignment does not parse; the line diff stands. */
    t_file(SC, "net.ipv4.ip_forward\n", 0644);
    t_rm(SD);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(NOT_KEYED(SC, "keyvalue", "does not parse") REMOVED(SD, "keyvalue", "", "", "a.b", "c = d"),
                  t_events(2, 3));
    ASSERT_TRUE(has_text_finding(2, 3, SC));
    t_file(SC, " = 1\n", 0644);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(NOT_KEYED(SC, "keyvalue", "does not parse"), t_events(3, 4));
}

/* ---- CF-I: ini ---- */

#define OV "etc/systemd/system/nginx.service.d/override.conf"
#define UF "etc/systemd/system/probe.service"
#define JD "etc/systemd/journald.conf"
#define JDD "etc/systemd/journald.conf.d/site.conf"
#define SVC "\"Service\""

TEST(ini_units_and_drop_ins_by_section_and_key) {
    t_reset();
    t_file(JD, "[Journal]\nStorage=auto\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(OV, "[Service]\n"
               "ExecStart=\n"
               "ExecStart=/usr/bin/nginx -g 'daemon off;' \\\n"
               "  # a comment within the continuation\n"
               "    -c /etc/x\n"
               "User = www\n"
               "; comment\n"
               "# comment \\\n"
               "Environment=A=1   B=2\n", 0644);
    t_file(JD, "[Journal]\nStorage=persistent\n", 0644);
    t_file(JDD, "Top=level\n[Journal]\nSystemMaxUse=1G\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        /* systemd's event of the same path stands before config's (E13) */
        "{\"event\":\"unit_file_added\",\"interp\":\"systemd\",\"path\":\"" OV "\",\"text\":\"unit file " OV
        " added\",\"paths\":[\"" OV "\"]}\n"
        CHANGED(JD, "ini", "\"Journal\"", " Journal", "Storage", "auto", "persistent")
        ADDED(JDD, "ini", "", "", "Top", "level")
        ADDED(JDD, "ini", "\"Journal\"", " Journal", "SystemMaxUse", "1G")
        ADDED(OV, "ini", SVC, " Service", "Environment", "A=1 B=2")
        /* an empty assignment is a value, the empty one; two values are a set */
        ADDED(OV, "ini", SVC, " Service", "ExecStart", "")
        ADDED(OV, "ini", SVC, " Service", "ExecStart", "/usr/bin/nginx -g 'daemon off;' -c /etc/x")
        ADDED(OV, "ini", SVC, " Service", "User", "www"),
        t_events(1, 2));
    /* One changed value; a unit file elsewhere; a repeated key never changed. */
    t_file(OV, "[Service]\nExecStart=\nExecStart=/usr/bin/nginx\nUser=nginx\nEnvironment=A=1 B=2\n", 0644);
    t_file(UF, "[Unit]\nDescription=probe\n[Service]\nExecStart=/bin/true\n", 0644);
    REQUIRE(t_snap(3) == 0);
    const char *ev = t_events(2, 3);
    ASSERT_TRUE(strstr(ev, CHANGED(OV, "ini", SVC, " Service", "User", "www", "nginx")) != NULL);
    ASSERT_TRUE(strstr(ev, REMOVED(OV, "ini", SVC, " Service", "ExecStart", "/usr/bin/nginx -g 'daemon off;' -c /etc/x")
                           ADDED(OV, "ini", SVC, " Service", "ExecStart", "/usr/bin/nginx")) != NULL);
    ASSERT_TRUE(strstr(ev, ADDED(UF, "ini", SVC, " Service", "ExecStart", "/bin/true")
                           ADDED(UF, "ini", "\"Unit\"", " Unit", "Description", "probe")) != NULL);
    ASSERT_TRUE(strstr(ev, "config_key_removed\",\"interp\":\"config\",\"path\":\"" OV "\",\"grammar\":\"ini\","
                           "\"context\":[\"Service\"],\"key\":\"ExecStart\",\"value\":\"\"") == NULL);
    /* CF-3: a section twice on a side; CF-4: a line without `=`, a bad header. */
    t_file(OV, "[Service]\nUser=a\n[Service]\nGroup=b\n", 0644);
    t_file(UF, "[Unit]\nDescription\n", 0644);
    t_file(JD, "[Journal\nStorage=auto\n", 0644);
    t_file(JDD, "[]\n", 0644);
    REQUIRE(t_snap(4) == 0);
    ev = t_events(3, 4);
    ASSERT_TRUE(strstr(ev, NOT_KEYED(JD, "ini", "does not parse") NOT_KEYED(JDD, "ini", "does not parse")
                           NOT_KEYED(OV, "ini", UNIQ)) != NULL);
    ASSERT_TRUE(strstr(ev, NOT_KEYED(UF, "ini", "does not parse")) != NULL);
}

/* ---- CF-S: sshd ---- */

#define SS "etc/ssh/sshd_config"
#define SSD "etc/ssh/sshd_config.d/50-site.conf"

TEST(sshd_keywords_and_match_contexts) {
    t_reset();
    t_file(SS, "Port 22\nPermitRootLogin no\n#PasswordAuthentication yes\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(SS, "port=2222\n"
               "PERMITROOTLOGIN   no\n"
               "AcceptEnv LANG\n"
               "AcceptEnv LC_*\n"
               "Match User bob\n"
               "  PasswordAuthentication yes\n"
               "match  Address 10.0.0.0/8\n"
               "  PermitRootLogin = yes\n", 0644);
    t_file(SSD, "X11Forwarding no\n", 0644);
    REQUIRE(t_snap(2) == 0);
    /* Keywords compared without regard to case, shown as written (after,
     * for a change); a Match runs to the next one. */
    ASSERT_EQ_STR(ADDED(SS, "sshd", "", "", "AcceptEnv", "LANG")
                  ADDED(SS, "sshd", "", "", "AcceptEnv", "LC_*")
                  CHANGED(SS, "sshd", "", "", "port", "22", "2222")
                  ADDED(SS, "sshd", "\"Match User bob\"", " Match User bob", "PasswordAuthentication", "yes")
                  ADDED(SS, "sshd", "\"match Address 10.0.0.0/8\"", " match Address 10.0.0.0/8", "PermitRootLogin", "yes")
                  ADDED(SSD, "sshd", "", "", "X11Forwarding", "no"),
                  t_events(1, 2));
    ASSERT_TRUE(has_text_finding(1, 2, SS));
    /* CF-3: one Match twice. */
    t_file(SS, "Match User bob\nX11Forwarding no\nMatch User bob\nX11Forwarding yes\n", 0644);
    t_file(SSD, "=yes\n", 0644);
    REQUIRE(t_snap(3) == 0);
    ASSERT_EQ_STR(NOT_KEYED(SS, "sshd", UNIQ) NOT_KEYED(SSD, "sshd", "does not parse"), t_events(2, 3));
}

/* ---- CF-N: nginx ---- */

#define NG "etc/nginx/nginx.conf"
#define AV "etc/nginx/sites-available/site"
#define EN "etc/nginx/sites-enabled/site"
#define HT "\"http\""
#define HS "\"http\",\"server\""

TEST(nginx_directives_blocks_and_opaque_blocks) {
    t_reset();
    t_file(NG, "user www-data;\n"
               "events { worker_connections 768; }\n"
               "http {\n"
               "    include /etc/nginx/mime.types;\n"
               "    server {\n"
               "        listen 80;\n"
               "        location / { root /var/www; }\n"
               "    }\n"
               "}\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(NG, "user www-data;  # a comment ; {\n"
               "events { worker_connections\n 1024; }\n"
               "http {\n"
               "    include /etc/nginx/mime.types;\n"
               "    map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n"
               "    server {\n"
               "        listen 80;\n"
               "        listen [::]:80   default_server;\n"
               "        location / { root \"/srv/www\"; }\n"
               "        location ~ \\.php$ { fastcgi_pass unix:/run/php.sock; }\n"
               "        add_header X-A \"a  b\" always;\n"
               "        set $x ${host}a;\n"
               "        content_by_lua_block { ngx.say(\"}\") -- }\n"
               "        local t = [[ { ]] }\n"
               "    }\n"
               "}\n", 0644);
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(
        CHANGED(NG, "nginx", "\"events\"", " events", "worker_connections", "768", "1024")
        ADDED(NG, "nginx", HT, " http", "map $http_upgrade $connection_upgrade",
              "82efc7faf265ad05558253324ea3a33eb4c252d0ef6b6db5636e786bb2e14e7d")
        /* words as written, quotes kept, one space between */
        ADDED(NG, "nginx", HS, " http, server", "add_header", "X-A \\\"a  b\\\" always")
        ADDED(NG, "nginx", HS, " http, server", "content_by_lua_block",
              "d0ea62f1db1d426cf548eb8087c6e4d04cea7373e62855c404b5ba8fa0c3def1")
        ADDED(NG, "nginx", HS, " http, server", "listen", "[::]:80 default_server")
        ADDED(NG, "nginx", HS, " http, server", "set", "$x ${host}a")
        CHANGED(NG, "nginx", HS ",\"location /\"", " http, server, location /", "root", "/var/www", "\\\"/srv/www\\\"")
        ADDED(NG, "nginx", HS ",\"location ~ \\\\.php$\"", " http, server, location ~ \\\\.php$", "fastcgi_pass",
              "unix:/run/php.sock"),
        t_events(1, 2));
    ASSERT_TRUE(has_text_finding(1, 2, NG));
}

/* CF-N: a link is its target's file, once: sites-enabled's link is no file
 * of its path, sites-available's file is keyed where it is. */
TEST(nginx_a_link_is_its_targets_file_once) {
    t_reset();
    t_file(AV, "server { listen 80; }\n", 0644);
    REQUIRE(t_snap(1) == 0);
    t_file(AV, "server { listen 8080; }\n", 0644);
    t_link(EN, "../sites-available/site");
    REQUIRE(t_snap(2) == 0);
    ASSERT_EQ_STR(CHANGED(AV, "nginx", "\"server\"", " server", "listen", "80", "8080"), t_events(1, 2));
    /* A file replaced by a link: its keys are gone from its path. */
    t_rm(EN);
    t_file(EN, "server { listen 81; }\n", 0644);
    REQUIRE(t_snap(3) == 0);
    t_rm(EN);
    t_link(EN, "../sites-available/site");
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(REMOVED(EN, "nginx", "\"server\"", " server", "listen", "81"), t_events(3, 4));
}

/* CF-3, CF-4: two blocks with one header under one parent; what does not
 * tokenize. */
TEST(nginx_what_is_not_keyed) {
    t_reset();
    t_file(NG, "http { server { listen 80; } }\n", 0644);
    REQUIRE(t_snap(1) == 0);
    static const struct { const char *text, *why; } C[] = {
        { "http { server { listen 80; } server { listen 81; } }\n", UNIQ },
        { "http { server { listen 80; } }\nhttp { }\n", UNIQ },
        { "http { server { listen 80; }\n", "does not parse" },
        { "http { server { listen 80 } }\n", "does not parse" },
        { "http { listen 80; } }\n", "does not parse" },
        { "listen \"80;\n", "does not parse" },
        { "listen \"80\"x;\n", "does not parse" },
        { "listen 80\n", "does not parse" },
        { "; listen 80;\n", "does not parse" },
        { "{ listen 80; }\n", "does not parse" },
        { "map $a $b { x y;\n", "does not parse" },
        { "content_by_lua_block { ngx.say('}) }\n", "does not parse" },
        { "content_by_lua_block { --[[ } \n}\n", "does not parse" },
        { "set $x ${host;\n", "does not parse" },
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        t_file(NG, C[i].text, 0644);
        REQUIRE(t_snap(2) == 0);
        char want[600];
        snprintf(want, sizeof want, "{\"event\":\"config_not_keyed\",\"interp\":\"config\",\"path\":\"" NG
                 "\",\"grammar\":\"nginx\",\"why\":\"%s\",\"text\":\"" NG ": shown as lines (%s)\",\"paths\":[\"" NG
                 "\"]}\n", C[i].why, C[i].why);
        ASSERT_EQ_STR(want, t_events(1, 2));
        ASSERT_TRUE(has_text_finding(1, 2, NG));
    }
    /* Not unique: the same header under different parents is keyed; two
     * opaque blocks of one header are two values of one key. */
    t_file(NG, "http { server { listen 80; } }\nstream { server { listen 81; } }\n"
               "types { a b; }\ntypes { c d; }\n", 0644);
    REQUIRE(t_snap(2) == 0);
    const char *ev = t_events(1, 2);
    ASSERT_TRUE(strstr(ev, "config_not_keyed") == NULL);
    /* One why, the first that holds of either side: does not parse before
     * not unique, whichever side. */
    t_file(NG, "server { } server { }\n", 0644);
    REQUIRE(t_snap(3) == 0);
    t_file(NG, "server {\n", 0644);
    REQUIRE(t_snap(4) == 0);
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), t_events(3, 4));
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), t_events(4, 3));
    ev = t_events(1, 2);
    ASSERT_TRUE(strstr(ev, ADDED(NG, "nginx", "\"stream\",\"server\"", " stream, server", "listen", "81")) != NULL);
}

/* ---- every grammar: what cannot be read, what is not a file ---- */

static const char *by_hand(const char *path, const struct belay_entry *b, const struct belay_entry *a,
                           const char *outcome) {
    static struct t_run r;
    tr_begin(&r, BELAY_INTERP_CONFIG);
    ASSERT_EQ_STR("", tr_path(&r, path, b, a, outcome));          /* events only, never a finding */
    static char *keep;
    free(keep);
    keep = strdup(tr_end(&r, NULL, 0));
    tr_free(&r);
    return keep != NULL ? keep : "(no memory)";
}

/* SI-2: a side that is sealed, under a metadata root, not a regular file,
 * without a copy, or holding a NUL is could_not_interpret; a directory, a
 * pair of links and a metadata change are nothing. */
TEST(what_cannot_be_read_could_not_be_interpreted) {
    t_reset();
    struct belay_entry b = t_entry(LD, BELAY_T_REG, 0644, t_put("UID_MIN 1000\n")), a = b;
    a.sealed = true;                    /* a copy or not, a sealed side's bytes are given to no interpreter */
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "modified"));
    a.has_stored = false;
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "modified"));
    a = b;
    a.meta = true;
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "modified"));
    a = t_entry(LD, BELAY_T_REG, 0644, NULL);
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "modified"));
    a = t_entry(LD, BELAY_T_DIR, 0755, NULL);
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "type_changed"));
    ASSERT_EQ_STR("", by_hand(LD, NULL, &a, "added"));
    a = t_entry(LD, BELAY_T_REG, 0644, t_put_n("UID_MIN 1\n\0", 11));
    ASSERT_EQ_STR(CNI(LD), by_hand(LD, &b, &a, "modified"));
    a = t_entry(LD, BELAY_T_REG, 0600, t_put("UID_MIN 1000\n"));
    ASSERT_EQ_STR("", by_hand(LD, &b, &a, "metadata_only"));
    struct belay_entry l = t_entry(EN, BELAY_T_LNK, 0777, NULL);
    ASSERT_EQ_STR("", by_hand(EN, &l, &l, "modified"));
    /* Unknown: read all the same, its events provisional (E2). */
    a = t_entry(LD, BELAY_T_REG, 0644, t_put("UID_MIN 500\n"));
    ASSERT_EQ_STR("{\"event\":\"config_key_changed\",\"interp\":\"config\",\"path\":\"" LD "\",\"grammar\":\"namevalue\","
                  "\"context\":[],\"key\":\"UID_MIN\",\"from\":\"1000\",\"to\":\"500\",\"text\":\"" LD ": \xe2\x80\xba "
                  "UID_MIN 1000 -> 500\",\"provisional\":true,\"paths\":[\"" LD "\"]}\n",
                  by_hand(LD, &b, &a, "unknown"));
    /* A path config does not claim is declined. */
    a = t_entry("etc/default/grub", BELAY_T_REG, 0644, t_put("A=1\n"));
    ASSERT_EQ_STR("", by_hand("etc/default/grub", NULL, &a, "added"));
}

/* ---- hostile files: each is written by the watched machine ---- */

static const char *hostile(const char *path, const char *data, size_t n) {
    const struct belay_entry a = t_entry(path, BELAY_T_REG, 0644, t_put_n(data, n));
    return by_hand(path, NULL, &a, "added");
}
#define HOSTILE(path, text) hostile(path, text, sizeof(text) - 1)

static size_t lines_of(const char *s) {
    size_t n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

TEST(hostile_files_are_read_within_bounds_and_never_silently) {
    t_reset();
    static char big[2200000];
    /* CF-4: over 1 MiB, by the copy read, is too large. */
    memset(big, '\n', 1024 * 1024 + 1);
    ASSERT_EQ_STR(NOT_KEYED(LD, "namevalue", "too large"), hostile(LD, big, 1024 * 1024 + 1));
    ASSERT_EQ_STR("", hostile(LD, big, 1024 * 1024));
    struct belay_entry a = t_entry(LD, BELAY_T_REG, 0644, NULL);
    a.size = 1024 * 1024 + 1;
    ASSERT_EQ_STR(NOT_KEYED(LD, "namevalue", "too large"), by_hand(LD, NULL, &a, "added"));
    /* More than 65,536 triples on a side: too large; 65,536 are keyed, and
     * all but the last 65,535 events counted into one and_more (E5). */
    size_t w = 0;
    for (int i = 0; i < 65537; i++) w += (size_t)snprintf(big + w, sizeof big - w, "k%d v\n", i);
    ASSERT_EQ_STR(NOT_KEYED(LD, "namevalue", "too large"), hostile(LD, big, w));
    {   /* too large on one side, does not parse on the other: too large */
        static struct t_run r;
        tr_begin(&r, BELAY_INTERP_CONFIG);
        const struct belay_entry b = t_entry(SC, BELAY_T_REG, 0644, t_put("x\n"));
        for (size_t i = 0; i < w; i++) if (big[i] == ' ') big[i] = '=';
        const struct belay_entry a2 = t_entry(SC, BELAY_T_REG, 0644, t_put_n(big, w));
        for (size_t i = 0; i < w; i++) if (big[i] == '=') big[i] = ' ';
        ASSERT_EQ_STR("", tr_path(&r, SC, &b, &a2, "modified"));
        ASSERT_EQ_STR(NOT_KEYED(SC, "keyvalue", "too large"), tr_end(&r, NULL, 0));
        tr_free(&r);
    }
    w -= strlen("k65536 v\n");
    const char *out = hostile(LD, big, w);
    ASSERT_EQ_INT(65536, (int)lines_of(out));
    ASSERT_TRUE(strstr(out, "config_not_keyed") == NULL && strstr(out, "and_more") == NULL);
    /* Both sides at the bound, every key another: 131,072 events, 65,535
     * of them stated and one and_more for the rest (E5). */
    {
        static struct t_run r;
        tr_begin(&r, BELAY_INTERP_CONFIG);
        const struct belay_entry b = t_entry(LD, BELAY_T_REG, 0644, t_put_n(big, w));
        for (size_t i = 0; i < w; i++) if (big[i] == 'k') big[i] = 'j';
        const struct belay_entry a2 = t_entry(LD, BELAY_T_REG, 0644, t_put_n(big, w));
        ASSERT_EQ_STR("", tr_path(&r, LD, &b, &a2, "modified"));
        out = tr_end(&r, NULL, 0);
        ASSERT_EQ_INT(65536, (int)lines_of(out));
        ASSERT_EQ_STR("{\"event\":\"and_more\",\"interp\":\"config\",\"n\":65537,\"text\":\"and 65537 more\",\"paths\":[]}\n",
                      strrchr(out, '{'));
        tr_free(&r);
    }
    /* nginx: 64 blocks deep is keyed; 65 does not parse; a million braces
     * are read without recursion. */
    w = 0;
    for (int i = 0; i < 64; i++) w += (size_t)snprintf(big + w, sizeof big - w, "b {");
    w += (size_t)snprintf(big + w, sizeof big - w, "k v;");
    for (int i = 0; i < 64; i++) big[w++] = '}';
    out = hostile(NG, big, w);
    ASSERT_TRUE(strstr(out, "\"config_key_added\"") != NULL && strstr(out, ",\"key\":\"k\",\"value\":\"v\"") != NULL);
    w = 0;
    for (int i = 0; i < 65; i++) w += (size_t)snprintf(big + w, sizeof big - w, "b {");
    for (int i = 0; i < 65; i++) big[w++] = '}';
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), hostile(NG, big, w));
    memset(big, '{', 1000000);
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), hostile(NG, big, 1000000));
    memcpy(big, "map", 3);
    big[3] = ' ';
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), hostile(NG, big, 1000000));
    /* Bytes that are not UTF-8 and a value over 1,024 bytes: the core
     * refuses that event in its place (E9); the others stand. */
    ASSERT_EQ_STR(ADDED(LD, "namevalue", "", "", "A", "1") INVALID(LD),
                  HOSTILE(LD, "A 1\nB \xff\xfe\n"));
    w = (size_t)snprintf(big, sizeof big, "A 1\nB ");
    memset(big + w, 'x', 2000);
    w += 2000;
    ASSERT_EQ_STR(ADDED(LD, "namevalue", "", "", "A", "1") INVALID(LD), hostile(LD, big, w));
    /* CRLF: the CR is a byte of a line grammar's value, as written; nginx's
     * whitespace. No final newline; a last line that ends `\`. */
    ASSERT_EQ_STR(ADDED(LD, "namevalue", "", "", "A", "1\\r"), HOSTILE(LD, "A 1\r\n"));
    ASSERT_EQ_STR(ADDED(NG, "nginx", "", "", "a", "1"), HOSTILE(NG, "a\r\n1;\r\n"));
    ASSERT_EQ_STR(ADDED(SC, "keyvalue", "", "", "a", "1"), HOSTILE(SC, "a=1"));
    ASSERT_EQ_STR(ADDED(JD, "ini", "", "", "A", "1"), HOSTILE(JD, "A=1 \\"));
    ASSERT_EQ_STR("", HOSTILE(JD, "\\"));
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), HOSTILE(NG, "a \\"));
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), HOSTILE(NG, "a '\\"));
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), HOSTILE(NG, "content_by_lua_block { [==[ ]=] }"));
    ASSERT_EQ_STR(NOT_KEYED(NG, "nginx", "does not parse"), HOSTILE(NG, "x # no newline"));
}

int main(void) {
    t_begin("config");
    RUN(namevalue_login_defs_by_key);
    RUN(a_file_past_the_store_threshold_is_kept_and_keyed);
    RUN(keyvalue_sysctl_by_key);
    RUN(ini_units_and_drop_ins_by_section_and_key);
    RUN(sshd_keywords_and_match_contexts);
    RUN(nginx_directives_blocks_and_opaque_blocks);
    RUN(nginx_a_link_is_its_targets_file_once);
    RUN(nginx_what_is_not_keyed);
    RUN(what_cannot_be_read_could_not_be_interpreted);
    RUN(hostile_files_are_read_within_bounds_and_never_silently);
    free(g_text);
    t_end();
    return belay_test_report();
}
