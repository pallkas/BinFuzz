/*
 * harness_llama_server.c
 *
 * AFL++ fuzzing harness for llama-server's HTTP API.
 *
 * Usage:
 *   afl-fuzz ... -- ./harness_llama_server @@
 *
 * The harness reads a file (AFL replaces @@ with the mutated input path),
 * treats its contents as an HTTP request body, and POSTs it to llama-server
 * at LLAMA_HOST:LLAMA_PORT/LLAMA_ENDPOINT.
 *
 * Environment overrides (optional):
 *   LLAMA_HOST      default: 127.0.0.1
 *   LLAMA_PORT      default: 8080
 *   LLAMA_ENDPOINT  default: /completion
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_BODY   (1 << 20)   /* 1 MB cap on fuzz input */
#define MAX_REQ    (MAX_BODY + 512)
#define RECV_BUF   4096
#define TIMEOUT_S  5

static const char *env_or(const char *var, const char *def) {
    const char *v = getenv(var);
    return (v && *v) ? v : def;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* ── Read fuzz input ──────────────────────────────────────────────── */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long body_len = ftell(f);
    rewind(f);

    if (body_len <= 0 || body_len > MAX_BODY) {
        fclose(f);
        return 0;   /* skip empty / oversized inputs gracefully */
    }

    char *body = malloc(body_len + 1);
    if (!body) { fclose(f); return 1; }
    if ((long)fread(body, 1, body_len, f) != body_len) {
        free(body); fclose(f); return 1;
    }
    body[body_len] = '\0';
    fclose(f);

    /* ── Config ───────────────────────────────────────────────────────── */
    const char *host     = env_or("LLAMA_HOST",     "127.0.0.1");
    int         port     = atoi(env_or("LLAMA_PORT", "8080"));
    const char *endpoint = env_or("LLAMA_ENDPOINT", "/completion");

    /* ── Build HTTP request ───────────────────────────────────────────── */
    char *req = malloc(MAX_REQ);
    if (!req) { free(body); return 1; }

    int req_len = snprintf(req, MAX_REQ,
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        endpoint, host, port, body_len, body);

    free(body);

    if (req_len <= 0 || req_len >= MAX_REQ) {
        free(req);
        return 0;
    }

    /* ── Connect ──────────────────────────────────────────────────────── */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); free(req); return 1; }

    struct timeval tv = { .tv_sec = TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        /* Server not running — skip this input */
        close(sock);
        free(req);
        return 0;
    }

    /* ── Send request ─────────────────────────────────────────────────── */
    ssize_t sent = 0, total = req_len;
    while (sent < total) {
        ssize_t n = write(sock, req + sent, total - sent);
        if (n <= 0) break;
        sent += n;
    }
    free(req);

    /* ── Drain response (detect hangs / crashes) ──────────────────────── */
    char rbuf[RECV_BUF];
    while (read(sock, rbuf, sizeof(rbuf)) > 0)
        ;   /* discard — we only care that the server didn't crash */

    close(sock);
    return 0;
}
