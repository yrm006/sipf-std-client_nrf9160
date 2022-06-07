/*
 * Copyright (c) 2021 SAKURA internet Inc.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include <net/net_ip.h>
#include <net/socket.h>
#include <fcntl.h>
#include <net/http_client.h>
#include <net/net_core.h>
#include <net/tls_credentials.h>
#include <sys/base64.h>
#include <logging/log.h>

LOG_MODULE_DECLARE(sipf);

#include "sipf/sipf_client_http.h"
#include "sipf/sipf_object.h"
#include "sys/reboot.h"

#define HTTP_BASIC_AUTH_HEADER_PREFIX "Authorization: Basic "
#define NEWLINE_STRING "\r\n"

uint8_t httpc_req_buff[BUFF_SZ];
uint8_t httpc_res_buff[BUFF_SZ];

static char req_auth_header[256];



int PATCH_http_client_req(int sock, struct http_request *req,
		    int32_t timeout, void *user_data);



//---
typedef struct{
    char host[256];
    struct zsock_addrinfo* res;
} addrinfo_map;

static
addrinfo_map PATCH_map[8] = {};

static
struct zsock_addrinfo* PATCH_map_find(const char* host)
{
    int i=0;
    while(i < sizeof(PATCH_map)/sizeof(PATCH_map[0])){
        if( strcmp(PATCH_map[i].host, host) == 0 ){
            return PATCH_map[i].res;
        }
        ++i;
    }

    return NULL;
}

static
void PATCH_map_add(const char* host, struct zsock_addrinfo* res)
{
    int i=0;
    while(i < sizeof(PATCH_map)/sizeof(PATCH_map[0])){
        if( PATCH_map[i].host[0] == 0 ){
            strcpy(PATCH_map[i].host, host);
            PATCH_map[i].res = res;
            break;
        }
        ++i;
    }
}

static
int PATCH_getaddrinfo(const char *host, const char *service,
		      const struct zsock_addrinfo *hints,
		      struct zsock_addrinfo **res)
{
    if( (*res = PATCH_map_find(host)) ){
        return 0;
    }else{
        int r = getaddrinfo(host, service, hints, res);
        PATCH_map_add(host, *res);
        return r;
    }
}

static
void PATCH_freeaddrinfo(struct zsock_addrinfo *ai)
{
    int i=0;
    while(i < sizeof(PATCH_map)/sizeof(PATCH_map[0])){
        if( PATCH_map[i].res == ai ){
            break;
        }
        ++i;
    }

    if(i < sizeof(PATCH_map)/sizeof(PATCH_map[0])){
        // none
    }else{
        freeaddrinfo(ai);
    }
}
//---//



/* Setup TLS options on a given socket */
static int tls_setup(int fd, const char *host_name)
{
    int err;
    int verify;

    /* Security tag that we have provisioned the certificate with */
    const sec_tag_t tls_sec_tag[] = {
        TLS_SEC_TAG,
    };

    /* Set up TLS peer verification */
    enum
    {
        NONE = 0,
        OPTIONAL = 1,
        REQUIRED = 2,
    };

    verify = REQUIRED;

    err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
    if (err) {
        LOG_ERR("Failed to setup peer verification, err %d", errno);
        return err;
    }

    /* Associate the socket with the security tag
     * we have provisioned the certificate with.
     */
    err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag, sizeof(tls_sec_tag));
    if (err) {
        LOG_ERR("Failed to setup TLS sec tag, err %d", errno);
        return err;
    }

    err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, host_name, strlen(host_name));
    if (err) {
        LOG_ERR("Failed to Set TLS Hostname, err %d", errno);
        return err;
    }

    return 0;
}

/** HTTP Client **/
int SipfClientHttpParseURL(char *url, const int url_len, char **protocol, char **host, char **path)
{
    // URL文字列からプロトコル、ホスト、パスのポインタをセットする
    enum url_delim
    {
        URL_PROTOCOL_END,
        URL_ROOT1,
        URL_ROOT2,
        URL_HOST_END,
        URL_PATH_END,
    };
    enum url_delim st = URL_PROTOCOL_END;

    char *cr = strstr(url, "\r");
    if (cr) {
        *cr = 0x00;
    }

    *protocol = url;
    for (int i = 0; i < url_len; i++) {
        switch (st) {
        case URL_PROTOCOL_END:
            if (url[i] == ':') {
                url[i] = 0x00;
                st = URL_ROOT1;
            }
            break;
        case URL_ROOT1:
            if (url[i] == '/') {
                url[i] = 0x00;
                st = URL_ROOT2;
            }
            break;
        case URL_ROOT2:
            if (url[i] == '/') {
                url[i] = 0x00;
                *host = &url[i + 1];
                st = URL_HOST_END;
            }
            break;
        case URL_HOST_END:
            if (url[i] == '/') {
                url[i] = 0x00;
                *path = &url[i + 1];
                st = URL_PATH_END;
            }
            break;
        case URL_PATH_END:
            if ((url[i] == '\r') || (url[i] == '\n')) {
                url[i] = 0x00;
                goto parse_finish;
            }
            break;
        }
    }
    // URL文字列の終端までみたけど分割が終わらなかった
    if (st != URL_PATH_END) {
        return -1;
    }
parse_finish:
    // URLの分割が終わった
    LOG_INF("protocol: %s", *protocol);
    LOG_INF("host: %s", *host);
    LOG_INF("path: %s", *path);
    return 0;
}

int SipfClientHttpRunRequest(const char *hostname, struct http_request *req, uint32_t timeout, struct http_response *http_res, bool tls)
{
    int sock;
    int ret;
    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_family = AF_INET, .ai_socktype = SOCK_STREAM,
    };
    // 接続先をセットアップするよ
    ret = PATCH_getaddrinfo(hostname, NULL, &hints, &res);
    if (ret) {
        LOG_ERR("getaddrinfo failed: ret=%d errno=%d", ret, errno);
        return -errno;
    }
    if (tls) {
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    } else {
        ((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTP_PORT);
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
    if (sock < 0) {
        LOG_ERR("socket() failed: ret=%d errno=%d", ret, errno);
        PATCH_freeaddrinfo(res);
        return -errno;
    }
    if (tls) {
        // TLSを設定
        ret = tls_setup(sock, hostname);
        if (ret != 0) {
            LOG_ERR("tls_setup() failed: ret=%d", ret);
            PATCH_freeaddrinfo(res);
            (void)close(sock);
            return -errno;
        }
    }
    // 接続するよ
    LOG_INF("Connect to %s:%d", hostname, HTTPS_PORT);

    int oldfl;
    oldfl = fcntl(sock, F_GETFL);
    fcntl(sock, F_SETFL, oldfl | O_NONBLOCK);

    ret = 1;

    connect(sock, res->ai_addr, sizeof(struct sockaddr_in));

    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;

    int s = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (s == 1){
        ret = 0;
        fcntl(sock, F_SETFL, oldfl);
    }

    if (ret) {
        sys_reboot(SYS_REBOOT_WARM);
    }

    ret = PATCH_http_client_req(sock, req, timeout, http_res);
    if(ret < 0){
        sys_reboot(SYS_REBOOT_WARM);
    }
    PATCH_freeaddrinfo(res);
    close(sock);
    return ret;
}

/**
 * Authorizationヘッダの文字列バッファへのポインタを返す
 */
char *SipfClientHttpGetAuthInfo(void)
{
    return req_auth_header;
}

/**
 * user_nameとpasswdからAuthorizationヘッダ文字列を生成してバッファに置く
 */
int SipfClientHttpSetAuthInfo(const char *user_name, const char *passwd)
{
    char tmp1[128], tmp2[128];

    int ilen, olen;

    ilen = sprintf(tmp1, "%s:%s", user_name, passwd);
    LOG_DBG("%s", tmp1);
    if (base64_encode(tmp2, sizeof(tmp2), &olen, tmp1, ilen) < 0) {
        return -1;
    }
    return sprintf(req_auth_header, "Authorization: BASIC %s\r\n", tmp2);
}
