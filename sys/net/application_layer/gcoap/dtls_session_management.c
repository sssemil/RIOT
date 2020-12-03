/*
 * Copyright (C) 2020 ML!PA Consulting GmbH
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_gcoap
 * @{
 *
 * @file
 * @brief       Implementation of DTLS Session Management for Gcoap
 *
 * @author      János Brodbeck <janos.brodbeck@ml-pa.com>
 */

#include "net/gcoap/dtls_session_management.h"
#include "mutex.h"
#include "net/sock/util.h"
#include "xtimer.h"

#define ENABLE_DEBUG 0
#include "debug.h"

typedef struct {
    sock_udp_ep_t ep;
    session_state_t state;
    uint64_t last_used;
} dsm_session_t;

static void _ep_to_session(const sock_udp_ep_t *ep, sock_dtls_session_t *session);
static int _find_session(const sock_udp_ep_t *ep, dsm_session_t **session);

static mutex_t _lock;
static dsm_session_t _sessions[CONFIG_GCOAP_DTLS_SESSIONS_MAX];
static uint8_t _available_slots;

void dtls_session_management_init(void) {
    mutex_init(&_lock);
    _available_slots = CONFIG_GCOAP_DTLS_SESSIONS_MAX;

    for (uint8_t i=0; i < CONFIG_GCOAP_DTLS_SESSIONS_MAX; i++) {
        _sessions[i].state = NO_SESSION;
        memset(&_sessions[i], 0, sizeof(dsm_session_t));
    }
}

ssize_t dtls_session_store(sock_dtls_session_t *session,
                           session_state_t new_state,
                           session_state_t *prev_state,
                           bool restore)
{
    mutex_lock(&_lock);
    dsm_session_t *session_slot = NULL;

    ssize_t res = _find_session(&session->ep, &session_slot);
    if (res != -1) {
        if (prev_state) {
            *prev_state = session_slot->state;
        }

        if (session_slot->state != SESSION_ESTABLISHED) {
            session_slot->state = new_state;
        }

        if (res == 0) {
            memcpy(&session_slot->ep, &session->ep, sizeof(sock_udp_ep_t));
            _available_slots--;
            res = 1;
        }

        if (restore) {
            _ep_to_session(&session->ep, session);
        }
        session_slot->last_used = xtimer_now_usec64();
    } else {
        DEBUG("gcoap_dtls_session_management: no space\n");
    }

    mutex_unlock(&_lock);
    return res;
}

int dtls_session_remove(sock_dtls_session_t *session)
{
    dsm_session_t *session_slot = NULL;
    mutex_lock(&_lock);

    int res = -1;
    if (_find_session(&session->ep, &session_slot) == 1) {
        memset(&session_slot->ep, 0 , sizeof(sock_udp_ep_t));
        session_slot->state = NO_SESSION;
        _available_slots++;
        res = 1;
    }
    mutex_unlock(&_lock);
    return res;
}

uint8_t dtls_session_get_num_available_slots(void)
{
    return _available_slots;
}

ssize_t dtls_session_get_oldest_used_session(sock_dtls_session_t *session)
{
    int res = -1;
    dsm_session_t *session_slot = NULL;

    mutex_lock(&_lock);
    for (uint8_t i=0; i < CONFIG_GCOAP_DTLS_SESSIONS_MAX; i++) {
        if (_sessions[i].state == SESSION_ESTABLISHED) {
            if (session_slot == NULL
                    ||  session_slot->last_used > _sessions[i].last_used)
            {
                session_slot = &_sessions[i];
            }
        }
    }

    if (session_slot) {
        _ep_to_session(&session_slot->ep, session);
        res = 1;
    }

    mutex_unlock(&_lock);
    return res;
}

/* Copied out of sock_dtls.c, should be officially provided by the DTLS API */
static void _ep_to_session(const sock_udp_ep_t *ep, sock_dtls_session_t *session) {
    memcpy(&session->dtls_session.addr, ep->addr.ipv6, sizeof(ipv6_addr_t));
    session->dtls_session.port = ep->port;
    session->dtls_session.size = sizeof(ipv6_addr_t) +  /* addr */
                sizeof(unsigned short);                 /* port */
    session->dtls_session.ifindex = ep->netif;
}

/* Search for existing session or empty slot for new one
 * Returns 1, if existing session found
 * Returns 0, if empty slot found
 * Returns -1, if no existing or empty session found */
static int _find_session(const sock_udp_ep_t *ep, dsm_session_t **session) {
    /* FIXME: optimize search / data structure */
    dsm_session_t *empty_session = NULL;
    for (uint8_t i=0; i < CONFIG_GCOAP_DTLS_SESSIONS_MAX; i++) {
        if (sock_udp_ep_equal(ep, &_sessions[i].ep)) {
            /* found existing session */
            *session = &_sessions[i];
            return 1;
        }
        if (_sessions[i].state == NO_SESSION) {
            empty_session = &_sessions[i];
        }
    }
    if (empty_session) {
        *session = empty_session;
        return 0;
    } else {
        (void)session;
    }
    return -1;
}
