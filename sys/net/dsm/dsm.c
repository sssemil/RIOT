/*
 * Copyright (C) 2021 ML!PA Consulting GmbH
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_dsm
 * @{
 *
 * @file
 * @brief       DTLS Session Management module implementation
 *
 * @author      János Brodbeck <janos.brodbeck@ml-pa.com>
 *
 * @}
 */

#include "net/dsm.h"
#include "mutex.h"
#include "net/sock/util.h"
#include "xtimer.h"

#define ENABLE_DEBUG 0
#include "debug.h"

typedef struct {
    sock_dtls_session_t session;
    dsm_state_t state;
    uint64_t last_used;
} dsm_session_t;

static int _find_session(sock_dtls_session_t *to_find, dsm_session_t **session);

static mutex_t _lock;
static dsm_session_t _sessions[DTLS_PEER_MAX];
static uint8_t _available_slots;

void dsm_init(void) {
    mutex_init(&_lock);
    _available_slots = DTLS_PEER_MAX;

    for (uint8_t i=0; i < DTLS_PEER_MAX; i++) {
        _sessions[i].state = NO_SESSION;
        memset(&_sessions[i], 0, sizeof(dsm_session_t));
    }
}

dsm_state_t dsm_store(sock_dtls_session_t *session,
                      dsm_state_t new_state, bool restore)
{
    sock_udp_ep_t ep;
    dsm_session_t *session_slot = NULL;
    dsm_state_t prev_state = NO_SPACE;
    mutex_lock(&_lock);

    ssize_t res = _find_session(session, &session_slot);
    if (res != -1) {
        prev_state = session_slot->state;
        if (session_slot->state != SESSION_ESTABLISHED) {
            session_slot->state = new_state;
        }

        /* no existing session found */
        if (res == 0) {
            sock_dtls_session_get_udp_ep(session, &ep);
            sock_dtls_session_set_udp_ep(&session_slot->session, &ep);
            _available_slots--;
        }

        /* existing session found and session should be restored */
        if (res == 1 && restore) {
            memcpy(session, &session_slot->session, sizeof(sock_dtls_session_t));
        }
        session_slot->last_used = xtimer_now_usec64();
    }

    mutex_unlock(&_lock);
    return prev_state;
}

void dsm_remove(sock_dtls_session_t *session)
{
    dsm_session_t *session_slot = NULL;
    mutex_lock(&_lock);
    if (_find_session(session, &session_slot) == 1) {
        memset(&session_slot->session, 0 , sizeof(session_slot->session));
        session_slot->state = NO_SESSION;
        _available_slots++;
    }
    mutex_unlock(&_lock);
}

uint8_t dsm_get_num_available_slots(void)
{
    return _available_slots;
}

uint8_t dsm_get_num_maximum_slots(void)
{
    return DTLS_PEER_MAX;
}

ssize_t dsm_get_oldest_used_session(sock_dtls_session_t *session)
{
    int res = -1;
    dsm_session_t *session_slot = NULL;

    if (dsm_get_num_available_slots() != DTLS_PEER_MAX) {
        mutex_lock(&_lock);
        for (uint8_t i=0; i < DTLS_PEER_MAX; i++) {
            if (_sessions[i].state == SESSION_ESTABLISHED) {
                if (session_slot == NULL
                        ||  session_slot->last_used > _sessions[i].last_used)
                {
                    session_slot = &_sessions[i];
                }
            }
        }

        if (session_slot) {
            memcpy(session, &session_slot->session, sizeof(sock_dtls_session_t));
            res = 1;
        }
        mutex_unlock(&_lock);
    }
    return res;
}

/* Search for existing session or empty slot for new one
 * Returns 1, if existing session found
 * Returns 0, if empty slot found
 * Returns -1, if no existing or empty session found */
static int _find_session(sock_dtls_session_t *to_find, dsm_session_t **session) {
    /* FIXME: optimize search / data structure */
    sock_udp_ep_t to_find_ep, curr_ep;
    dsm_session_t *empty_session = NULL;


    sock_dtls_session_get_udp_ep(to_find, &to_find_ep);
    for (uint8_t i=0; i < DTLS_PEER_MAX; i++) {
        sock_dtls_session_get_udp_ep(&_sessions[i].session, &curr_ep);

        if (sock_udp_ep_equal(&curr_ep, &to_find_ep)) {
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
