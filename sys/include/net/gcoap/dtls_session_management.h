/*
 * Copyright (C) 2020 ML!PA Consulting GmbH
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    net_gcoap  DTLS Session Management (DSM) for Gcoap
 * @ingroup     net
 * @brief       This module provides functionality to store and retrieve session
 *              information of DTLS connections. Currently only tinyDTLS sessions
 *              are supported.
 * @{
 *
 * @file
 * @brief       DTLS session management definition
 *
 * @author      János Brodbeck <janos.brodbeck@ml-pa.com>
 */

#ifndef NET_GCOAP_SESSION_MANAGEMENT_H
#define NET_GCOAP_SESSION_MANAGEMENT_H

#include <stdint.h>
#include "net/sock/dtls.h"
#include "net/gcoap/gcoap.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NO_SESSION = 0,
    HANDSHAKE_ONGOING,
    SESSION_ESTABLISHED
} session_state_t;

/**
 * @brief   Initialize the gcoap DTLS session management
 *
 * Must call once before first use.
 */
void dtls_session_management_init(void);

/**
 * @brief   Stores a session
 *
 * Stores a given session in the internal storage of the session management.
 * If the session is already stored only the state will be updated when the session
 * gets established.
 *
 * @param[in]   session     Session to store
 * @param[in]   new_state   New state of the session
 * @param[out]  prev_state  Previous state of the session. It returns NO_SESSION
 *                          when the session did not exist before.
 *                          Can be NULL if not needed.
 * @param[in]   restore     Indicates, whether the session object should be restored
 *                          when an already established session is found
 *
 * @return   1, on success
 * @return  -1, if no space is available
 */
ssize_t dtls_session_store(sock_dtls_session_t *session,
                           session_state_t new_state,
                           session_state_t *prev_state,
                           bool restore);

/**
 * @brief   Removes a session
 *
 * Removes a given session in the internal storage of the session management.
 *
 * @param[in]  session      Session to store
 *
 * @return  1, on success
 * @return  -1, when no existing session found
 */
ssize_t dtls_session_remove(sock_dtls_session_t *session);

/**
 * @brief   Returns the number of available session slots
 *
 * @return  Number of available session slots in the session management.
 */
uint8_t dtls_session_get_num_available_slots(void);

/**
 * @brief   Returns the oldest used session
 *
 * @param[in]   session     Empty session
 *
 * @return   1, on success
 * @return   -1, when no session is stored
 */
ssize_t dtls_session_get_oldest_used_session(sock_dtls_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* NET_GCOAP_SESSION_MANAGEMENT_H */
/** @} */
