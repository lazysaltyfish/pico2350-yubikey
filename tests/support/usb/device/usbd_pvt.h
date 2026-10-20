/* SPDX-License-Identifier: AGPL-3.0-only */
#pragma once
#include <stdbool.h>
#include <stdint.h>

/* USB descriptor and driver shapes needed only to compile the production
 * CCID callbacks. All endpoint and vendor functions below are host mocks. */
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define TUSB_CLASS_SMART_CARD 0x0B
#define TUSB_CLASS_VENDOR_SPECIFIC 0xFF
#define CONTROL_STAGE_SETUP 0
#define TU_VERIFY(condition, value) do { if (!(condition)) return (value); } while (0)
#define TU_ASSERT(condition, value) TU_VERIFY(condition, value)
#define TU_LOG2(...) ((void)0)
typedef struct {
    uint8_t bLength, bDescriptorType, bInterfaceNumber, bAlternateSetting;
    uint8_t bNumEndpoints, bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol, iInterface;
} tusb_desc_interface_t;
typedef struct {
    uint8_t bLength, bDescriptorType, bEndpointAddress, bmAttributes;
    uint16_t wMaxPacketSize;
    uint8_t bInterval;
} __attribute__((packed)) tusb_desc_endpoint_t;
typedef struct {
    uint8_t bmRequestType, bRequest;
    uint16_t wValue, wIndex, wLength;
} tusb_control_request_t;
typedef enum { XFER_RESULT_SUCCESS } xfer_result_t;
typedef struct {
    void (*init)(void);
    void (*reset)(uint8_t);
    uint16_t (*open)(uint8_t, const tusb_desc_interface_t *, uint16_t);
    bool (*control_xfer_cb)(uint8_t, uint8_t, const tusb_control_request_t *);
    bool (*xfer_cb)(uint8_t, uint8_t, xfer_result_t, uint32_t);
    void *sof;
} usbd_class_driver_t;
uint32_t tud_vendor_n_available(uint8_t itf);
uint32_t tud_vendor_n_read(uint8_t itf, void *data, uint32_t size);
uint32_t tud_vendor_n_write(uint8_t itf, const void *data, uint32_t size);
uint32_t tud_vendor_n_write_flush(uint8_t itf);
void vendord_init(void);
void vendord_reset(uint8_t rhport);
uint16_t vendord_open(uint8_t rhport, const tusb_desc_interface_t *descriptor, uint16_t size);
bool vendord_xfer_cb(uint8_t rhport, uint8_t endpoint, xfer_result_t result, uint32_t size);
bool usbd_edpt_open(uint8_t rhport, const tusb_desc_endpoint_t *endpoint);
bool usbd_edpt_xfer(uint8_t rhport, uint8_t endpoint, uint8_t *data, uint16_t size);
