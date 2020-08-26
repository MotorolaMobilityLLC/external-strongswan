LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# the executables that should be installed on the final system have to be added
# to PRODUCT_PACKAGES in
#   build/target/product/core.mk
# possible executables are
#   starter - allows to control and configure the daemon from the command line
#   charon - the IKE daemon
#   scepclient - SCEP client

# if you enable starter or scepclient (see above) uncomment the proper
# lines here
# strongswan_BUILD_STARTER := true
# strongswan_BUILD_SCEPCLIENT := true

strongswan_BUILD_VoWiFi := true
strongswan_BUILD_USE_BORINGSSL := true

# this is the list of plugins that are built into libstrongswan and charon
# also these plugins are loaded by default (if not changed in strongswan.conf)
ifneq ($(strongswan_BUILD_VoWiFi),)
strongswan_CHARON_PLUGINS := android-log openssl fips-prf random nonce pubkey \
	pkcs1 pkcs8 pem xcbc hmac kernel-netlink socket-default \
	counters stroke eap-identity eap-mschapv2 eap-md5 eap-gtc
strongswan_CHARON_PLUGINS +=  eap-aka eap-aka-3gpp-simril ctr des
else
strongswan_CHARON_PLUGINS := android-log openssl fips-prf random nonce pubkey \
	pkcs1 pkcs8 pem xcbc hmac kernel-netlink socket-default android-dns \
	counters stroke eap-identity eap-mschapv2 eap-md5 eap-gtc
endif

ifneq ($(strongswan_BUILD_SCEPCLIENT),)
# plugins loaded by scepclient
strongswan_SCEPCLIENT_PLUGINS := openssl curl fips-prf random pkcs1 pkcs7 pem
endif

strongswan_STARTER_PLUGINS := kernel-netlink

# list of all plugins - used to enable them with the function below
strongswan_PLUGINS := $(sort $(strongswan_CHARON_PLUGINS) \
	$(strongswan_STARTER_PLUGINS) \
	$(strongswan_SCEPCLIENT_PLUGINS))

include $(LOCAL_PATH)/Android.common.mk

# includes
strongswan_PATH := $(LOCAL_PATH)
libcurl_PATH := external/strongswan-support/libcurl/include
libgmp_PATH := external/strongswan-support/gmp
ifneq ($(strongswan_BUILD_USE_BORINGSSL),)
openssl_PATH := external/boringssl/include
else
openssl_PATH := external/openssl/include
endif

# some definitions
strongswan_DIR := "/system/bin"
strongswan_SBINDIR := "/system/bin"
strongswan_PIDDIR := "/data/vendor/misc/vpn"
strongswan_PLUGINDIR := "$(strongswan_IPSEC_DIR)/ipsec"
strongswan_CONFDIR := "/system/etc"
strongswan_STRONGSWAN_CONF := "$(strongswan_CONFDIR)/strongswan.conf"

# CFLAGS (partially from a configure run using droid-gcc)
strongswan_CFLAGS := \
	-Wno-error=typedef-redefinition \
	-Wno-error=unused-parameter \
	-Wno-error=unused-variable \
	-Wno-error=unused-function \
	-Wno-error=macro-redefined \
	-Wno-error=implicit-function-declaration \
	-Wno-error=incompatible-pointer-types \
	-Wno-error=int-conversion \
	-Wno-format \
	-Wno-pointer-sign \
	-Wno-pointer-arith \
	-Wno-sign-compare \
	-Wno-strict-aliasing \
	-Wno-error=date-time \
	-DHAVE___BOOL \
	-DHAVE_STDBOOL_H \
	-DHAVE_ALLOCA_H \
	-DHAVE_ALLOCA \
	-DHAVE_CLOCK_GETTIME \
	-DHAVE_DLADDR \
	-DHAVE_PRCTL \
	-DHAVE_LINUX_UDP_H \
	-DHAVE_STRUCT_SADB_X_POLICY_SADB_X_POLICY_PRIORITY \
	-DHAVE_IPSEC_MODE_BEET \
	-DHAVE_IPSEC_DIR_FWD \
	-DOPENSSL_NO_ENGINE \
	-DCONFIG_H_INCLUDED \
	-DMONOLITHIC \
	-DUSE_IKEV1 \
	-DUSE_IKEV2 \
	-DUSE_BUILTIN_PRINTF \
	-DDEBUG \
	-DROUTING_TABLE=0 \
	-DROUTING_TABLE_PRIO=220 \
	-DVERSION=\"$(strongswan_VERSION)\" \
	-DPLUGINDIR=\"$(strongswan_PLUGINDIR)\" \
	-DIPSEC_DIR=\"$(strongswan_DIR)\" \
	-DIPSEC_PIDDIR=\"$(strongswan_PIDDIR)\" \
	-DIPSEC_CONFDIR=\"$(strongswan_CONFDIR)\" \
	-DSTRONGSWAN_CONF=\"$(strongswan_STRONGSWAN_CONF)\" \
	-DDEV_RANDOM=\"/dev/random\" \
	-DDEV_URANDOM=\"/dev/urandom\"

ifeq ($(strongswan_BUILD_VoWiFi),)
strongswan_CFLAGS += \
	-DCAPABILITIES \
	-DCAPABILITIES_NATIVE \

endif
# only for Android 2.0+
strongswan_CFLAGS += \
	-DHAVE_IN6ADDR_ANY \
	-DHAVE_SIGWAITINFO

ifneq ($(strongswan_BUILD_USE_BORINGSSL),)
strongswan_CFLAGS += \
	-DOPENSSL_NO_CHACHA
endif

ifneq ($(strongswan_BUILD_VoWiFi),)
strongswan_BUILD := \
	charon \
	libcharon \
	libstrongswan
else
strongswan_BUILD := \
	charon \
	libcharon \
	libstrongswan \
	libtncif \
	libtnccs \
	libimcv \
	libtpmtss
endif

ifneq ($(strongswan_BUILD_VoWiFi),)
strongswan_CFLAGS += \
	-DVOWIFI_CFG -DVOWIFI_USE_TIMER -DVOWIFI_PMTU_DISCOVERY -DVOWIFI_STRONGSWAN_5_8_2
endif

ifneq ($(strongswan_BUILD_USE_BORINGSSL),)
strongswan_CFLAGS += \
	-DVOWIFI_BORINGSSL
endif

ifneq ($(strongswan_BUILD_STARTER),)
strongswan_BUILD += \
	starter \
	stroke \
	ipsec
endif

ifneq ($(strongswan_BUILD_SCEPCLIENT),)
strongswan_BUILD += \
	scepclient
endif

include $(addprefix $(LOCAL_PATH)/src/,$(addsuffix /Android.mk, \
		$(sort $(strongswan_BUILD))))
