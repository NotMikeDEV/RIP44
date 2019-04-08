include $(TOPDIR)/rules.mk

PKG_NAME:=rip44
PKG_VERSION:=2019.04.07
PKG_RELEASE:=1
SOURCE_DIR:=..

include $(INCLUDE_DIR)/package.mk

define Package/rip44
	SECTION:=networks
	CATEGORY:=Network
	TITLE:=AMPR RIP44 Daemon
	DEPENDS:=+luasocket +ip +ipip
	MAINTAINER:=Mike Jones <m6xcv@m6xcv.uk>
	PKGARCH:=all
endef

define Package/rip44/description
	A RIP44 daemon for the AMPR network.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp $(SOURCE_DIR)/rip44.* $(PKG_BUILD_DIR)
endef
define Build/Compile
endef

define Package/rip44/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_BUILD_DIR)/rip44.lua $(1)/usr/sbin
	chmod +x $(1)/usr/sbin/rip44.lua
	$(INSTALL_DIR) $(1)/etc/
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/rip44.conf $(1)/etc/rip44.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/rip44.init $(1)/etc/init.d/rip44
endef

$(eval $(call BuildPackage,rip44))