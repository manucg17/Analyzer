diff --git a/COMSoft/Apps/CTM/src/vhKeeperClient.cpp b/COMSoft/Apps/CTM/src/vhKeeperClient.cpp
index 1c8253cca5..d1eb09d3af 100644
--- a/COMSoft/Apps/CTM/src/vhKeeperClient.cpp
+++ b/COMSoft/Apps/CTM/src/vhKeeperClient.cpp
@@ -1311,8 +1311,6 @@ int vhKeeperClient::checkMgmtPortStatusTimerCb(void *pCbData)
                                }
                                else {
                                        ctmMgr::instance().endUpdate(true); // Update LTM about the change.
-                                       pMgmtPortInfo->provisionNumber = ctmMgr::instance().getProvisionNumberForSlot(newActivePortInfo->sfcSlotNum);
-                                       NE_DEBUG(DL_INFO,("Provision number in recovery: %d", pMgmtPortInfo->provisionNumber));
                                }

        //                      mgmtState = MGMT_PORT_DOWN;
diff --git a/COMSoft/Apps/LTM/src/PortsHandlerExtSwitch.cpp b/COMSoft/Apps/LTM/src/PortsHandlerExtSwitch.cpp
index 146604023a..b5f75d8455 100644
--- a/COMSoft/Apps/LTM/src/PortsHandlerExtSwitch.cpp
+++ b/COMSoft/Apps/LTM/src/PortsHandlerExtSwitch.cpp
@@ -399,7 +399,7 @@ LtmStatus PortsHandlerExtSwitch::checkIfSwitchExist()
                m_switchConnected = CONNECTION_STATUS_NOT_CONNECTED;
        }

-       NE_DEBUG(DL_ERROR, ("%s: Switch was determined to be [%s].", __func__, m_switchConnected));
+       NE_DEBUG(DL_ERROR, ("%s: Switch was determined to be [%d].", __func__, m_switchConnected));^M

        return LTM_OK_E;
 }
diff --git a/COMSoft/Apps/LTM/src/ctmClientListener.cpp b/COMSoft/Apps/LTM/src/ctmClientListener.cpp
index 7bfbfd7273..bf958c13c3 100644
--- a/COMSoft/Apps/LTM/src/ctmClientListener.cpp
+++ b/COMSoft/Apps/LTM/src/ctmClientListener.cpp
@@ -212,6 +212,7 @@ LtmStatus ctmClientListener::sendPortStatusMsg(ctmCommPortStatusMsg *pPortStatus

        pPortStatusReply->numOfPorts = pPortStatus->numOfPorts;
        memcpy(pPortStatusReply->portStateInfo, pPortStatus->portStateInfo , portStatusInfoSize );
+       NE_DEBUG(DL_INFO, ("%s: actual admin [in] %d, actual admin [ass] %d", __func__, pPortStatusReply->portStateInfo->portStatusAttr.actualAdminState, pPortStatus->portStateInfo->portStatusAttr.actualAdminState));^M
        h2nPortStatusMsg(pPortStatusReply);

        // send port status reply to CTM server
diff --git a/COMSoft/Apps/LTM/src/ltmMgr.cpp b/COMSoft/Apps/LTM/src/ltmMgr.cpp
index 6093290ed5..b9040bcbe7 100644
--- a/COMSoft/Apps/LTM/src/ltmMgr.cpp
+++ b/COMSoft/Apps/LTM/src/ltmMgr.cpp
@@ -306,12 +306,12 @@ LtmStatus ltmMgr::reportPortStatusChangeToCtm(PortInfo aPortInfo, PortStatusAttr
        memcpy(&portStatus.portStateInfo[0].portStatusAttr, pPortAttr, sizeof(PortStatusAttributes));

        retVal = m_ctmClient.sendPortStatusMsg(&portStatus);
-       NE_DBG_F(DL_INFO,"Sent event to CTM: [%s] is %s, CH%d speed [%s] mode [%s], capabilities [%x]",
+       NE_DBG_F(DL_INFO,"Sent event to CTM: [%s] is %s, CH%d speed [%s] mode [%s], capabilities [%x], actualAdmin= [%d], in actualAdmin [%d]",^M
                                                m_pPortsHandler->portNameFromDbGet(aPortInfo), portStatusToString(portStatus.portStateInfo[0].portStatusAttr.portState),
                                                portStatus.portStateInfo[0].port.channel_id,
                                                portSpeedToString(portStatus.portStateInfo[0].portStatusAttr.speed),
                                                portDuplexModeToString(portStatus.portStateInfo[0].portStatusAttr.mode),
-                                               portStatus.portStateInfo[0].portStatusAttr.caps);
+                                               portStatus.portStateInfo[0].portStatusAttr.caps, portStatus.portStateInfo[0].portStatusAttr.actualAdminState, pPortAttr->actualAdminState);^M
        return retVal;
 }

diff --git a/build/build-scripts/xg-make_ci.sh b/build/build-scripts/xg-make_ci.sh
index 09ebd4294b..5e32593dea 100755
--- a/build/build-scripts/xg-make_ci.sh
+++ b/build/build-scripts/xg-make_ci.sh
@@ -785,7 +785,7 @@ prepare_install_dir_for_archive()

     local user=$(id -un)
     # If user is not 'build' then add an indication of "private build".
-    [ "$user" != "build" ] && sed -i "1s/$/ \(Private: $user\)/" $INSTALLROOT/opt/allot/conf/actype
+    [ "$user" != "build" ] && sed -i "1s/$/ \(Priv: $user\)/" $INSTALLROOT/opt/allot/conf/actype
   fi
   ################################
   return 0
