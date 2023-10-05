# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: opensync_stats.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x14opensync_stats.proto\x12\x03sts"=\n\x07\x41vgType\x12\x0b\n\x03\x61vg\x18\x01 \x02(\r\x12\x0b\n\x03min\x18\x02 \x01(\r\x12\x0b\n\x03max\x18\x03 \x01(\r\x12\x0b\n\x03num\x18\x04 \x01(\r"C\n\rAvgTypeSigned\x12\x0b\n\x03\x61vg\x18\x01 \x02(\x05\x12\x0b\n\x03min\x18\x02 \x01(\x05\x12\x0b\n\x03max\x18\x03 \x01(\x05\x12\x0b\n\x03num\x18\x04 \x01(\r"\xed\x02\n\x08Neighbor\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12$\n\tscan_type\x18\x02 \x02(\x0e\x32\x11.sts.NeighborType\x12\x14\n\x0ctimestamp_ms\x18\x03 \x01(\x04\x12+\n\x08\x62ss_list\x18\x04 \x03(\x0b\x32\x19.sts.Neighbor.NeighborBss\x12$\n\x0breport_type\x18\x05 \x01(\x0e\x32\x0f.sts.ReportType\x1a\xaf\x01\n\x0bNeighborBss\x12\r\n\x05\x62ssid\x18\x01 \x02(\t\x12\x0c\n\x04ssid\x18\x02 \x01(\t\x12\x0c\n\x04rssi\x18\x03 \x01(\r\x12\x0b\n\x03tsf\x18\x04 \x01(\x04\x12"\n\nchan_width\x18\x05 \x01(\x0e\x32\x0e.sts.ChanWidth\x12\x0f\n\x07\x63hannel\x18\x06 \x02(\r\x12\x1d\n\x06status\x18\x07 \x01(\x0e\x32\r.sts.DiffType\x12\x14\n\x0c\x63_freq0_chan\x18\x08 \x01(\r"\xd3\t\n\x06\x43lient\x12\x13\n\x0bmac_address\x18\x01 \x02(\t\x12\x0c\n\x04ssid\x18\x02 \x01(\t\x12\x11\n\tconnected\x18\x03 \x01(\x08\x12\x15\n\rconnect_count\x18\x04 \x01(\r\x12\x18\n\x10\x64isconnect_count\x18\x05 \x01(\r\x12\x19\n\x11\x63onnect_offset_ms\x18\x06 \x01(\r\x12\x1c\n\x14\x64isconnect_offset_ms\x18\x07 \x01(\r\x12\x13\n\x0b\x64uration_ms\x18\x08 \x01(\r\x12 \n\x05stats\x18\t \x01(\x0b\x32\x11.sts.Client.Stats\x12%\n\x08rx_stats\x18\n \x03(\x0b\x32\x13.sts.Client.RxStats\x12%\n\x08tx_stats\x18\x0b \x03(\x0b\x32\x13.sts.Client.TxStats\x12\'\n\ttid_stats\x18\x0c \x03(\x0b\x32\x14.sts.Client.TidStats\x12\r\n\x05uapsd\x18\r \x01(\r\x12\x12\n\nnetwork_id\x18\x0e \x01(\t\x1a\x85\x02\n\x05Stats\x12\x10\n\x08rx_bytes\x18\x01 \x01(\x04\x12\x10\n\x08tx_bytes\x18\x02 \x01(\x04\x12\x11\n\trx_frames\x18\x03 \x01(\x04\x12\x11\n\ttx_frames\x18\x04 \x01(\x04\x12\x12\n\nrx_retries\x18\x05 \x01(\x04\x12\x12\n\ntx_retries\x18\x06 \x01(\x04\x12\x11\n\trx_errors\x18\x07 \x01(\x04\x12\x11\n\ttx_errors\x18\x08 \x01(\x04\x12\x0f\n\x07rx_rate\x18\t \x01(\x01\x12\x0f\n\x07tx_rate\x18\n \x01(\x01\x12\x0c\n\x04rssi\x18\x0b \x01(\r\x12\x19\n\x11rx_rate_perceived\x18\x0c \x01(\x01\x12\x19\n\x11tx_rate_perceived\x18\r \x01(\x01\x1a\x83\x02\n\x07RxStats\x12\x0b\n\x03mcs\x18\x01 \x02(\r\x12\x0b\n\x03nss\x18\x02 \x02(\r\x12\n\n\x02\x62w\x18\x03 \x02(\r\x12\r\n\x05\x62ytes\x18\x04 \x01(\x04\x12\r\n\x05msdus\x18\x05 \x01(\x04\x12\r\n\x05mpdus\x18\x06 \x01(\x04\x12\r\n\x05ppdus\x18\x07 \x01(\x04\x12\x0f\n\x07retries\x18\x08 \x01(\x04\x12\x0e\n\x06\x65rrors\x18\t \x01(\x04\x12\x0c\n\x04rssi\x18\n \x01(\r\x12\x31\n\nchain_rssi\x18\x0b \x03(\x0b\x32\x1d.sts.Client.RxStats.ChainRSSI\x1a\x34\n\tChainRSSI\x12\r\n\x05\x63hain\x18\x01 \x02(\r\x12\n\n\x02ht\x18\x02 \x02(\r\x12\x0c\n\x04rssi\x18\x03 \x01(\r\x1a\x8c\x01\n\x07TxStats\x12\x0b\n\x03mcs\x18\x01 \x02(\r\x12\x0b\n\x03nss\x18\x02 \x02(\r\x12\n\n\x02\x62w\x18\x03 \x02(\r\x12\r\n\x05\x62ytes\x18\x04 \x01(\x04\x12\r\n\x05msdus\x18\x05 \x01(\x04\x12\r\n\x05mpdus\x18\x06 \x01(\x04\x12\r\n\x05ppdus\x18\x07 \x01(\x04\x12\x0f\n\x07retries\x18\x08 \x01(\x04\x12\x0e\n\x06\x65rrors\x18\t \x01(\x04\x1a\xba\x01\n\x08TidStats\x12-\n\x07sojourn\x18\x04 \x03(\x0b\x32\x1c.sts.Client.TidStats.Sojourn\x12\x11\n\toffset_ms\x18\x05 \x01(\r\x1al\n\x07Sojourn\x12\x16\n\x02\x61\x63\x18\x01 \x02(\x0e\x32\n.sts.WmmAc\x12\x0b\n\x03tid\x18\x02 \x02(\r\x12\x14\n\x0c\x65wma_time_ms\x18\x03 \x01(\r\x12\x13\n\x0bsum_time_ms\x18\x04 \x01(\r\x12\x11\n\tnum_msdus\x18\x05 \x01(\r"\xa6\x01\n\x0c\x43lientReport\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12\x14\n\x0ctimestamp_ms\x18\x02 \x01(\x04\x12 \n\x0b\x63lient_list\x18\x03 \x03(\x0b\x32\x0b.sts.Client\x12\x0f\n\x07\x63hannel\x18\x04 \x02(\r\x12\x13\n\x0buplink_type\x18\x05 \x01(\t\x12\x16\n\x0euplink_changed\x18\x06 \x01(\x08"\x87\x02\n\x15\x43lientAuthFailsReport\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12\x30\n\x08\x62ss_list\x18\x02 \x03(\x0b\x32\x1e.sts.ClientAuthFailsReport.BSS\x1a\x99\x01\n\x03\x42SS\x12\x0e\n\x06ifname\x18\x01 \x02(\t\x12:\n\x0b\x63lient_list\x18\x02 \x03(\x0b\x32%.sts.ClientAuthFailsReport.BSS.Client\x1a\x46\n\x06\x43lient\x12\x13\n\x0bmac_address\x18\x01 \x02(\t\x12\x12\n\nauth_fails\x18\x02 \x02(\r\x12\x13\n\x0binvalid_psk\x18\x03 \x02(\r"\xa8\x05\n\x06Survey\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12$\n\x0bsurvey_type\x18\x02 \x02(\x0e\x32\x0f.sts.SurveyType\x12\x14\n\x0ctimestamp_ms\x18\x03 \x01(\x04\x12-\n\x0bsurvey_list\x18\x04 \x03(\x0b\x32\x18.sts.Survey.SurveySample\x12)\n\nsurvey_avg\x18\x05 \x03(\x0b\x32\x15.sts.Survey.SurveyAvg\x12$\n\x0breport_type\x18\x06 \x01(\x0e\x32\x0f.sts.ReportType\x1a\xdc\x01\n\x0cSurveySample\x12\x0f\n\x07\x63hannel\x18\x01 \x02(\r\x12\x13\n\x0b\x64uration_ms\x18\x02 \x01(\r\x12\x13\n\x0btotal_count\x18\x03 \x01(\r\x12\x14\n\x0csample_count\x18\x04 \x01(\r\x12\x0c\n\x04\x62usy\x18\x05 \x01(\r\x12\x0f\n\x07\x62usy_tx\x18\x06 \x01(\r\x12\x0f\n\x07\x62usy_rx\x18\x07 \x01(\r\x12\x11\n\tbusy_self\x18\x08 \x01(\r\x12\x11\n\toffset_ms\x18\t \x01(\r\x12\x10\n\x08\x62usy_ext\x18\n \x01(\r\x12\x13\n\x0bnoise_floor\x18\x0b \x01(\x05\x1a\xe0\x01\n\tSurveyAvg\x12\x0f\n\x07\x63hannel\x18\x01 \x02(\r\x12\x1a\n\x04\x62usy\x18\x02 \x01(\x0b\x32\x0c.sts.AvgType\x12\x1d\n\x07\x62usy_tx\x18\x03 \x01(\x0b\x32\x0c.sts.AvgType\x12\x1d\n\x07\x62usy_rx\x18\x04 \x01(\x0b\x32\x0c.sts.AvgType\x12\x1f\n\tbusy_self\x18\x05 \x01(\x0b\x32\x0c.sts.AvgType\x12\x1e\n\x08\x62usy_ext\x18\x06 \x01(\x0b\x32\x0c.sts.AvgType\x12\'\n\x0bnoise_floor\x18\x07 \x01(\x0b\x32\x12.sts.AvgTypeSigned"\xbb\x02\n\x08\x43\x61pacity\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12\x14\n\x0ctimestamp_ms\x18\x02 \x01(\x04\x12-\n\nqueue_list\x18\x03 \x03(\x0b\x32\x19.sts.Capacity.QueueSample\x1a\xc7\x01\n\x0bQueueSample\x12\x0f\n\x07\x62usy_tx\x18\x01 \x01(\r\x12\x10\n\x08\x62ytes_tx\x18\x02 \x01(\r\x12\x14\n\x0csample_count\x18\x03 \x01(\r\x12\x10\n\x08Vo_count\x18\x04 \x01(\r\x12\x10\n\x08Vi_count\x18\x05 \x01(\r\x12\x10\n\x08\x42\x65_count\x18\x06 \x01(\r\x12\x10\n\x08\x42k_count\x18\x07 \x01(\r\x12\x11\n\tBcn_count\x18\x08 \x01(\r\x12\x11\n\tCab_count\x18\t \x01(\r\x12\x11\n\toffset_ms\x18\n \x01(\r"\xf5\x08\n\x06\x44\x65vice\x12!\n\x04load\x18\x01 \x01(\x0b\x32\x13.sts.Device.LoadAvg\x12)\n\nradio_temp\x18\x02 \x03(\x0b\x32\x15.sts.Device.RadioTemp\x12\x14\n\x0ctimestamp_ms\x18\x03 \x01(\x04\x12\x0e\n\x06uptime\x18\x04 \x01(\r\x12*\n\rthermal_stats\x18\x05 \x03(\x0b\x32\x13.sts.Device.Thermal\x12%\n\x08mem_util\x18\x06 \x01(\x0b\x32\x13.sts.Device.MemUtil\x12#\n\x07\x66s_util\x18\x07 \x03(\x0b\x32\x12.sts.Device.FsUtil\x12$\n\x07\x63puUtil\x18\x08 \x01(\x0b\x32\x13.sts.Device.CpuUtil\x12/\n\x0bps_cpu_util\x18\t \x03(\x0b\x32\x1a.sts.Device.PerProcessUtil\x12/\n\x0bps_mem_util\x18\n \x03(\x0b\x32\x1a.sts.Device.PerProcessUtil\x12(\n\tpowerInfo\x18\x0b \x01(\x0b\x32\x15.sts.Device.PowerInfo\x12\x19\n\x11used_file_handles\x18\x0c \x01(\r\x12\x1a\n\x12total_file_handles\x18\r \x01(\r\x1a\x35\n\x07LoadAvg\x12\x0b\n\x03one\x18\x01 \x01(\x01\x12\x0c\n\x04\x66ive\x18\x02 \x01(\x01\x12\x0f\n\x07\x66ifteen\x18\x03 \x01(\x01\x1a<\n\tRadioTemp\x12 \n\x04\x62\x61nd\x18\x01 \x01(\x0e\x32\x12.sts.RadioBandType\x12\r\n\x05value\x18\x02 \x01(\x05\x1a\xc8\x01\n\x07Thermal\x12\x39\n\x0btxchainmask\x18\x01 \x03(\x0b\x32$.sts.Device.Thermal.RadioTxChainMask\x12\x0f\n\x07\x66\x61n_rpm\x18\x02 \x01(\r\x12\x14\n\x0ctimestamp_ms\x18\x03 \x01(\x04\x12\x16\n\x0e\x66\x61n_duty_cycle\x18\x04 \x01(\r\x1a\x43\n\x10RadioTxChainMask\x12 \n\x04\x62\x61nd\x18\x01 \x01(\x0e\x32\x12.sts.RadioBandType\x12\r\n\x05value\x18\x02 \x01(\r\x1aU\n\x07MemUtil\x12\x11\n\tmem_total\x18\x01 \x02(\r\x12\x10\n\x08mem_used\x18\x02 \x02(\r\x12\x12\n\nswap_total\x18\x03 \x01(\r\x12\x11\n\tswap_used\x18\x04 \x01(\r\x1aI\n\x06\x46sUtil\x12\x1c\n\x07\x66s_type\x18\x01 \x02(\x0e\x32\x0b.sts.FsType\x12\x10\n\x08\x66s_total\x18\x02 \x02(\r\x12\x0f\n\x07\x66s_used\x18\x03 \x02(\r\x1a\x1b\n\x07\x43puUtil\x12\x10\n\x08\x63pu_util\x18\x01 \x01(\r\x1a\x38\n\x0ePerProcessUtil\x12\x0b\n\x03pid\x18\x01 \x02(\r\x12\x0b\n\x03\x63md\x18\x02 \x02(\t\x12\x0c\n\x04util\x18\x03 \x02(\r\x1a]\n\tPowerInfo\x12%\n\x07ps_type\x18\x01 \x01(\x0e\x32\x14.sts.PowerSupplyType\x12\x15\n\rp_consumption\x18\x02 \x01(\r\x12\x12\n\nbatt_level\x18\x03 \x01(\r"\xca\n\n\x08\x42SClient\x12\x13\n\x0bmac_address\x18\x01 \x02(\t\x12\x32\n\x0e\x62s_band_report\x18\x02 \x03(\x0b\x32\x1a.sts.BSClient.BSBandReport\x1a\xc6\x06\n\x07\x42SEvent\x12\x1e\n\x04type\x18\x01 \x02(\x0e\x32\x10.sts.BSEventType\x12\x11\n\toffset_ms\x18\x02 \x02(\r\x12\x0c\n\x04rssi\x18\x03 \x01(\r\x12\x13\n\x0bprobe_bcast\x18\x04 \x01(\x08\x12\x15\n\rprobe_blocked\x18\x05 \x01(\x08\x12*\n\x0e\x64isconnect_src\x18\x06 \x01(\x0e\x32\x12.sts.DisconnectSrc\x12,\n\x0f\x64isconnect_type\x18\x07 \x01(\x0e\x32\x13.sts.DisconnectType\x12\x19\n\x11\x64isconnect_reason\x18\x08 \x01(\r\x12\x17\n\x0f\x62\x61\x63koff_enabled\x18\t \x01(\x08\x12\x0e\n\x06\x61\x63tive\x18\n \x01(\x08\x12\x10\n\x08rejected\x18\x0b \x01(\x08\x12\x18\n\x10is_BTM_supported\x18\x0c \x01(\x08\x12\x18\n\x10is_RRM_supported\x18\r \x01(\x08\x12\x13\n\x0bmax_chwidth\x18\x0e \x01(\r\x12\x13\n\x0bmax_streams\x18\x0f \x01(\r\x12\x10\n\x08phy_mode\x18\x10 \x01(\r\x12\x0f\n\x07max_mcs\x18\x11 \x01(\r\x12\x13\n\x0bmax_txpower\x18\x12 \x01(\r\x12\x16\n\x0eis_static_smps\x18\x13 \x01(\x08\x12\x1c\n\x14is_mu_mimo_supported\x18\x14 \x01(\x08\x12\x13\n\x0b\x62\x61nd_cap_2G\x18\x15 \x01(\x08\x12\x13\n\x0b\x62\x61nd_cap_5G\x18\x16 \x01(\x08\x12\x1a\n\x12rrm_caps_link_meas\x18\x17 \x01(\x08\x12\x1a\n\x12rrm_caps_neigh_rpt\x18\x18 \x01(\x08\x12 \n\x18rrm_caps_bcn_rpt_passive\x18\x19 \x01(\x08\x12\x1f\n\x17rrm_caps_bcn_rpt_active\x18\x1a \x01(\x08\x12\x1e\n\x16rrm_caps_bcn_rpt_table\x18\x1b \x01(\x08\x12\x19\n\x11rrm_caps_lci_meas\x18\x1c \x01(\x08\x12\x1e\n\x16rrm_caps_ftm_range_rpt\x18\x1d \x01(\x08\x12\x16\n\x0e\x62\x61\x63koff_period\x18\x1e \x01(\r\x12\x11\n\tassoc_ies\x18\x1f \x01(\x0c\x12\x12\n\nbtm_status\x18  \x01(\r\x12\x13\n\x0b\x62\x61nd_cap_6G\x18! \x01(\x08\x1a\xab\x03\n\x0c\x42SBandReport\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12\x11\n\tconnected\x18\x02 \x01(\x08\x12\x0f\n\x07rejects\x18\x03 \x01(\r\x12\x10\n\x08\x63onnects\x18\x04 \x01(\r\x12\x13\n\x0b\x64isconnects\x18\x05 \x01(\r\x12\x18\n\x10\x61\x63tivity_changes\x18\x06 \x01(\r\x12\x1c\n\x14steering_success_cnt\x18\x07 \x01(\r\x12\x19\n\x11steering_fail_cnt\x18\x08 \x01(\r\x12\x19\n\x11steering_kick_cnt\x18\t \x01(\r\x12\x17\n\x0fsticky_kick_cnt\x18\n \x01(\r\x12\x17\n\x0fprobe_bcast_cnt\x18\x0b \x01(\r\x12\x1b\n\x13probe_bcast_blocked\x18\x0c \x01(\r\x12\x18\n\x10probe_direct_cnt\x18\r \x01(\r\x12\x1c\n\x14probe_direct_blocked\x18\x0e \x01(\r\x12)\n\nevent_list\x18\x0f \x03(\x0b\x32\x15.sts.BSClient.BSEvent\x12\x0e\n\x06ifname\x18\x10 \x01(\t"@\n\x08\x42SReport\x12\x14\n\x0ctimestamp_ms\x18\x01 \x02(\x04\x12\x1e\n\x07\x63lients\x18\x02 \x03(\x0b\x32\r.sts.BSClient"\xa1\x02\n\x08RssiPeer\x12\x13\n\x0bmac_address\x18\x01 \x02(\t\x12-\n\x0brssi_source\x18\x02 \x01(\x0e\x32\x18.sts.RssiPeer.RssiSource\x12+\n\trssi_list\x18\x03 \x03(\x0b\x32\x18.sts.RssiPeer.RssiSample\x12\x1e\n\x08rssi_avg\x18\x04 \x01(\x0b\x32\x0c.sts.AvgType\x12\x10\n\x08rx_ppdus\x18\x05 \x01(\x04\x12\x10\n\x08tx_ppdus\x18\x06 \x01(\x04\x1a-\n\nRssiSample\x12\x0c\n\x04rssi\x18\x01 \x02(\r\x12\x11\n\toffset_ms\x18\x02 \x01(\r"1\n\nRssiSource\x12\n\n\x06\x43LIENT\x10\x00\x12\t\n\x05PROBE\x10\x01\x12\x0c\n\x08NEIGHBOR\x10\x02"\x8c\x01\n\nRssiReport\x12 \n\x04\x62\x61nd\x18\x01 \x02(\x0e\x32\x12.sts.RadioBandType\x12$\n\x0breport_type\x18\x02 \x02(\x0e\x32\x0f.sts.ReportType\x12\x14\n\x0ctimestamp_ms\x18\x03 \x01(\x04\x12 \n\tpeer_list\x18\x04 \x03(\x0b\x32\r.sts.RssiPeer"\xce\x04\n\x0cRadiusReport\x12\x14\n\x0ctimestamp_ms\x18\x01 \x01(\x04\x12\x33\n\x0bradius_list\x18\x02 \x03(\x0b\x32\x1e.sts.RadiusReport.RadiusRecord\x1a\xf2\x03\n\x0cRadiusRecord\x12\x10\n\x08vif_name\x18\x01 \x02(\t\x12\x10\n\x08vif_role\x18\x02 \x02(\t\x12\x15\n\rServerAddress\x18\x03 \x02(\t\x12\x13\n\x0bServerIndex\x18\x04 \x02(\r\x12\x1e\n\x16\x43lientServerPortNumber\x18\x05 \x02(\r\x12\x1b\n\x13\x43lientRoundTripTime\x18\x06 \x02(\r\x12\x1c\n\x14\x43lientAccessRequests\x18\x07 \x02(\r\x12#\n\x1b\x43lientAccessRetransmissions\x18\x08 \x02(\r\x12\x1b\n\x13\x43lientAccessAccepts\x18\t \x02(\r\x12\x1b\n\x13\x43lientAccessRejects\x18\n \x02(\r\x12\x1e\n\x16\x43lientAccessChallenges\x18\x0b \x02(\r\x12&\n\x1e\x43lientMalformedAccessResponses\x18\x0c \x02(\r\x12\x1f\n\x17\x43lientBadAuthenticators\x18\r \x02(\r\x12\x1d\n\x15\x43lientPendingRequests\x18\x0e \x02(\r\x12\x16\n\x0e\x43lientTimeouts\x18\x0f \x02(\r\x12\x1a\n\x12\x43lientUnknownTypes\x18\x10 \x02(\r\x12\x1c\n\x14\x43lientPacketsDropped\x18\x11 \x02(\r"\xfd\x02\n\x06Report\x12\x0e\n\x06nodeID\x18\x01 \x02(\t\x12\x1b\n\x06survey\x18\x02 \x03(\x0b\x32\x0b.sts.Survey\x12\x1f\n\x08\x63\x61pacity\x18\x03 \x03(\x0b\x32\r.sts.Capacity\x12 \n\tneighbors\x18\x04 \x03(\x0b\x32\r.sts.Neighbor\x12"\n\x07\x63lients\x18\x05 \x03(\x0b\x32\x11.sts.ClientReport\x12\x1b\n\x06\x64\x65vice\x18\x06 \x03(\x0b\x32\x0b.sts.Device\x12 \n\tbs_report\x18\x07 \x03(\x0b\x32\r.sts.BSReport\x12$\n\x0brssi_report\x18\x08 \x03(\x0b\x32\x0f.sts.RssiReport\x12<\n\x18\x63lient_auth_fails_report\x18\t \x03(\x0b\x32\x1a.sts.ClientAuthFailsReport\x12(\n\rradius_report\x18\n \x03(\x0b\x32\x11.sts.RadiusReport\x12\x12\n\npower_mode\x18\x0b \x01(\t*M\n\rRadioBandType\x12\n\n\x06\x42\x41ND2G\x10\x00\x12\n\n\x06\x42\x41ND5G\x10\x01\x12\x0b\n\x07\x42\x41ND5GL\x10\x02\x12\x0b\n\x07\x42\x41ND5GU\x10\x03\x12\n\n\x06\x42\x41ND6G\x10\x04*7\n\nSurveyType\x12\x0e\n\nON_CHANNEL\x10\x00\x12\x0f\n\x0bOFF_CHANNEL\x10\x01\x12\x08\n\x04\x46ULL\x10\x02*@\n\x0cNeighborType\x12\x0f\n\x0bONCHAN_SCAN\x10\x00\x12\x10\n\x0cOFFCHAN_SCAN\x10\x01\x12\r\n\tFULL_SCAN\x10\x02*\xe9\x01\n\tChanWidth\x12\x16\n\x12\x43HAN_WIDTH_UNKNOWN\x10\x00\x12\x14\n\x10\x43HAN_WIDTH_20MHZ\x10\x01\x12\x14\n\x10\x43HAN_WIDTH_40MHZ\x10\x02\x12\x1a\n\x16\x43HAN_WIDTH_40MHZ_ABOVE\x10\x03\x12\x1a\n\x16\x43HAN_WIDTH_40MHZ_BELOW\x10\x04\x12\x14\n\x10\x43HAN_WIDTH_80MHZ\x10\x05\x12\x15\n\x11\x43HAN_WIDTH_160MHZ\x10\x06\x12\x1c\n\x18\x43HAN_WIDTH_80_PLUS_80MHZ\x10\x07\x12\x15\n\x11\x43HAN_WIDTH_320MHZ\x10\x08*C\n\x05WmmAc\x12\r\n\tWMM_AC_VO\x10\x01\x12\r\n\tWMM_AC_VI\x10\x02\x12\r\n\tWMM_AC_BE\x10\x03\x12\r\n\tWMM_AC_BK\x10\x04*\xfb\x04\n\x0b\x42SEventType\x12\t\n\x05PROBE\x10\x00\x12\x0b\n\x07\x43ONNECT\x10\x01\x12\x0e\n\nDISCONNECT\x10\x02\x12\x0b\n\x07\x42\x41\x43KOFF\x10\x03\x12\x0c\n\x08\x41\x43TIVITY\x10\x04\x12\x0b\n\x07OVERRUN\x10\x05\x12\x19\n\x15\x42\x41ND_STEERING_ATTEMPT\x10\x06\x12\x1b\n\x17\x43LIENT_STEERING_ATTEMPT\x10\x07\x12\x1b\n\x17\x43LIENT_STEERING_STARTED\x10\x08\x12\x1c\n\x18\x43LIENT_STEERING_DISABLED\x10\t\x12\x1b\n\x17\x43LIENT_STEERING_EXPIRED\x10\n\x12\x1a\n\x16\x43LIENT_STEERING_FAILED\x10\x0b\x12\x0e\n\nAUTH_BLOCK\x10\x0c\x12\x11\n\rCLIENT_KICKED\x10\r\x12\x11\n\rCLIENT_BS_BTM\x10\x0e\x12\x15\n\x11\x43LIENT_STICKY_BTM\x10\x0f\x12\x0e\n\nCLIENT_BTM\x10\x10\x12\x17\n\x13\x43LIENT_CAPABILITIES\x10\x11\x12\x17\n\x13\x43LIENT_BS_BTM_RETRY\x10\x12\x12\x1b\n\x17\x43LIENT_STICKY_BTM_RETRY\x10\x13\x12\x14\n\x10\x43LIENT_BTM_RETRY\x10\x14\x12\x16\n\x12\x43LIENT_RRM_BCN_RPT\x10\x15\x12\x12\n\x0e\x43LIENT_BS_KICK\x10\x16\x12\x16\n\x12\x43LIENT_STICKY_KICK\x10\x17\x12\x1b\n\x17\x43LIENT_SPECULATIVE_KICK\x10\x18\x12\x18\n\x14\x43LIENT_DIRECTED_KICK\x10\x19\x12\x1c\n\x18\x43LIENT_GHOST_DEVICE_KICK\x10\x1a\x12\x15\n\x11\x43LIENT_BTM_STATUS\x10\x1b*&\n\rDisconnectSrc\x12\t\n\x05LOCAL\x10\x00\x12\n\n\x06REMOTE\x10\x01**\n\x0e\x44isconnectType\x12\x0c\n\x08\x44ISASSOC\x10\x00\x12\n\n\x06\x44\x45\x41UTH\x10\x01*K\n\nReportType\x12\x07\n\x03RAW\x10\x00\x12\x0b\n\x07\x41VERAGE\x10\x01\x12\r\n\tHISTOGRAM\x10\x02\x12\x0e\n\nPERCENTILE\x10\x03\x12\x08\n\x04\x44IFF\x10\x04*/\n\x06\x46sType\x12\x12\n\x0e\x46S_TYPE_ROOTFS\x10\x00\x12\x11\n\rFS_TYPE_TMPFS\x10\x01*"\n\x08\x44iffType\x12\t\n\x05\x41\x44\x44\x45\x44\x10\x00\x12\x0b\n\x07REMOVED\x10\x01*r\n\x0fPowerSupplyType\x12\x13\n\x0fPS_TYPE_UNKNOWN\x10\x00\x12\x0e\n\nPS_TYPE_AC\x10\x01\x12\x13\n\x0fPS_TYPE_BATTERY\x10\x02\x12\x0f\n\x0bPS_TYPE_POE\x10\x03\x12\x14\n\x10PS_TYPE_POE_PLUS\x10\x04'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "opensync_stats_pb2", globals())
if _descriptor._USE_C_DESCRIPTORS is False:
    DESCRIPTOR._options = None
    _RADIOBANDTYPE._serialized_start = 7182
    _RADIOBANDTYPE._serialized_end = 7259
    _SURVEYTYPE._serialized_start = 7261
    _SURVEYTYPE._serialized_end = 7316
    _NEIGHBORTYPE._serialized_start = 7318
    _NEIGHBORTYPE._serialized_end = 7382
    _CHANWIDTH._serialized_start = 7385
    _CHANWIDTH._serialized_end = 7618
    _WMMAC._serialized_start = 7620
    _WMMAC._serialized_end = 7687
    _BSEVENTTYPE._serialized_start = 7690
    _BSEVENTTYPE._serialized_end = 8325
    _DISCONNECTSRC._serialized_start = 8327
    _DISCONNECTSRC._serialized_end = 8365
    _DISCONNECTTYPE._serialized_start = 8367
    _DISCONNECTTYPE._serialized_end = 8409
    _REPORTTYPE._serialized_start = 8411
    _REPORTTYPE._serialized_end = 8486
    _FSTYPE._serialized_start = 8488
    _FSTYPE._serialized_end = 8535
    _DIFFTYPE._serialized_start = 8537
    _DIFFTYPE._serialized_end = 8571
    _POWERSUPPLYTYPE._serialized_start = 8573
    _POWERSUPPLYTYPE._serialized_end = 8687
    _AVGTYPE._serialized_start = 29
    _AVGTYPE._serialized_end = 90
    _AVGTYPESIGNED._serialized_start = 92
    _AVGTYPESIGNED._serialized_end = 159
    _NEIGHBOR._serialized_start = 162
    _NEIGHBOR._serialized_end = 527
    _NEIGHBOR_NEIGHBORBSS._serialized_start = 352
    _NEIGHBOR_NEIGHBORBSS._serialized_end = 527
    _CLIENT._serialized_start = 530
    _CLIENT._serialized_end = 1765
    _CLIENT_STATS._serialized_start = 910
    _CLIENT_STATS._serialized_end = 1171
    _CLIENT_RXSTATS._serialized_start = 1174
    _CLIENT_RXSTATS._serialized_end = 1433
    _CLIENT_RXSTATS_CHAINRSSI._serialized_start = 1381
    _CLIENT_RXSTATS_CHAINRSSI._serialized_end = 1433
    _CLIENT_TXSTATS._serialized_start = 1436
    _CLIENT_TXSTATS._serialized_end = 1576
    _CLIENT_TIDSTATS._serialized_start = 1579
    _CLIENT_TIDSTATS._serialized_end = 1765
    _CLIENT_TIDSTATS_SOJOURN._serialized_start = 1657
    _CLIENT_TIDSTATS_SOJOURN._serialized_end = 1765
    _CLIENTREPORT._serialized_start = 1768
    _CLIENTREPORT._serialized_end = 1934
    _CLIENTAUTHFAILSREPORT._serialized_start = 1937
    _CLIENTAUTHFAILSREPORT._serialized_end = 2200
    _CLIENTAUTHFAILSREPORT_BSS._serialized_start = 2047
    _CLIENTAUTHFAILSREPORT_BSS._serialized_end = 2200
    _CLIENTAUTHFAILSREPORT_BSS_CLIENT._serialized_start = 2130
    _CLIENTAUTHFAILSREPORT_BSS_CLIENT._serialized_end = 2200
    _SURVEY._serialized_start = 2203
    _SURVEY._serialized_end = 2883
    _SURVEY_SURVEYSAMPLE._serialized_start = 2436
    _SURVEY_SURVEYSAMPLE._serialized_end = 2656
    _SURVEY_SURVEYAVG._serialized_start = 2659
    _SURVEY_SURVEYAVG._serialized_end = 2883
    _CAPACITY._serialized_start = 2886
    _CAPACITY._serialized_end = 3201
    _CAPACITY_QUEUESAMPLE._serialized_start = 3002
    _CAPACITY_QUEUESAMPLE._serialized_end = 3201
    _DEVICE._serialized_start = 3204
    _DEVICE._serialized_end = 4345
    _DEVICE_LOADAVG._serialized_start = 3683
    _DEVICE_LOADAVG._serialized_end = 3736
    _DEVICE_RADIOTEMP._serialized_start = 3738
    _DEVICE_RADIOTEMP._serialized_end = 3798
    _DEVICE_THERMAL._serialized_start = 3801
    _DEVICE_THERMAL._serialized_end = 4001
    _DEVICE_THERMAL_RADIOTXCHAINMASK._serialized_start = 3934
    _DEVICE_THERMAL_RADIOTXCHAINMASK._serialized_end = 4001
    _DEVICE_MEMUTIL._serialized_start = 4003
    _DEVICE_MEMUTIL._serialized_end = 4088
    _DEVICE_FSUTIL._serialized_start = 4090
    _DEVICE_FSUTIL._serialized_end = 4163
    _DEVICE_CPUUTIL._serialized_start = 4165
    _DEVICE_CPUUTIL._serialized_end = 4192
    _DEVICE_PERPROCESSUTIL._serialized_start = 4194
    _DEVICE_PERPROCESSUTIL._serialized_end = 4250
    _DEVICE_POWERINFO._serialized_start = 4252
    _DEVICE_POWERINFO._serialized_end = 4345
    _BSCLIENT._serialized_start = 4348
    _BSCLIENT._serialized_end = 5702
    _BSCLIENT_BSEVENT._serialized_start = 4434
    _BSCLIENT_BSEVENT._serialized_end = 5272
    _BSCLIENT_BSBANDREPORT._serialized_start = 5275
    _BSCLIENT_BSBANDREPORT._serialized_end = 5702
    _BSREPORT._serialized_start = 5704
    _BSREPORT._serialized_end = 5768
    _RSSIPEER._serialized_start = 5771
    _RSSIPEER._serialized_end = 6060
    _RSSIPEER_RSSISAMPLE._serialized_start = 5964
    _RSSIPEER_RSSISAMPLE._serialized_end = 6009
    _RSSIPEER_RSSISOURCE._serialized_start = 6011
    _RSSIPEER_RSSISOURCE._serialized_end = 6060
    _RSSIREPORT._serialized_start = 6063
    _RSSIREPORT._serialized_end = 6203
    _RADIUSREPORT._serialized_start = 6206
    _RADIUSREPORT._serialized_end = 6796
    _RADIUSREPORT_RADIUSRECORD._serialized_start = 6298
    _RADIUSREPORT_RADIUSRECORD._serialized_end = 6796
    _REPORT._serialized_start = 6799
    _REPORT._serialized_end = 7180
# @@protoc_insertion_point(module_scope)
