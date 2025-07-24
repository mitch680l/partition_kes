#
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

if(SB_CONFIG_BOARD_KESTREL_NRF9151_NS)
  # Use static partition layout to ensure the partition layout remains
  # unchanged after DFU. This needs to be made globally available
  # because it is used in other CMake files.
  if(SB_CONFIG_KESTREL_STATIC_PARTITIONS_FACTORY)
    set(PM_STATIC_YML_FILE ${CMAKE_CURRENT_LIST_DIR}/kestrel_nrf9151_pm_static.yml CACHE INTERNAL "")
  endif()
endif()

