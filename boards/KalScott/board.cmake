# Copyright (c) 2024 Nordic Semiconductor
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

if(CONFIG_KESTREL_NRF9151 OR CONFIG_KESTREL_NRF9151_NS)
  board_runner_args(nrfjprog)
  board_runner_args(nrfutil "--nrf-family=NRF91")
  board_runner_args(jlink "--device=nRF9151_xxAA" "--speed=4000")
endif()

include(${ZEPHYR_BASE}/boards/common/nrfutil.board.cmake)
include(${ZEPHYR_BASE}/boards/common/nrfjprog.board.cmake)
include(${ZEPHYR_BASE}/boards/common/jlink.board.cmake)
