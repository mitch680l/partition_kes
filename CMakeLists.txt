cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(provision_config)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/fota.c)
target_sources(app PRIVATE src/enc.c)
target_sources(app PRIVATE src/ca.c)
target_sources(app PRIVATE src/aes.c)
target_sources(app PRIVATE src/private.c)
target_sources(app PRIVATE src/public.c)

