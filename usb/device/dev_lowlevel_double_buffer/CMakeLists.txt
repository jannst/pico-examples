add_executable(dev_lowlevel_double_buffer
        dev_lowlevel.c
        dev_lowlevel_speedtest.c
        )

target_link_libraries(dev_lowlevel_double_buffer PRIVATE pico_stdlib hardware_resets hardware_irq)
pico_add_extra_outputs(dev_lowlevel_double_buffer)

# add url via pico_set_program_url
example_auto_set_url(dev_lowlevel_double_buffer)
