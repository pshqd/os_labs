#pragma once

extern "C" {
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}
