# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# lcd_display.py - LCD rendering for Q1's 320x240 pixel *colour* display!
#
import machine, uzlib, ckcc, utime, struct, array, sys
from version import is_devmode
import framebuf
import uasyncio
from uasyncio import sleep_ms
from graphics import Graphics
import sram2
from st7788 import ST7788

# we support 4 fonts
from zevvpeep import FontSmall, FontLarge, FontTiny
FontFixed = object()    # ugly 8x8 PET font

# free unused screen buffers, we will make bigger ones
del sram2.display_buf
del sram2.display2_buf

# one byte per pixel; fixed palette maps to BGR565 in C code
display2_buf = bytearray(320 * 240)

class Display:

    WIDTH = 320
    HEIGHT = 240

    # use these negative X values for auto layout features
    CENTER = -2
    RJUST = -1

    def __init__(self):
        self.dis = ST7788()

        self.last_bar_update = 0
        self.clear()
        self.show()

    def width(self, msg, font):
        if font == FontFixed:
            return len(msg) * 8
        else:
            return sum(font.lookup(ord(ch)).w for ch in msg)

    def icon(self, x, y, name, invert=0):
        if isinstance(name, tuple):
            w,h, bw, wbits, data = name
        else:
            # see graphics.py (auto generated file) for names
            w,h, bw, wbits, data = getattr(Graphics, name)

        if wbits:
            data = uzlib.decompress(data, wbits)

        if invert:
            data = bytearray(i^0xff for i in data)

        gly = framebuf.FrameBuffer(bytearray(data), w, h, framebuf.MONO_HLSB)
        self.dis.blit(gly, x, y, invert)

        return (w, h)

    def text(self, x,y, msg, font=FontSmall, invert=0):
        # Draw at x,y (top left corner of first letter)
        # using font. Use invert=1 to get reverse video

        if x is None or x < 0:
            # center/rjust
            w = self.width(msg, font)
            if x == None:
                x = max(0, (self.WIDTH - w) // 2)
            else:
                # measure from right edge (right justify)
                x = max(0, self.WIDTH - w + 1 + x)

        if y < 0:
            # measure up from bottom edge
            y = self.HEIGHT - font.height + 1 + y

        if font == FontFixed:
            # use font provided by Micropython: 8x8
            self.dis.text(msg, x, y)

            return x + (len(msg) * 8)

        for ch in msg:
            fn = font.lookup(ord(ch))
            if fn is None:
                # use last char in font as error char for junk we don't
                # know how to render
                fn = font.lookup(font.code_range.stop)
            bits = bytearray(fn.w * fn.h)
            bits[0:len(fn.bits)] = fn.bits
            if invert:
                bits = bytearray(i^0xff for i in bits)
            gly = framebuf.FrameBuffer(bits, fn.w, fn.h, framebuf.MONO_HLSB)
            self.dis.blit(gly, x, y, invert)
            x += fn.w

        return x

    def clear(self):
        self.dis.fill(0x0)

    def clear_rect(self, x,y, w,h):
        self.dis.fill_rect(x,y, w,h, 0)

    def show(self):
        self.dis.show()

    # rather than clearing and redrawing, use this buffer w/ fixed parts of screen
    def save(self):
        display2_buf[:] = self.dis.buffer
    def restore(self):
        self.dis.buffer[:] = display2_buf

    def hline(self, y):
        self.dis.line(0, y, self.WIDTH, y, 1)
    def vline(self, x):
        self.dis.line(x, 0, x, self.HEIGHT, 1)

    def scroll_bar(self, fraction):
        # along right edge
        self.dis.fill_rect(self.WIDTH-5, 0, 5, self.HEIGHT, 0)
        #self.icon(self.WIDTH-3, 1, 'scroll');      // dots + arrow
        mm = self.HEIGHT-6
        pos = min(int(mm*fraction), mm)
        self.dis.fill_rect(self.WIDTH-2, pos, 1, 16, 1)

        if is_devmode and not ckcc.is_simulator():
            self.dis.fill_rect(self.WIDTH-6, 20, 5, 21, 1)
            self.text(-2, 21, 'D', font=FontTiny, invert=1)
            self.text(-2, 28, 'E', font=FontTiny, invert=1)
            self.text(-2, 35, 'V', font=FontTiny, invert=1)

    def fullscreen(self, msg, percent=None):
        # show a simple message "fullscreen". 
        self.clear()
        y = 60
        self.text(None, y, msg, font=FontLarge)
        if percent is not None:
            self.progress_bar(percent)
        self.show()

    def splash(self):
        # display a splash screen with some version numbers
        self.clear()
        y = 40
        self.text(None,    y, 'COLDCARD Q1', font=FontLarge)
        self.text(None, y+20, 'Wallet', font=FontLarge)

        from version import get_mpy_version
        timestamp, label, *_ = get_mpy_version()

        y = self.HEIGHT-10
        self.text(0,  y, 'Version '+label, font=FontTiny)
        self.text(-1, y, timestamp, font=FontTiny)
        
        self.show()

    def progress_bar(self, percent):
        # Horizontal progress bar
        # takes 0.0 .. 1.0 as fraction of doneness
        percent = max(0, min(1.0, percent))
        self.dis.hline(0, self.HEIGHT-1, int(self.WIDTH * percent), 1)

    def progress_sofar(self, done, total):
        # Update progress bar, but only if it's been a while since last update
        if utime.ticks_diff(utime.ticks_ms(), self.last_bar_update) < 100:
            return
        self.last_bar_update = utime.ticks_ms()
        self.progress_bar_show(done / total)

    def progress_bar_show(self, percent):
        # useful as a callback
        self.progress_bar(percent)
        self.dis.show_partial(self.HEIGHT-1, 1)

    def mark_sensitive(self, from_y, to_y):
        wx = self.WIDTH-4       # avoid scroll bar
        for y in range(from_y, to_y):
            ln = max(2, ckcc.rng() % 32)
            self.dis.line(wx-ln, y, wx, y, 1)

    def busy_bar(self, enable, speed_code=5):
        print("busy_bar")       # XXX TODO not obvious how to do on this platform
        if not enable:
            self.show()
        return

    def set_brightness(self, val):
        # normal = 0x7f, brightness=0xff, dim=0x00 (but they are all very similar)
        # XXX maybe control BL_ENABLE timing
        return 

# EOF
