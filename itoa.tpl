i8 itoa: i8 n -> {;
    i8 r = 0;
    whilea(n > 0) {;
        r = mod(n, 10);
        r += 48;
        putc(r);
        n = div(n, 10);
    }whilea;
}itoa;

0 main: -> {;
    i8 p = 3;
    i8 temp = 0;
    whileb(p < 100) {;
        i8 d = 2;
        i8 e = 0;
        whilec(d < p) {;
            temp = mod(p, d);
            ifa(temp == 0) {;e=1;}ifa;
            d += 1;
        }whilec;
        if b(e == 0) {;
            itoa(p);
            putc('\n');
        }if b;
        p += 1;
    }whileb;
}main