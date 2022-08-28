i8 itoa: i8 n -> {;
    i8 p = n;
    i8 r = 0;
    whilea(p > 0) {;
        r = p;
        #r = mod(p, 10);
        r += 48;
        putc(r);
        p = div(p, 10);
    }whilea;
}itoa;

0 main: -> {;
    itoa(10);
}main