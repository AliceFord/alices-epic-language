i8 itoa: i8 n -> {;
    i8 r = 0;
    while a(n > 0) {;
        r = mod(n, 10);
        r += 48;
        putc(r);
        n = div(n, 10);
    }while a;
}itoa;

0 main: -> {;
    itoa(17);
}main