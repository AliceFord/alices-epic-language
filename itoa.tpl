i8 f: i8 g -> {;
    g += 1;
    return g;
}f;

0 main: -> {;
    i8 n = 0;
    n += 48;
    n = f(n);
    putc(n);
}main