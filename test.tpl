i8 f1: i8 char -> {;
    char += 1;
    return char;
}f1;

0 main: -> {;
    i8 a = 5;
    i8 b = 6;
    ifa(a < b) {;
        putc(f1('y'));
    }ifa;
}main