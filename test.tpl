0 f1: i8 char -> {;
    putc(char);
}f1;

0 main: -> {;
    i8 c = '1';
    c = '2';
    putc('d');
    while1(c <= '9') {;
        if1 (c == '5') {;
            f1('a');
        }if1;
        putc(c);
        c += 1;
    }while1;
    putc('\n');
}main