0 main: i16 a, i64 b -> {;
    i8 c = 97;  # i8 is a character (single byte)
    putc(c);  # putc is compiler defined, it is the same as __putc
}main

### The code above and below do the same (bottom has no main function yet though)

0main:i16a,i64b->{;i8c=97;putc(c);}main