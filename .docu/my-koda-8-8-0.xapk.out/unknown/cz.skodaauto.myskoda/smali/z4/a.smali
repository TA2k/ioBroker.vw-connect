.class public abstract Lz4/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)Llz0/n;
    .locals 9

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p0, :cond_0

    .line 3
    .line 4
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move p0, v0

    .line 10
    :goto_0
    add-int/2addr p0, p5

    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p5, :cond_2

    .line 18
    .line 19
    add-int/lit8 p1, p1, 0x1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const p1, 0x7fffffff

    .line 23
    .line 24
    .line 25
    :cond_2
    :goto_1
    if-eqz p2, :cond_3

    .line 26
    .line 27
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    goto :goto_2

    .line 32
    :cond_3
    const/4 p2, 0x0

    .line 33
    :goto_2
    invoke-static {p1, p2}, Ljava/lang/Math;->min(II)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-lt p0, v1, :cond_4

    .line 38
    .line 39
    invoke-static {p5, p3, p4, p0, p1}, Lz4/a;->b(ZLlz0/a;Ljava/lang/String;II)Llz0/n;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :cond_4
    invoke-static {p5, p3, p4, p0, p0}, Lz4/a;->b(ZLlz0/a;Ljava/lang/String;II)Llz0/n;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    :goto_3
    const-string v3, " "

    .line 49
    .line 50
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 51
    .line 52
    if-ge p0, v1, :cond_5

    .line 53
    .line 54
    new-instance v5, Llz0/n;

    .line 55
    .line 56
    add-int/lit8 p0, p0, 0x1

    .line 57
    .line 58
    invoke-static {p5, p3, p4, p0, p0}, Lz4/a;->b(ZLlz0/a;Ljava/lang/String;II)Llz0/n;

    .line 59
    .line 60
    .line 61
    move-result-object v6

    .line 62
    new-instance v7, Llz0/n;

    .line 63
    .line 64
    new-instance v8, Llz0/o;

    .line 65
    .line 66
    invoke-direct {v8, v3}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-static {v8}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-direct {v7, v3, v4}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 74
    .line 75
    .line 76
    filled-new-array {v7, v2}, [Llz0/n;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-static {v2}, Lvo/a;->b(Ljava/util/List;)Llz0/n;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    filled-new-array {v6, v2}, [Llz0/n;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-direct {v5, v4, v2}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 97
    .line 98
    .line 99
    move-object v2, v5

    .line 100
    goto :goto_3

    .line 101
    :cond_5
    if-le p2, p1, :cond_6

    .line 102
    .line 103
    new-instance p0, Llz0/o;

    .line 104
    .line 105
    sub-int/2addr p2, p1

    .line 106
    invoke-static {p2, v3}, Lly0/w;->s(ILjava/lang/String;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-direct {p0, p1}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    new-instance p1, Llz0/n;

    .line 114
    .line 115
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-direct {p1, p0, v4}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 120
    .line 121
    .line 122
    filled-new-array {p1, v2}, [Llz0/n;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-static {p0}, Lvo/a;->b(Ljava/util/List;)Llz0/n;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :cond_6
    if-ne p2, p1, :cond_7

    .line 136
    .line 137
    return-object v2

    .line 138
    :cond_7
    new-instance p0, Llz0/n;

    .line 139
    .line 140
    add-int/2addr p2, v0

    .line 141
    invoke-static {p5, p3, p4, p2, p1}, Lz4/a;->b(ZLlz0/a;Ljava/lang/String;II)Llz0/n;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    filled-new-array {p1, v2}, [Llz0/n;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-direct {p0, v4, p1}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 154
    .line 155
    .line 156
    return-object p0
.end method

.method public static final b(ZLlz0/a;Ljava/lang/String;II)Llz0/n;
    .locals 8

    .line 1
    add-int/lit8 v0, p0, 0x1

    .line 2
    .line 3
    if-lt p4, v0, :cond_1

    .line 4
    .line 5
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    new-instance v1, Llz0/o;

    .line 12
    .line 13
    const-string v2, "-"

    .line 14
    .line 15
    invoke-direct {v1, v2}, Llz0/o;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    :cond_0
    new-instance v1, Llz0/g;

    .line 22
    .line 23
    new-instance v2, Llz0/u;

    .line 24
    .line 25
    sub-int/2addr p3, p0

    .line 26
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    sub-int/2addr p4, p0

    .line 31
    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 32
    .line 33
    .line 34
    move-result-object v4

    .line 35
    move v7, p0

    .line 36
    move-object v5, p1

    .line 37
    move-object v6, p2

    .line 38
    invoke-direct/range {v2 .. v7}, Llz0/u;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Llz0/a;Ljava/lang/String;Z)V

    .line 39
    .line 40
    .line 41
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-direct {v1, p0}, Llz0/g;-><init>(Ljava/util/List;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0, v1}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    invoke-static {v0}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    new-instance p1, Llz0/n;

    .line 56
    .line 57
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 58
    .line 59
    invoke-direct {p1, p0, p2}, Llz0/n;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 60
    .line 61
    .line 62
    return-object p1

    .line 63
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string p1, "Check failed."

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0
.end method

.method public static c(Ljava/time/OffsetTime;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefault(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {p0, v1}, Ljava/time/OffsetTime;->atDate(Ljava/time/LocalDate;)Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    sget-object v1, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 19
    .line 20
    invoke-static {v1}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1, v0}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p0, v0}, Ljava/time/OffsetDateTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    const-string v0, "format(...)"

    .line 33
    .line 34
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method
