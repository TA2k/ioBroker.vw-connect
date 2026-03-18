.class public abstract Llp/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lij0/a;Lto0/s;)Ljava/util/List;
    .locals 7

    .line 1
    new-instance v0, Ltz/z3;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Ljj0/f;

    .line 7
    .line 8
    const v3, 0x7f120ea5

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const/4 v3, 0x0

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget-object v4, p1, Lto0/s;->a:Lla/w;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move-object v4, v3

    .line 22
    :goto_0
    instance-of v5, v4, Lto0/p;

    .line 23
    .line 24
    sget-object v6, Lto0/r;->a:Lto0/r;

    .line 25
    .line 26
    if-eqz v5, :cond_1

    .line 27
    .line 28
    iget-object v4, p1, Lto0/s;->a:Lla/w;

    .line 29
    .line 30
    check-cast v4, Lto0/p;

    .line 31
    .line 32
    iget-object v4, v4, Lto0/p;->a:Ljava/lang/String;

    .line 33
    .line 34
    goto :goto_2

    .line 35
    :cond_1
    instance-of v5, v4, Lto0/q;

    .line 36
    .line 37
    if-eqz v5, :cond_2

    .line 38
    .line 39
    iget-object v4, p1, Lto0/s;->a:Lla/w;

    .line 40
    .line 41
    check-cast v4, Lto0/q;

    .line 42
    .line 43
    iget-object v4, v4, Lto0/q;->a:Ljava/lang/String;

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    if-nez v5, :cond_4

    .line 51
    .line 52
    if-nez v4, :cond_3

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    new-instance p0, La8/r0;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_4
    :goto_1
    const v4, 0x7f120ea2

    .line 62
    .line 63
    .line 64
    new-array v5, v1, [Ljava/lang/Object;

    .line 65
    .line 66
    invoke-virtual {p0, v4, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    :goto_2
    if-eqz p1, :cond_5

    .line 71
    .line 72
    iget-object v3, p1, Lto0/s;->a:Lla/w;

    .line 73
    .line 74
    :cond_5
    instance-of p1, v3, Lto0/p;

    .line 75
    .line 76
    if-eqz p1, :cond_6

    .line 77
    .line 78
    const p1, 0x7f120ea3

    .line 79
    .line 80
    .line 81
    new-array v3, v1, [Ljava/lang/Object;

    .line 82
    .line 83
    invoke-virtual {p0, p1, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    goto :goto_4

    .line 88
    :cond_6
    instance-of p1, v3, Lto0/q;

    .line 89
    .line 90
    if-eqz p1, :cond_7

    .line 91
    .line 92
    const p1, 0x7f120ea4

    .line 93
    .line 94
    .line 95
    new-array v3, v1, [Ljava/lang/Object;

    .line 96
    .line 97
    invoke-virtual {p0, p1, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    goto :goto_4

    .line 102
    :cond_7
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-nez p1, :cond_9

    .line 107
    .line 108
    if-nez v3, :cond_8

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_8
    new-instance p0, La8/r0;

    .line 112
    .line 113
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :cond_9
    :goto_3
    const-string p1, ""

    .line 118
    .line 119
    :goto_4
    invoke-direct {v0, v2, v4, p1}, Ltz/z3;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    new-instance p1, Ltz/j4;

    .line 123
    .line 124
    const v2, 0x7f120eac

    .line 125
    .line 126
    .line 127
    new-array v3, v1, [Ljava/lang/Object;

    .line 128
    .line 129
    invoke-virtual {p0, v2, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    const v3, 0x7f120eab

    .line 134
    .line 135
    .line 136
    new-array v4, v1, [Ljava/lang/Object;

    .line 137
    .line 138
    invoke-virtual {p0, v3, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-direct {p1, v2, p0}, Ltz/j4;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    const/4 p0, 0x2

    .line 146
    new-array p0, p0, [Ltz/w3;

    .line 147
    .line 148
    aput-object v0, p0, v1

    .line 149
    .line 150
    const/4 v0, 0x1

    .line 151
    aput-object p1, p0, v0

    .line 152
    .line 153
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    return-object p0
.end method

.method public static b(Lgz0/p;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "UTC"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/time/ZoneId;->of(Ljava/lang/String;)Ljava/time/ZoneId;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "of(...)"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "<this>"

    .line 13
    .line 14
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p1, v0}, Ljava/time/format/DateTimeFormatter;->withZone(Ljava/time/ZoneId;)Ljava/time/format/DateTimeFormatter;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0}, Lkp/t9;->e(Lgz0/p;)Lmy0/f;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {p0}, Ljp/ab;->c(Lmy0/f;)Ljava/time/Instant;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p1, p0}, Ljava/time/format/DateTimeFormatter;->format(Ljava/time/temporal/TemporalAccessor;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
