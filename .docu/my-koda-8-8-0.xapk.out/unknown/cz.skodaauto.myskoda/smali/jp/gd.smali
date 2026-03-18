.class public abstract Ljp/gd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/String;Lb3/g;Lws/a;I)Lp6/b;
    .locals 1

    .line 1
    and-int/lit8 v0, p3, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    :cond_0
    and-int/lit8 p3, p3, 0x4

    .line 7
    .line 8
    if-eqz p3, :cond_1

    .line 9
    .line 10
    sget-object p2, Lp6/a;->f:Lp6/a;

    .line 11
    .line 12
    :cond_1
    sget-object p3, Lvy0/p0;->a:Lcz0/e;

    .line 13
    .line 14
    sget-object p3, Lcz0/d;->e:Lcz0/d;

    .line 15
    .line 16
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {p3, v0}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 21
    .line 22
    .line 23
    move-result-object p3

    .line 24
    invoke-static {p3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    const-string v0, "name"

    .line 29
    .line 30
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    new-instance v0, Lp6/b;

    .line 34
    .line 35
    invoke-direct {v0, p0, p1, p2, p3}, Lp6/b;-><init>(Ljava/lang/String;Lb3/g;Lay0/k;Lvy0/b0;)V

    .line 36
    .line 37
    .line 38
    return-object v0
.end method

.method public static final b(Lb90/c;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "stringResource"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x0

    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :pswitch_0
    new-array p0, v0, [Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Ljj0/f;

    .line 23
    .line 24
    const v0, 0x7f1212e3

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :pswitch_1
    new-array p0, v0, [Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Ljj0/f;

    .line 35
    .line 36
    const v0, 0x7f1212e2

    .line 37
    .line 38
    .line 39
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    :pswitch_2
    new-array p0, v0, [Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, Ljj0/f;

    .line 47
    .line 48
    const v0, 0x7f1212d7

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_3
    new-array p0, v0, [Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p1, Ljj0/f;

    .line 59
    .line 60
    const v0, 0x7f1212d6

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :pswitch_4
    new-array p0, v0, [Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p1, Ljj0/f;

    .line 71
    .line 72
    const v0, 0x7f121294

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :pswitch_5
    new-array p0, v0, [Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p1, Ljj0/f;

    .line 83
    .line 84
    const v0, 0x7f121295

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :pswitch_6
    new-array p0, v0, [Ljava/lang/Object;

    .line 93
    .line 94
    check-cast p1, Ljj0/f;

    .line 95
    .line 96
    const v0, 0x7f1212da

    .line 97
    .line 98
    .line 99
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    return-object p0

    .line 104
    :pswitch_7
    new-array p0, v0, [Ljava/lang/Object;

    .line 105
    .line 106
    check-cast p1, Ljj0/f;

    .line 107
    .line 108
    const v0, 0x7f1212d8

    .line 109
    .line 110
    .line 111
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :pswitch_8
    new-array p0, v0, [Ljava/lang/Object;

    .line 117
    .line 118
    check-cast p1, Ljj0/f;

    .line 119
    .line 120
    const v0, 0x7f1212d9

    .line 121
    .line 122
    .line 123
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    return-object p0

    .line 128
    :pswitch_9
    new-array p0, v0, [Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p1, Ljj0/f;

    .line 131
    .line 132
    const v0, 0x7f1212aa

    .line 133
    .line 134
    .line 135
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    return-object p0

    .line 140
    :pswitch_a
    new-array p0, v0, [Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p1, Ljj0/f;

    .line 143
    .line 144
    const v0, 0x7f1212ae

    .line 145
    .line 146
    .line 147
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_b
    new-array p0, v0, [Ljava/lang/Object;

    .line 153
    .line 154
    check-cast p1, Ljj0/f;

    .line 155
    .line 156
    const v0, 0x7f1212ab

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_c
    new-array p0, v0, [Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p1, Ljj0/f;

    .line 167
    .line 168
    const v0, 0x7f1212ad

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0

    .line 176
    :pswitch_d
    new-array p0, v0, [Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p1, Ljj0/f;

    .line 179
    .line 180
    const v0, 0x7f1212ac

    .line 181
    .line 182
    .line 183
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    return-object p0

    .line 188
    nop

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
