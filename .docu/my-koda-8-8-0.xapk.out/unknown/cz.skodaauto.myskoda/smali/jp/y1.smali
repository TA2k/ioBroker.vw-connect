.class public abstract Ljp/y1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lmk0/d;Lij0/a;)Ljava/lang/String;
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
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const p0, 0x7f120642

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :pswitch_1
    const p0, 0x7f120651

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :pswitch_2
    const p0, 0x7f120653

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_3
    const p0, 0x7f12064d

    .line 32
    .line 33
    .line 34
    :goto_0
    const/4 v0, 0x0

    .line 35
    new-array v0, v0, [Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Ljj0/f;

    .line 38
    .line 39
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final b(Lc1/i0;JJLc1/f0;Ll2/o;)Lc1/g0;
    .locals 8

    .line 1
    move-object v6, p6

    .line 2
    check-cast v6, Ll2/t;

    .line 3
    .line 4
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p6

    .line 8
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 9
    .line 10
    if-ne p6, v0, :cond_0

    .line 11
    .line 12
    sget p6, Le3/s;->j:I

    .line 13
    .line 14
    invoke-static {p3, p4}, Le3/s;->f(J)Lf3/c;

    .line 15
    .line 16
    .line 17
    move-result-object p6

    .line 18
    sget-object v0, Lb1/c;->l:Lb1/c;

    .line 19
    .line 20
    new-instance v1, La3/f;

    .line 21
    .line 22
    const/4 v2, 0x7

    .line 23
    invoke-direct {v1, p6, v2}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    new-instance p6, Lc1/b2;

    .line 27
    .line 28
    invoke-direct {p6, v0, v1}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v6, p6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    :cond_0
    move-object v3, p6

    .line 35
    check-cast v3, Lc1/b2;

    .line 36
    .line 37
    new-instance v1, Le3/s;

    .line 38
    .line 39
    invoke-direct {v1, p1, p2}, Le3/s;-><init>(J)V

    .line 40
    .line 41
    .line 42
    new-instance v2, Le3/s;

    .line 43
    .line 44
    invoke-direct {v2, p3, p4}, Le3/s;-><init>(J)V

    .line 45
    .line 46
    .line 47
    const v7, 0x38008

    .line 48
    .line 49
    .line 50
    const-string v5, "gaugeBackgroundAnimation"

    .line 51
    .line 52
    move-object v0, p0

    .line 53
    move-object v4, p5

    .line 54
    invoke-static/range {v0 .. v7}, Lc1/d;->j(Lc1/i0;Ljava/lang/Object;Ljava/lang/Object;Lc1/b2;Lc1/f0;Ljava/lang/String;Ll2/o;I)Lc1/g0;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public static final c(Lmk0/d;)Z
    .locals 3

    .line 1
    sget-object v0, Lmk0/d;->d:Lmk0/d;

    .line 2
    .line 3
    sget-object v1, Lmk0/d;->e:Lmk0/d;

    .line 4
    .line 5
    sget-object v2, Lmk0/d;->f:Lmk0/d;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lmk0/d;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {v0, p0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public static final d(Lmk0/d;Lij0/a;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    packed-switch p0, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    new-instance p0, La8/r0;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :pswitch_0
    const p0, 0x7f120710

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_1
    const p0, 0x7f120650

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :pswitch_2
    const p0, 0x7f120652

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :pswitch_3
    const p0, 0x7f12064c

    .line 37
    .line 38
    .line 39
    :goto_0
    const/4 v0, 0x0

    .line 40
    new-array v0, v0, [Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p1, Ljj0/f;

    .line 43
    .line 44
    invoke-virtual {p1, p0, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final e(Ljava/util/Map;ZZLij0/a;)Ljava/util/ArrayList;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Ljava/util/Map$Entry;

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lmk0/d;

    .line 41
    .line 42
    invoke-static {v2}, Ljp/y1;->c(Lmk0/d;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-interface {v0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_1
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 61
    .line 62
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_3

    .line 78
    .line 79
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    check-cast v1, Ljava/util/Map$Entry;

    .line 84
    .line 85
    if-nez p1, :cond_2

    .line 86
    .line 87
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    sget-object v3, Lmk0/d;->f:Lmk0/d;

    .line 92
    .line 93
    if-ne v2, v3, :cond_2

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    invoke-interface {p0, v2, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    new-instance p1, Ljava/util/ArrayList;

    .line 109
    .line 110
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 111
    .line 112
    .line 113
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    :cond_4
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-eqz v0, :cond_9

    .line 126
    .line 127
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    check-cast v0, Ljava/util/Map$Entry;

    .line 132
    .line 133
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    check-cast v1, Lmk0/d;

    .line 138
    .line 139
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    check-cast v0, Ljava/util/List;

    .line 144
    .line 145
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    if-nez v2, :cond_5

    .line 150
    .line 151
    const/4 v2, 0x1

    .line 152
    goto :goto_3

    .line 153
    :cond_5
    const/4 v2, 0x0

    .line 154
    :goto_3
    invoke-static {v0}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    check-cast v0, Lmk0/a;

    .line 159
    .line 160
    invoke-static {v1, p3}, Ljp/y1;->d(Lmk0/d;Lij0/a;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    const/4 v4, 0x0

    .line 165
    if-nez v2, :cond_6

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_6
    move-object v3, v4

    .line 169
    :goto_4
    if-nez v3, :cond_7

    .line 170
    .line 171
    invoke-static {v1, p3}, Ljp/y1;->a(Lmk0/d;Lij0/a;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    :cond_7
    new-instance v5, Ln50/n;

    .line 176
    .line 177
    invoke-direct {v5, v3, v0, v1}, Ln50/n;-><init>(Ljava/lang/String;Lmk0/a;Lmk0/d;)V

    .line 178
    .line 179
    .line 180
    if-nez p2, :cond_8

    .line 181
    .line 182
    if-eqz v2, :cond_8

    .line 183
    .line 184
    goto :goto_5

    .line 185
    :cond_8
    move-object v4, v5

    .line 186
    :goto_5
    if-eqz v4, :cond_4

    .line 187
    .line 188
    invoke-virtual {p1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_9
    return-object p1
.end method
