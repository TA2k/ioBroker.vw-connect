.class public abstract Ljp/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(ZILeb/a;JJIZJJJJ)J
    .locals 3

    .line 1
    const-string v0, "backoffPolicy"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide v0, 0x7fffffffffffffffL

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    cmp-long v2, p15, v0

    .line 12
    .line 13
    if-eqz v2, :cond_2

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    if-nez p7, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const-wide/32 p0, 0xdbba0

    .line 21
    .line 22
    .line 23
    add-long/2addr p5, p0

    .line 24
    cmp-long p0, p15, p5

    .line 25
    .line 26
    if-gez p0, :cond_1

    .line 27
    .line 28
    return-wide p5

    .line 29
    :cond_1
    :goto_0
    return-wide p15

    .line 30
    :cond_2
    if-eqz p0, :cond_5

    .line 31
    .line 32
    sget-object p0, Leb/a;->e:Leb/a;

    .line 33
    .line 34
    if-ne p2, p0, :cond_3

    .line 35
    .line 36
    int-to-long p0, p1

    .line 37
    mul-long/2addr p3, p0

    .line 38
    goto :goto_1

    .line 39
    :cond_3
    long-to-float p0, p3

    .line 40
    add-int/lit8 p1, p1, -0x1

    .line 41
    .line 42
    invoke-static {p0, p1}, Ljava/lang/Math;->scalb(FI)F

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    float-to-long p3, p0

    .line 47
    :goto_1
    const-wide/32 p0, 0x112a880

    .line 48
    .line 49
    .line 50
    cmp-long p2, p3, p0

    .line 51
    .line 52
    if-lez p2, :cond_4

    .line 53
    .line 54
    move-wide p3, p0

    .line 55
    :cond_4
    add-long/2addr p5, p3

    .line 56
    return-wide p5

    .line 57
    :cond_5
    if-eqz p8, :cond_8

    .line 58
    .line 59
    if-nez p7, :cond_6

    .line 60
    .line 61
    add-long/2addr p5, p9

    .line 62
    goto :goto_2

    .line 63
    :cond_6
    add-long p5, p5, p13

    .line 64
    .line 65
    :goto_2
    cmp-long p0, p11, p13

    .line 66
    .line 67
    if-eqz p0, :cond_7

    .line 68
    .line 69
    if-nez p7, :cond_7

    .line 70
    .line 71
    sub-long p0, p13, p11

    .line 72
    .line 73
    add-long/2addr p0, p5

    .line 74
    return-wide p0

    .line 75
    :cond_7
    return-wide p5

    .line 76
    :cond_8
    const-wide/16 p0, -0x1

    .line 77
    .line 78
    cmp-long p0, p5, p0

    .line 79
    .line 80
    if-nez p0, :cond_9

    .line 81
    .line 82
    return-wide v0

    .line 83
    :cond_9
    add-long/2addr p5, p9

    .line 84
    return-wide p5
.end method

.method public static b(Ltc/q;Ljava/util/List;)Lzc/h;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "chargingCardGetResponse"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ltc/q;->d:Ljava/lang/String;

    .line 9
    .line 10
    new-instance v2, Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 13
    .line 14
    .line 15
    iget-object v3, v0, Ltc/q;->e:Ljava/util/List;

    .line 16
    .line 17
    check-cast v3, Ljava/lang/Iterable;

    .line 18
    .line 19
    move-object/from16 v4, p1

    .line 20
    .line 21
    check-cast v4, Ljava/lang/Iterable;

    .line 22
    .line 23
    invoke-static {v3, v4}, Lmx0/q;->E0(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    const/4 v5, 0x0

    .line 32
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    if-eqz v6, :cond_7

    .line 37
    .line 38
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    check-cast v6, Llx0/l;

    .line 43
    .line 44
    iget-object v8, v6, Llx0/l;->d:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v8, Ltc/e;

    .line 47
    .line 48
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v14, v6

    .line 51
    check-cast v14, Lkc/e;

    .line 52
    .line 53
    if-nez v1, :cond_0

    .line 54
    .line 55
    const-string v6, ""

    .line 56
    .line 57
    move-object v10, v6

    .line 58
    goto :goto_1

    .line 59
    :cond_0
    move-object v10, v1

    .line 60
    :goto_1
    iget-object v6, v8, Ltc/e;->j:Ljava/lang/String;

    .line 61
    .line 62
    iget-object v9, v8, Ltc/e;->f:Ltc/d;

    .line 63
    .line 64
    iget-object v11, v8, Ltc/e;->i:Ljava/lang/Boolean;

    .line 65
    .line 66
    iget-object v12, v8, Ltc/e;->e:Ljava/lang/String;

    .line 67
    .line 68
    move-object v13, v12

    .line 69
    iget-object v12, v8, Ltc/e;->d:Ljava/lang/String;

    .line 70
    .line 71
    sget-object v15, Ltc/d;->e:Ltc/d;

    .line 72
    .line 73
    move-object/from16 v16, v13

    .line 74
    .line 75
    if-ne v9, v15, :cond_1

    .line 76
    .line 77
    const/4 v13, 0x1

    .line 78
    goto :goto_2

    .line 79
    :cond_1
    const/4 v13, 0x0

    .line 80
    :goto_2
    sget-object v4, Ltc/d;->f:Ltc/d;

    .line 81
    .line 82
    if-ne v9, v4, :cond_2

    .line 83
    .line 84
    const/4 v4, 0x1

    .line 85
    :goto_3
    const/16 v17, 0x1

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_2
    const/4 v4, 0x0

    .line 89
    goto :goto_3

    .line 90
    :goto_4
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 91
    .line 92
    move-object/from16 v18, v16

    .line 93
    .line 94
    invoke-static {v11, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v16

    .line 98
    iget-object v8, v8, Ltc/e;->h:Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    if-ne v9, v15, :cond_5

    .line 105
    .line 106
    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 107
    .line 108
    invoke-static {v11, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    if-eqz v9, :cond_5

    .line 113
    .line 114
    if-eqz v1, :cond_4

    .line 115
    .line 116
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 117
    .line 118
    .line 119
    move-result v9

    .line 120
    if-nez v9, :cond_3

    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_3
    const/4 v9, 0x0

    .line 124
    goto :goto_6

    .line 125
    :cond_4
    :goto_5
    move/from16 v9, v17

    .line 126
    .line 127
    :goto_6
    if-nez v9, :cond_5

    .line 128
    .line 129
    move-object v9, v11

    .line 130
    move-object/from16 v11, v18

    .line 131
    .line 132
    move/from16 v18, v17

    .line 133
    .line 134
    goto :goto_7

    .line 135
    :cond_5
    move-object v9, v11

    .line 136
    move-object/from16 v11, v18

    .line 137
    .line 138
    const/16 v18, 0x0

    .line 139
    .line 140
    :goto_7
    new-instance v15, Lzc/a;

    .line 141
    .line 142
    move-object/from16 v17, v15

    .line 143
    .line 144
    move v15, v4

    .line 145
    move-object v4, v9

    .line 146
    move-object/from16 v9, v17

    .line 147
    .line 148
    move-object/from16 v19, v6

    .line 149
    .line 150
    move/from16 v17, v8

    .line 151
    .line 152
    invoke-direct/range {v9 .. v19}, Lzc/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLkc/e;ZZZZLjava/lang/String;)V

    .line 153
    .line 154
    .line 155
    if-nez v5, :cond_6

    .line 156
    .line 157
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    :cond_6
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    goto/16 :goto_0

    .line 165
    .line 166
    :cond_7
    const/16 v17, 0x1

    .line 167
    .line 168
    new-instance v3, Lzc/h;

    .line 169
    .line 170
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    iget-boolean v0, v0, Ltc/q;->f:Z

    .line 175
    .line 176
    if-nez v0, :cond_9

    .line 177
    .line 178
    if-eqz v1, :cond_8

    .line 179
    .line 180
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 181
    .line 182
    .line 183
    move-result v0

    .line 184
    if-nez v0, :cond_9

    .line 185
    .line 186
    :cond_8
    const/4 v0, 0x0

    .line 187
    goto :goto_8

    .line 188
    :cond_9
    move/from16 v0, v17

    .line 189
    .line 190
    :goto_8
    if-eqz v1, :cond_b

    .line 191
    .line 192
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 193
    .line 194
    .line 195
    move-result v6

    .line 196
    if-nez v6, :cond_a

    .line 197
    .line 198
    goto :goto_9

    .line 199
    :cond_a
    const/4 v6, 0x0

    .line 200
    goto :goto_a

    .line 201
    :cond_b
    :goto_9
    move/from16 v6, v17

    .line 202
    .line 203
    :goto_a
    xor-int/lit8 v6, v6, 0x1

    .line 204
    .line 205
    if-lez v4, :cond_c

    .line 206
    .line 207
    new-instance v4, Lzc/m;

    .line 208
    .line 209
    invoke-direct {v4, v0, v6}, Lzc/m;-><init>(ZZ)V

    .line 210
    .line 211
    .line 212
    goto :goto_b

    .line 213
    :cond_c
    new-instance v4, Lzc/l;

    .line 214
    .line 215
    invoke-direct {v4, v0, v6}, Lzc/l;-><init>(ZZ)V

    .line 216
    .line 217
    .line 218
    :goto_b
    if-nez v5, :cond_f

    .line 219
    .line 220
    if-eqz v1, :cond_e

    .line 221
    .line 222
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 223
    .line 224
    .line 225
    move-result v0

    .line 226
    if-nez v0, :cond_d

    .line 227
    .line 228
    goto :goto_c

    .line 229
    :cond_d
    const/4 v0, 0x0

    .line 230
    goto :goto_d

    .line 231
    :cond_e
    :goto_c
    move/from16 v0, v17

    .line 232
    .line 233
    :goto_d
    if-nez v0, :cond_f

    .line 234
    .line 235
    move/from16 v0, v17

    .line 236
    .line 237
    goto :goto_e

    .line 238
    :cond_f
    const/4 v0, 0x0

    .line 239
    :goto_e
    invoke-direct {v3, v2, v4, v0}, Lzc/h;-><init>(Ljava/util/ArrayList;Ljp/z0;Z)V

    .line 240
    .line 241
    .line 242
    return-object v3
.end method

.method public static c(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x7f

    .line 6
    .line 7
    if-gt v0, v1, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
