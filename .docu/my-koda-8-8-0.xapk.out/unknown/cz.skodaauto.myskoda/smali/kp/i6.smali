.class public abstract Lkp/i6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lqe/a;Ljava/util/List;Lay0/k;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v4, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    const-string v0, "season"

    .line 8
    .line 9
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "selectedDays"

    .line 13
    .line 14
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "onNext"

    .line 18
    .line 19
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v11, p3

    .line 23
    .line 24
    check-cast v11, Ll2/t;

    .line 25
    .line 26
    const v0, 0x5007d12

    .line 27
    .line 28
    .line 29
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-virtual {v11, v0}, Ll2/t;->e(I)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v1, 0x4

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    move v0, v1

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/4 v0, 0x2

    .line 46
    :goto_0
    or-int v0, p4, v0

    .line 47
    .line 48
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_1

    .line 53
    .line 54
    const/16 v2, 0x20

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    const/16 v2, 0x10

    .line 58
    .line 59
    :goto_1
    or-int/2addr v0, v2

    .line 60
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    const/16 v6, 0x100

    .line 65
    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    move v2, v6

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    const/16 v2, 0x80

    .line 71
    .line 72
    :goto_2
    or-int/2addr v0, v2

    .line 73
    and-int/lit16 v2, v0, 0x93

    .line 74
    .line 75
    const/16 v7, 0x92

    .line 76
    .line 77
    const/4 v8, 0x1

    .line 78
    const/4 v12, 0x0

    .line 79
    if-eq v2, v7, :cond_3

    .line 80
    .line 81
    move v2, v8

    .line 82
    goto :goto_3

    .line 83
    :cond_3
    move v2, v12

    .line 84
    :goto_3
    and-int/lit8 v7, v0, 0x1

    .line 85
    .line 86
    invoke-virtual {v11, v7, v2}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-eqz v2, :cond_d

    .line 91
    .line 92
    and-int/lit8 v2, v0, 0xe

    .line 93
    .line 94
    if-ne v2, v1, :cond_4

    .line 95
    .line 96
    move v1, v8

    .line 97
    goto :goto_4

    .line 98
    :cond_4
    move v1, v12

    .line 99
    :goto_4
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    or-int/2addr v1, v2

    .line 104
    and-int/lit16 v0, v0, 0x380

    .line 105
    .line 106
    if-ne v0, v6, :cond_5

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_5
    move v8, v12

    .line 110
    :goto_5
    or-int v0, v1, v8

    .line 111
    .line 112
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 117
    .line 118
    if-nez v0, :cond_6

    .line 119
    .line 120
    if-ne v1, v2, :cond_7

    .line 121
    .line 122
    :cond_6
    new-instance v1, Laa/o;

    .line 123
    .line 124
    const/16 v0, 0xb

    .line 125
    .line 126
    invoke-direct {v1, v3, v4, v5, v0}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v11, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    :cond_7
    check-cast v1, Lay0/k;

    .line 133
    .line 134
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 135
    .line 136
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    check-cast v0, Ljava/lang/Boolean;

    .line 141
    .line 142
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    if-eqz v0, :cond_8

    .line 147
    .line 148
    const v0, -0x105bcaaa

    .line 149
    .line 150
    .line 151
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    const/4 v0, 0x0

    .line 158
    goto :goto_6

    .line 159
    :cond_8
    const v0, 0x31054eee

    .line 160
    .line 161
    .line 162
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 163
    .line 164
    .line 165
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 166
    .line 167
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    check-cast v0, Lhi/a;

    .line 172
    .line 173
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 174
    .line 175
    .line 176
    :goto_6
    new-instance v9, Laf/a;

    .line 177
    .line 178
    const/16 v6, 0x9

    .line 179
    .line 180
    invoke-direct {v9, v0, v1, v6}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 181
    .line 182
    .line 183
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 184
    .line 185
    .line 186
    move-result-object v7

    .line 187
    if-eqz v7, :cond_c

    .line 188
    .line 189
    instance-of v0, v7, Landroidx/lifecycle/k;

    .line 190
    .line 191
    if-eqz v0, :cond_9

    .line 192
    .line 193
    move-object v0, v7

    .line 194
    check-cast v0, Landroidx/lifecycle/k;

    .line 195
    .line 196
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    :goto_7
    move-object v10, v0

    .line 201
    goto :goto_8

    .line 202
    :cond_9
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 203
    .line 204
    goto :goto_7

    .line 205
    :goto_8
    const-class v0, Lef/b;

    .line 206
    .line 207
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 208
    .line 209
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    const/4 v8, 0x0

    .line 214
    invoke-static/range {v6 .. v11}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    move-object v15, v0

    .line 219
    check-cast v15, Lef/b;

    .line 220
    .line 221
    iget-object v0, v15, Lef/b;->e:Lyy0/l1;

    .line 222
    .line 223
    invoke-static {v0, v11}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    invoke-static {v11}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    check-cast v0, Lef/a;

    .line 236
    .line 237
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result v6

    .line 241
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v7

    .line 245
    if-nez v6, :cond_a

    .line 246
    .line 247
    if-ne v7, v2, :cond_b

    .line 248
    .line 249
    :cond_a
    new-instance v13, Lcz/j;

    .line 250
    .line 251
    const/16 v19, 0x0

    .line 252
    .line 253
    const/16 v20, 0x1d

    .line 254
    .line 255
    const/4 v14, 0x1

    .line 256
    const-class v16, Lef/b;

    .line 257
    .line 258
    const-string v17, "onUiEvent"

    .line 259
    .line 260
    const-string v18, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/pricesperdayselection/PricesPerDayUiEvent;)V"

    .line 261
    .line 262
    invoke-direct/range {v13 .. v20}, Lcz/j;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    move-object v7, v13

    .line 269
    :cond_b
    check-cast v7, Lhy0/g;

    .line 270
    .line 271
    check-cast v7, Lay0/k;

    .line 272
    .line 273
    invoke-interface {v1, v0, v7, v11, v12}, Lle/c;->n(Lef/a;Lay0/k;Ll2/o;I)V

    .line 274
    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 278
    .line 279
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 280
    .line 281
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    throw v0

    .line 285
    :cond_d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 286
    .line 287
    .line 288
    :goto_9
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 289
    .line 290
    .line 291
    move-result-object v6

    .line 292
    if-eqz v6, :cond_e

    .line 293
    .line 294
    new-instance v0, Laa/w;

    .line 295
    .line 296
    const/16 v2, 0x1d

    .line 297
    .line 298
    move/from16 v1, p4

    .line 299
    .line 300
    invoke-direct/range {v0 .. v5}, Laa/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 304
    .line 305
    :cond_e
    return-void
.end method

.method public static final b(DLqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Lkp/i6;->e(DLqr0/s;)Llx0/l;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p1, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 13
    .line 14
    new-instance p2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p1, " "

    .line 23
    .line 24
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final c(Lqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    sget-object p0, Lqr0/f;->i:Lqr0/f;

    .line 14
    .line 15
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, La8/r0;

    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    sget-object p0, Lqr0/f;->i:Lqr0/f;

    .line 27
    .line 28
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_2
    sget-object p0, Lqr0/t;->f:Lqr0/t;

    .line 34
    .line 35
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public static final d(DLqr0/s;)D
    .locals 3

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    if-eqz p2, :cond_4

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    const-wide/16 v1, 0x0

    .line 14
    .line 15
    if-eq p2, v0, :cond_2

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-ne p2, v0, :cond_1

    .line 19
    .line 20
    cmpg-double p2, p0, v1

    .line 21
    .line 22
    if-gtz p2, :cond_0

    .line 23
    .line 24
    return-wide v1

    .line 25
    :cond_0
    const-wide v0, 0x406d66b8c03aee13L    # 235.2100526

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    :goto_0
    div-double/2addr v0, p0

    .line 31
    return-wide v0

    .line 32
    :cond_1
    new-instance p0, La8/r0;

    .line 33
    .line 34
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    cmpg-double p2, p0, v1

    .line 39
    .line 40
    if-gtz p2, :cond_3

    .line 41
    .line 42
    return-wide v1

    .line 43
    :cond_3
    const-wide v0, 0x4071a79ba0cd6a81L    # 282.47549515

    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_4
    return-wide p0
.end method

.method public static final e(DLqr0/s;)Llx0/l;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Lkp/i6;->d(DLqr0/s;)D

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-static {v0, p0, p1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    if-eq p1, v0, :cond_1

    .line 22
    .line 23
    const/4 p2, 0x2

    .line 24
    if-ne p1, p2, :cond_0

    .line 25
    .line 26
    sget-object p1, Lqr0/f;->i:Lqr0/f;

    .line 27
    .line 28
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, La8/r0;

    .line 34
    .line 35
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    sget-object p1, Lqr0/f;->i:Lqr0/f;

    .line 40
    .line 41
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    sget-object p1, Lqr0/t;->f:Lqr0/t;

    .line 47
    .line 48
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    :goto_0
    new-instance p2, Llx0/l;

    .line 53
    .line 54
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    return-object p2
.end method
