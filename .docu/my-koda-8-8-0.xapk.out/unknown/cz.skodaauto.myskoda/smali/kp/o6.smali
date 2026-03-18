.class public abstract Lkp/o6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(DLqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Lkp/o6;->d(DLqr0/s;)Llx0/l;

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

.method public static final b(Len0/h;Ljava/util/List;)Lss0/u;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v3, "renders"

    .line 11
    .line 12
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v3, v0, Len0/h;->a:Len0/i;

    .line 16
    .line 17
    iget-object v0, v0, Len0/h;->b:Ljava/util/List;

    .line 18
    .line 19
    iget-object v4, v3, Len0/i;->i:Ljava/time/LocalDate;

    .line 20
    .line 21
    iget-object v6, v3, Len0/i;->a:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v7, v3, Len0/i;->b:Ljava/lang/String;

    .line 27
    .line 28
    iget-object v5, v3, Len0/i;->c:Ljava/lang/String;

    .line 29
    .line 30
    const/4 v8, 0x0

    .line 31
    if-eqz v5, :cond_0

    .line 32
    .line 33
    move-object v10, v5

    .line 34
    move-object v5, v8

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    move-object v5, v8

    .line 37
    move-object v10, v5

    .line 38
    :goto_0
    iget-object v8, v3, Len0/i;->f:Lss0/a;

    .line 39
    .line 40
    iget-object v11, v3, Len0/i;->g:Lss0/t;

    .line 41
    .line 42
    iget-object v9, v3, Len0/i;->h:Ljava/time/LocalDate;

    .line 43
    .line 44
    if-nez v9, :cond_1

    .line 45
    .line 46
    if-nez v4, :cond_1

    .line 47
    .line 48
    move-object v12, v5

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    new-instance v12, Lss0/j;

    .line 51
    .line 52
    invoke-direct {v12, v9, v4}, Lss0/j;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 53
    .line 54
    .line 55
    :goto_1
    check-cast v1, Ljava/lang/Iterable;

    .line 56
    .line 57
    new-instance v9, Ljava/util/ArrayList;

    .line 58
    .line 59
    const/16 v4, 0xa

    .line 60
    .line 61
    invoke-static {v1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 62
    .line 63
    .line 64
    move-result v13

    .line 65
    invoke-direct {v9, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 66
    .line 67
    .line 68
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v13

    .line 76
    if-eqz v13, :cond_2

    .line 77
    .line 78
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v13

    .line 82
    check-cast v13, Lgp0/f;

    .line 83
    .line 84
    invoke-static {v13}, Lkp/f9;->b(Lgp0/f;)Lhp0/e;

    .line 85
    .line 86
    .line 87
    move-result-object v13

    .line 88
    invoke-virtual {v9, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_2
    iget-object v1, v3, Len0/i;->j:Len0/j;

    .line 93
    .line 94
    if-eqz v1, :cond_a

    .line 95
    .line 96
    iget-object v14, v1, Len0/j;->a:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v15, v1, Len0/j;->b:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v13, v1, Len0/j;->c:Ljava/lang/String;

    .line 101
    .line 102
    iget-object v5, v1, Len0/j;->d:Ljava/lang/String;

    .line 103
    .line 104
    iget-object v4, v1, Len0/j;->e:Ljava/lang/String;

    .line 105
    .line 106
    move-object/from16 v23, v0

    .line 107
    .line 108
    iget-object v0, v1, Len0/j;->f:Ljava/lang/Integer;

    .line 109
    .line 110
    if-eqz v0, :cond_3

    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    move-object/from16 v18, v4

    .line 117
    .line 118
    new-instance v4, Lqr0/h;

    .line 119
    .line 120
    invoke-direct {v4, v0}, Lqr0/h;-><init>(I)V

    .line 121
    .line 122
    .line 123
    move-object/from16 v19, v4

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_3
    move-object/from16 v18, v4

    .line 127
    .line 128
    const/16 v19, 0x0

    .line 129
    .line 130
    :goto_3
    iget-object v0, v1, Len0/j;->g:Ljava/lang/Integer;

    .line 131
    .line 132
    if-eqz v0, :cond_4

    .line 133
    .line 134
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    move-object/from16 v17, v5

    .line 139
    .line 140
    int-to-double v4, v0

    .line 141
    new-instance v0, Lqr0/n;

    .line 142
    .line 143
    invoke-direct {v0, v4, v5}, Lqr0/n;-><init>(D)V

    .line 144
    .line 145
    .line 146
    move-object/from16 v20, v0

    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_4
    move-object/from16 v17, v5

    .line 150
    .line 151
    const/16 v20, 0x0

    .line 152
    .line 153
    :goto_4
    iget-object v0, v1, Len0/j;->h:Ljava/lang/Integer;

    .line 154
    .line 155
    if-eqz v0, :cond_5

    .line 156
    .line 157
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    int-to-double v4, v0

    .line 162
    new-instance v0, Lqr0/d;

    .line 163
    .line 164
    invoke-direct {v0, v4, v5}, Lqr0/d;-><init>(D)V

    .line 165
    .line 166
    .line 167
    move-object/from16 v21, v0

    .line 168
    .line 169
    goto :goto_5

    .line 170
    :cond_5
    const/16 v21, 0x0

    .line 171
    .line 172
    :goto_5
    iget-object v0, v1, Len0/j;->j:Ljava/lang/Double;

    .line 173
    .line 174
    iget-object v4, v1, Len0/j;->k:Ljava/lang/Double;

    .line 175
    .line 176
    iget-object v1, v1, Len0/j;->i:Ljava/lang/Double;

    .line 177
    .line 178
    if-nez v1, :cond_6

    .line 179
    .line 180
    if-nez v4, :cond_6

    .line 181
    .line 182
    if-nez v0, :cond_6

    .line 183
    .line 184
    move-object/from16 v24, v6

    .line 185
    .line 186
    const/16 v22, 0x0

    .line 187
    .line 188
    :goto_6
    move-object/from16 v16, v13

    .line 189
    .line 190
    goto :goto_a

    .line 191
    :cond_6
    move-object v5, v0

    .line 192
    if-eqz v1, :cond_7

    .line 193
    .line 194
    invoke-virtual {v1}, Ljava/lang/Number;->doubleValue()D

    .line 195
    .line 196
    .line 197
    move-result-wide v0

    .line 198
    move-object/from16 v16, v4

    .line 199
    .line 200
    new-instance v4, Lqr0/i;

    .line 201
    .line 202
    invoke-direct {v4, v0, v1}, Lqr0/i;-><init>(D)V

    .line 203
    .line 204
    .line 205
    goto :goto_7

    .line 206
    :cond_7
    move-object/from16 v16, v4

    .line 207
    .line 208
    const/4 v4, 0x0

    .line 209
    :goto_7
    if-eqz v5, :cond_8

    .line 210
    .line 211
    invoke-virtual {v5}, Ljava/lang/Number;->doubleValue()D

    .line 212
    .line 213
    .line 214
    move-result-wide v0

    .line 215
    new-instance v5, Lqr0/g;

    .line 216
    .line 217
    invoke-direct {v5, v0, v1}, Lqr0/g;-><init>(D)V

    .line 218
    .line 219
    .line 220
    goto :goto_8

    .line 221
    :cond_8
    const/4 v5, 0x0

    .line 222
    :goto_8
    if-eqz v16, :cond_9

    .line 223
    .line 224
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Number;->doubleValue()D

    .line 225
    .line 226
    .line 227
    move-result-wide v0

    .line 228
    move-object/from16 v24, v6

    .line 229
    .line 230
    new-instance v6, Lqr0/j;

    .line 231
    .line 232
    invoke-direct {v6, v0, v1}, Lqr0/j;-><init>(D)V

    .line 233
    .line 234
    .line 235
    goto :goto_9

    .line 236
    :cond_9
    move-object/from16 v24, v6

    .line 237
    .line 238
    const/4 v6, 0x0

    .line 239
    :goto_9
    new-instance v0, Lss0/k0;

    .line 240
    .line 241
    invoke-direct {v0, v4, v5, v6}, Lss0/k0;-><init>(Lqr0/i;Lqr0/g;Lqr0/j;)V

    .line 242
    .line 243
    .line 244
    move-object/from16 v22, v0

    .line 245
    .line 246
    goto :goto_6

    .line 247
    :goto_a
    new-instance v13, Lss0/v;

    .line 248
    .line 249
    invoke-direct/range {v13 .. v22}, Lss0/v;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqr0/h;Lqr0/n;Lqr0/d;Lss0/k0;)V

    .line 250
    .line 251
    .line 252
    move-object v15, v13

    .line 253
    goto :goto_b

    .line 254
    :cond_a
    move-object/from16 v23, v0

    .line 255
    .line 256
    move-object/from16 v24, v6

    .line 257
    .line 258
    const/4 v15, 0x0

    .line 259
    :goto_b
    iget-object v13, v3, Len0/i;->d:Ljava/lang/String;

    .line 260
    .line 261
    iget v14, v3, Len0/i;->e:I

    .line 262
    .line 263
    move-object/from16 v0, v23

    .line 264
    .line 265
    check-cast v0, Ljava/lang/Iterable;

    .line 266
    .line 267
    new-instance v1, Ljava/util/ArrayList;

    .line 268
    .line 269
    const/16 v3, 0xa

    .line 270
    .line 271
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 272
    .line 273
    .line 274
    move-result v3

    .line 275
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 276
    .line 277
    .line 278
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    :goto_c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 283
    .line 284
    .line 285
    move-result v3

    .line 286
    if-eqz v3, :cond_c

    .line 287
    .line 288
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v3

    .line 292
    check-cast v3, Len0/d;

    .line 293
    .line 294
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    iget-object v4, v3, Len0/d;->e:Ljava/time/LocalDate;

    .line 298
    .line 299
    new-instance v5, Lss0/s;

    .line 300
    .line 301
    iget-object v6, v3, Len0/d;->b:Lss0/t;

    .line 302
    .line 303
    move-object/from16 p1, v0

    .line 304
    .line 305
    iget-object v0, v3, Len0/d;->c:Ljava/time/LocalDate;

    .line 306
    .line 307
    iget-object v3, v3, Len0/d;->d:Ljava/time/LocalDate;

    .line 308
    .line 309
    if-nez v3, :cond_b

    .line 310
    .line 311
    if-nez v4, :cond_b

    .line 312
    .line 313
    move-object/from16 v16, v2

    .line 314
    .line 315
    const/4 v2, 0x0

    .line 316
    goto :goto_d

    .line 317
    :cond_b
    move-object/from16 v16, v2

    .line 318
    .line 319
    new-instance v2, Lss0/j;

    .line 320
    .line 321
    invoke-direct {v2, v3, v4}, Lss0/j;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 322
    .line 323
    .line 324
    :goto_d
    invoke-direct {v5, v6, v0, v2}, Lss0/s;-><init>(Lss0/t;Ljava/time/LocalDate;Lss0/j;)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-object/from16 v0, p1

    .line 331
    .line 332
    move-object/from16 v2, v16

    .line 333
    .line 334
    goto :goto_c

    .line 335
    :cond_c
    new-instance v5, Lss0/u;

    .line 336
    .line 337
    move-object/from16 v16, v1

    .line 338
    .line 339
    move-object/from16 v6, v24

    .line 340
    .line 341
    invoke-direct/range {v5 .. v16}, Lss0/u;-><init>(Ljava/lang/String;Ljava/lang/String;Lss0/a;Ljava/util/List;Ljava/lang/String;Lss0/t;Lss0/j;Ljava/lang/String;ILss0/v;Ljava/util/List;)V

    .line 342
    .line 343
    .line 344
    return-object v5
.end method

.method public static final c(DLqr0/s;)I
    .locals 2

    .line 1
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p2, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p2, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p2, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :cond_1
    :goto_0
    const-wide v0, 0x3fe3e22cbce486daL    # 0.6213592233

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    mul-double/2addr p0, v0

    .line 26
    invoke-static {p0, p1}, Lcy0/a;->h(D)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_2
    invoke-static {p0, p1}, Lcy0/a;->h(D)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public static final d(DLqr0/s;)Llx0/l;
    .locals 2

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
    if-eqz p2, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p2, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p2, v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, La8/r0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    const-wide v0, 0x3fe3e22cbce486daL    # 0.6213592233

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    mul-double/2addr p0, v0

    .line 31
    invoke-static {p0, p1}, Lcy0/a;->h(D)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-static {}, Ljava/text/NumberFormat;->getInstance()Ljava/text/NumberFormat;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {p1, p0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    sget-object p1, Lqr0/f;->j:Lqr0/f;

    .line 48
    .line 49
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    new-instance p2, Llx0/l;

    .line 54
    .line 55
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object p2

    .line 59
    :cond_2
    invoke-static {p0, p1}, Lcy0/a;->h(D)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    invoke-static {}, Ljava/text/NumberFormat;->getInstance()Ljava/text/NumberFormat;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {p1, p0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    sget-object p1, Lqr0/f;->f:Lqr0/f;

    .line 76
    .line 77
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    new-instance p2, Llx0/l;

    .line 82
    .line 83
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    return-object p2
.end method
