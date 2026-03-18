.class public abstract Lzl/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lzl/i;

.field public static final b:Lt2/b;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lzl/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzl/j;->a:Lzl/i;

    .line 7
    .line 8
    new-instance v0, Lxf0/i2;

    .line 9
    .line 10
    const/16 v1, 0x1d

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lxf0/i2;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lt2/b;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    const v3, 0x7384b724

    .line 19
    .line 20
    .line 21
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 22
    .line 23
    .line 24
    sput-object v1, Lzl/j;->b:Lt2/b;

    .line 25
    .line 26
    return-void
.end method

.method public static final a(Lam/c;Lx2/s;Lay0/k;Lay0/k;Lx2/e;Lt3/k;Le3/m;Ll2/o;II)V
    .locals 14

    .line 1
    move-object/from16 v6, p5

    .line 2
    .line 3
    move/from16 v0, p8

    .line 4
    .line 5
    move-object/from16 v1, p7

    .line 6
    .line 7
    check-cast v1, Ll2/t;

    .line 8
    .line 9
    const v3, 0x49b4d5f6    # 1481406.8f

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v3, v0, 0x6

    .line 16
    .line 17
    const/4 v4, 0x4

    .line 18
    const/4 v5, 0x2

    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    invoke-virtual {v1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    move v3, v4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    or-int/2addr v3, v0

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v3, v0

    .line 33
    :goto_1
    and-int/lit8 v7, v0, 0x30

    .line 34
    .line 35
    if-nez v7, :cond_3

    .line 36
    .line 37
    const/4 v7, 0x0

    .line 38
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    if-eqz v7, :cond_2

    .line 43
    .line 44
    const/16 v7, 0x20

    .line 45
    .line 46
    goto :goto_2

    .line 47
    :cond_2
    const/16 v7, 0x10

    .line 48
    .line 49
    :goto_2
    or-int/2addr v3, v7

    .line 50
    :cond_3
    and-int/lit16 v7, v0, 0x180

    .line 51
    .line 52
    if-nez v7, :cond_5

    .line 53
    .line 54
    invoke-virtual {v1, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    if-eqz v7, :cond_4

    .line 59
    .line 60
    const/16 v7, 0x100

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_4
    const/16 v7, 0x80

    .line 64
    .line 65
    :goto_3
    or-int/2addr v3, v7

    .line 66
    :cond_5
    and-int/lit16 v7, v0, 0xc00

    .line 67
    .line 68
    if-nez v7, :cond_7

    .line 69
    .line 70
    move-object/from16 v7, p2

    .line 71
    .line 72
    invoke-virtual {v1, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v8

    .line 76
    if-eqz v8, :cond_6

    .line 77
    .line 78
    const/16 v8, 0x800

    .line 79
    .line 80
    goto :goto_4

    .line 81
    :cond_6
    const/16 v8, 0x400

    .line 82
    .line 83
    :goto_4
    or-int/2addr v3, v8

    .line 84
    goto :goto_5

    .line 85
    :cond_7
    move-object/from16 v7, p2

    .line 86
    .line 87
    :goto_5
    and-int/lit16 v8, v0, 0x6000

    .line 88
    .line 89
    if-nez v8, :cond_9

    .line 90
    .line 91
    move-object/from16 v8, p3

    .line 92
    .line 93
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v9

    .line 97
    if-eqz v9, :cond_8

    .line 98
    .line 99
    const/16 v9, 0x4000

    .line 100
    .line 101
    goto :goto_6

    .line 102
    :cond_8
    const/16 v9, 0x2000

    .line 103
    .line 104
    :goto_6
    or-int/2addr v3, v9

    .line 105
    goto :goto_7

    .line 106
    :cond_9
    move-object/from16 v8, p3

    .line 107
    .line 108
    :goto_7
    const/high16 v9, 0x30000

    .line 109
    .line 110
    and-int/2addr v9, v0

    .line 111
    if-nez v9, :cond_b

    .line 112
    .line 113
    move-object/from16 v9, p4

    .line 114
    .line 115
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v10

    .line 119
    if-eqz v10, :cond_a

    .line 120
    .line 121
    const/high16 v10, 0x20000

    .line 122
    .line 123
    goto :goto_8

    .line 124
    :cond_a
    const/high16 v10, 0x10000

    .line 125
    .line 126
    :goto_8
    or-int/2addr v3, v10

    .line 127
    goto :goto_9

    .line 128
    :cond_b
    move-object/from16 v9, p4

    .line 129
    .line 130
    :goto_9
    const/high16 v10, 0x180000

    .line 131
    .line 132
    and-int/2addr v10, v0

    .line 133
    if-nez v10, :cond_d

    .line 134
    .line 135
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v10

    .line 139
    if-eqz v10, :cond_c

    .line 140
    .line 141
    const/high16 v10, 0x100000

    .line 142
    .line 143
    goto :goto_a

    .line 144
    :cond_c
    const/high16 v10, 0x80000

    .line 145
    .line 146
    :goto_a
    or-int/2addr v3, v10

    .line 147
    :cond_d
    const/high16 v10, 0xc00000

    .line 148
    .line 149
    and-int/2addr v10, v0

    .line 150
    if-nez v10, :cond_f

    .line 151
    .line 152
    const/high16 v10, 0x3f800000    # 1.0f

    .line 153
    .line 154
    invoke-virtual {v1, v10}, Ll2/t;->d(F)Z

    .line 155
    .line 156
    .line 157
    move-result v10

    .line 158
    if-eqz v10, :cond_e

    .line 159
    .line 160
    const/high16 v10, 0x800000

    .line 161
    .line 162
    goto :goto_b

    .line 163
    :cond_e
    const/high16 v10, 0x400000

    .line 164
    .line 165
    :goto_b
    or-int/2addr v3, v10

    .line 166
    :cond_f
    const/high16 v10, 0x6000000

    .line 167
    .line 168
    and-int/2addr v10, v0

    .line 169
    move-object/from16 v11, p6

    .line 170
    .line 171
    if-nez v10, :cond_11

    .line 172
    .line 173
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result v10

    .line 177
    if-eqz v10, :cond_10

    .line 178
    .line 179
    const/high16 v10, 0x4000000

    .line 180
    .line 181
    goto :goto_c

    .line 182
    :cond_10
    const/high16 v10, 0x2000000

    .line 183
    .line 184
    :goto_c
    or-int/2addr v3, v10

    .line 185
    :cond_11
    const/high16 v10, 0x30000000

    .line 186
    .line 187
    and-int/2addr v10, v0

    .line 188
    const/4 v13, 0x1

    .line 189
    if-nez v10, :cond_13

    .line 190
    .line 191
    invoke-virtual {v1, v13}, Ll2/t;->e(I)Z

    .line 192
    .line 193
    .line 194
    move-result v10

    .line 195
    if-eqz v10, :cond_12

    .line 196
    .line 197
    const/high16 v10, 0x20000000

    .line 198
    .line 199
    goto :goto_d

    .line 200
    :cond_12
    const/high16 v10, 0x10000000

    .line 201
    .line 202
    :goto_d
    or-int/2addr v3, v10

    .line 203
    :cond_13
    and-int/lit8 v10, p9, 0x6

    .line 204
    .line 205
    if-nez v10, :cond_15

    .line 206
    .line 207
    invoke-virtual {v1, v13}, Ll2/t;->h(Z)Z

    .line 208
    .line 209
    .line 210
    move-result v10

    .line 211
    if-eqz v10, :cond_14

    .line 212
    .line 213
    goto :goto_e

    .line 214
    :cond_14
    move v4, v5

    .line 215
    :goto_e
    or-int v4, p9, v4

    .line 216
    .line 217
    goto :goto_f

    .line 218
    :cond_15
    move/from16 v4, p9

    .line 219
    .line 220
    :goto_f
    const v10, 0x12492493

    .line 221
    .line 222
    .line 223
    and-int/2addr v10, v3

    .line 224
    const v12, 0x12492492

    .line 225
    .line 226
    .line 227
    if-ne v10, v12, :cond_17

    .line 228
    .line 229
    and-int/lit8 v4, v4, 0x3

    .line 230
    .line 231
    if-eq v4, v5, :cond_16

    .line 232
    .line 233
    goto :goto_10

    .line 234
    :cond_16
    const/4 v4, 0x0

    .line 235
    goto :goto_11

    .line 236
    :cond_17
    :goto_10
    move v4, v13

    .line 237
    :goto_11
    and-int/lit8 v5, v3, 0x1

    .line 238
    .line 239
    invoke-virtual {v1, v5, v4}, Ll2/t;->O(IZ)Z

    .line 240
    .line 241
    .line 242
    move-result v4

    .line 243
    if-eqz v4, :cond_1b

    .line 244
    .line 245
    iget-object v4, p0, Lam/c;->a:Ljava/lang/Object;

    .line 246
    .line 247
    shr-int/lit8 v3, v3, 0xf

    .line 248
    .line 249
    and-int/lit8 v3, v3, 0x70

    .line 250
    .line 251
    invoke-static {v4, v6, v1, v3}, Lam/i;->d(Ljava/lang/Object;Lt3/k;Ll2/o;I)Lmm/g;

    .line 252
    .line 253
    .line 254
    move-result-object v4

    .line 255
    invoke-static {v4}, Lam/i;->g(Lmm/g;)V

    .line 256
    .line 257
    .line 258
    iget-object v5, p0, Lam/c;->c:Lyl/l;

    .line 259
    .line 260
    iget-object v6, p0, Lam/c;->b:Lzl/a;

    .line 261
    .line 262
    invoke-static {v1}, Lam/i;->a(Ll2/o;)Lzl/l;

    .line 263
    .line 264
    .line 265
    move-result-object v12

    .line 266
    new-instance v3, Lcoil3/compose/internal/ContentPainterElement;

    .line 267
    .line 268
    move-object/from16 v10, p5

    .line 269
    .line 270
    invoke-direct/range {v3 .. v12}, Lcoil3/compose/internal/ContentPainterElement;-><init>(Lmm/g;Lyl/l;Lzl/a;Lay0/k;Lay0/k;Lx2/e;Lt3/k;Le3/m;Lzl/l;)V

    .line 271
    .line 272
    .line 273
    invoke-interface {p1, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 274
    .line 275
    .line 276
    move-result-object v3

    .line 277
    iget-wide v4, v1, Ll2/t;->T:J

    .line 278
    .line 279
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 280
    .line 281
    .line 282
    move-result v4

    .line 283
    invoke-static {v1, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 292
    .line 293
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 294
    .line 295
    .line 296
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 297
    .line 298
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 299
    .line 300
    .line 301
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 302
    .line 303
    if-eqz v7, :cond_18

    .line 304
    .line 305
    invoke-virtual {v1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 306
    .line 307
    .line 308
    goto :goto_12

    .line 309
    :cond_18
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 310
    .line 311
    .line 312
    :goto_12
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 313
    .line 314
    sget-object v7, Lam/h;->a:Lam/h;

    .line 315
    .line 316
    invoke-static {v6, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 317
    .line 318
    .line 319
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 320
    .line 321
    invoke-static {v6, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 322
    .line 323
    .line 324
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 325
    .line 326
    invoke-static {v5, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 327
    .line 328
    .line 329
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 330
    .line 331
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 332
    .line 333
    if-nez v5, :cond_19

    .line 334
    .line 335
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v5

    .line 339
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 340
    .line 341
    .line 342
    move-result-object v6

    .line 343
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result v5

    .line 347
    if-nez v5, :cond_1a

    .line 348
    .line 349
    :cond_19
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 350
    .line 351
    .line 352
    :cond_1a
    invoke-virtual {v1, v13}, Ll2/t;->q(Z)V

    .line 353
    .line 354
    .line 355
    goto :goto_13

    .line 356
    :cond_1b
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 357
    .line 358
    .line 359
    :goto_13
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 360
    .line 361
    .line 362
    move-result-object v11

    .line 363
    if-eqz v11, :cond_1c

    .line 364
    .line 365
    new-instance v0, Lf2/d;

    .line 366
    .line 367
    const/16 v10, 0x8

    .line 368
    .line 369
    move-object v1, p0

    .line 370
    move-object v2, p1

    .line 371
    move-object/from16 v3, p2

    .line 372
    .line 373
    move-object/from16 v4, p3

    .line 374
    .line 375
    move-object/from16 v5, p4

    .line 376
    .line 377
    move-object/from16 v6, p5

    .line 378
    .line 379
    move-object/from16 v7, p6

    .line 380
    .line 381
    move/from16 v8, p8

    .line 382
    .line 383
    move/from16 v9, p9

    .line 384
    .line 385
    invoke-direct/range {v0 .. v10}, Lf2/d;-><init>(Ljava/lang/Object;Lx2/s;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 386
    .line 387
    .line 388
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 389
    .line 390
    :cond_1c
    return-void
.end method

.method public static final b(Ljava/lang/Object;Lyl/l;Lx2/s;Li3/c;Li3/c;Li3/c;Lay0/k;Lay0/k;Lay0/k;Lx2/e;Lt3/k;Le3/m;Ll2/o;III)V
    .locals 16

    .line 1
    move-object/from16 v0, p8

    .line 2
    .line 3
    move/from16 v1, p15

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x10

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    move-object v2, v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move-object/from16 v2, p3

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v4, v1, 0x20

    .line 15
    .line 16
    if-eqz v4, :cond_1

    .line 17
    .line 18
    move-object v4, v3

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    move-object/from16 v4, p4

    .line 21
    .line 22
    :goto_1
    and-int/lit8 v5, v1, 0x40

    .line 23
    .line 24
    if-eqz v5, :cond_2

    .line 25
    .line 26
    move-object v5, v4

    .line 27
    goto :goto_2

    .line 28
    :cond_2
    move-object/from16 v5, p5

    .line 29
    .line 30
    :goto_2
    and-int/lit16 v6, v1, 0x80

    .line 31
    .line 32
    if-eqz v6, :cond_3

    .line 33
    .line 34
    move-object v6, v3

    .line 35
    goto :goto_3

    .line 36
    :cond_3
    move-object/from16 v6, p6

    .line 37
    .line 38
    :goto_3
    and-int/lit16 v7, v1, 0x100

    .line 39
    .line 40
    if-eqz v7, :cond_4

    .line 41
    .line 42
    move-object v7, v3

    .line 43
    goto :goto_4

    .line 44
    :cond_4
    move-object/from16 v7, p7

    .line 45
    .line 46
    :goto_4
    and-int/lit16 v8, v1, 0x400

    .line 47
    .line 48
    if-eqz v8, :cond_5

    .line 49
    .line 50
    sget-object v8, Lx2/c;->h:Lx2/j;

    .line 51
    .line 52
    goto :goto_5

    .line 53
    :cond_5
    move-object/from16 v8, p9

    .line 54
    .line 55
    :goto_5
    and-int/lit16 v9, v1, 0x800

    .line 56
    .line 57
    if-eqz v9, :cond_6

    .line 58
    .line 59
    sget-object v9, Lt3/j;->b:Lt3/x0;

    .line 60
    .line 61
    goto :goto_6

    .line 62
    :cond_6
    move-object/from16 v9, p10

    .line 63
    .line 64
    :goto_6
    and-int/lit16 v1, v1, 0x2000

    .line 65
    .line 66
    if-eqz v1, :cond_7

    .line 67
    .line 68
    move-object v1, v3

    .line 69
    goto :goto_7

    .line 70
    :cond_7
    move-object/from16 v1, p11

    .line 71
    .line 72
    :goto_7
    shr-int/lit8 v10, p13, 0x3

    .line 73
    .line 74
    new-instance v11, Lam/c;

    .line 75
    .line 76
    sget-object v12, Lzl/q;->a:Ll2/u2;

    .line 77
    .line 78
    move-object/from16 v13, p12

    .line 79
    .line 80
    check-cast v13, Ll2/t;

    .line 81
    .line 82
    invoke-virtual {v13, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v12

    .line 86
    check-cast v12, Lzl/a;

    .line 87
    .line 88
    move-object/from16 v14, p0

    .line 89
    .line 90
    move-object/from16 v15, p1

    .line 91
    .line 92
    invoke-direct {v11, v14, v12, v15}, Lam/c;-><init>(Ljava/lang/Object;Lzl/a;Lyl/l;)V

    .line 93
    .line 94
    .line 95
    sget v12, Lam/i;->b:I

    .line 96
    .line 97
    if-nez v2, :cond_9

    .line 98
    .line 99
    if-nez v4, :cond_9

    .line 100
    .line 101
    if-eqz v5, :cond_8

    .line 102
    .line 103
    goto :goto_8

    .line 104
    :cond_8
    sget-object v2, Lzl/h;->y:Lz70/e0;

    .line 105
    .line 106
    goto :goto_9

    .line 107
    :cond_9
    :goto_8
    new-instance v12, Laa/o;

    .line 108
    .line 109
    const/4 v14, 0x1

    .line 110
    invoke-direct {v12, v2, v5, v4, v14}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    move-object v2, v12

    .line 114
    :goto_9
    if-nez v6, :cond_a

    .line 115
    .line 116
    if-nez v7, :cond_a

    .line 117
    .line 118
    if-eqz v0, :cond_b

    .line 119
    .line 120
    :cond_a
    new-instance v3, Laa/o;

    .line 121
    .line 122
    const/4 v4, 0x2

    .line 123
    invoke-direct {v3, v6, v7, v0, v4}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 124
    .line 125
    .line 126
    :cond_b
    and-int/lit8 v0, p13, 0x70

    .line 127
    .line 128
    and-int/lit16 v4, v10, 0x380

    .line 129
    .line 130
    or-int/2addr v0, v4

    .line 131
    shl-int/lit8 v4, p14, 0xf

    .line 132
    .line 133
    const/high16 v5, 0x70000

    .line 134
    .line 135
    and-int/2addr v5, v4

    .line 136
    or-int/2addr v0, v5

    .line 137
    const/high16 v5, 0x380000

    .line 138
    .line 139
    and-int/2addr v5, v4

    .line 140
    or-int/2addr v0, v5

    .line 141
    const/high16 v5, 0x1c00000

    .line 142
    .line 143
    and-int/2addr v5, v4

    .line 144
    or-int/2addr v0, v5

    .line 145
    const/high16 v5, 0xe000000

    .line 146
    .line 147
    and-int/2addr v5, v4

    .line 148
    or-int/2addr v0, v5

    .line 149
    const/high16 v5, 0x70000000

    .line 150
    .line 151
    and-int/2addr v4, v5

    .line 152
    or-int/2addr v0, v4

    .line 153
    shr-int/lit8 v4, p14, 0xf

    .line 154
    .line 155
    and-int/lit8 v4, v4, 0xe

    .line 156
    .line 157
    move-object/from16 p4, p2

    .line 158
    .line 159
    move/from16 p11, v0

    .line 160
    .line 161
    move-object/from16 p9, v1

    .line 162
    .line 163
    move-object/from16 p5, v2

    .line 164
    .line 165
    move-object/from16 p6, v3

    .line 166
    .line 167
    move/from16 p12, v4

    .line 168
    .line 169
    move-object/from16 p7, v8

    .line 170
    .line 171
    move-object/from16 p8, v9

    .line 172
    .line 173
    move-object/from16 p3, v11

    .line 174
    .line 175
    move-object/from16 p10, v13

    .line 176
    .line 177
    invoke-static/range {p3 .. p12}, Lzl/j;->a(Lam/c;Lx2/s;Lay0/k;Lay0/k;Lx2/e;Lt3/k;Le3/m;Ll2/o;II)V

    .line 178
    .line 179
    .line 180
    return-void
.end method

.method public static final c(Ljava/lang/Object;Lyl/l;Lx2/s;Lt2/b;Lt2/b;Lay0/k;Lay0/k;Lay0/k;Lt3/k;Ll2/o;III)V
    .locals 15

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    move-object/from16 v1, p6

    .line 4
    .line 5
    move-object/from16 v2, p7

    .line 6
    .line 7
    move/from16 v3, p12

    .line 8
    .line 9
    and-int/lit8 v4, v3, 0x20

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v4, :cond_0

    .line 13
    .line 14
    move-object v4, v5

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move-object/from16 v4, p3

    .line 17
    .line 18
    :goto_0
    and-int/lit16 v3, v3, 0x80

    .line 19
    .line 20
    if-eqz v3, :cond_1

    .line 21
    .line 22
    move-object v3, v5

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move-object/from16 v3, p4

    .line 25
    .line 26
    :goto_1
    shr-int/lit8 v6, p10, 0x3

    .line 27
    .line 28
    new-instance v7, Lam/c;

    .line 29
    .line 30
    sget-object v8, Lzl/q;->a:Ll2/u2;

    .line 31
    .line 32
    move-object/from16 v12, p9

    .line 33
    .line 34
    check-cast v12, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v12, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v8

    .line 40
    check-cast v8, Lzl/a;

    .line 41
    .line 42
    move-object/from16 v9, p1

    .line 43
    .line 44
    invoke-direct {v7, p0, v8, v9}, Lam/c;-><init>(Ljava/lang/Object;Lzl/a;Lyl/l;)V

    .line 45
    .line 46
    .line 47
    sget p0, Lam/i;->b:I

    .line 48
    .line 49
    if-nez v0, :cond_3

    .line 50
    .line 51
    if-nez v1, :cond_3

    .line 52
    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_2
    :goto_2
    move-object v9, v5

    .line 57
    goto :goto_4

    .line 58
    :cond_3
    :goto_3
    new-instance v5, Laa/o;

    .line 59
    .line 60
    const/4 p0, 0x2

    .line 61
    invoke-direct {v5, v0, v1, v2, p0}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :goto_4
    if-nez v4, :cond_5

    .line 66
    .line 67
    if-eqz v3, :cond_4

    .line 68
    .line 69
    goto :goto_5

    .line 70
    :cond_4
    sget-object p0, Lzl/j;->b:Lt2/b;

    .line 71
    .line 72
    move-object v11, p0

    .line 73
    goto :goto_6

    .line 74
    :cond_5
    :goto_5
    new-instance p0, Lx40/j;

    .line 75
    .line 76
    const/16 v0, 0x14

    .line 77
    .line 78
    invoke-direct {p0, v0, v4, v3}, Lx40/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    new-instance v0, Lt2/b;

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    const v2, -0x41f77c73

    .line 85
    .line 86
    .line 87
    invoke-direct {v0, p0, v1, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 88
    .line 89
    .line 90
    move-object v11, v0

    .line 91
    :goto_6
    and-int/lit8 p0, p10, 0x70

    .line 92
    .line 93
    and-int/lit16 v0, v6, 0x380

    .line 94
    .line 95
    or-int/2addr p0, v0

    .line 96
    and-int/lit16 v0, v6, 0x1c00

    .line 97
    .line 98
    or-int/2addr p0, v0

    .line 99
    shl-int/lit8 v0, p11, 0xc

    .line 100
    .line 101
    const/high16 v1, 0x70000

    .line 102
    .line 103
    and-int/2addr v1, v0

    .line 104
    or-int/2addr p0, v1

    .line 105
    const/high16 v1, 0x380000

    .line 106
    .line 107
    and-int/2addr v1, v0

    .line 108
    or-int/2addr p0, v1

    .line 109
    const/high16 v1, 0x1c00000

    .line 110
    .line 111
    and-int/2addr v1, v0

    .line 112
    or-int/2addr p0, v1

    .line 113
    const/high16 v1, 0xe000000

    .line 114
    .line 115
    and-int/2addr v1, v0

    .line 116
    or-int/2addr p0, v1

    .line 117
    const/high16 v1, 0x70000000

    .line 118
    .line 119
    and-int/2addr v0, v1

    .line 120
    or-int v13, p0, v0

    .line 121
    .line 122
    shr-int/lit8 p0, p11, 0x12

    .line 123
    .line 124
    and-int/lit8 v14, p0, 0xe

    .line 125
    .line 126
    move-object/from16 v8, p2

    .line 127
    .line 128
    move-object/from16 v10, p8

    .line 129
    .line 130
    invoke-static/range {v7 .. v14}, Lzl/j;->d(Lam/c;Lx2/s;Lay0/k;Lt3/k;Lt2/b;Ll2/o;II)V

    .line 131
    .line 132
    .line 133
    return-void
.end method

.method public static final d(Lam/c;Lx2/s;Lay0/k;Lt3/k;Lt2/b;Ll2/o;II)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move-object/from16 v5, p4

    .line 10
    .line 11
    move/from16 v9, p6

    .line 12
    .line 13
    sget-object v10, Lx2/c;->h:Lx2/j;

    .line 14
    .line 15
    move-object/from16 v11, p5

    .line 16
    .line 17
    check-cast v11, Ll2/t;

    .line 18
    .line 19
    const v3, -0xc43f3ee

    .line 20
    .line 21
    .line 22
    invoke-virtual {v11, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    and-int/lit8 v3, v9, 0x6

    .line 26
    .line 27
    const/4 v6, 0x2

    .line 28
    const/4 v7, 0x4

    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    move v3, v7

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v3, v6

    .line 40
    :goto_0
    or-int/2addr v3, v9

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v3, v9

    .line 43
    :goto_1
    and-int/lit8 v8, v9, 0x30

    .line 44
    .line 45
    const/4 v12, 0x0

    .line 46
    const/16 v13, 0x10

    .line 47
    .line 48
    const/16 v14, 0x20

    .line 49
    .line 50
    if-nez v8, :cond_3

    .line 51
    .line 52
    invoke-virtual {v11, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v8

    .line 56
    if-eqz v8, :cond_2

    .line 57
    .line 58
    move v8, v14

    .line 59
    goto :goto_2

    .line 60
    :cond_2
    move v8, v13

    .line 61
    :goto_2
    or-int/2addr v3, v8

    .line 62
    :cond_3
    and-int/lit16 v8, v9, 0x180

    .line 63
    .line 64
    if-nez v8, :cond_5

    .line 65
    .line 66
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v8

    .line 70
    if-eqz v8, :cond_4

    .line 71
    .line 72
    const/16 v8, 0x100

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    const/16 v8, 0x80

    .line 76
    .line 77
    :goto_3
    or-int/2addr v3, v8

    .line 78
    :cond_5
    and-int/lit16 v8, v9, 0xc00

    .line 79
    .line 80
    sget-object v15, Lzl/h;->y:Lz70/e0;

    .line 81
    .line 82
    if-nez v8, :cond_7

    .line 83
    .line 84
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v8

    .line 88
    if-eqz v8, :cond_6

    .line 89
    .line 90
    const/16 v8, 0x800

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_6
    const/16 v8, 0x400

    .line 94
    .line 95
    :goto_4
    or-int/2addr v3, v8

    .line 96
    :cond_7
    and-int/lit16 v8, v9, 0x6000

    .line 97
    .line 98
    if-nez v8, :cond_9

    .line 99
    .line 100
    invoke-virtual {v11, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    if-eqz v8, :cond_8

    .line 105
    .line 106
    const/16 v8, 0x4000

    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_8
    const/16 v8, 0x2000

    .line 110
    .line 111
    :goto_5
    or-int/2addr v3, v8

    .line 112
    :cond_9
    const/high16 v8, 0x30000

    .line 113
    .line 114
    and-int/2addr v8, v9

    .line 115
    if-nez v8, :cond_b

    .line 116
    .line 117
    invoke-virtual {v11, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v8

    .line 121
    if-eqz v8, :cond_a

    .line 122
    .line 123
    const/high16 v8, 0x20000

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_a
    const/high16 v8, 0x10000

    .line 127
    .line 128
    :goto_6
    or-int/2addr v3, v8

    .line 129
    :cond_b
    const/high16 v8, 0x180000

    .line 130
    .line 131
    and-int/2addr v8, v9

    .line 132
    if-nez v8, :cond_d

    .line 133
    .line 134
    invoke-virtual {v11, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v8

    .line 138
    if-eqz v8, :cond_c

    .line 139
    .line 140
    const/high16 v8, 0x100000

    .line 141
    .line 142
    goto :goto_7

    .line 143
    :cond_c
    const/high16 v8, 0x80000

    .line 144
    .line 145
    :goto_7
    or-int/2addr v3, v8

    .line 146
    :cond_d
    const/high16 v8, 0xc00000

    .line 147
    .line 148
    and-int/2addr v8, v9

    .line 149
    if-nez v8, :cond_f

    .line 150
    .line 151
    const/high16 v8, 0x3f800000    # 1.0f

    .line 152
    .line 153
    invoke-virtual {v11, v8}, Ll2/t;->d(F)Z

    .line 154
    .line 155
    .line 156
    move-result v8

    .line 157
    if-eqz v8, :cond_e

    .line 158
    .line 159
    const/high16 v8, 0x800000

    .line 160
    .line 161
    goto :goto_8

    .line 162
    :cond_e
    const/high16 v8, 0x400000

    .line 163
    .line 164
    :goto_8
    or-int/2addr v3, v8

    .line 165
    :cond_f
    const/high16 v8, 0x6000000

    .line 166
    .line 167
    and-int/2addr v8, v9

    .line 168
    if-nez v8, :cond_11

    .line 169
    .line 170
    invoke-virtual {v11, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v8

    .line 174
    if-eqz v8, :cond_10

    .line 175
    .line 176
    const/high16 v8, 0x4000000

    .line 177
    .line 178
    goto :goto_9

    .line 179
    :cond_10
    const/high16 v8, 0x2000000

    .line 180
    .line 181
    :goto_9
    or-int/2addr v3, v8

    .line 182
    :cond_11
    const/high16 v8, 0x30000000

    .line 183
    .line 184
    and-int/2addr v8, v9

    .line 185
    const/4 v12, 0x1

    .line 186
    if-nez v8, :cond_13

    .line 187
    .line 188
    invoke-virtual {v11, v12}, Ll2/t;->e(I)Z

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    if-eqz v8, :cond_12

    .line 193
    .line 194
    const/high16 v8, 0x20000000

    .line 195
    .line 196
    goto :goto_a

    .line 197
    :cond_12
    const/high16 v8, 0x10000000

    .line 198
    .line 199
    :goto_a
    or-int/2addr v3, v8

    .line 200
    :cond_13
    and-int/lit8 v8, p7, 0x6

    .line 201
    .line 202
    if-nez v8, :cond_15

    .line 203
    .line 204
    invoke-virtual {v11, v12}, Ll2/t;->h(Z)Z

    .line 205
    .line 206
    .line 207
    move-result v8

    .line 208
    if-eqz v8, :cond_14

    .line 209
    .line 210
    move v6, v7

    .line 211
    :cond_14
    or-int v6, p7, v6

    .line 212
    .line 213
    goto :goto_b

    .line 214
    :cond_15
    move/from16 v6, p7

    .line 215
    .line 216
    :goto_b
    and-int/lit8 v7, p7, 0x30

    .line 217
    .line 218
    if-nez v7, :cond_17

    .line 219
    .line 220
    invoke-virtual {v11, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    move-result v7

    .line 224
    if-eqz v7, :cond_16

    .line 225
    .line 226
    move v13, v14

    .line 227
    :cond_16
    or-int/2addr v6, v13

    .line 228
    :cond_17
    const v7, 0x12492493

    .line 229
    .line 230
    .line 231
    and-int/2addr v7, v3

    .line 232
    const v8, 0x12492492

    .line 233
    .line 234
    .line 235
    if-ne v7, v8, :cond_19

    .line 236
    .line 237
    and-int/lit8 v7, v6, 0x13

    .line 238
    .line 239
    const/16 v8, 0x12

    .line 240
    .line 241
    if-eq v7, v8, :cond_18

    .line 242
    .line 243
    goto :goto_c

    .line 244
    :cond_18
    const/4 v7, 0x0

    .line 245
    goto :goto_d

    .line 246
    :cond_19
    :goto_c
    move v7, v12

    .line 247
    :goto_d
    and-int/lit8 v8, v3, 0x1

    .line 248
    .line 249
    invoke-virtual {v11, v8, v7}, Ll2/t;->O(IZ)Z

    .line 250
    .line 251
    .line 252
    move-result v7

    .line 253
    if-eqz v7, :cond_20

    .line 254
    .line 255
    iget-object v7, v1, Lam/c;->a:Ljava/lang/Object;

    .line 256
    .line 257
    shr-int/lit8 v8, v3, 0xf

    .line 258
    .line 259
    and-int/lit8 v8, v8, 0x70

    .line 260
    .line 261
    invoke-static {v7, v4, v11, v8}, Lam/i;->d(Ljava/lang/Object;Lt3/k;Ll2/o;I)Lmm/g;

    .line 262
    .line 263
    .line 264
    move-result-object v7

    .line 265
    iget-object v8, v1, Lam/c;->c:Lyl/l;

    .line 266
    .line 267
    shr-int/lit8 v14, v3, 0x6

    .line 268
    .line 269
    shr-int/lit8 v16, v3, 0xc

    .line 270
    .line 271
    sget-object v3, Lzl/q;->a:Ll2/u2;

    .line 272
    .line 273
    invoke-virtual {v11, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v3

    .line 277
    check-cast v3, Lzl/a;

    .line 278
    .line 279
    const v13, -0x4a168af5

    .line 280
    .line 281
    .line 282
    invoke-virtual {v11, v13}, Ll2/t;->Y(I)V

    .line 283
    .line 284
    .line 285
    const-string v13, "rememberAsyncImagePainter"

    .line 286
    .line 287
    invoke-static {v13}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    :try_start_0
    invoke-static {v7, v11}, Lam/i;->c(Ljava/lang/Object;Ll2/o;)Lmm/g;

    .line 291
    .line 292
    .line 293
    move-result-object v13

    .line 294
    invoke-static {v13}, Lam/i;->g(Lmm/g;)V

    .line 295
    .line 296
    .line 297
    new-instance v12, Lzl/b;

    .line 298
    .line 299
    invoke-direct {v12, v8, v13, v3}, Lzl/b;-><init>(Lyl/l;Lmm/g;Lzl/a;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v3

    .line 306
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 307
    .line 308
    if-ne v3, v8, :cond_1a

    .line 309
    .line 310
    new-instance v3, Lzl/h;

    .line 311
    .line 312
    invoke-direct {v3, v12}, Lzl/h;-><init>(Lzl/b;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    :cond_1a
    check-cast v3, Lzl/h;

    .line 319
    .line 320
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v13

    .line 324
    if-ne v13, v8, :cond_1b

    .line 325
    .line 326
    invoke-static {v11}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 327
    .line 328
    .line 329
    move-result-object v13

    .line 330
    invoke-virtual {v11, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    :cond_1b
    check-cast v13, Lvy0/b0;

    .line 334
    .line 335
    iput-object v13, v3, Lzl/h;->o:Lvy0/b0;

    .line 336
    .line 337
    iput-object v15, v3, Lzl/h;->p:Lay0/k;

    .line 338
    .line 339
    iput-object v0, v3, Lzl/h;->q:Lay0/k;

    .line 340
    .line 341
    iput-object v4, v3, Lzl/h;->r:Lt3/k;

    .line 342
    .line 343
    const/4 v8, 0x1

    .line 344
    iput v8, v3, Lzl/h;->s:I

    .line 345
    .line 346
    invoke-static {v11}, Lam/i;->a(Ll2/o;)Lzl/l;

    .line 347
    .line 348
    .line 349
    move-result-object v8

    .line 350
    iput-object v8, v3, Lzl/h;->t:Lzl/l;

    .line 351
    .line 352
    invoke-virtual {v3, v12}, Lzl/h;->m(Lzl/b;)V

    .line 353
    .line 354
    .line 355
    const/4 v8, 0x0

    .line 356
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 357
    .line 358
    .line 359
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 360
    .line 361
    .line 362
    iget-object v7, v7, Lmm/g;->o:Lnm/i;

    .line 363
    .line 364
    instance-of v8, v7, Lzl/n;

    .line 365
    .line 366
    if-nez v8, :cond_1f

    .line 367
    .line 368
    const v7, -0x57b15495

    .line 369
    .line 370
    .line 371
    invoke-virtual {v11, v7}, Ll2/t;->Y(I)V

    .line 372
    .line 373
    .line 374
    const/4 v8, 0x1

    .line 375
    invoke-static {v10, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 376
    .line 377
    .line 378
    move-result-object v7

    .line 379
    iget-wide v12, v11, Ll2/t;->T:J

    .line 380
    .line 381
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 382
    .line 383
    .line 384
    move-result v8

    .line 385
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 386
    .line 387
    .line 388
    move-result-object v10

    .line 389
    invoke-static {v11, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 390
    .line 391
    .line 392
    move-result-object v12

    .line 393
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 394
    .line 395
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 396
    .line 397
    .line 398
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 399
    .line 400
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 401
    .line 402
    .line 403
    iget-boolean v14, v11, Ll2/t;->S:Z

    .line 404
    .line 405
    if-eqz v14, :cond_1c

    .line 406
    .line 407
    invoke-virtual {v11, v13}, Ll2/t;->l(Lay0/a;)V

    .line 408
    .line 409
    .line 410
    goto :goto_e

    .line 411
    :cond_1c
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 412
    .line 413
    .line 414
    :goto_e
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 415
    .line 416
    invoke-static {v13, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 417
    .line 418
    .line 419
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 420
    .line 421
    invoke-static {v7, v10, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 422
    .line 423
    .line 424
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 425
    .line 426
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 427
    .line 428
    if-nez v10, :cond_1d

    .line 429
    .line 430
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v10

    .line 434
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 435
    .line 436
    .line 437
    move-result-object v13

    .line 438
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v10

    .line 442
    if-nez v10, :cond_1e

    .line 443
    .line 444
    :cond_1d
    invoke-static {v8, v11, v8, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 445
    .line 446
    .line 447
    :cond_1e
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 448
    .line 449
    invoke-static {v7, v12, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 450
    .line 451
    .line 452
    new-instance v7, Lzl/s;

    .line 453
    .line 454
    sget-object v8, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 455
    .line 456
    invoke-direct {v7, v8, v3, v4}, Lzl/s;-><init>(Lk1/q;Lzl/h;Lt3/k;)V

    .line 457
    .line 458
    .line 459
    and-int/lit8 v3, v6, 0x70

    .line 460
    .line 461
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 462
    .line 463
    .line 464
    move-result-object v3

    .line 465
    invoke-virtual {v5, v7, v11, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    const/4 v8, 0x1

    .line 469
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 470
    .line 471
    .line 472
    const/4 v8, 0x0

    .line 473
    invoke-virtual {v11, v8}, Ll2/t;->q(Z)V

    .line 474
    .line 475
    .line 476
    move-object v6, v11

    .line 477
    goto :goto_f

    .line 478
    :cond_1f
    const v6, -0x57a6d23e

    .line 479
    .line 480
    .line 481
    invoke-virtual {v11, v6}, Ll2/t;->Y(I)V

    .line 482
    .line 483
    .line 484
    move-object v6, v3

    .line 485
    new-instance v3, Lv50/e;

    .line 486
    .line 487
    const/16 v8, 0x9

    .line 488
    .line 489
    move-object/from16 v17, v7

    .line 490
    .line 491
    move-object v7, v4

    .line 492
    move-object/from16 v4, v17

    .line 493
    .line 494
    invoke-direct/range {v3 .. v8}, Lv50/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 495
    .line 496
    .line 497
    const v4, -0x16596474

    .line 498
    .line 499
    .line 500
    invoke-static {v4, v11, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 501
    .line 502
    .line 503
    move-result-object v5

    .line 504
    and-int/lit8 v3, v14, 0xe

    .line 505
    .line 506
    or-int/lit16 v3, v3, 0xd80

    .line 507
    .line 508
    and-int/lit8 v4, v16, 0x70

    .line 509
    .line 510
    or-int v7, v3, v4

    .line 511
    .line 512
    const/4 v8, 0x0

    .line 513
    const/4 v4, 0x1

    .line 514
    move-object v3, v10

    .line 515
    move-object v6, v11

    .line 516
    invoke-static/range {v2 .. v8}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 517
    .line 518
    .line 519
    const/4 v8, 0x0

    .line 520
    invoke-virtual {v6, v8}, Ll2/t;->q(Z)V

    .line 521
    .line 522
    .line 523
    goto :goto_f

    .line 524
    :catchall_0
    move-exception v0

    .line 525
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 526
    .line 527
    .line 528
    throw v0

    .line 529
    :cond_20
    move-object v6, v11

    .line 530
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 531
    .line 532
    .line 533
    :goto_f
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 534
    .line 535
    .line 536
    move-result-object v10

    .line 537
    if-eqz v10, :cond_21

    .line 538
    .line 539
    new-instance v0, Ld80/n;

    .line 540
    .line 541
    const/16 v8, 0xa

    .line 542
    .line 543
    move-object/from16 v2, p1

    .line 544
    .line 545
    move-object/from16 v3, p2

    .line 546
    .line 547
    move-object/from16 v4, p3

    .line 548
    .line 549
    move-object/from16 v5, p4

    .line 550
    .line 551
    move/from16 v7, p7

    .line 552
    .line 553
    move v6, v9

    .line 554
    invoke-direct/range {v0 .. v8}, Ld80/n;-><init>(Ljava/lang/Object;Lx2/s;Llx0/e;Ljava/lang/Object;Llx0/e;III)V

    .line 555
    .line 556
    .line 557
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 558
    .line 559
    :cond_21
    return-void
.end method

.method public static final e(Lzl/s;Lx2/s;Li3/c;Lx2/e;Lt3/k;FZLl2/o;I)V
    .locals 14

    .line 1
    move/from16 v8, p8

    .line 2
    .line 3
    move-object/from16 v0, p7

    .line 4
    .line 5
    check-cast v0, Ll2/t;

    .line 6
    .line 7
    const v1, -0x52016e6e

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    and-int/lit8 v1, v8, 0x6

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {v0, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int/2addr v1, v8

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v1, v8

    .line 29
    :goto_1
    or-int/lit8 v2, v1, 0x30

    .line 30
    .line 31
    and-int/lit16 v3, v8, 0x180

    .line 32
    .line 33
    if-nez v3, :cond_2

    .line 34
    .line 35
    or-int/lit16 v2, v1, 0xb0

    .line 36
    .line 37
    :cond_2
    and-int/lit16 v1, v8, 0xc00

    .line 38
    .line 39
    if-nez v1, :cond_3

    .line 40
    .line 41
    or-int/lit16 v2, v2, 0x400

    .line 42
    .line 43
    :cond_3
    and-int/lit16 v1, v8, 0x6000

    .line 44
    .line 45
    if-nez v1, :cond_4

    .line 46
    .line 47
    or-int/lit16 v2, v2, 0x2000

    .line 48
    .line 49
    :cond_4
    const/high16 v1, 0x30000

    .line 50
    .line 51
    and-int/2addr v1, v8

    .line 52
    if-nez v1, :cond_5

    .line 53
    .line 54
    const/high16 v1, 0x10000

    .line 55
    .line 56
    or-int/2addr v2, v1

    .line 57
    :cond_5
    const/high16 v1, 0x180000

    .line 58
    .line 59
    and-int/2addr v1, v8

    .line 60
    if-nez v1, :cond_6

    .line 61
    .line 62
    const/high16 v1, 0x80000

    .line 63
    .line 64
    or-int/2addr v2, v1

    .line 65
    :cond_6
    const/high16 v1, 0xc00000

    .line 66
    .line 67
    and-int/2addr v1, v8

    .line 68
    if-nez v1, :cond_7

    .line 69
    .line 70
    const/high16 v1, 0x400000

    .line 71
    .line 72
    or-int/2addr v2, v1

    .line 73
    :cond_7
    const/high16 v1, 0x6000000

    .line 74
    .line 75
    and-int/2addr v1, v8

    .line 76
    if-nez v1, :cond_8

    .line 77
    .line 78
    const/high16 v1, 0x2000000

    .line 79
    .line 80
    or-int/2addr v2, v1

    .line 81
    :cond_8
    const v1, 0x2492493

    .line 82
    .line 83
    .line 84
    and-int/2addr v1, v2

    .line 85
    const v3, 0x2492492

    .line 86
    .line 87
    .line 88
    const/4 v4, 0x1

    .line 89
    if-eq v1, v3, :cond_9

    .line 90
    .line 91
    move v1, v4

    .line 92
    goto :goto_2

    .line 93
    :cond_9
    const/4 v1, 0x0

    .line 94
    :goto_2
    and-int/2addr v2, v4

    .line 95
    invoke-virtual {v0, v2, v1}, Ll2/t;->O(IZ)Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-eqz v1, :cond_f

    .line 100
    .line 101
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 102
    .line 103
    .line 104
    and-int/lit8 v1, v8, 0x1

    .line 105
    .line 106
    if-eqz v1, :cond_b

    .line 107
    .line 108
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_a

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    move-object v5, p1

    .line 119
    move-object/from16 v1, p2

    .line 120
    .line 121
    move-object/from16 v2, p3

    .line 122
    .line 123
    move-object/from16 v3, p4

    .line 124
    .line 125
    move/from16 v6, p5

    .line 126
    .line 127
    move/from16 v7, p6

    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_b
    :goto_3
    iget-object v1, p0, Lzl/s;->b:Lzl/h;

    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 133
    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    sget-object v2, Lx2/c;->h:Lx2/j;

    .line 139
    .line 140
    iget-object v3, p0, Lzl/s;->c:Lt3/k;

    .line 141
    .line 142
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 152
    .line 153
    const/high16 v6, 0x3f800000    # 1.0f

    .line 154
    .line 155
    move v7, v4

    .line 156
    :goto_4
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 157
    .line 158
    .line 159
    new-instance v9, Lcoil3/compose/internal/SubcomposeContentPainterElement;

    .line 160
    .line 161
    move-object/from16 p2, v1

    .line 162
    .line 163
    move-object/from16 p3, v2

    .line 164
    .line 165
    move-object/from16 p4, v3

    .line 166
    .line 167
    move/from16 p5, v6

    .line 168
    .line 169
    move/from16 p6, v7

    .line 170
    .line 171
    move-object p1, v9

    .line 172
    invoke-direct/range {p1 .. p6}, Lcoil3/compose/internal/SubcomposeContentPainterElement;-><init>(Li3/c;Lx2/e;Lt3/k;FZ)V

    .line 173
    .line 174
    .line 175
    invoke-interface {v5, v9}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 176
    .line 177
    .line 178
    move-result-object v9

    .line 179
    sget v10, Lam/i;->b:I

    .line 180
    .line 181
    iget-wide v10, v0, Ll2/t;->T:J

    .line 182
    .line 183
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 184
    .line 185
    .line 186
    move-result v10

    .line 187
    invoke-static {v0, v9}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 188
    .line 189
    .line 190
    move-result-object v9

    .line 191
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 192
    .line 193
    .line 194
    move-result-object v11

    .line 195
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 196
    .line 197
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 198
    .line 199
    .line 200
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 201
    .line 202
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 203
    .line 204
    .line 205
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 206
    .line 207
    if-eqz v13, :cond_c

    .line 208
    .line 209
    invoke-virtual {v0, v12}, Ll2/t;->l(Lay0/a;)V

    .line 210
    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_c
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 214
    .line 215
    .line 216
    :goto_5
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 217
    .line 218
    sget-object v13, Lam/h;->a:Lam/h;

    .line 219
    .line 220
    invoke-static {v12, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 221
    .line 222
    .line 223
    sget-object v12, Lv3/j;->f:Lv3/h;

    .line 224
    .line 225
    invoke-static {v12, v11, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 226
    .line 227
    .line 228
    sget-object v11, Lv3/j;->d:Lv3/h;

    .line 229
    .line 230
    invoke-static {v11, v9, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 234
    .line 235
    iget-boolean v11, v0, Ll2/t;->S:Z

    .line 236
    .line 237
    if-nez v11, :cond_d

    .line 238
    .line 239
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v11

    .line 243
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 244
    .line 245
    .line 246
    move-result-object v12

    .line 247
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v11

    .line 251
    if-nez v11, :cond_e

    .line 252
    .line 253
    :cond_d
    invoke-static {v10, v0, v10, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 254
    .line 255
    .line 256
    :cond_e
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 257
    .line 258
    .line 259
    move-object v4, v2

    .line 260
    move-object v2, v5

    .line 261
    move-object v5, v3

    .line 262
    move-object v3, v1

    .line 263
    goto :goto_6

    .line 264
    :cond_f
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 265
    .line 266
    .line 267
    move-object v2, p1

    .line 268
    move-object/from16 v3, p2

    .line 269
    .line 270
    move-object/from16 v4, p3

    .line 271
    .line 272
    move-object/from16 v5, p4

    .line 273
    .line 274
    move/from16 v6, p5

    .line 275
    .line 276
    move/from16 v7, p6

    .line 277
    .line 278
    :goto_6
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 279
    .line 280
    .line 281
    move-result-object v9

    .line 282
    if-eqz v9, :cond_10

    .line 283
    .line 284
    new-instance v0, Lzl/t;

    .line 285
    .line 286
    move-object v1, p0

    .line 287
    invoke-direct/range {v0 .. v8}, Lzl/t;-><init>(Lzl/s;Lx2/s;Li3/c;Lx2/e;Lt3/k;FZI)V

    .line 288
    .line 289
    .line 290
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 291
    .line 292
    :cond_10
    return-void
.end method

.method public static final f(Lyl/j;Landroid/content/Context;I)Li3/c;
    .locals 1

    .line 1
    instance-of v0, p0, Lyl/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lyl/a;

    .line 6
    .line 7
    iget-object p0, p0, Lyl/a;->a:Landroid/graphics/Bitmap;

    .line 8
    .line 9
    new-instance p1, Le3/f;

    .line 10
    .line 11
    invoke-direct {p1, p0}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p1, p2}, Llp/t1;->a(Le3/f;I)Li3/a;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_0
    instance-of p2, p0, Lyl/e;

    .line 20
    .line 21
    if-eqz p2, :cond_1

    .line 22
    .line 23
    new-instance p2, Lln/a;

    .line 24
    .line 25
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-static {p0, p1}, Lyl/m;->b(Lyl/j;Landroid/content/res/Resources;)Landroid/graphics/drawable/Drawable;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p0}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {p2, p0}, Lln/a;-><init>(Landroid/graphics/drawable/Drawable;)V

    .line 38
    .line 39
    .line 40
    return-object p2

    .line 41
    :cond_1
    new-instance p1, Lzl/p;

    .line 42
    .line 43
    invoke-direct {p1, p0}, Lzl/p;-><init>(Lyl/j;)V

    .line 44
    .line 45
    .line 46
    return-object p1
.end method
