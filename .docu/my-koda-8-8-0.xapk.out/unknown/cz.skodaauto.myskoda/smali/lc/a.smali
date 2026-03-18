.class public abstract Llc/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;

.field public static final b:Lt2/b;

.field public static final c:Llc/c;

.field public static final d:Llc/c;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ll20/f;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ll20/f;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, 0x5e9f5a05

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Llc/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, Li40/s;

    .line 20
    .line 21
    const/16 v1, 0x15

    .line 22
    .line 23
    invoke-direct {v0, v1}, Li40/s;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, -0x14a7748a

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    sput-object v1, Llc/a;->b:Lt2/b;

    .line 35
    .line 36
    new-instance v0, Llc/c;

    .line 37
    .line 38
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v0, Llc/a;->c:Llc/c;

    .line 42
    .line 43
    new-instance v0, Llc/c;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 46
    .line 47
    .line 48
    sput-object v0, Llc/a;->d:Llc/c;

    .line 49
    .line 50
    return-void
.end method

.method public static final a(Llc/q;Lay0/o;Lay0/o;Lt2/b;Lt2/b;Lay0/n;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v5, p4

    .line 8
    .line 9
    move/from16 v7, p7

    .line 10
    .line 11
    const-string v0, "uiState"

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, v1, Llc/q;->a:Ljava/lang/Object;

    .line 17
    .line 18
    const-string v2, "loading"

    .line 19
    .line 20
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    move-object/from16 v2, p6

    .line 24
    .line 25
    check-cast v2, Ll2/t;

    .line 26
    .line 27
    const v6, 0x6080d9cc

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2, v6}, Ll2/t;->a0(I)Ll2/t;

    .line 31
    .line 32
    .line 33
    and-int/lit8 v6, v7, 0x6

    .line 34
    .line 35
    if-nez v6, :cond_1

    .line 36
    .line 37
    invoke-virtual {v2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v6

    .line 41
    if-eqz v6, :cond_0

    .line 42
    .line 43
    const/4 v6, 0x4

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const/4 v6, 0x2

    .line 46
    :goto_0
    or-int/2addr v6, v7

    .line 47
    goto :goto_1

    .line 48
    :cond_1
    move v6, v7

    .line 49
    :goto_1
    and-int/lit8 v9, p8, 0x2

    .line 50
    .line 51
    if-eqz v9, :cond_3

    .line 52
    .line 53
    or-int/lit8 v6, v6, 0x30

    .line 54
    .line 55
    :cond_2
    move-object/from16 v10, p1

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_3
    and-int/lit8 v10, v7, 0x30

    .line 59
    .line 60
    if-nez v10, :cond_2

    .line 61
    .line 62
    move-object/from16 v10, p1

    .line 63
    .line 64
    invoke-virtual {v2, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v11

    .line 68
    if-eqz v11, :cond_4

    .line 69
    .line 70
    const/16 v11, 0x20

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    const/16 v11, 0x10

    .line 74
    .line 75
    :goto_2
    or-int/2addr v6, v11

    .line 76
    :goto_3
    and-int/lit16 v11, v7, 0x180

    .line 77
    .line 78
    if-nez v11, :cond_6

    .line 79
    .line 80
    invoke-virtual {v2, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v11

    .line 84
    if-eqz v11, :cond_5

    .line 85
    .line 86
    const/16 v11, 0x100

    .line 87
    .line 88
    goto :goto_4

    .line 89
    :cond_5
    const/16 v11, 0x80

    .line 90
    .line 91
    :goto_4
    or-int/2addr v6, v11

    .line 92
    :cond_6
    and-int/lit16 v11, v7, 0xc00

    .line 93
    .line 94
    if-nez v11, :cond_8

    .line 95
    .line 96
    invoke-virtual {v2, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v11

    .line 100
    if-eqz v11, :cond_7

    .line 101
    .line 102
    const/16 v11, 0x800

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_7
    const/16 v11, 0x400

    .line 106
    .line 107
    :goto_5
    or-int/2addr v6, v11

    .line 108
    :cond_8
    and-int/lit16 v11, v7, 0x6000

    .line 109
    .line 110
    if-nez v11, :cond_a

    .line 111
    .line 112
    invoke-virtual {v2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v11

    .line 116
    if-eqz v11, :cond_9

    .line 117
    .line 118
    const/16 v11, 0x4000

    .line 119
    .line 120
    goto :goto_6

    .line 121
    :cond_9
    const/16 v11, 0x2000

    .line 122
    .line 123
    :goto_6
    or-int/2addr v6, v11

    .line 124
    :cond_a
    and-int/lit8 v11, p8, 0x20

    .line 125
    .line 126
    const/high16 v12, 0x30000

    .line 127
    .line 128
    if-eqz v11, :cond_c

    .line 129
    .line 130
    or-int/2addr v6, v12

    .line 131
    :cond_b
    move-object/from16 v12, p5

    .line 132
    .line 133
    goto :goto_8

    .line 134
    :cond_c
    and-int/2addr v12, v7

    .line 135
    if-nez v12, :cond_b

    .line 136
    .line 137
    move-object/from16 v12, p5

    .line 138
    .line 139
    invoke-virtual {v2, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v13

    .line 143
    if-eqz v13, :cond_d

    .line 144
    .line 145
    const/high16 v13, 0x20000

    .line 146
    .line 147
    goto :goto_7

    .line 148
    :cond_d
    const/high16 v13, 0x10000

    .line 149
    .line 150
    :goto_7
    or-int/2addr v6, v13

    .line 151
    :goto_8
    const v13, 0x12493

    .line 152
    .line 153
    .line 154
    and-int/2addr v13, v6

    .line 155
    const v14, 0x12492

    .line 156
    .line 157
    .line 158
    const/4 v8, 0x0

    .line 159
    if-eq v13, v14, :cond_e

    .line 160
    .line 161
    const/4 v13, 0x1

    .line 162
    goto :goto_9

    .line 163
    :cond_e
    move v13, v8

    .line 164
    :goto_9
    and-int/lit8 v14, v6, 0x1

    .line 165
    .line 166
    invoke-virtual {v2, v14, v13}, Ll2/t;->O(IZ)Z

    .line 167
    .line 168
    .line 169
    move-result v13

    .line 170
    if-eqz v13, :cond_1a

    .line 171
    .line 172
    if-eqz v9, :cond_f

    .line 173
    .line 174
    sget-object v9, Llc/a;->b:Lt2/b;

    .line 175
    .line 176
    goto :goto_a

    .line 177
    :cond_f
    move-object v9, v10

    .line 178
    :goto_a
    sget-object v10, Llc/a;->a:Lt2/b;

    .line 179
    .line 180
    if-eqz v11, :cond_10

    .line 181
    .line 182
    move-object v12, v10

    .line 183
    :cond_10
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v11

    .line 187
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 188
    .line 189
    if-ne v11, v13, :cond_11

    .line 190
    .line 191
    const/4 v11, 0x0

    .line 192
    invoke-static {v11}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 193
    .line 194
    .line 195
    move-result-object v11

    .line 196
    invoke-virtual {v2, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_11
    check-cast v11, Ll2/b1;

    .line 200
    .line 201
    sget-object v13, Lk1/j;->c:Lk1/e;

    .line 202
    .line 203
    sget-object v14, Lx2/c;->p:Lx2/h;

    .line 204
    .line 205
    invoke-static {v13, v14, v2, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 206
    .line 207
    .line 208
    move-result-object v13

    .line 209
    move-object/from16 p1, v9

    .line 210
    .line 211
    iget-wide v8, v2, Ll2/t;->T:J

    .line 212
    .line 213
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 214
    .line 215
    .line 216
    move-result v8

    .line 217
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 218
    .line 219
    .line 220
    move-result-object v9

    .line 221
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 222
    .line 223
    invoke-static {v2, v14}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v14

    .line 227
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 228
    .line 229
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 230
    .line 231
    .line 232
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 233
    .line 234
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 235
    .line 236
    .line 237
    iget-boolean v1, v2, Ll2/t;->S:Z

    .line 238
    .line 239
    if-eqz v1, :cond_12

    .line 240
    .line 241
    invoke-virtual {v2, v15}, Ll2/t;->l(Lay0/a;)V

    .line 242
    .line 243
    .line 244
    goto :goto_b

    .line 245
    :cond_12
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 246
    .line 247
    .line 248
    :goto_b
    sget-object v1, Lv3/j;->g:Lv3/h;

    .line 249
    .line 250
    invoke-static {v1, v13, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 251
    .line 252
    .line 253
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 254
    .line 255
    invoke-static {v1, v9, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 256
    .line 257
    .line 258
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 259
    .line 260
    iget-boolean v9, v2, Ll2/t;->S:Z

    .line 261
    .line 262
    if-nez v9, :cond_13

    .line 263
    .line 264
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v9

    .line 268
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 269
    .line 270
    .line 271
    move-result-object v13

    .line 272
    invoke-static {v9, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result v9

    .line 276
    if-nez v9, :cond_14

    .line 277
    .line 278
    :cond_13
    invoke-static {v8, v2, v8, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 279
    .line 280
    .line 281
    :cond_14
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 282
    .line 283
    invoke-static {v1, v14, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 284
    .line 285
    .line 286
    invoke-virtual/range {p0 .. p0}, Llc/q;->a()Llc/r;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 291
    .line 292
    .line 293
    move-result v1

    .line 294
    const/4 v8, 0x3

    .line 295
    if-eqz v1, :cond_19

    .line 296
    .line 297
    const/4 v9, 0x1

    .line 298
    if-eq v1, v9, :cond_18

    .line 299
    .line 300
    const/4 v9, 0x2

    .line 301
    if-eq v1, v9, :cond_17

    .line 302
    .line 303
    if-ne v1, v8, :cond_16

    .line 304
    .line 305
    const v0, 0x2e52c7f8

    .line 306
    .line 307
    .line 308
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 309
    .line 310
    .line 311
    invoke-static {v12, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 312
    .line 313
    .line 314
    move-result v0

    .line 315
    if-nez v0, :cond_15

    .line 316
    .line 317
    new-instance v0, Llc/p;

    .line 318
    .line 319
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v1

    .line 323
    invoke-virtual/range {p0 .. p0}, Llc/q;->a()Llc/r;

    .line 324
    .line 325
    .line 326
    move-result-object v8

    .line 327
    invoke-direct {v0, v1, v8}, Llc/p;-><init>(Ljava/lang/Object;Llc/r;)V

    .line 328
    .line 329
    .line 330
    and-int/lit8 v1, v6, 0x70

    .line 331
    .line 332
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 333
    .line 334
    .line 335
    move-result-object v1

    .line 336
    move-object/from16 v9, p1

    .line 337
    .line 338
    invoke-interface {v9, v0, v2, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    shr-int/lit8 v0, v6, 0xf

    .line 342
    .line 343
    and-int/lit8 v0, v0, 0xe

    .line 344
    .line 345
    const/4 v14, 0x0

    .line 346
    invoke-static {v0, v12, v2, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 347
    .line 348
    .line 349
    :goto_c
    const/4 v0, 0x1

    .line 350
    goto/16 :goto_d

    .line 351
    .line 352
    :cond_15
    new-instance v0, Llx0/k;

    .line 353
    .line 354
    const-string v1, "Missing empty UI implementation"

    .line 355
    .line 356
    invoke-direct {v0, v1}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    .line 357
    .line 358
    .line 359
    throw v0

    .line 360
    :cond_16
    const/4 v14, 0x0

    .line 361
    const v0, 0x6cd91795

    .line 362
    .line 363
    .line 364
    invoke-static {v0, v2, v14}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    throw v0

    .line 369
    :cond_17
    move-object/from16 v9, p1

    .line 370
    .line 371
    const v1, 0x2e506ff3

    .line 372
    .line 373
    .line 374
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 375
    .line 376
    .line 377
    new-instance v1, Llc/p;

    .line 378
    .line 379
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v8

    .line 383
    invoke-virtual/range {p0 .. p0}, Llc/q;->a()Llc/r;

    .line 384
    .line 385
    .line 386
    move-result-object v10

    .line 387
    invoke-direct {v1, v8, v10}, Llc/p;-><init>(Ljava/lang/Object;Llc/r;)V

    .line 388
    .line 389
    .line 390
    and-int/lit8 v8, v6, 0x70

    .line 391
    .line 392
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 393
    .line 394
    .line 395
    move-result-object v8

    .line 396
    invoke-interface {v9, v1, v2, v8}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    const-string v1, "null cannot be cast to non-null type cariad.charging.multicharge.common.presentation.loadingcontenterror.ErrorUiState"

    .line 400
    .line 401
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    check-cast v0, Llc/l;

    .line 405
    .line 406
    shr-int/lit8 v1, v6, 0x9

    .line 407
    .line 408
    and-int/lit8 v1, v1, 0x70

    .line 409
    .line 410
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    invoke-virtual {v5, v0, v2, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 415
    .line 416
    .line 417
    const/4 v14, 0x0

    .line 418
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 419
    .line 420
    .line 421
    goto :goto_c

    .line 422
    :cond_18
    move-object/from16 v9, p1

    .line 423
    .line 424
    const v1, 0x2e4cf6a3

    .line 425
    .line 426
    .line 427
    invoke-virtual {v2, v1}, Ll2/t;->Y(I)V

    .line 428
    .line 429
    .line 430
    const-string v1, "null cannot be cast to non-null type T of cariad.charging.multicharge.common.presentation.loadingcontenterror.UiState"

    .line 431
    .line 432
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    new-instance v1, Llc/p;

    .line 436
    .line 437
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v8

    .line 441
    invoke-virtual/range {p0 .. p0}, Llc/q;->a()Llc/r;

    .line 442
    .line 443
    .line 444
    move-result-object v10

    .line 445
    invoke-direct {v1, v8, v10}, Llc/p;-><init>(Ljava/lang/Object;Llc/r;)V

    .line 446
    .line 447
    .line 448
    and-int/lit8 v8, v6, 0x70

    .line 449
    .line 450
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 451
    .line 452
    .line 453
    move-result-object v8

    .line 454
    invoke-interface {v9, v1, v2, v8}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    invoke-interface {v11, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    shr-int/lit8 v1, v6, 0x6

    .line 461
    .line 462
    and-int/lit8 v1, v1, 0x70

    .line 463
    .line 464
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 465
    .line 466
    .line 467
    move-result-object v1

    .line 468
    invoke-virtual {v4, v0, v2, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    const/4 v14, 0x0

    .line 472
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 473
    .line 474
    .line 475
    goto :goto_c

    .line 476
    :cond_19
    move-object/from16 v9, p1

    .line 477
    .line 478
    const v0, 0x2e4a5fe4

    .line 479
    .line 480
    .line 481
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 482
    .line 483
    .line 484
    new-instance v0, Llc/p;

    .line 485
    .line 486
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v1

    .line 490
    invoke-virtual/range {p0 .. p0}, Llc/q;->a()Llc/r;

    .line 491
    .line 492
    .line 493
    move-result-object v10

    .line 494
    invoke-direct {v0, v1, v10}, Llc/p;-><init>(Ljava/lang/Object;Llc/r;)V

    .line 495
    .line 496
    .line 497
    and-int/lit8 v1, v6, 0x70

    .line 498
    .line 499
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    invoke-interface {v9, v0, v2, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    new-instance v0, Llc/o;

    .line 507
    .line 508
    invoke-interface {v11}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v1

    .line 512
    invoke-direct {v0, v1}, Llc/o;-><init>(Ljava/lang/Object;)V

    .line 513
    .line 514
    .line 515
    shr-int/lit8 v1, v6, 0x3

    .line 516
    .line 517
    and-int/lit8 v1, v1, 0x70

    .line 518
    .line 519
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 520
    .line 521
    .line 522
    move-result-object v1

    .line 523
    invoke-interface {v3, v0, v2, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    const/4 v14, 0x0

    .line 527
    invoke-virtual {v2, v14}, Ll2/t;->q(Z)V

    .line 528
    .line 529
    .line 530
    goto/16 :goto_c

    .line 531
    .line 532
    :goto_d
    invoke-virtual {v2, v0}, Ll2/t;->q(Z)V

    .line 533
    .line 534
    .line 535
    :goto_e
    move-object v6, v12

    .line 536
    goto :goto_f

    .line 537
    :cond_1a
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 538
    .line 539
    .line 540
    move-object v9, v10

    .line 541
    goto :goto_e

    .line 542
    :goto_f
    invoke-virtual {v2}, Ll2/t;->s()Ll2/u1;

    .line 543
    .line 544
    .line 545
    move-result-object v10

    .line 546
    if-eqz v10, :cond_1b

    .line 547
    .line 548
    new-instance v0, Lh2/z0;

    .line 549
    .line 550
    move-object/from16 v1, p0

    .line 551
    .line 552
    move/from16 v8, p8

    .line 553
    .line 554
    move-object v2, v9

    .line 555
    invoke-direct/range {v0 .. v8}, Lh2/z0;-><init>(Llc/q;Lay0/o;Lay0/o;Lt2/b;Lt2/b;Lay0/n;II)V

    .line 556
    .line 557
    .line 558
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 559
    .line 560
    :cond_1b
    return-void
.end method

.method public static final b(Llc/q;Lay0/k;)Llc/q;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llc/q;->a:Ljava/lang/Object;

    .line 7
    .line 8
    invoke-virtual {p0}, Llc/q;->a()Llc/r;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    if-eqz p0, :cond_3

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    if-eq p0, v1, :cond_2

    .line 20
    .line 21
    const/4 p1, 0x2

    .line 22
    if-eq p0, p1, :cond_1

    .line 23
    .line 24
    const/4 p1, 0x3

    .line 25
    if-ne p0, p1, :cond_0

    .line 26
    .line 27
    new-instance p0, Llc/q;

    .line 28
    .line 29
    sget-object p1, Llc/a;->d:Llc/c;

    .line 30
    .line 31
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    new-instance p0, La8/r0;

    .line 36
    .line 37
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_1
    const-string p0, "null cannot be cast to non-null type cariad.charging.multicharge.common.presentation.loadingcontenterror.ErrorUiState"

    .line 42
    .line 43
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    check-cast v0, Llc/l;

    .line 47
    .line 48
    new-instance p0, Llc/q;

    .line 49
    .line 50
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_2
    const-string p0, "null cannot be cast to non-null type T of cariad.charging.multicharge.common.presentation.loadingcontenterror.UiState"

    .line 55
    .line 56
    invoke-static {v0, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    const-string p1, "value"

    .line 64
    .line 65
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    new-instance p1, Llc/q;

    .line 69
    .line 70
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    return-object p1

    .line 74
    :cond_3
    new-instance p0, Llc/q;

    .line 75
    .line 76
    sget-object p1, Llc/a;->c:Llc/c;

    .line 77
    .line 78
    invoke-direct {p0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-object p0
.end method
