.class public abstract Lvv/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg4/p0;

.field public static final b:J

.field public static final c:J


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    new-instance v0, Lg4/p0;

    .line 2
    .line 3
    sget-object v5, Lk4/x;->n:Lk4/x;

    .line 4
    .line 5
    const-wide/16 v11, 0x0

    .line 6
    .line 7
    const v13, 0xfffffb

    .line 8
    .line 9
    .line 10
    const-wide/16 v1, 0x0

    .line 11
    .line 12
    const-wide/16 v3, 0x0

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    const/4 v7, 0x0

    .line 16
    const-wide/16 v8, 0x0

    .line 17
    .line 18
    const/4 v10, 0x0

    .line 19
    invoke-direct/range {v0 .. v13}, Lg4/p0;-><init>(JJLk4/x;Lk4/t;Lk4/n;JIJI)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lvv/z0;->a:Lg4/p0;

    .line 23
    .line 24
    const/16 v0, 0x8

    .line 25
    .line 26
    invoke-static {v0}, Lgq/b;->c(I)J

    .line 27
    .line 28
    .line 29
    move-result-wide v0

    .line 30
    sput-wide v0, Lvv/z0;->b:J

    .line 31
    .line 32
    sget-wide v0, Le3/s;->i:J

    .line 33
    .line 34
    sput-wide v0, Lvv/z0;->c:J

    .line 35
    .line 36
    return-void
.end method

.method public static final a(Lvv/m0;Lx2/s;Lay0/k;Lay0/k;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    move-object/from16 v7, p3

    .line 6
    .line 7
    move/from16 v8, p5

    .line 8
    .line 9
    const-string v0, "<this>"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "bodyRows"

    .line 15
    .line 16
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v14, p4

    .line 20
    .line 21
    check-cast v14, Ll2/t;

    .line 22
    .line 23
    const v0, -0x2cb906be

    .line 24
    .line 25
    .line 26
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v0, v8, 0xe

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    const/4 v0, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v0, 0x2

    .line 42
    :goto_0
    or-int/2addr v0, v8

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v0, v8

    .line 45
    :goto_1
    or-int/lit8 v0, v0, 0x30

    .line 46
    .line 47
    and-int/lit16 v2, v8, 0x380

    .line 48
    .line 49
    if-nez v2, :cond_3

    .line 50
    .line 51
    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    if-eqz v2, :cond_2

    .line 56
    .line 57
    const/16 v2, 0x100

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_2
    const/16 v2, 0x80

    .line 61
    .line 62
    :goto_2
    or-int/2addr v0, v2

    .line 63
    :cond_3
    and-int/lit16 v2, v8, 0x1c00

    .line 64
    .line 65
    if-nez v2, :cond_5

    .line 66
    .line 67
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_4

    .line 72
    .line 73
    const/16 v2, 0x800

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_4
    const/16 v2, 0x400

    .line 77
    .line 78
    :goto_3
    or-int/2addr v0, v2

    .line 79
    :cond_5
    move v9, v0

    .line 80
    and-int/lit16 v0, v9, 0x16db

    .line 81
    .line 82
    const/16 v2, 0x492

    .line 83
    .line 84
    if-ne v0, v2, :cond_7

    .line 85
    .line 86
    invoke-virtual {v14}, Ll2/t;->A()Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-nez v0, :cond_6

    .line 91
    .line 92
    goto :goto_4

    .line 93
    :cond_6
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 94
    .line 95
    .line 96
    move-object/from16 v2, p1

    .line 97
    .line 98
    goto/16 :goto_15

    .line 99
    .line 100
    :cond_7
    :goto_4
    invoke-static {v1, v14}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-static {v0}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iget-object v10, v0, Lvv/n0;->f:Lvv/c1;

    .line 109
    .line 110
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    invoke-static {v1, v14}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 114
    .line 115
    .line 116
    move-result-wide v11

    .line 117
    const v0, 0x44faf204

    .line 118
    .line 119
    .line 120
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 132
    .line 133
    if-nez v2, :cond_8

    .line 134
    .line 135
    if-ne v3, v13, :cond_a

    .line 136
    .line 137
    :cond_8
    if-eqz v6, :cond_9

    .line 138
    .line 139
    new-instance v2, Lvv/r0;

    .line 140
    .line 141
    invoke-direct {v2}, Lvv/r0;-><init>()V

    .line 142
    .line 143
    .line 144
    invoke-interface {v6, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    iget-object v2, v2, Lvv/r0;->a:Lvv/b1;

    .line 148
    .line 149
    move-object v3, v2

    .line 150
    goto :goto_5

    .line 151
    :cond_9
    const/4 v3, 0x0

    .line 152
    :goto_5
    invoke-virtual {v14, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    :cond_a
    const/4 v15, 0x0

    .line 156
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 157
    .line 158
    .line 159
    check-cast v3, Lvv/b1;

    .line 160
    .line 161
    invoke-virtual {v14, v0}, Ll2/t;->Z(I)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    const/16 v5, 0xa

    .line 173
    .line 174
    if-nez v0, :cond_b

    .line 175
    .line 176
    if-ne v2, v13, :cond_d

    .line 177
    .line 178
    :cond_b
    new-instance v0, Lvv/v0;

    .line 179
    .line 180
    invoke-direct {v0}, Lvv/v0;-><init>()V

    .line 181
    .line 182
    .line 183
    invoke-interface {v7, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    new-instance v2, Ljava/util/ArrayList;

    .line 187
    .line 188
    iget-object v0, v0, Lvv/v0;->a:Ljava/util/ArrayList;

    .line 189
    .line 190
    invoke-static {v0, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    if-eqz v4, :cond_c

    .line 206
    .line 207
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    check-cast v4, Lvv/r0;

    .line 212
    .line 213
    iget-object v4, v4, Lvv/r0;->a:Lvv/b1;

    .line 214
    .line 215
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_c
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    :cond_d
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 223
    .line 224
    .line 225
    move-object v0, v2

    .line 226
    check-cast v0, Ljava/util/List;

    .line 227
    .line 228
    const v2, 0x1e7b2b64

    .line 229
    .line 230
    .line 231
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    move-result v4

    .line 242
    or-int/2addr v2, v4

    .line 243
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    if-nez v2, :cond_f

    .line 248
    .line 249
    if-ne v4, v13, :cond_e

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_e
    move v2, v15

    .line 253
    goto :goto_d

    .line 254
    :cond_f
    :goto_7
    if-eqz v3, :cond_10

    .line 255
    .line 256
    iget-object v2, v3, Lvv/b1;->a:Ljava/lang/Object;

    .line 257
    .line 258
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    goto :goto_8

    .line 263
    :cond_10
    move v2, v15

    .line 264
    :goto_8
    move-object v4, v0

    .line 265
    check-cast v4, Ljava/lang/Iterable;

    .line 266
    .line 267
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 268
    .line 269
    .line 270
    move-result-object v4

    .line 271
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 272
    .line 273
    .line 274
    move-result v16

    .line 275
    if-nez v16, :cond_11

    .line 276
    .line 277
    const/4 v4, 0x0

    .line 278
    goto :goto_b

    .line 279
    :cond_11
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v16

    .line 283
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 284
    .line 285
    .line 286
    move-result v17

    .line 287
    if-nez v17, :cond_12

    .line 288
    .line 289
    :goto_9
    move-object/from16 v4, v16

    .line 290
    .line 291
    goto :goto_b

    .line 292
    :cond_12
    move-object/from16 v5, v16

    .line 293
    .line 294
    check-cast v5, Lvv/b1;

    .line 295
    .line 296
    iget-object v5, v5, Lvv/b1;->a:Ljava/lang/Object;

    .line 297
    .line 298
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 299
    .line 300
    .line 301
    move-result v5

    .line 302
    :goto_a
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v17

    .line 306
    move-object/from16 v15, v17

    .line 307
    .line 308
    check-cast v15, Lvv/b1;

    .line 309
    .line 310
    iget-object v15, v15, Lvv/b1;->a:Ljava/lang/Object;

    .line 311
    .line 312
    invoke-interface {v15}, Ljava/util/List;->size()I

    .line 313
    .line 314
    .line 315
    move-result v15

    .line 316
    if-ge v5, v15, :cond_13

    .line 317
    .line 318
    move v5, v15

    .line 319
    move-object/from16 v16, v17

    .line 320
    .line 321
    :cond_13
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 322
    .line 323
    .line 324
    move-result v15

    .line 325
    if-nez v15, :cond_1e

    .line 326
    .line 327
    goto :goto_9

    .line 328
    :goto_b
    check-cast v4, Lvv/b1;

    .line 329
    .line 330
    if-eqz v4, :cond_14

    .line 331
    .line 332
    iget-object v4, v4, Lvv/b1;->a:Ljava/lang/Object;

    .line 333
    .line 334
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 335
    .line 336
    .line 337
    move-result v4

    .line 338
    goto :goto_c

    .line 339
    :cond_14
    const/4 v4, 0x0

    .line 340
    :goto_c
    invoke-static {v2, v4}, Ljava/lang/Math;->max(II)I

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 345
    .line 346
    .line 347
    move-result-object v4

    .line 348
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    const/4 v2, 0x0

    .line 352
    :goto_d
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 353
    .line 354
    .line 355
    check-cast v4, Ljava/lang/Number;

    .line 356
    .line 357
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 358
    .line 359
    .line 360
    move-result v15

    .line 361
    invoke-static {v1, v14}, Lvv/l0;->e(Lvv/m0;Ll2/o;)Lg4/p0;

    .line 362
    .line 363
    .line 364
    move-result-object v2

    .line 365
    iget-object v4, v10, Lvv/c1;->a:Lg4/p0;

    .line 366
    .line 367
    invoke-virtual {v2, v4}, Lg4/p0;->d(Lg4/p0;)Lg4/p0;

    .line 368
    .line 369
    .line 370
    move-result-object v2

    .line 371
    sget-object v4, Lw3/h1;->h:Ll2/u2;

    .line 372
    .line 373
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v4

    .line 377
    check-cast v4, Lt4/c;

    .line 378
    .line 379
    iget-object v5, v10, Lvv/c1;->b:Lt4/o;

    .line 380
    .line 381
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 382
    .line 383
    .line 384
    move-object/from16 v16, v2

    .line 385
    .line 386
    iget-wide v1, v5, Lt4/o;->a:J

    .line 387
    .line 388
    invoke-interface {v4, v1, v2}, Lt4/c;->s(J)F

    .line 389
    .line 390
    .line 391
    move-result v1

    .line 392
    sget-object v17, Lx2/p;->b:Lx2/p;

    .line 393
    .line 394
    invoke-static/range {v17 .. v17}, Ljp/ba;->d(Lx2/s;)Lx2/s;

    .line 395
    .line 396
    .line 397
    move-result-object v2

    .line 398
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    const v2, 0x607fb4c4

    .line 403
    .line 404
    .line 405
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 409
    .line 410
    .line 411
    move-result v2

    .line 412
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    move-result v4

    .line 416
    or-int/2addr v2, v4

    .line 417
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 418
    .line 419
    .line 420
    move-result v4

    .line 421
    or-int/2addr v2, v4

    .line 422
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    if-nez v2, :cond_16

    .line 427
    .line 428
    if-ne v4, v13, :cond_15

    .line 429
    .line 430
    goto :goto_f

    .line 431
    :cond_15
    :goto_e
    const/4 v2, 0x0

    .line 432
    goto/16 :goto_14

    .line 433
    .line 434
    :cond_16
    :goto_f
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 435
    .line 436
    .line 437
    move-result-object v2

    .line 438
    if-eqz v3, :cond_18

    .line 439
    .line 440
    iget-object v3, v3, Lvv/b1;->a:Ljava/lang/Object;

    .line 441
    .line 442
    check-cast v3, Ljava/lang/Iterable;

    .line 443
    .line 444
    new-instance v5, Ljava/util/ArrayList;

    .line 445
    .line 446
    move-object/from16 p1, v0

    .line 447
    .line 448
    const/16 v4, 0xa

    .line 449
    .line 450
    invoke-static {v3, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 451
    .line 452
    .line 453
    move-result v0

    .line 454
    invoke-direct {v5, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 455
    .line 456
    .line 457
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 458
    .line 459
    .line 460
    move-result-object v19

    .line 461
    :goto_10
    invoke-interface/range {v19 .. v19}, Ljava/util/Iterator;->hasNext()Z

    .line 462
    .line 463
    .line 464
    move-result v0

    .line 465
    if-eqz v0, :cond_17

    .line 466
    .line 467
    invoke-interface/range {v19 .. v19}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    check-cast v0, Lay0/o;

    .line 472
    .line 473
    move v3, v4

    .line 474
    move-object v4, v0

    .line 475
    new-instance v0, Lb1/g0;

    .line 476
    .line 477
    move-object/from16 v20, v5

    .line 478
    .line 479
    const/4 v5, 0x3

    .line 480
    move-object/from16 v18, p1

    .line 481
    .line 482
    move-object v3, v1

    .line 483
    move-object v6, v2

    .line 484
    move-object/from16 v2, v16

    .line 485
    .line 486
    move-object/from16 v7, v20

    .line 487
    .line 488
    const/4 v8, 0x1

    .line 489
    move-object/from16 v1, p0

    .line 490
    .line 491
    invoke-direct/range {v0 .. v5}, Lb1/g0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 492
    .line 493
    .line 494
    new-instance v1, Lt2/b;

    .line 495
    .line 496
    const v2, -0x3ff28ce8

    .line 497
    .line 498
    .line 499
    invoke-direct {v1, v0, v8, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 500
    .line 501
    .line 502
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 503
    .line 504
    .line 505
    move/from16 v8, p5

    .line 506
    .line 507
    move-object v1, v3

    .line 508
    move-object v2, v6

    .line 509
    move-object v5, v7

    .line 510
    const/16 v4, 0xa

    .line 511
    .line 512
    move-object/from16 v6, p2

    .line 513
    .line 514
    move-object/from16 v7, p3

    .line 515
    .line 516
    goto :goto_10

    .line 517
    :cond_17
    move-object/from16 v18, p1

    .line 518
    .line 519
    move-object v3, v1

    .line 520
    move-object v6, v2

    .line 521
    move-object v7, v5

    .line 522
    const/4 v8, 0x1

    .line 523
    invoke-virtual {v6, v7}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 524
    .line 525
    .line 526
    goto :goto_11

    .line 527
    :cond_18
    move-object/from16 v18, v0

    .line 528
    .line 529
    move-object v3, v1

    .line 530
    move-object v6, v2

    .line 531
    const/4 v8, 0x1

    .line 532
    :goto_11
    move-object/from16 v0, v18

    .line 533
    .line 534
    check-cast v0, Ljava/lang/Iterable;

    .line 535
    .line 536
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    :goto_12
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 541
    .line 542
    .line 543
    move-result v1

    .line 544
    if-eqz v1, :cond_1a

    .line 545
    .line 546
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 547
    .line 548
    .line 549
    move-result-object v1

    .line 550
    check-cast v1, Lvv/b1;

    .line 551
    .line 552
    iget-object v1, v1, Lvv/b1;->a:Ljava/lang/Object;

    .line 553
    .line 554
    check-cast v1, Ljava/lang/Iterable;

    .line 555
    .line 556
    new-instance v2, Ljava/util/ArrayList;

    .line 557
    .line 558
    const/16 v7, 0xa

    .line 559
    .line 560
    invoke-static {v1, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 561
    .line 562
    .line 563
    move-result v4

    .line 564
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 565
    .line 566
    .line 567
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 568
    .line 569
    .line 570
    move-result-object v1

    .line 571
    :goto_13
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 572
    .line 573
    .line 574
    move-result v4

    .line 575
    if-eqz v4, :cond_19

    .line 576
    .line 577
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v4

    .line 581
    check-cast v4, Lay0/o;

    .line 582
    .line 583
    new-instance v5, Lvv/x0;

    .line 584
    .line 585
    const/4 v7, 0x1

    .line 586
    invoke-direct {v5, v3, v4, v7}, Lvv/x0;-><init>(Lx2/s;Lay0/o;I)V

    .line 587
    .line 588
    .line 589
    new-instance v4, Lt2/b;

    .line 590
    .line 591
    const v7, -0x2e7da88f

    .line 592
    .line 593
    .line 594
    invoke-direct {v4, v5, v8, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 595
    .line 596
    .line 597
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 598
    .line 599
    .line 600
    const/16 v7, 0xa

    .line 601
    .line 602
    goto :goto_13

    .line 603
    :cond_19
    invoke-virtual {v6, v2}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 604
    .line 605
    .line 606
    goto :goto_12

    .line 607
    :cond_1a
    invoke-static {v6}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 608
    .line 609
    .line 610
    move-result-object v4

    .line 611
    invoke-virtual {v14, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 612
    .line 613
    .line 614
    goto/16 :goto_e

    .line 615
    .line 616
    :goto_14
    invoke-virtual {v14, v2}, Ll2/t;->q(Z)V

    .line 617
    .line 618
    .line 619
    check-cast v4, Ljava/util/List;

    .line 620
    .line 621
    iget-object v0, v10, Lvv/c1;->d:Ljava/lang/Float;

    .line 622
    .line 623
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 627
    .line 628
    .line 629
    move-result v0

    .line 630
    const v1, -0x7a238346

    .line 631
    .line 632
    .line 633
    invoke-virtual {v14, v1}, Ll2/t;->Z(I)V

    .line 634
    .line 635
    .line 636
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 637
    .line 638
    .line 639
    move-result v1

    .line 640
    invoke-virtual {v14, v11, v12}, Ll2/t;->f(J)Z

    .line 641
    .line 642
    .line 643
    move-result v2

    .line 644
    or-int/2addr v1, v2

    .line 645
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 646
    .line 647
    .line 648
    move-result-object v2

    .line 649
    if-nez v1, :cond_1b

    .line 650
    .line 651
    if-ne v2, v13, :cond_1c

    .line 652
    .line 653
    :cond_1b
    new-instance v2, Lb1/q;

    .line 654
    .line 655
    const/4 v1, 0x2

    .line 656
    invoke-direct {v2, v10, v11, v12, v1}, Lb1/q;-><init>(Ljava/lang/Object;JI)V

    .line 657
    .line 658
    .line 659
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 660
    .line 661
    .line 662
    :cond_1c
    move-object v11, v2

    .line 663
    check-cast v11, Lay0/k;

    .line 664
    .line 665
    const/4 v1, 0x0

    .line 666
    invoke-virtual {v14, v1}, Ll2/t;->q(Z)V

    .line 667
    .line 668
    .line 669
    shl-int/lit8 v1, v9, 0x9

    .line 670
    .line 671
    const v2, 0xe000

    .line 672
    .line 673
    .line 674
    and-int/2addr v1, v2

    .line 675
    or-int/lit8 v1, v1, 0x40

    .line 676
    .line 677
    move v12, v0

    .line 678
    move-object v10, v4

    .line 679
    move v9, v15

    .line 680
    move-object/from16 v13, v17

    .line 681
    .line 682
    move v15, v1

    .line 683
    invoke-static/range {v9 .. v15}, Llp/ic;->a(ILjava/util/List;Lay0/k;FLx2/s;Ll2/o;I)V

    .line 684
    .line 685
    .line 686
    move-object v2, v13

    .line 687
    :goto_15
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 688
    .line 689
    .line 690
    move-result-object v6

    .line 691
    if-eqz v6, :cond_1d

    .line 692
    .line 693
    new-instance v0, Lvv/w0;

    .line 694
    .line 695
    move-object/from16 v1, p0

    .line 696
    .line 697
    move-object/from16 v3, p2

    .line 698
    .line 699
    move-object/from16 v4, p3

    .line 700
    .line 701
    move/from16 v5, p5

    .line 702
    .line 703
    invoke-direct/range {v0 .. v5}, Lvv/w0;-><init>(Lvv/m0;Lx2/s;Lay0/k;Lay0/k;I)V

    .line 704
    .line 705
    .line 706
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 707
    .line 708
    :cond_1d
    return-void

    .line 709
    :cond_1e
    move-object/from16 v1, p0

    .line 710
    .line 711
    move-object/from16 v6, p2

    .line 712
    .line 713
    move-object/from16 v7, p3

    .line 714
    .line 715
    move/from16 v8, p5

    .line 716
    .line 717
    const/4 v15, 0x0

    .line 718
    goto/16 :goto_a
.end method
