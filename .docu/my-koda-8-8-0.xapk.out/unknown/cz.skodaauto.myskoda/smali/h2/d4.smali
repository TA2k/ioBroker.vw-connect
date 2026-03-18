.class public final Lh2/d4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Li2/z;

.field public final synthetic e:Li2/c0;

.field public final synthetic f:Ljava/lang/Long;

.field public final synthetic g:Ljava/lang/Long;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Li2/y;

.field public final synthetic j:Lh2/g2;

.field public final synthetic k:Lh2/e8;

.field public final synthetic l:Lh2/z1;

.field public final synthetic m:Ljava/util/List;


# direct methods
.method public constructor <init>(Li2/z;Li2/c0;Ljava/lang/Long;Ljava/lang/Long;Lay0/k;Li2/y;Lh2/g2;Lh2/e8;Lh2/z1;Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/d4;->d:Li2/z;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/d4;->e:Li2/c0;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/d4;->f:Ljava/lang/Long;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/d4;->g:Ljava/lang/Long;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/d4;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/d4;->i:Li2/y;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/d4;->j:Lh2/g2;

    .line 17
    .line 18
    iput-object p8, p0, Lh2/d4;->k:Lh2/e8;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/d4;->l:Lh2/z1;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/d4;->m:Ljava/util/List;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    move-object/from16 v3, p3

    .line 16
    .line 17
    check-cast v3, Ll2/o;

    .line 18
    .line 19
    move-object/from16 v4, p4

    .line 20
    .line 21
    check-cast v4, Ljava/lang/Number;

    .line 22
    .line 23
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    and-int/lit8 v5, v4, 0x6

    .line 28
    .line 29
    if-nez v5, :cond_1

    .line 30
    .line 31
    move-object v5, v3

    .line 32
    check-cast v5, Ll2/t;

    .line 33
    .line 34
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_0

    .line 39
    .line 40
    const/4 v5, 0x4

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v5, 0x2

    .line 43
    :goto_0
    or-int/2addr v5, v4

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v5, v4

    .line 46
    :goto_1
    const/16 v6, 0x30

    .line 47
    .line 48
    and-int/2addr v4, v6

    .line 49
    if-nez v4, :cond_3

    .line 50
    .line 51
    move-object v4, v3

    .line 52
    check-cast v4, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_2

    .line 59
    .line 60
    const/16 v4, 0x20

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    const/16 v4, 0x10

    .line 64
    .line 65
    :goto_2
    or-int/2addr v5, v4

    .line 66
    :cond_3
    and-int/lit16 v4, v5, 0x93

    .line 67
    .line 68
    const/16 v8, 0x92

    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    const/4 v10, 0x1

    .line 72
    if-eq v4, v8, :cond_4

    .line 73
    .line 74
    move v4, v10

    .line 75
    goto :goto_3

    .line 76
    :cond_4
    move v4, v9

    .line 77
    :goto_3
    and-int/2addr v5, v10

    .line 78
    check-cast v3, Ll2/t;

    .line 79
    .line 80
    invoke-virtual {v3, v5, v4}, Ll2/t;->O(IZ)Z

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    if-eqz v4, :cond_12

    .line 85
    .line 86
    iget-object v4, v0, Lh2/d4;->d:Li2/z;

    .line 87
    .line 88
    check-cast v4, Li2/b0;

    .line 89
    .line 90
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    iget-object v5, v0, Lh2/d4;->e:Li2/c0;

    .line 94
    .line 95
    if-gtz v2, :cond_5

    .line 96
    .line 97
    :goto_4
    move-object v11, v5

    .line 98
    goto :goto_5

    .line 99
    :cond_5
    iget-wide v11, v5, Li2/c0;->e:J

    .line 100
    .line 101
    invoke-static {v11, v12}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    sget-object v8, Li2/b0;->e:Ljava/time/ZoneId;

    .line 106
    .line 107
    invoke-virtual {v5, v8}, Ljava/time/Instant;->atZone(Ljava/time/ZoneId;)Ljava/time/ZonedDateTime;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    invoke-virtual {v5}, Ljava/time/ZonedDateTime;->toLocalDate()Ljava/time/LocalDate;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    int-to-long v11, v2

    .line 116
    invoke-virtual {v5, v11, v12}, Ljava/time/LocalDate;->plusMonths(J)Ljava/time/LocalDate;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v4, v2}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    goto :goto_4

    .line 125
    :goto_5
    invoke-static {v1}, Landroidx/compose/foundation/lazy/a;->d(Landroidx/compose/foundation/lazy/a;)Lx2/s;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 130
    .line 131
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 132
    .line 133
    invoke-static {v2, v4, v3, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    iget-wide v4, v3, Ll2/t;->T:J

    .line 138
    .line 139
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 140
    .line 141
    .line 142
    move-result v4

    .line 143
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    invoke-static {v3, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 152
    .line 153
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 157
    .line 158
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 159
    .line 160
    .line 161
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 162
    .line 163
    if-eqz v12, :cond_6

    .line 164
    .line 165
    invoke-virtual {v3, v8}, Ll2/t;->l(Lay0/a;)V

    .line 166
    .line 167
    .line 168
    goto :goto_6

    .line 169
    :cond_6
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 170
    .line 171
    .line 172
    :goto_6
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 173
    .line 174
    invoke-static {v8, v2, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 175
    .line 176
    .line 177
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 178
    .line 179
    invoke-static {v2, v5, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 180
    .line 181
    .line 182
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 183
    .line 184
    iget-boolean v5, v3, Ll2/t;->S:Z

    .line 185
    .line 186
    if-nez v5, :cond_7

    .line 187
    .line 188
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v5

    .line 192
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 193
    .line 194
    .line 195
    move-result-object v8

    .line 196
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v5

    .line 200
    if-nez v5, :cond_8

    .line 201
    .line 202
    :cond_7
    invoke-static {v4, v3, v4, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 203
    .line 204
    .line 205
    :cond_8
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 206
    .line 207
    invoke-static {v2, v1, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 208
    .line 209
    .line 210
    sget-object v1, Lk2/m;->z:Lk2/p0;

    .line 211
    .line 212
    invoke-static {v1, v3}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    move-object v13, v11

    .line 217
    new-instance v11, Laa/r;

    .line 218
    .line 219
    const/16 v17, 0x5

    .line 220
    .line 221
    iget-object v12, v0, Lh2/d4;->j:Lh2/g2;

    .line 222
    .line 223
    iget-object v14, v0, Lh2/d4;->d:Li2/z;

    .line 224
    .line 225
    iget-object v15, v0, Lh2/d4;->m:Ljava/util/List;

    .line 226
    .line 227
    iget-object v2, v0, Lh2/d4;->l:Lh2/z1;

    .line 228
    .line 229
    move-object/from16 v16, v2

    .line 230
    .line 231
    invoke-direct/range {v11 .. v17}, Laa/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 232
    .line 233
    .line 234
    const v2, -0x2264cd2d

    .line 235
    .line 236
    .line 237
    invoke-static {v2, v3, v11}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    invoke-static {v1, v2, v3, v6}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 242
    .line 243
    .line 244
    iget-object v15, v0, Lh2/d4;->f:Ljava/lang/Long;

    .line 245
    .line 246
    iget-object v2, v0, Lh2/d4;->g:Ljava/lang/Long;

    .line 247
    .line 248
    if-eqz v15, :cond_11

    .line 249
    .line 250
    if-eqz v2, :cond_11

    .line 251
    .line 252
    const v4, 0xb15795d

    .line 253
    .line 254
    .line 255
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v3, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v4

    .line 262
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v5

    .line 266
    or-int/2addr v4, v5

    .line 267
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    if-nez v4, :cond_a

    .line 272
    .line 273
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 274
    .line 275
    if-ne v5, v4, :cond_9

    .line 276
    .line 277
    goto :goto_7

    .line 278
    :cond_9
    move-object v6, v2

    .line 279
    move/from16 p3, v10

    .line 280
    .line 281
    goto/16 :goto_f

    .line 282
    .line 283
    :cond_a
    :goto_7
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 284
    .line 285
    .line 286
    move-result-wide v4

    .line 287
    invoke-virtual {v14, v4, v5}, Li2/z;->a(J)Li2/y;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 292
    .line 293
    .line 294
    move-result-wide v5

    .line 295
    invoke-virtual {v14, v5, v6}, Li2/z;->a(J)Li2/y;

    .line 296
    .line 297
    .line 298
    move-result-object v5

    .line 299
    move-object v6, v2

    .line 300
    iget-wide v1, v4, Li2/y;->g:J

    .line 301
    .line 302
    const/16 p2, 0x20

    .line 303
    .line 304
    iget-wide v7, v13, Li2/c0;->f:J

    .line 305
    .line 306
    iget v11, v13, Li2/c0;->d:I

    .line 307
    .line 308
    cmp-long v17, v1, v7

    .line 309
    .line 310
    move/from16 p3, v10

    .line 311
    .line 312
    if-gtz v17, :cond_10

    .line 313
    .line 314
    move/from16 v17, v11

    .line 315
    .line 316
    iget-wide v10, v5, Li2/y;->g:J

    .line 317
    .line 318
    move-wide/from16 v18, v10

    .line 319
    .line 320
    iget-wide v9, v13, Li2/c0;->e:J

    .line 321
    .line 322
    cmp-long v11, v18, v9

    .line 323
    .line 324
    if-gez v11, :cond_b

    .line 325
    .line 326
    goto :goto_d

    .line 327
    :cond_b
    cmp-long v1, v1, v9

    .line 328
    .line 329
    if-ltz v1, :cond_c

    .line 330
    .line 331
    move/from16 v25, p3

    .line 332
    .line 333
    goto :goto_8

    .line 334
    :cond_c
    const/16 v25, 0x0

    .line 335
    .line 336
    :goto_8
    cmp-long v1, v18, v7

    .line 337
    .line 338
    if-gtz v1, :cond_d

    .line 339
    .line 340
    move/from16 v26, p3

    .line 341
    .line 342
    goto :goto_9

    .line 343
    :cond_d
    const/16 v26, 0x0

    .line 344
    .line 345
    :goto_9
    if-eqz v25, :cond_e

    .line 346
    .line 347
    iget v1, v4, Li2/y;->f:I

    .line 348
    .line 349
    add-int v11, v17, v1

    .line 350
    .line 351
    add-int/lit8 v11, v11, -0x1

    .line 352
    .line 353
    goto :goto_a

    .line 354
    :cond_e
    move/from16 v11, v17

    .line 355
    .line 356
    :goto_a
    if-eqz v26, :cond_f

    .line 357
    .line 358
    iget v1, v5, Li2/y;->f:I

    .line 359
    .line 360
    :goto_b
    add-int v1, v17, v1

    .line 361
    .line 362
    add-int/lit8 v1, v1, -0x1

    .line 363
    .line 364
    goto :goto_c

    .line 365
    :cond_f
    iget v1, v13, Li2/c0;->c:I

    .line 366
    .line 367
    goto :goto_b

    .line 368
    :goto_c
    rem-int/lit8 v2, v11, 0x7

    .line 369
    .line 370
    div-int/lit8 v11, v11, 0x7

    .line 371
    .line 372
    int-to-long v4, v2

    .line 373
    shl-long v4, v4, p2

    .line 374
    .line 375
    int-to-long v7, v11

    .line 376
    const-wide v9, 0xffffffffL

    .line 377
    .line 378
    .line 379
    .line 380
    .line 381
    and-long/2addr v7, v9

    .line 382
    or-long v21, v4, v7

    .line 383
    .line 384
    rem-int/lit8 v2, v1, 0x7

    .line 385
    .line 386
    div-int/lit8 v1, v1, 0x7

    .line 387
    .line 388
    int-to-long v4, v2

    .line 389
    shl-long v4, v4, p2

    .line 390
    .line 391
    int-to-long v1, v1

    .line 392
    and-long/2addr v1, v9

    .line 393
    or-long v23, v4, v1

    .line 394
    .line 395
    new-instance v20, Lh2/f8;

    .line 396
    .line 397
    invoke-direct/range {v20 .. v26}, Lh2/f8;-><init>(JJZZ)V

    .line 398
    .line 399
    .line 400
    move-object/from16 v1, v20

    .line 401
    .line 402
    goto :goto_e

    .line 403
    :cond_10
    :goto_d
    const/4 v1, 0x0

    .line 404
    :goto_e
    invoke-virtual {v3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 405
    .line 406
    .line 407
    move-object v5, v1

    .line 408
    :goto_f
    move-object v1, v5

    .line 409
    check-cast v1, Lh2/f8;

    .line 410
    .line 411
    const/4 v2, 0x0

    .line 412
    invoke-virtual {v3, v2}, Ll2/t;->q(Z)V

    .line 413
    .line 414
    .line 415
    move-object/from16 v17, v1

    .line 416
    .line 417
    goto :goto_10

    .line 418
    :cond_11
    move-object v6, v2

    .line 419
    move v2, v9

    .line 420
    move/from16 p3, v10

    .line 421
    .line 422
    const v1, 0xb1d95c2

    .line 423
    .line 424
    .line 425
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 426
    .line 427
    .line 428
    invoke-virtual {v3, v2}, Ll2/t;->q(Z)V

    .line 429
    .line 430
    .line 431
    const/16 v17, 0x0

    .line 432
    .line 433
    :goto_10
    iget-object v1, v0, Lh2/d4;->i:Li2/y;

    .line 434
    .line 435
    iget-wide v1, v1, Li2/y;->g:J

    .line 436
    .line 437
    iget-object v4, v14, Li2/z;->a:Ljava/util/Locale;

    .line 438
    .line 439
    const/16 v23, 0x0

    .line 440
    .line 441
    move-object/from16 v18, v12

    .line 442
    .line 443
    iget-object v12, v0, Lh2/d4;->h:Lay0/k;

    .line 444
    .line 445
    iget-object v0, v0, Lh2/d4;->k:Lh2/e8;

    .line 446
    .line 447
    move-object/from16 v19, v0

    .line 448
    .line 449
    move-object/from16 v22, v3

    .line 450
    .line 451
    move-object/from16 v21, v4

    .line 452
    .line 453
    move-object v11, v13

    .line 454
    move-object/from16 v20, v16

    .line 455
    .line 456
    move-wide v13, v1

    .line 457
    move-object/from16 v16, v6

    .line 458
    .line 459
    invoke-static/range {v11 .. v23}, Lh2/m3;->i(Li2/c0;Lay0/k;JLjava/lang/Long;Ljava/lang/Long;Lh2/f8;Lh2/g2;Lh2/e8;Lh2/z1;Ljava/util/Locale;Ll2/o;I)V

    .line 460
    .line 461
    .line 462
    move/from16 v0, p3

    .line 463
    .line 464
    invoke-virtual {v3, v0}, Ll2/t;->q(Z)V

    .line 465
    .line 466
    .line 467
    goto :goto_11

    .line 468
    :cond_12
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 469
    .line 470
    .line 471
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 472
    .line 473
    return-object v0
.end method
