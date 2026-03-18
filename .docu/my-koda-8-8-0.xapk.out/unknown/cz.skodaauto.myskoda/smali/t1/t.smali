.class public final Lt1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:Lt1/p0;

.field public final synthetic b:Lay0/k;

.field public final synthetic c:Ll4/v;

.field public final synthetic d:Ll4/p;

.field public final synthetic e:Lt4/c;

.field public final synthetic f:I


# direct methods
.method public constructor <init>(Lt1/p0;Lay0/k;Ll4/v;Ll4/p;Lt4/c;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/t;->a:Lt1/p0;

    .line 5
    .line 6
    iput-object p2, p0, Lt1/t;->b:Lay0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lt1/t;->c:Ll4/v;

    .line 9
    .line 10
    iput-object p4, p0, Lt1/t;->d:Ll4/p;

    .line 11
    .line 12
    iput-object p5, p0, Lt1/t;->e:Lt4/c;

    .line 13
    .line 14
    iput p6, p0, Lt1/t;->f:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v13, v0, Lt1/t;->a:Lt1/p0;

    .line 4
    .line 5
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Lv2/f;->e()Lay0/k;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v2, 0x0

    .line 17
    :goto_0
    invoke-static {v1}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    :try_start_0
    invoke-virtual {v13}, Lt1/p0;->d()Lt1/j1;

    .line 22
    .line 23
    .line 24
    move-result-object v15
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 26
    .line 27
    .line 28
    if-eqz v15, :cond_1

    .line 29
    .line 30
    iget-object v1, v15, Lt1/j1;->a:Lg4/l0;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/4 v1, 0x0

    .line 34
    :goto_1
    iget-object v2, v13, Lt1/p0;->a:Lt1/v0;

    .line 35
    .line 36
    invoke-interface/range {p1 .. p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 37
    .line 38
    .line 39
    move-result-object v9

    .line 40
    iget v3, v2, Lt1/v0;->f:I

    .line 41
    .line 42
    iget-boolean v4, v2, Lt1/v0;->e:Z

    .line 43
    .line 44
    iget v5, v2, Lt1/v0;->c:I

    .line 45
    .line 46
    const-wide v16, 0xffffffffL

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    const/16 v18, 0x20

    .line 52
    .line 53
    if-eqz v1, :cond_9

    .line 54
    .line 55
    iget-object v10, v1, Lg4/l0;->b:Lg4/o;

    .line 56
    .line 57
    iget-object v11, v1, Lg4/l0;->a:Lg4/k0;

    .line 58
    .line 59
    iget-object v12, v2, Lt1/v0;->a:Lg4/g;

    .line 60
    .line 61
    iget-object v6, v2, Lt1/v0;->b:Lg4/p0;

    .line 62
    .line 63
    iget-object v7, v2, Lt1/v0;->i:Ljava/util/List;

    .line 64
    .line 65
    iget-object v14, v2, Lt1/v0;->g:Lt4/c;

    .line 66
    .line 67
    iget-object v8, v2, Lt1/v0;->h:Lk4/m;

    .line 68
    .line 69
    move-object/from16 v20, v1

    .line 70
    .line 71
    iget-object v1, v10, Lg4/o;->a:Landroidx/lifecycle/c1;

    .line 72
    .line 73
    invoke-virtual {v1}, Landroidx/lifecycle/c1;->a()Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    if-eqz v1, :cond_2

    .line 78
    .line 79
    move-wide/from16 v11, p3

    .line 80
    .line 81
    move-object v6, v9

    .line 82
    goto/16 :goto_3

    .line 83
    .line 84
    :cond_2
    iget-object v1, v11, Lg4/k0;->a:Lg4/g;

    .line 85
    .line 86
    move-object/from16 v22, v8

    .line 87
    .line 88
    move-object/from16 v21, v9

    .line 89
    .line 90
    iget-wide v8, v11, Lg4/k0;->j:J

    .line 91
    .line 92
    invoke-static {v1, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-eqz v1, :cond_8

    .line 97
    .line 98
    iget-object v1, v11, Lg4/k0;->b:Lg4/p0;

    .line 99
    .line 100
    invoke-virtual {v1, v6}, Lg4/p0;->c(Lg4/p0;)Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-eqz v1, :cond_8

    .line 105
    .line 106
    iget-object v1, v11, Lg4/k0;->c:Ljava/util/List;

    .line 107
    .line 108
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_8

    .line 113
    .line 114
    iget v1, v11, Lg4/k0;->d:I

    .line 115
    .line 116
    if-ne v1, v5, :cond_8

    .line 117
    .line 118
    iget-boolean v1, v11, Lg4/k0;->e:Z

    .line 119
    .line 120
    if-ne v1, v4, :cond_8

    .line 121
    .line 122
    iget v1, v11, Lg4/k0;->f:I

    .line 123
    .line 124
    if-ne v1, v3, :cond_8

    .line 125
    .line 126
    iget-object v1, v11, Lg4/k0;->g:Lt4/c;

    .line 127
    .line 128
    invoke-static {v1, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-eqz v1, :cond_8

    .line 133
    .line 134
    iget-object v1, v11, Lg4/k0;->h:Lt4/m;

    .line 135
    .line 136
    move-object/from16 v6, v21

    .line 137
    .line 138
    if-ne v1, v6, :cond_7

    .line 139
    .line 140
    iget-object v1, v11, Lg4/k0;->i:Lk4/m;

    .line 141
    .line 142
    move-object/from16 v7, v22

    .line 143
    .line 144
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-nez v1, :cond_3

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_3
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    invoke-static {v8, v9}, Lt4/a;->j(J)I

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    if-eq v1, v7, :cond_4

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_4
    if-nez v4, :cond_5

    .line 163
    .line 164
    const/4 v1, 0x2

    .line 165
    if-ne v3, v1, :cond_6

    .line 166
    .line 167
    :cond_5
    invoke-static/range {p3 .. p4}, Lt4/a;->h(J)I

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    invoke-static {v8, v9}, Lt4/a;->h(J)I

    .line 172
    .line 173
    .line 174
    move-result v7

    .line 175
    if-ne v1, v7, :cond_7

    .line 176
    .line 177
    invoke-static/range {p3 .. p4}, Lt4/a;->g(J)I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    invoke-static {v8, v9}, Lt4/a;->g(J)I

    .line 182
    .line 183
    .line 184
    move-result v7

    .line 185
    if-ne v1, v7, :cond_7

    .line 186
    .line 187
    :cond_6
    new-instance v1, Lg4/k0;

    .line 188
    .line 189
    iget-object v3, v11, Lg4/k0;->a:Lg4/g;

    .line 190
    .line 191
    move-object v4, v3

    .line 192
    iget-object v3, v2, Lt1/v0;->b:Lg4/p0;

    .line 193
    .line 194
    move-object v2, v4

    .line 195
    iget-object v4, v11, Lg4/k0;->c:Ljava/util/List;

    .line 196
    .line 197
    iget v5, v11, Lg4/k0;->d:I

    .line 198
    .line 199
    iget-boolean v6, v11, Lg4/k0;->e:Z

    .line 200
    .line 201
    iget v7, v11, Lg4/k0;->f:I

    .line 202
    .line 203
    iget-object v8, v11, Lg4/k0;->g:Lt4/c;

    .line 204
    .line 205
    iget-object v9, v11, Lg4/k0;->h:Lt4/m;

    .line 206
    .line 207
    iget-object v11, v11, Lg4/k0;->i:Lk4/m;

    .line 208
    .line 209
    move-object v14, v10

    .line 210
    move-object v10, v11

    .line 211
    move-object/from16 v23, v20

    .line 212
    .line 213
    move-wide/from16 v11, p3

    .line 214
    .line 215
    invoke-direct/range {v1 .. v12}, Lg4/k0;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;IZILt4/c;Lt4/m;Lk4/m;J)V

    .line 216
    .line 217
    .line 218
    iget v2, v14, Lg4/o;->d:F

    .line 219
    .line 220
    invoke-static {v2}, Lt1/l0;->o(F)I

    .line 221
    .line 222
    .line 223
    move-result v2

    .line 224
    iget v3, v14, Lg4/o;->e:F

    .line 225
    .line 226
    invoke-static {v3}, Lt1/l0;->o(F)I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    int-to-long v4, v2

    .line 231
    shl-long v4, v4, v18

    .line 232
    .line 233
    int-to-long v2, v3

    .line 234
    and-long v2, v2, v16

    .line 235
    .line 236
    or-long/2addr v2, v4

    .line 237
    invoke-static {v11, v12, v2, v3}, Lt4/b;->d(JJ)J

    .line 238
    .line 239
    .line 240
    move-result-wide v2

    .line 241
    new-instance v4, Lg4/l0;

    .line 242
    .line 243
    invoke-direct {v4, v1, v14, v2, v3}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 244
    .line 245
    .line 246
    goto/16 :goto_8

    .line 247
    .line 248
    :cond_7
    :goto_2
    move-wide/from16 v11, p3

    .line 249
    .line 250
    :goto_3
    move-object/from16 v23, v20

    .line 251
    .line 252
    goto :goto_4

    .line 253
    :cond_8
    move-wide/from16 v11, p3

    .line 254
    .line 255
    move-object/from16 v23, v20

    .line 256
    .line 257
    move-object/from16 v6, v21

    .line 258
    .line 259
    goto :goto_4

    .line 260
    :cond_9
    move-wide/from16 v11, p3

    .line 261
    .line 262
    move-object/from16 v23, v1

    .line 263
    .line 264
    move-object v6, v9

    .line 265
    :goto_4
    invoke-virtual {v2, v6}, Lt1/v0;->a(Lt4/m;)V

    .line 266
    .line 267
    .line 268
    invoke-static {v11, v12}, Lt4/a;->j(J)I

    .line 269
    .line 270
    .line 271
    move-result v1

    .line 272
    if-nez v4, :cond_a

    .line 273
    .line 274
    const/4 v7, 0x2

    .line 275
    if-ne v3, v7, :cond_b

    .line 276
    .line 277
    :cond_a
    invoke-static {v11, v12}, Lt4/a;->d(J)Z

    .line 278
    .line 279
    .line 280
    move-result v7

    .line 281
    if-eqz v7, :cond_b

    .line 282
    .line 283
    invoke-static {v11, v12}, Lt4/a;->h(J)I

    .line 284
    .line 285
    .line 286
    move-result v7

    .line 287
    goto :goto_5

    .line 288
    :cond_b
    const v7, 0x7fffffff

    .line 289
    .line 290
    .line 291
    :goto_5
    if-nez v4, :cond_c

    .line 292
    .line 293
    const/4 v4, 0x2

    .line 294
    if-ne v3, v4, :cond_c

    .line 295
    .line 296
    const/16 v28, 0x1

    .line 297
    .line 298
    goto :goto_6

    .line 299
    :cond_c
    move/from16 v28, v5

    .line 300
    .line 301
    :goto_6
    const-string v3, "layoutIntrinsics must be called first"

    .line 302
    .line 303
    if-ne v1, v7, :cond_d

    .line 304
    .line 305
    goto :goto_7

    .line 306
    :cond_d
    iget-object v4, v2, Lt1/v0;->j:Landroidx/lifecycle/c1;

    .line 307
    .line 308
    if-eqz v4, :cond_12

    .line 309
    .line 310
    invoke-virtual {v4}, Landroidx/lifecycle/c1;->b()F

    .line 311
    .line 312
    .line 313
    move-result v4

    .line 314
    invoke-static {v4}, Lt1/l0;->o(F)I

    .line 315
    .line 316
    .line 317
    move-result v4

    .line 318
    invoke-static {v4, v1, v7}, Lkp/r9;->e(III)I

    .line 319
    .line 320
    .line 321
    move-result v7

    .line 322
    :goto_7
    new-instance v24, Lg4/o;

    .line 323
    .line 324
    iget-object v1, v2, Lt1/v0;->j:Landroidx/lifecycle/c1;

    .line 325
    .line 326
    if-eqz v1, :cond_11

    .line 327
    .line 328
    invoke-static {v11, v12}, Lt4/a;->g(J)I

    .line 329
    .line 330
    .line 331
    move-result v3

    .line 332
    const/4 v4, 0x0

    .line 333
    invoke-static {v4, v7, v4, v3}, Lkp/a9;->b(IIII)J

    .line 334
    .line 335
    .line 336
    move-result-wide v26

    .line 337
    iget v3, v2, Lt1/v0;->f:I

    .line 338
    .line 339
    move-object/from16 v25, v1

    .line 340
    .line 341
    move/from16 v29, v3

    .line 342
    .line 343
    invoke-direct/range {v24 .. v29}, Lg4/o;-><init>(Landroidx/lifecycle/c1;JII)V

    .line 344
    .line 345
    .line 346
    move-object/from16 v14, v24

    .line 347
    .line 348
    iget v1, v14, Lg4/o;->d:F

    .line 349
    .line 350
    invoke-static {v1}, Lt1/l0;->o(F)I

    .line 351
    .line 352
    .line 353
    move-result v1

    .line 354
    iget v3, v14, Lg4/o;->e:F

    .line 355
    .line 356
    invoke-static {v3}, Lt1/l0;->o(F)I

    .line 357
    .line 358
    .line 359
    move-result v3

    .line 360
    int-to-long v4, v1

    .line 361
    shl-long v4, v4, v18

    .line 362
    .line 363
    int-to-long v7, v3

    .line 364
    and-long v7, v7, v16

    .line 365
    .line 366
    or-long v3, v4, v7

    .line 367
    .line 368
    invoke-static {v11, v12, v3, v4}, Lt4/b;->d(JJ)J

    .line 369
    .line 370
    .line 371
    move-result-wide v3

    .line 372
    new-instance v1, Lg4/l0;

    .line 373
    .line 374
    move-object v5, v1

    .line 375
    new-instance v1, Lg4/k0;

    .line 376
    .line 377
    iget-object v7, v2, Lt1/v0;->a:Lg4/g;

    .line 378
    .line 379
    move-wide v8, v3

    .line 380
    iget-object v3, v2, Lt1/v0;->b:Lg4/p0;

    .line 381
    .line 382
    iget-object v4, v2, Lt1/v0;->i:Ljava/util/List;

    .line 383
    .line 384
    move-object v10, v5

    .line 385
    iget v5, v2, Lt1/v0;->c:I

    .line 386
    .line 387
    move-object/from16 v21, v6

    .line 388
    .line 389
    iget-boolean v6, v2, Lt1/v0;->e:Z

    .line 390
    .line 391
    move-object/from16 v19, v7

    .line 392
    .line 393
    iget v7, v2, Lt1/v0;->f:I

    .line 394
    .line 395
    move-wide/from16 v24, v8

    .line 396
    .line 397
    iget-object v8, v2, Lt1/v0;->g:Lt4/c;

    .line 398
    .line 399
    iget-object v2, v2, Lt1/v0;->h:Lk4/m;

    .line 400
    .line 401
    move-object v0, v10

    .line 402
    move-object/from16 v9, v21

    .line 403
    .line 404
    move-wide/from16 v30, v24

    .line 405
    .line 406
    move-object v10, v2

    .line 407
    move-object/from16 v2, v19

    .line 408
    .line 409
    invoke-direct/range {v1 .. v12}, Lg4/k0;-><init>(Lg4/g;Lg4/p0;Ljava/util/List;IZILt4/c;Lt4/m;Lk4/m;J)V

    .line 410
    .line 411
    .line 412
    move-wide/from16 v8, v30

    .line 413
    .line 414
    invoke-direct {v0, v1, v14, v8, v9}, Lg4/l0;-><init>(Lg4/k0;Lg4/o;J)V

    .line 415
    .line 416
    .line 417
    move-object v4, v0

    .line 418
    :goto_8
    iget-wide v0, v4, Lg4/l0;->c:J

    .line 419
    .line 420
    shr-long v2, v0, v18

    .line 421
    .line 422
    long-to-int v2, v2

    .line 423
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 424
    .line 425
    .line 426
    move-result-object v2

    .line 427
    and-long v0, v0, v16

    .line 428
    .line 429
    long-to-int v0, v0

    .line 430
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 435
    .line 436
    .line 437
    move-result v1

    .line 438
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 439
    .line 440
    .line 441
    move-result v0

    .line 442
    move-object/from16 v14, v23

    .line 443
    .line 444
    invoke-static {v14, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 445
    .line 446
    .line 447
    move-result v2

    .line 448
    if-nez v2, :cond_f

    .line 449
    .line 450
    new-instance v2, Lt1/j1;

    .line 451
    .line 452
    if-eqz v15, :cond_e

    .line 453
    .line 454
    iget-object v14, v15, Lt1/j1;->c:Lt3/y;

    .line 455
    .line 456
    goto :goto_9

    .line 457
    :cond_e
    const/4 v14, 0x0

    .line 458
    :goto_9
    invoke-direct {v2, v4, v14}, Lt1/j1;-><init>(Lg4/l0;Lt3/y;)V

    .line 459
    .line 460
    .line 461
    iget-object v3, v13, Lt1/p0;->i:Ll2/j1;

    .line 462
    .line 463
    invoke-virtual {v3, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 464
    .line 465
    .line 466
    const/4 v2, 0x0

    .line 467
    iput-boolean v2, v13, Lt1/p0;->p:Z

    .line 468
    .line 469
    move-object/from16 v3, p0

    .line 470
    .line 471
    iget-object v5, v3, Lt1/t;->b:Lay0/k;

    .line 472
    .line 473
    invoke-interface {v5, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    iget-object v5, v3, Lt1/t;->c:Ll4/v;

    .line 477
    .line 478
    iget-object v6, v3, Lt1/t;->d:Ll4/p;

    .line 479
    .line 480
    invoke-static {v13, v5, v6}, Lt1/l0;->v(Lt1/p0;Ll4/v;Ll4/p;)V

    .line 481
    .line 482
    .line 483
    goto :goto_a

    .line 484
    :cond_f
    const/4 v2, 0x0

    .line 485
    move-object/from16 v3, p0

    .line 486
    .line 487
    :goto_a
    iget v5, v3, Lt1/t;->f:I

    .line 488
    .line 489
    const/4 v6, 0x1

    .line 490
    if-ne v5, v6, :cond_10

    .line 491
    .line 492
    iget-object v5, v4, Lg4/l0;->b:Lg4/o;

    .line 493
    .line 494
    invoke-virtual {v5, v2}, Lg4/o;->b(I)F

    .line 495
    .line 496
    .line 497
    move-result v2

    .line 498
    invoke-static {v2}, Lt1/l0;->o(F)I

    .line 499
    .line 500
    .line 501
    move-result v7

    .line 502
    goto :goto_b

    .line 503
    :cond_10
    move v7, v2

    .line 504
    :goto_b
    iget-object v2, v3, Lt1/t;->e:Lt4/c;

    .line 505
    .line 506
    invoke-interface {v2, v7}, Lt4/c;->n0(I)F

    .line 507
    .line 508
    .line 509
    move-result v2

    .line 510
    iget-object v3, v13, Lt1/p0;->g:Ll2/j1;

    .line 511
    .line 512
    new-instance v5, Lt4/f;

    .line 513
    .line 514
    invoke-direct {v5, v2}, Lt4/f;-><init>(F)V

    .line 515
    .line 516
    .line 517
    invoke-virtual {v3, v5}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    sget-object v2, Lt3/d;->a:Lt3/o;

    .line 521
    .line 522
    iget v3, v4, Lg4/l0;->d:F

    .line 523
    .line 524
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 525
    .line 526
    .line 527
    move-result v3

    .line 528
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 529
    .line 530
    .line 531
    move-result-object v3

    .line 532
    new-instance v5, Llx0/l;

    .line 533
    .line 534
    invoke-direct {v5, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 535
    .line 536
    .line 537
    sget-object v2, Lt3/d;->b:Lt3/o;

    .line 538
    .line 539
    iget v3, v4, Lg4/l0;->e:F

    .line 540
    .line 541
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 542
    .line 543
    .line 544
    move-result v3

    .line 545
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 546
    .line 547
    .line 548
    move-result-object v3

    .line 549
    new-instance v4, Llx0/l;

    .line 550
    .line 551
    invoke-direct {v4, v2, v3}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 552
    .line 553
    .line 554
    filled-new-array {v5, v4}, [Llx0/l;

    .line 555
    .line 556
    .line 557
    move-result-object v2

    .line 558
    invoke-static {v2}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 559
    .line 560
    .line 561
    move-result-object v2

    .line 562
    new-instance v3, Ldj/a;

    .line 563
    .line 564
    const/16 v4, 0xe

    .line 565
    .line 566
    invoke-direct {v3, v4}, Ldj/a;-><init>(I)V

    .line 567
    .line 568
    .line 569
    move-object/from16 v4, p1

    .line 570
    .line 571
    invoke-interface {v4, v1, v0, v2, v3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 572
    .line 573
    .line 574
    move-result-object v0

    .line 575
    return-object v0

    .line 576
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 577
    .line 578
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    throw v0

    .line 582
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 583
    .line 584
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 585
    .line 586
    .line 587
    throw v0

    .line 588
    :catchall_0
    move-exception v0

    .line 589
    invoke-static {v1, v3, v2}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 590
    .line 591
    .line 592
    throw v0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/t;->a:Lt1/p0;

    .line 2
    .line 3
    iget-object p2, p0, Lt1/p0;->a:Lt1/v0;

    .line 4
    .line 5
    invoke-interface {p1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p2, p1}, Lt1/v0;->a(Lt4/m;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lt1/p0;->a:Lt1/v0;

    .line 13
    .line 14
    iget-object p0, p0, Lt1/v0;->j:Landroidx/lifecycle/c1;

    .line 15
    .line 16
    if-eqz p0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0}, Landroidx/lifecycle/c1;->b()F

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-static {p0}, Lt1/l0;->o(F)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "layoutIntrinsics must be called first"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method
