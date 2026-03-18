.class public final Li40/w2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Ljava/util/List;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;Lay0/k;Lay0/k;I)V
    .locals 0

    .line 1
    iput p5, p0, Li40/w2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/w2;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p2, p0, Li40/w2;->f:Ljava/util/List;

    .line 6
    .line 7
    iput-object p3, p0, Li40/w2;->g:Lay0/k;

    .line 8
    .line 9
    iput-object p4, p0, Li40/w2;->h:Lay0/k;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/w2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v3, p3

    .line 21
    .line 22
    check-cast v3, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v4, p4

    .line 25
    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    and-int/lit8 v5, v4, 0x6

    .line 33
    .line 34
    if-nez v5, :cond_1

    .line 35
    .line 36
    move-object v5, v3

    .line 37
    check-cast v5, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    const/4 v1, 0x4

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v1, 0x2

    .line 48
    :goto_0
    or-int/2addr v1, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move v1, v4

    .line 51
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 52
    .line 53
    if-nez v4, :cond_3

    .line 54
    .line 55
    move-object v4, v3

    .line 56
    check-cast v4, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_2

    .line 63
    .line 64
    const/16 v4, 0x20

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    const/16 v4, 0x10

    .line 68
    .line 69
    :goto_2
    or-int/2addr v1, v4

    .line 70
    :cond_3
    and-int/lit16 v4, v1, 0x93

    .line 71
    .line 72
    const/16 v5, 0x92

    .line 73
    .line 74
    const/4 v6, 0x1

    .line 75
    const/4 v7, 0x0

    .line 76
    if-eq v4, v5, :cond_4

    .line 77
    .line 78
    move v4, v6

    .line 79
    goto :goto_3

    .line 80
    :cond_4
    move v4, v7

    .line 81
    :goto_3
    and-int/2addr v1, v6

    .line 82
    check-cast v3, Ll2/t;

    .line 83
    .line 84
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_a

    .line 89
    .line 90
    iget-object v1, v0, Li40/w2;->e:Ljava/util/List;

    .line 91
    .line 92
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Lh40/w;

    .line 97
    .line 98
    const v4, -0x6f24b950

    .line 99
    .line 100
    .line 101
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 102
    .line 103
    .line 104
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    check-cast v5, Lj91/c;

    .line 111
    .line 112
    iget v9, v5, Lj91/c;->k:F

    .line 113
    .line 114
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v5

    .line 118
    check-cast v5, Lj91/c;

    .line 119
    .line 120
    iget v11, v5, Lj91/c;->k:F

    .line 121
    .line 122
    iget-object v5, v0, Li40/w2;->f:Ljava/util/List;

    .line 123
    .line 124
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    if-ne v2, v5, :cond_5

    .line 129
    .line 130
    const v2, -0x6f207d68

    .line 131
    .line 132
    .line 133
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    check-cast v2, Lj91/c;

    .line 141
    .line 142
    iget v2, v2, Lj91/c;->g:F

    .line 143
    .line 144
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 145
    .line 146
    .line 147
    :goto_4
    move v12, v2

    .line 148
    goto :goto_5

    .line 149
    :cond_5
    const v2, -0x6f1f3fa8

    .line 150
    .line 151
    .line 152
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    check-cast v2, Lj91/c;

    .line 160
    .line 161
    iget v2, v2, Lj91/c;->c:F

    .line 162
    .line 163
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    goto :goto_4

    .line 167
    :goto_5
    const/4 v13, 0x2

    .line 168
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 169
    .line 170
    const/4 v10, 0x0

    .line 171
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object v14

    .line 175
    iget-object v2, v0, Li40/w2;->g:Lay0/k;

    .line 176
    .line 177
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v5

    .line 185
    or-int/2addr v4, v5

    .line 186
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v5

    .line 190
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 191
    .line 192
    if-nez v4, :cond_6

    .line 193
    .line 194
    if-ne v5, v6, :cond_7

    .line 195
    .line 196
    :cond_6
    new-instance v5, Li40/x2;

    .line 197
    .line 198
    const/4 v4, 0x2

    .line 199
    invoke-direct {v5, v2, v1, v4}, Li40/x2;-><init>(Lay0/k;Lh40/w;I)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    :cond_7
    move-object/from16 v18, v5

    .line 206
    .line 207
    check-cast v18, Lay0/a;

    .line 208
    .line 209
    const/16 v19, 0xf

    .line 210
    .line 211
    const/4 v15, 0x0

    .line 212
    const/16 v16, 0x0

    .line 213
    .line 214
    const/16 v17, 0x0

    .line 215
    .line 216
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    iget-object v0, v0, Li40/w2;->h:Lay0/k;

    .line 221
    .line 222
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v4

    .line 226
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v5

    .line 230
    or-int/2addr v4, v5

    .line 231
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v5

    .line 235
    if-nez v4, :cond_8

    .line 236
    .line 237
    if-ne v5, v6, :cond_9

    .line 238
    .line 239
    :cond_8
    new-instance v5, Li40/x2;

    .line 240
    .line 241
    const/4 v4, 0x3

    .line 242
    invoke-direct {v5, v0, v1, v4}, Li40/x2;-><init>(Lay0/k;Lh40/w;I)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    :cond_9
    check-cast v5, Lay0/a;

    .line 249
    .line 250
    invoke-static {v1, v2, v5, v3, v7}, Li40/a3;->a(Lh40/w;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 254
    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_a
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 258
    .line 259
    .line 260
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 261
    .line 262
    return-object v0

    .line 263
    :pswitch_0
    move-object/from16 v1, p1

    .line 264
    .line 265
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 266
    .line 267
    move-object/from16 v2, p2

    .line 268
    .line 269
    check-cast v2, Ljava/lang/Number;

    .line 270
    .line 271
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 272
    .line 273
    .line 274
    move-result v2

    .line 275
    move-object/from16 v3, p3

    .line 276
    .line 277
    check-cast v3, Ll2/o;

    .line 278
    .line 279
    move-object/from16 v4, p4

    .line 280
    .line 281
    check-cast v4, Ljava/lang/Number;

    .line 282
    .line 283
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 284
    .line 285
    .line 286
    move-result v4

    .line 287
    and-int/lit8 v5, v4, 0x6

    .line 288
    .line 289
    if-nez v5, :cond_c

    .line 290
    .line 291
    move-object v5, v3

    .line 292
    check-cast v5, Ll2/t;

    .line 293
    .line 294
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    move-result v1

    .line 298
    if-eqz v1, :cond_b

    .line 299
    .line 300
    const/4 v1, 0x4

    .line 301
    goto :goto_7

    .line 302
    :cond_b
    const/4 v1, 0x2

    .line 303
    :goto_7
    or-int/2addr v1, v4

    .line 304
    goto :goto_8

    .line 305
    :cond_c
    move v1, v4

    .line 306
    :goto_8
    and-int/lit8 v4, v4, 0x30

    .line 307
    .line 308
    if-nez v4, :cond_e

    .line 309
    .line 310
    move-object v4, v3

    .line 311
    check-cast v4, Ll2/t;

    .line 312
    .line 313
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    if-eqz v4, :cond_d

    .line 318
    .line 319
    const/16 v4, 0x20

    .line 320
    .line 321
    goto :goto_9

    .line 322
    :cond_d
    const/16 v4, 0x10

    .line 323
    .line 324
    :goto_9
    or-int/2addr v1, v4

    .line 325
    :cond_e
    and-int/lit16 v4, v1, 0x93

    .line 326
    .line 327
    const/16 v5, 0x92

    .line 328
    .line 329
    const/4 v6, 0x1

    .line 330
    const/4 v7, 0x0

    .line 331
    if-eq v4, v5, :cond_f

    .line 332
    .line 333
    move v4, v6

    .line 334
    goto :goto_a

    .line 335
    :cond_f
    move v4, v7

    .line 336
    :goto_a
    and-int/2addr v1, v6

    .line 337
    check-cast v3, Ll2/t;

    .line 338
    .line 339
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 340
    .line 341
    .line 342
    move-result v1

    .line 343
    if-eqz v1, :cond_15

    .line 344
    .line 345
    iget-object v1, v0, Li40/w2;->e:Ljava/util/List;

    .line 346
    .line 347
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v1

    .line 351
    check-cast v1, Lh40/w;

    .line 352
    .line 353
    const v4, -0x6b1178e2

    .line 354
    .line 355
    .line 356
    invoke-virtual {v3, v4}, Ll2/t;->Y(I)V

    .line 357
    .line 358
    .line 359
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 360
    .line 361
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 362
    .line 363
    .line 364
    move-result-object v5

    .line 365
    check-cast v5, Lj91/c;

    .line 366
    .line 367
    iget v9, v5, Lj91/c;->k:F

    .line 368
    .line 369
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v5

    .line 373
    check-cast v5, Lj91/c;

    .line 374
    .line 375
    iget v11, v5, Lj91/c;->k:F

    .line 376
    .line 377
    iget-object v5, v0, Li40/w2;->f:Ljava/util/List;

    .line 378
    .line 379
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 380
    .line 381
    .line 382
    move-result v5

    .line 383
    if-ne v2, v5, :cond_10

    .line 384
    .line 385
    const v2, -0x6b0d3d76

    .line 386
    .line 387
    .line 388
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    check-cast v2, Lj91/c;

    .line 396
    .line 397
    iget v2, v2, Lj91/c;->e:F

    .line 398
    .line 399
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 400
    .line 401
    .line 402
    :goto_b
    move v12, v2

    .line 403
    goto :goto_c

    .line 404
    :cond_10
    const v2, -0x6b0c0377

    .line 405
    .line 406
    .line 407
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v3, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object v2

    .line 414
    check-cast v2, Lj91/c;

    .line 415
    .line 416
    iget v2, v2, Lj91/c;->c:F

    .line 417
    .line 418
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 419
    .line 420
    .line 421
    goto :goto_b

    .line 422
    :goto_c
    const/4 v13, 0x2

    .line 423
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 424
    .line 425
    const/4 v10, 0x0

    .line 426
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 427
    .line 428
    .line 429
    move-result-object v14

    .line 430
    iget-object v2, v0, Li40/w2;->g:Lay0/k;

    .line 431
    .line 432
    invoke-virtual {v3, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 433
    .line 434
    .line 435
    move-result v4

    .line 436
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    move-result v5

    .line 440
    or-int/2addr v4, v5

    .line 441
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v5

    .line 445
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 446
    .line 447
    if-nez v4, :cond_11

    .line 448
    .line 449
    if-ne v5, v6, :cond_12

    .line 450
    .line 451
    :cond_11
    new-instance v5, Li40/x2;

    .line 452
    .line 453
    const/4 v4, 0x0

    .line 454
    invoke-direct {v5, v2, v1, v4}, Li40/x2;-><init>(Lay0/k;Lh40/w;I)V

    .line 455
    .line 456
    .line 457
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    :cond_12
    move-object/from16 v18, v5

    .line 461
    .line 462
    check-cast v18, Lay0/a;

    .line 463
    .line 464
    const/16 v19, 0xf

    .line 465
    .line 466
    const/4 v15, 0x0

    .line 467
    const/16 v16, 0x0

    .line 468
    .line 469
    const/16 v17, 0x0

    .line 470
    .line 471
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 472
    .line 473
    .line 474
    move-result-object v2

    .line 475
    iget-object v0, v0, Li40/w2;->h:Lay0/k;

    .line 476
    .line 477
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 478
    .line 479
    .line 480
    move-result v4

    .line 481
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 482
    .line 483
    .line 484
    move-result v5

    .line 485
    or-int/2addr v4, v5

    .line 486
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v5

    .line 490
    if-nez v4, :cond_13

    .line 491
    .line 492
    if-ne v5, v6, :cond_14

    .line 493
    .line 494
    :cond_13
    new-instance v5, Li40/x2;

    .line 495
    .line 496
    const/4 v4, 0x1

    .line 497
    invoke-direct {v5, v0, v1, v4}, Li40/x2;-><init>(Lay0/k;Lh40/w;I)V

    .line 498
    .line 499
    .line 500
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 501
    .line 502
    .line 503
    :cond_14
    check-cast v5, Lay0/a;

    .line 504
    .line 505
    invoke-static {v1, v2, v5, v3, v7}, Li40/a3;->a(Lh40/w;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 506
    .line 507
    .line 508
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 509
    .line 510
    .line 511
    goto :goto_d

    .line 512
    :cond_15
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 513
    .line 514
    .line 515
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 516
    .line 517
    return-object v0

    .line 518
    nop

    .line 519
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
