.class public final Lb60/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb60/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb60/h;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb60/h;->d:I

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
    move-object/from16 v2, p3

    .line 20
    .line 21
    check-cast v2, Ll2/o;

    .line 22
    .line 23
    move-object/from16 v3, p4

    .line 24
    .line 25
    check-cast v3, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    and-int/lit8 v4, v3, 0x6

    .line 32
    .line 33
    if-nez v4, :cond_1

    .line 34
    .line 35
    move-object v4, v2

    .line 36
    check-cast v4, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    if-eqz v4, :cond_0

    .line 43
    .line 44
    const/4 v4, 0x4

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 v4, 0x2

    .line 47
    :goto_0
    or-int/2addr v3, v4

    .line 48
    :cond_1
    and-int/lit16 v4, v3, 0x83

    .line 49
    .line 50
    const/16 v5, 0x82

    .line 51
    .line 52
    if-eq v4, v5, :cond_2

    .line 53
    .line 54
    const/4 v4, 0x1

    .line 55
    goto :goto_1

    .line 56
    :cond_2
    const/4 v4, 0x0

    .line 57
    :goto_1
    and-int/lit8 v5, v3, 0x1

    .line 58
    .line 59
    check-cast v2, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_3

    .line 66
    .line 67
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lay0/o;

    .line 70
    .line 71
    and-int/lit8 v3, v3, 0xe

    .line 72
    .line 73
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    invoke-interface {v0, v1, v2, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_3
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 82
    .line 83
    .line 84
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object v0

    .line 87
    :pswitch_0
    move-object/from16 v1, p1

    .line 88
    .line 89
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 90
    .line 91
    move-object/from16 v2, p2

    .line 92
    .line 93
    check-cast v2, Ljava/lang/Number;

    .line 94
    .line 95
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    move-object/from16 v3, p3

    .line 100
    .line 101
    check-cast v3, Ll2/o;

    .line 102
    .line 103
    move-object/from16 v4, p4

    .line 104
    .line 105
    check-cast v4, Ljava/lang/Number;

    .line 106
    .line 107
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    and-int/lit8 v5, v4, 0x6

    .line 112
    .line 113
    if-nez v5, :cond_5

    .line 114
    .line 115
    move-object v5, v3

    .line 116
    check-cast v5, Ll2/t;

    .line 117
    .line 118
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-eqz v1, :cond_4

    .line 123
    .line 124
    const/4 v1, 0x4

    .line 125
    goto :goto_3

    .line 126
    :cond_4
    const/4 v1, 0x2

    .line 127
    :goto_3
    or-int/2addr v1, v4

    .line 128
    goto :goto_4

    .line 129
    :cond_5
    move v1, v4

    .line 130
    :goto_4
    and-int/lit8 v4, v4, 0x30

    .line 131
    .line 132
    if-nez v4, :cond_7

    .line 133
    .line 134
    move-object v4, v3

    .line 135
    check-cast v4, Ll2/t;

    .line 136
    .line 137
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    if-eqz v4, :cond_6

    .line 142
    .line 143
    const/16 v4, 0x20

    .line 144
    .line 145
    goto :goto_5

    .line 146
    :cond_6
    const/16 v4, 0x10

    .line 147
    .line 148
    :goto_5
    or-int/2addr v1, v4

    .line 149
    :cond_7
    and-int/lit16 v4, v1, 0x93

    .line 150
    .line 151
    const/16 v5, 0x92

    .line 152
    .line 153
    const/4 v6, 0x0

    .line 154
    const/4 v7, 0x1

    .line 155
    if-eq v4, v5, :cond_8

    .line 156
    .line 157
    move v4, v7

    .line 158
    goto :goto_6

    .line 159
    :cond_8
    move v4, v6

    .line 160
    :goto_6
    and-int/2addr v1, v7

    .line 161
    check-cast v3, Ll2/t;

    .line 162
    .line 163
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    if-eqz v1, :cond_9

    .line 168
    .line 169
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Ljava/util/List;

    .line 172
    .line 173
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    check-cast v0, Ljava/lang/String;

    .line 178
    .line 179
    const v1, -0x4eb8eac9

    .line 180
    .line 181
    .line 182
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 183
    .line 184
    .line 185
    new-instance v1, Ljava/lang/StringBuilder;

    .line 186
    .line 187
    const-string v2, "  > "

    .line 188
    .line 189
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 200
    .line 201
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    check-cast v0, Lj91/f;

    .line 206
    .line 207
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 208
    .line 209
    .line 210
    move-result-object v8

    .line 211
    const/16 v27, 0x0

    .line 212
    .line 213
    const v28, 0xfffc

    .line 214
    .line 215
    .line 216
    const/4 v9, 0x0

    .line 217
    const-wide/16 v10, 0x0

    .line 218
    .line 219
    const-wide/16 v12, 0x0

    .line 220
    .line 221
    const/4 v14, 0x0

    .line 222
    const-wide/16 v15, 0x0

    .line 223
    .line 224
    const/16 v17, 0x0

    .line 225
    .line 226
    const/16 v18, 0x0

    .line 227
    .line 228
    const-wide/16 v19, 0x0

    .line 229
    .line 230
    const/16 v21, 0x0

    .line 231
    .line 232
    const/16 v22, 0x0

    .line 233
    .line 234
    const/16 v23, 0x0

    .line 235
    .line 236
    const/16 v24, 0x0

    .line 237
    .line 238
    const/16 v26, 0x0

    .line 239
    .line 240
    move-object/from16 v25, v3

    .line 241
    .line 242
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 246
    .line 247
    .line 248
    goto :goto_7

    .line 249
    :cond_9
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 250
    .line 251
    .line 252
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 253
    .line 254
    return-object v0

    .line 255
    :pswitch_1
    move-object/from16 v1, p1

    .line 256
    .line 257
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 258
    .line 259
    move-object/from16 v2, p2

    .line 260
    .line 261
    check-cast v2, Ljava/lang/Number;

    .line 262
    .line 263
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    move-object/from16 v3, p3

    .line 268
    .line 269
    check-cast v3, Ll2/o;

    .line 270
    .line 271
    move-object/from16 v4, p4

    .line 272
    .line 273
    check-cast v4, Ljava/lang/Number;

    .line 274
    .line 275
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 276
    .line 277
    .line 278
    move-result v4

    .line 279
    and-int/lit8 v5, v4, 0x6

    .line 280
    .line 281
    if-nez v5, :cond_b

    .line 282
    .line 283
    move-object v5, v3

    .line 284
    check-cast v5, Ll2/t;

    .line 285
    .line 286
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v1

    .line 290
    if-eqz v1, :cond_a

    .line 291
    .line 292
    const/4 v1, 0x4

    .line 293
    goto :goto_8

    .line 294
    :cond_a
    const/4 v1, 0x2

    .line 295
    :goto_8
    or-int/2addr v1, v4

    .line 296
    goto :goto_9

    .line 297
    :cond_b
    move v1, v4

    .line 298
    :goto_9
    and-int/lit8 v4, v4, 0x30

    .line 299
    .line 300
    if-nez v4, :cond_d

    .line 301
    .line 302
    move-object v4, v3

    .line 303
    check-cast v4, Ll2/t;

    .line 304
    .line 305
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 306
    .line 307
    .line 308
    move-result v4

    .line 309
    if-eqz v4, :cond_c

    .line 310
    .line 311
    const/16 v4, 0x20

    .line 312
    .line 313
    goto :goto_a

    .line 314
    :cond_c
    const/16 v4, 0x10

    .line 315
    .line 316
    :goto_a
    or-int/2addr v1, v4

    .line 317
    :cond_d
    and-int/lit16 v4, v1, 0x93

    .line 318
    .line 319
    const/16 v5, 0x92

    .line 320
    .line 321
    const/4 v6, 0x0

    .line 322
    const/4 v7, 0x1

    .line 323
    if-eq v4, v5, :cond_e

    .line 324
    .line 325
    move v4, v7

    .line 326
    goto :goto_b

    .line 327
    :cond_e
    move v4, v6

    .line 328
    :goto_b
    and-int/2addr v1, v7

    .line 329
    check-cast v3, Ll2/t;

    .line 330
    .line 331
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 332
    .line 333
    .line 334
    move-result v1

    .line 335
    if-eqz v1, :cond_f

    .line 336
    .line 337
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v0, Ljava/util/List;

    .line 340
    .line 341
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    check-cast v0, Lp30/b;

    .line 346
    .line 347
    const v1, 0x78f6c15c

    .line 348
    .line 349
    .line 350
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 351
    .line 352
    .line 353
    iget-object v0, v0, Lp30/b;->a:Ljava/lang/String;

    .line 354
    .line 355
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 356
    .line 357
    .line 358
    move-result-object v7

    .line 359
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 360
    .line 361
    const/high16 v1, 0x3f800000    # 1.0f

    .line 362
    .line 363
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 364
    .line 365
    .line 366
    move-result-object v0

    .line 367
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 368
    .line 369
    invoke-virtual {v3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    check-cast v1, Lj91/c;

    .line 374
    .line 375
    iget v1, v1, Lj91/c;->b:F

    .line 376
    .line 377
    invoke-static {v1}, Ls1/f;->b(F)Ls1/e;

    .line 378
    .line 379
    .line 380
    move-result-object v1

    .line 381
    invoke-static {v0, v1}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 382
    .line 383
    .line 384
    move-result-object v8

    .line 385
    const v0, 0x7f08023c

    .line 386
    .line 387
    .line 388
    invoke-static {v0, v6, v3}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 389
    .line 390
    .line 391
    move-result-object v18

    .line 392
    const/16 v24, 0x0

    .line 393
    .line 394
    const v25, 0x1ddfc

    .line 395
    .line 396
    .line 397
    const/4 v9, 0x0

    .line 398
    const/4 v10, 0x0

    .line 399
    const/4 v11, 0x0

    .line 400
    const/4 v12, 0x0

    .line 401
    const/4 v13, 0x0

    .line 402
    sget-object v14, Lt3/j;->c:Lt3/x0;

    .line 403
    .line 404
    const/4 v15, 0x0

    .line 405
    const/16 v16, 0x0

    .line 406
    .line 407
    const/16 v17, 0x0

    .line 408
    .line 409
    const/16 v19, 0x0

    .line 410
    .line 411
    const/16 v20, 0x0

    .line 412
    .line 413
    const/16 v21, 0x0

    .line 414
    .line 415
    const/high16 v23, 0x30000000

    .line 416
    .line 417
    move-object/from16 v22, v3

    .line 418
    .line 419
    invoke-static/range {v7 .. v25}, Lxf0/i0;->c(Landroid/net/Uri;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ld01/h0;Lx2/e;Lt3/k;Ljava/util/List;Li3/c;Li3/c;Li3/c;ZZLe3/m;Ll2/o;III)V

    .line 420
    .line 421
    .line 422
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 423
    .line 424
    .line 425
    goto :goto_c

    .line 426
    :cond_f
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 427
    .line 428
    .line 429
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 430
    .line 431
    return-object v0

    .line 432
    :pswitch_2
    move-object/from16 v1, p1

    .line 433
    .line 434
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 435
    .line 436
    move-object/from16 v2, p2

    .line 437
    .line 438
    check-cast v2, Ljava/lang/Number;

    .line 439
    .line 440
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 441
    .line 442
    .line 443
    move-result v2

    .line 444
    move-object/from16 v3, p3

    .line 445
    .line 446
    check-cast v3, Ll2/o;

    .line 447
    .line 448
    move-object/from16 v4, p4

    .line 449
    .line 450
    check-cast v4, Ljava/lang/Number;

    .line 451
    .line 452
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 453
    .line 454
    .line 455
    move-result v4

    .line 456
    and-int/lit8 v5, v4, 0x6

    .line 457
    .line 458
    if-nez v5, :cond_11

    .line 459
    .line 460
    move-object v5, v3

    .line 461
    check-cast v5, Ll2/t;

    .line 462
    .line 463
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    move-result v5

    .line 467
    if-eqz v5, :cond_10

    .line 468
    .line 469
    const/4 v5, 0x4

    .line 470
    goto :goto_d

    .line 471
    :cond_10
    const/4 v5, 0x2

    .line 472
    :goto_d
    or-int/2addr v5, v4

    .line 473
    goto :goto_e

    .line 474
    :cond_11
    move v5, v4

    .line 475
    :goto_e
    and-int/lit8 v4, v4, 0x30

    .line 476
    .line 477
    if-nez v4, :cond_13

    .line 478
    .line 479
    move-object v4, v3

    .line 480
    check-cast v4, Ll2/t;

    .line 481
    .line 482
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 483
    .line 484
    .line 485
    move-result v4

    .line 486
    if-eqz v4, :cond_12

    .line 487
    .line 488
    const/16 v4, 0x20

    .line 489
    .line 490
    goto :goto_f

    .line 491
    :cond_12
    const/16 v4, 0x10

    .line 492
    .line 493
    :goto_f
    or-int/2addr v5, v4

    .line 494
    :cond_13
    and-int/lit16 v4, v5, 0x93

    .line 495
    .line 496
    const/16 v6, 0x92

    .line 497
    .line 498
    const/4 v7, 0x1

    .line 499
    const/4 v8, 0x0

    .line 500
    if-eq v4, v6, :cond_14

    .line 501
    .line 502
    move v4, v7

    .line 503
    goto :goto_10

    .line 504
    :cond_14
    move v4, v8

    .line 505
    :goto_10
    and-int/2addr v5, v7

    .line 506
    check-cast v3, Ll2/t;

    .line 507
    .line 508
    invoke-virtual {v3, v5, v4}, Ll2/t;->O(IZ)Z

    .line 509
    .line 510
    .line 511
    move-result v4

    .line 512
    if-eqz v4, :cond_15

    .line 513
    .line 514
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast v0, Ljava/util/List;

    .line 517
    .line 518
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object v0

    .line 522
    check-cast v0, Llu0/a;

    .line 523
    .line 524
    const v2, 0x1d36b102

    .line 525
    .line 526
    .line 527
    invoke-virtual {v3, v2}, Ll2/t;->Y(I)V

    .line 528
    .line 529
    .line 530
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 531
    .line 532
    invoke-static {v1, v2}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 533
    .line 534
    .line 535
    move-result-object v1

    .line 536
    invoke-static {v0, v1, v3, v8}, Ljp/wa;->f(Llu0/a;Lx2/s;Ll2/o;I)V

    .line 537
    .line 538
    .line 539
    invoke-virtual {v3, v8}, Ll2/t;->q(Z)V

    .line 540
    .line 541
    .line 542
    goto :goto_11

    .line 543
    :cond_15
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 544
    .line 545
    .line 546
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 547
    .line 548
    return-object v0

    .line 549
    :pswitch_3
    move-object/from16 v1, p1

    .line 550
    .line 551
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 552
    .line 553
    move-object/from16 v2, p2

    .line 554
    .line 555
    check-cast v2, Ljava/lang/Number;

    .line 556
    .line 557
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 558
    .line 559
    .line 560
    move-result v2

    .line 561
    move-object/from16 v3, p3

    .line 562
    .line 563
    check-cast v3, Ll2/o;

    .line 564
    .line 565
    move-object/from16 v4, p4

    .line 566
    .line 567
    check-cast v4, Ljava/lang/Number;

    .line 568
    .line 569
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 570
    .line 571
    .line 572
    move-result v4

    .line 573
    and-int/lit8 v5, v4, 0x6

    .line 574
    .line 575
    if-nez v5, :cond_17

    .line 576
    .line 577
    move-object v5, v3

    .line 578
    check-cast v5, Ll2/t;

    .line 579
    .line 580
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 581
    .line 582
    .line 583
    move-result v1

    .line 584
    if-eqz v1, :cond_16

    .line 585
    .line 586
    const/4 v1, 0x4

    .line 587
    goto :goto_12

    .line 588
    :cond_16
    const/4 v1, 0x2

    .line 589
    :goto_12
    or-int/2addr v1, v4

    .line 590
    goto :goto_13

    .line 591
    :cond_17
    move v1, v4

    .line 592
    :goto_13
    and-int/lit8 v4, v4, 0x30

    .line 593
    .line 594
    if-nez v4, :cond_19

    .line 595
    .line 596
    move-object v4, v3

    .line 597
    check-cast v4, Ll2/t;

    .line 598
    .line 599
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 600
    .line 601
    .line 602
    move-result v4

    .line 603
    if-eqz v4, :cond_18

    .line 604
    .line 605
    const/16 v4, 0x20

    .line 606
    .line 607
    goto :goto_14

    .line 608
    :cond_18
    const/16 v4, 0x10

    .line 609
    .line 610
    :goto_14
    or-int/2addr v1, v4

    .line 611
    :cond_19
    and-int/lit16 v4, v1, 0x93

    .line 612
    .line 613
    const/16 v5, 0x92

    .line 614
    .line 615
    const/4 v6, 0x1

    .line 616
    const/4 v7, 0x0

    .line 617
    if-eq v4, v5, :cond_1a

    .line 618
    .line 619
    move v4, v6

    .line 620
    goto :goto_15

    .line 621
    :cond_1a
    move v4, v7

    .line 622
    :goto_15
    and-int/2addr v1, v6

    .line 623
    check-cast v3, Ll2/t;

    .line 624
    .line 625
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 626
    .line 627
    .line 628
    move-result v1

    .line 629
    if-eqz v1, :cond_1e

    .line 630
    .line 631
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast v0, Ljava/util/List;

    .line 634
    .line 635
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 636
    .line 637
    .line 638
    move-result-object v0

    .line 639
    check-cast v0, Lba0/b;

    .line 640
    .line 641
    const v1, 0x41b945d5

    .line 642
    .line 643
    .line 644
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 645
    .line 646
    .line 647
    iget-object v1, v0, Lba0/b;->a:Ljava/lang/String;

    .line 648
    .line 649
    invoke-static {v1, v3, v7}, Lca0/b;->e(Ljava/lang/String;Ll2/o;I)V

    .line 650
    .line 651
    .line 652
    const v1, 0x7dfdc0b2

    .line 653
    .line 654
    .line 655
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 656
    .line 657
    .line 658
    iget-object v0, v0, Lba0/b;->b:Ljava/util/List;

    .line 659
    .line 660
    check-cast v0, Ljava/lang/Iterable;

    .line 661
    .line 662
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 663
    .line 664
    .line 665
    move-result-object v0

    .line 666
    move v1, v7

    .line 667
    :goto_16
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 668
    .line 669
    .line 670
    move-result v2

    .line 671
    if-eqz v2, :cond_1d

    .line 672
    .line 673
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 674
    .line 675
    .line 676
    move-result-object v2

    .line 677
    add-int/lit8 v4, v1, 0x1

    .line 678
    .line 679
    if-ltz v1, :cond_1c

    .line 680
    .line 681
    check-cast v2, Lba0/a;

    .line 682
    .line 683
    if-lez v1, :cond_1b

    .line 684
    .line 685
    move v1, v6

    .line 686
    goto :goto_17

    .line 687
    :cond_1b
    move v1, v7

    .line 688
    :goto_17
    invoke-static {v2, v1, v3, v7}, Lca0/b;->d(Lba0/a;ZLl2/o;I)V

    .line 689
    .line 690
    .line 691
    move v1, v4

    .line 692
    goto :goto_16

    .line 693
    :cond_1c
    invoke-static {}, Ljp/k1;->r()V

    .line 694
    .line 695
    .line 696
    const/4 v0, 0x0

    .line 697
    throw v0

    .line 698
    :cond_1d
    invoke-virtual {v3, v7}, Ll2/t;->q(Z)V

    .line 699
    .line 700
    .line 701
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 702
    .line 703
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 704
    .line 705
    .line 706
    move-result-object v0

    .line 707
    check-cast v0, Lj91/c;

    .line 708
    .line 709
    iget v0, v0, Lj91/c;->f:F

    .line 710
    .line 711
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 712
    .line 713
    invoke-static {v1, v0, v3, v7}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 714
    .line 715
    .line 716
    goto :goto_18

    .line 717
    :cond_1e
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 718
    .line 719
    .line 720
    :goto_18
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 721
    .line 722
    return-object v0

    .line 723
    :pswitch_4
    move-object/from16 v1, p1

    .line 724
    .line 725
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 726
    .line 727
    move-object/from16 v2, p2

    .line 728
    .line 729
    check-cast v2, Ljava/lang/Number;

    .line 730
    .line 731
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 732
    .line 733
    .line 734
    move-result v2

    .line 735
    move-object/from16 v3, p3

    .line 736
    .line 737
    check-cast v3, Ll2/o;

    .line 738
    .line 739
    move-object/from16 v4, p4

    .line 740
    .line 741
    check-cast v4, Ljava/lang/Number;

    .line 742
    .line 743
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 744
    .line 745
    .line 746
    move-result v4

    .line 747
    and-int/lit8 v5, v4, 0x6

    .line 748
    .line 749
    if-nez v5, :cond_20

    .line 750
    .line 751
    move-object v5, v3

    .line 752
    check-cast v5, Ll2/t;

    .line 753
    .line 754
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 755
    .line 756
    .line 757
    move-result v5

    .line 758
    if-eqz v5, :cond_1f

    .line 759
    .line 760
    const/4 v5, 0x4

    .line 761
    goto :goto_19

    .line 762
    :cond_1f
    const/4 v5, 0x2

    .line 763
    :goto_19
    or-int/2addr v5, v4

    .line 764
    goto :goto_1a

    .line 765
    :cond_20
    move v5, v4

    .line 766
    :goto_1a
    and-int/lit8 v4, v4, 0x30

    .line 767
    .line 768
    if-nez v4, :cond_22

    .line 769
    .line 770
    move-object v4, v3

    .line 771
    check-cast v4, Ll2/t;

    .line 772
    .line 773
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 774
    .line 775
    .line 776
    move-result v4

    .line 777
    if-eqz v4, :cond_21

    .line 778
    .line 779
    const/16 v4, 0x20

    .line 780
    .line 781
    goto :goto_1b

    .line 782
    :cond_21
    const/16 v4, 0x10

    .line 783
    .line 784
    :goto_1b
    or-int/2addr v5, v4

    .line 785
    :cond_22
    and-int/lit16 v4, v5, 0x93

    .line 786
    .line 787
    const/16 v6, 0x92

    .line 788
    .line 789
    const/4 v7, 0x0

    .line 790
    const/4 v8, 0x1

    .line 791
    if-eq v4, v6, :cond_23

    .line 792
    .line 793
    move v4, v8

    .line 794
    goto :goto_1c

    .line 795
    :cond_23
    move v4, v7

    .line 796
    :goto_1c
    and-int/2addr v5, v8

    .line 797
    move-object v12, v3

    .line 798
    check-cast v12, Ll2/t;

    .line 799
    .line 800
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 801
    .line 802
    .line 803
    move-result v3

    .line 804
    if-eqz v3, :cond_24

    .line 805
    .line 806
    iget-object v0, v0, Lb60/h;->e:Ljava/lang/Object;

    .line 807
    .line 808
    check-cast v0, Ljava/util/List;

    .line 809
    .line 810
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 811
    .line 812
    .line 813
    move-result-object v0

    .line 814
    move-object v8, v0

    .line 815
    check-cast v8, La60/c;

    .line 816
    .line 817
    const v0, 0x2dca1edd

    .line 818
    .line 819
    .line 820
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 821
    .line 822
    .line 823
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 824
    .line 825
    invoke-static {v1, v0}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 826
    .line 827
    .line 828
    move-result-object v9

    .line 829
    const/16 v13, 0xc00

    .line 830
    .line 831
    const/4 v14, 0x2

    .line 832
    const/4 v10, 0x0

    .line 833
    const/4 v11, 0x1

    .line 834
    invoke-static/range {v8 .. v14}, Lb60/i;->e(La60/c;Lx2/s;Lay0/k;ZLl2/o;II)V

    .line 835
    .line 836
    .line 837
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 838
    .line 839
    .line 840
    goto :goto_1d

    .line 841
    :cond_24
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 842
    .line 843
    .line 844
    :goto_1d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 845
    .line 846
    return-object v0

    .line 847
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
