.class public final synthetic Luz/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Luz/i0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Luz/i0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Luz/i0;->d:I

    .line 4
    .line 5
    const-string v1, "it"

    .line 6
    .line 7
    const/4 v2, 0x6

    .line 8
    const/16 v3, 0x36

    .line 9
    .line 10
    const/4 v4, 0x0

    .line 11
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 12
    .line 13
    const/4 v6, 0x3

    .line 14
    const/4 v7, 0x0

    .line 15
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    const/4 v9, 0x1

    .line 18
    const/4 v10, 0x2

    .line 19
    packed-switch v0, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    move-object/from16 v0, p1

    .line 23
    .line 24
    check-cast v0, Ll2/o;

    .line 25
    .line 26
    move-object/from16 v1, p2

    .line 27
    .line 28
    check-cast v1, Ljava/lang/Integer;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    and-int/lit8 v2, v1, 0x3

    .line 35
    .line 36
    if-eq v2, v10, :cond_0

    .line 37
    .line 38
    move v7, v9

    .line 39
    :cond_0
    and-int/2addr v1, v9

    .line 40
    check-cast v0, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_3

    .line 47
    .line 48
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-ne v1, v5, :cond_1

    .line 53
    .line 54
    new-instance v1, Lz81/g;

    .line 55
    .line 56
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    :cond_1
    check-cast v1, Lay0/a;

    .line 63
    .line 64
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    if-ne v2, v5, :cond_2

    .line 69
    .line 70
    new-instance v2, Lz81/g;

    .line 71
    .line 72
    invoke-direct {v2, v10}, Lz81/g;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    check-cast v2, Lay0/a;

    .line 79
    .line 80
    invoke-static {v1, v2, v0, v3}, Lv50/a;->O(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_3
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_0
    return-object v8

    .line 88
    :pswitch_0
    move-object/from16 v0, p1

    .line 89
    .line 90
    check-cast v0, Ll2/o;

    .line 91
    .line 92
    move-object/from16 v1, p2

    .line 93
    .line 94
    check-cast v1, Ljava/lang/Integer;

    .line 95
    .line 96
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    and-int/lit8 v2, v1, 0x3

    .line 101
    .line 102
    if-eq v2, v10, :cond_4

    .line 103
    .line 104
    move v7, v9

    .line 105
    :cond_4
    and-int/2addr v1, v9

    .line 106
    check-cast v0, Ll2/t;

    .line 107
    .line 108
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    const v1, 0x7f12074f

    .line 115
    .line 116
    .line 117
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v10

    .line 121
    const/16 v17, 0x0

    .line 122
    .line 123
    const/16 v18, 0x3fd

    .line 124
    .line 125
    const/4 v9, 0x0

    .line 126
    const/4 v11, 0x0

    .line 127
    const/4 v12, 0x0

    .line 128
    const/4 v13, 0x0

    .line 129
    const/4 v14, 0x0

    .line 130
    const/4 v15, 0x0

    .line 131
    move-object/from16 v16, v0

    .line 132
    .line 133
    invoke-static/range {v9 .. v18}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_5
    move-object/from16 v16, v0

    .line 138
    .line 139
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 140
    .line 141
    .line 142
    :goto_1
    return-object v8

    .line 143
    :pswitch_1
    move-object/from16 v0, p1

    .line 144
    .line 145
    check-cast v0, Ll2/o;

    .line 146
    .line 147
    move-object/from16 v1, p2

    .line 148
    .line 149
    check-cast v1, Ljava/lang/Integer;

    .line 150
    .line 151
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    and-int/lit8 v2, v1, 0x3

    .line 156
    .line 157
    if-eq v2, v10, :cond_6

    .line 158
    .line 159
    move v7, v9

    .line 160
    :cond_6
    and-int/2addr v1, v9

    .line 161
    move-object v15, v0

    .line 162
    check-cast v15, Ll2/t;

    .line 163
    .line 164
    invoke-virtual {v15, v1, v7}, Ll2/t;->O(IZ)Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    if-eqz v0, :cond_a

    .line 169
    .line 170
    new-instance v11, Lu50/t;

    .line 171
    .line 172
    invoke-direct {v11}, Lu50/t;-><init>()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    if-ne v0, v5, :cond_7

    .line 180
    .line 181
    new-instance v0, Lz81/g;

    .line 182
    .line 183
    invoke-direct {v0, v10}, Lz81/g;-><init>(I)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    :cond_7
    move-object v12, v0

    .line 190
    check-cast v12, Lay0/a;

    .line 191
    .line 192
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    if-ne v0, v5, :cond_8

    .line 197
    .line 198
    new-instance v0, Lz81/g;

    .line 199
    .line 200
    invoke-direct {v0, v10}, Lz81/g;-><init>(I)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    :cond_8
    move-object v13, v0

    .line 207
    check-cast v13, Lay0/a;

    .line 208
    .line 209
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    if-ne v0, v5, :cond_9

    .line 214
    .line 215
    new-instance v0, Lz81/g;

    .line 216
    .line 217
    invoke-direct {v0, v10}, Lz81/g;-><init>(I)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    :cond_9
    move-object v14, v0

    .line 224
    check-cast v14, Lay0/a;

    .line 225
    .line 226
    const/16 v16, 0xdb0

    .line 227
    .line 228
    invoke-static/range {v11 .. v16}, Lv50/a;->L(Lu50/t;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 229
    .line 230
    .line 231
    goto :goto_2

    .line 232
    :cond_a
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 233
    .line 234
    .line 235
    :goto_2
    return-object v8

    .line 236
    :pswitch_2
    move-object/from16 v0, p1

    .line 237
    .line 238
    check-cast v0, Ll2/o;

    .line 239
    .line 240
    move-object/from16 v1, p2

    .line 241
    .line 242
    check-cast v1, Ljava/lang/Integer;

    .line 243
    .line 244
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    and-int/lit8 v2, v1, 0x3

    .line 249
    .line 250
    if-eq v2, v10, :cond_b

    .line 251
    .line 252
    move v7, v9

    .line 253
    :cond_b
    and-int/2addr v1, v9

    .line 254
    check-cast v0, Ll2/t;

    .line 255
    .line 256
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 257
    .line 258
    .line 259
    move-result v1

    .line 260
    if-eqz v1, :cond_e

    .line 261
    .line 262
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    if-ne v1, v5, :cond_c

    .line 267
    .line 268
    new-instance v1, Lz81/g;

    .line 269
    .line 270
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 274
    .line 275
    .line 276
    :cond_c
    check-cast v1, Lay0/a;

    .line 277
    .line 278
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v2

    .line 282
    if-ne v2, v5, :cond_d

    .line 283
    .line 284
    new-instance v2, Lz81/g;

    .line 285
    .line 286
    invoke-direct {v2, v10}, Lz81/g;-><init>(I)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    :cond_d
    check-cast v2, Lay0/a;

    .line 293
    .line 294
    invoke-static {v1, v2, v0, v3}, Lv50/a;->I(Lay0/a;Lay0/a;Ll2/o;I)V

    .line 295
    .line 296
    .line 297
    goto :goto_3

    .line 298
    :cond_e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 299
    .line 300
    .line 301
    :goto_3
    return-object v8

    .line 302
    :pswitch_3
    move-object/from16 v0, p1

    .line 303
    .line 304
    check-cast v0, Ll2/o;

    .line 305
    .line 306
    move-object/from16 v1, p2

    .line 307
    .line 308
    check-cast v1, Ljava/lang/Integer;

    .line 309
    .line 310
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 311
    .line 312
    .line 313
    move-result v1

    .line 314
    and-int/lit8 v2, v1, 0x3

    .line 315
    .line 316
    if-eq v2, v10, :cond_f

    .line 317
    .line 318
    move v7, v9

    .line 319
    :cond_f
    and-int/2addr v1, v9

    .line 320
    move-object v15, v0

    .line 321
    check-cast v15, Ll2/t;

    .line 322
    .line 323
    invoke-virtual {v15, v1, v7}, Ll2/t;->O(IZ)Z

    .line 324
    .line 325
    .line 326
    move-result v0

    .line 327
    if-eqz v0, :cond_12

    .line 328
    .line 329
    new-instance v11, Lu50/p;

    .line 330
    .line 331
    invoke-direct {v11}, Lu50/p;-><init>()V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v0

    .line 338
    if-ne v0, v5, :cond_10

    .line 339
    .line 340
    new-instance v0, Lz81/g;

    .line 341
    .line 342
    invoke-direct {v0, v10}, Lz81/g;-><init>(I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    :cond_10
    move-object v12, v0

    .line 349
    check-cast v12, Lay0/a;

    .line 350
    .line 351
    invoke-virtual {v15}, Ll2/t;->L()Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    if-ne v0, v5, :cond_11

    .line 356
    .line 357
    new-instance v0, Lz81/g;

    .line 358
    .line 359
    invoke-direct {v0, v10}, Lz81/g;-><init>(I)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {v15, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    :cond_11
    move-object v13, v0

    .line 366
    check-cast v13, Lay0/a;

    .line 367
    .line 368
    const/16 v16, 0x1b0

    .line 369
    .line 370
    const/16 v17, 0x8

    .line 371
    .line 372
    const/4 v14, 0x0

    .line 373
    invoke-static/range {v11 .. v17}, Lv50/a;->F(Lu50/p;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 374
    .line 375
    .line 376
    goto :goto_4

    .line 377
    :cond_12
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 378
    .line 379
    .line 380
    :goto_4
    return-object v8

    .line 381
    :pswitch_4
    move-object/from16 v0, p1

    .line 382
    .line 383
    check-cast v0, Ll2/o;

    .line 384
    .line 385
    move-object/from16 v1, p2

    .line 386
    .line 387
    check-cast v1, Ljava/lang/Integer;

    .line 388
    .line 389
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 390
    .line 391
    .line 392
    move-result v1

    .line 393
    and-int/lit8 v3, v1, 0x3

    .line 394
    .line 395
    if-eq v3, v10, :cond_13

    .line 396
    .line 397
    move v7, v9

    .line 398
    :cond_13
    and-int/2addr v1, v9

    .line 399
    check-cast v0, Ll2/t;

    .line 400
    .line 401
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 402
    .line 403
    .line 404
    move-result v1

    .line 405
    if-eqz v1, :cond_15

    .line 406
    .line 407
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    if-ne v1, v5, :cond_14

    .line 412
    .line 413
    new-instance v1, Lz81/g;

    .line 414
    .line 415
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 416
    .line 417
    .line 418
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 419
    .line 420
    .line 421
    :cond_14
    check-cast v1, Lay0/a;

    .line 422
    .line 423
    invoke-static {v1, v0, v2}, Lv50/a;->B(Lay0/a;Ll2/o;I)V

    .line 424
    .line 425
    .line 426
    goto :goto_5

    .line 427
    :cond_15
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 428
    .line 429
    .line 430
    :goto_5
    return-object v8

    .line 431
    :pswitch_5
    move-object/from16 v0, p1

    .line 432
    .line 433
    check-cast v0, Ll2/o;

    .line 434
    .line 435
    move-object/from16 v1, p2

    .line 436
    .line 437
    check-cast v1, Ljava/lang/Integer;

    .line 438
    .line 439
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 440
    .line 441
    .line 442
    move-result v1

    .line 443
    and-int/lit8 v2, v1, 0x3

    .line 444
    .line 445
    if-eq v2, v10, :cond_16

    .line 446
    .line 447
    move v7, v9

    .line 448
    :cond_16
    and-int/2addr v1, v9

    .line 449
    check-cast v0, Ll2/t;

    .line 450
    .line 451
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 452
    .line 453
    .line 454
    move-result v1

    .line 455
    if-eqz v1, :cond_1c

    .line 456
    .line 457
    new-instance v11, Lu50/h;

    .line 458
    .line 459
    const/16 v1, 0x7b

    .line 460
    .line 461
    invoke-direct {v11, v1}, Lu50/h;-><init>(I)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v1

    .line 468
    if-ne v1, v5, :cond_17

    .line 469
    .line 470
    new-instance v1, Lz81/g;

    .line 471
    .line 472
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 473
    .line 474
    .line 475
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 476
    .line 477
    .line 478
    :cond_17
    move-object v12, v1

    .line 479
    check-cast v12, Lay0/a;

    .line 480
    .line 481
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object v1

    .line 485
    if-ne v1, v5, :cond_18

    .line 486
    .line 487
    new-instance v1, Lz81/g;

    .line 488
    .line 489
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 490
    .line 491
    .line 492
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 493
    .line 494
    .line 495
    :cond_18
    move-object v13, v1

    .line 496
    check-cast v13, Lay0/a;

    .line 497
    .line 498
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v1

    .line 502
    if-ne v1, v5, :cond_19

    .line 503
    .line 504
    new-instance v1, Lz81/g;

    .line 505
    .line 506
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 507
    .line 508
    .line 509
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 510
    .line 511
    .line 512
    :cond_19
    move-object v14, v1

    .line 513
    check-cast v14, Lay0/a;

    .line 514
    .line 515
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v1

    .line 519
    if-ne v1, v5, :cond_1a

    .line 520
    .line 521
    new-instance v1, Lz81/g;

    .line 522
    .line 523
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 527
    .line 528
    .line 529
    :cond_1a
    move-object v15, v1

    .line 530
    check-cast v15, Lay0/a;

    .line 531
    .line 532
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v1

    .line 536
    if-ne v1, v5, :cond_1b

    .line 537
    .line 538
    new-instance v1, Lz81/g;

    .line 539
    .line 540
    invoke-direct {v1, v10}, Lz81/g;-><init>(I)V

    .line 541
    .line 542
    .line 543
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 544
    .line 545
    .line 546
    :cond_1b
    move-object/from16 v16, v1

    .line 547
    .line 548
    check-cast v16, Lay0/a;

    .line 549
    .line 550
    const v18, 0x36db0

    .line 551
    .line 552
    .line 553
    move-object/from16 v17, v0

    .line 554
    .line 555
    invoke-static/range {v11 .. v18}, Lv50/a;->u(Lu50/h;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 556
    .line 557
    .line 558
    goto :goto_6

    .line 559
    :cond_1c
    move-object/from16 v17, v0

    .line 560
    .line 561
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 562
    .line 563
    .line 564
    :goto_6
    return-object v8

    .line 565
    :pswitch_6
    move-object/from16 v0, p1

    .line 566
    .line 567
    check-cast v0, Lk21/a;

    .line 568
    .line 569
    move-object/from16 v2, p2

    .line 570
    .line 571
    check-cast v2, Lg21/a;

    .line 572
    .line 573
    const-string v3, "$this$viewModel"

    .line 574
    .line 575
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    new-instance v5, Ly20/m;

    .line 582
    .line 583
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 584
    .line 585
    const-class v2, Lci0/h;

    .line 586
    .line 587
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 588
    .line 589
    .line 590
    move-result-object v2

    .line 591
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v2

    .line 595
    move-object v6, v2

    .line 596
    check-cast v6, Lci0/h;

    .line 597
    .line 598
    const-class v2, Lij0/a;

    .line 599
    .line 600
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 601
    .line 602
    .line 603
    move-result-object v2

    .line 604
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 605
    .line 606
    .line 607
    move-result-object v2

    .line 608
    move-object v7, v2

    .line 609
    check-cast v7, Lij0/a;

    .line 610
    .line 611
    const-class v2, Lws0/c;

    .line 612
    .line 613
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 614
    .line 615
    .line 616
    move-result-object v2

    .line 617
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 618
    .line 619
    .line 620
    move-result-object v2

    .line 621
    move-object v8, v2

    .line 622
    check-cast v8, Lws0/c;

    .line 623
    .line 624
    const-class v2, Lci0/b;

    .line 625
    .line 626
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 627
    .line 628
    .line 629
    move-result-object v2

    .line 630
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 631
    .line 632
    .line 633
    move-result-object v2

    .line 634
    move-object v9, v2

    .line 635
    check-cast v9, Lci0/b;

    .line 636
    .line 637
    const-class v2, Lci0/d;

    .line 638
    .line 639
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 640
    .line 641
    .line 642
    move-result-object v2

    .line 643
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 644
    .line 645
    .line 646
    move-result-object v2

    .line 647
    move-object v10, v2

    .line 648
    check-cast v10, Lci0/d;

    .line 649
    .line 650
    const-class v2, Lug0/a;

    .line 651
    .line 652
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 653
    .line 654
    .line 655
    move-result-object v2

    .line 656
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    move-result-object v2

    .line 660
    move-object v11, v2

    .line 661
    check-cast v11, Lug0/a;

    .line 662
    .line 663
    const-class v2, Lkf0/i;

    .line 664
    .line 665
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 666
    .line 667
    .line 668
    move-result-object v2

    .line 669
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v2

    .line 673
    move-object v12, v2

    .line 674
    check-cast v12, Lkf0/i;

    .line 675
    .line 676
    const-class v2, Lgn0/b;

    .line 677
    .line 678
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 679
    .line 680
    .line 681
    move-result-object v2

    .line 682
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    move-result-object v2

    .line 686
    move-object v13, v2

    .line 687
    check-cast v13, Lgn0/b;

    .line 688
    .line 689
    const-class v2, Lkf0/h;

    .line 690
    .line 691
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 696
    .line 697
    .line 698
    move-result-object v2

    .line 699
    move-object v14, v2

    .line 700
    check-cast v14, Lkf0/h;

    .line 701
    .line 702
    const-class v2, Ltr0/b;

    .line 703
    .line 704
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 705
    .line 706
    .line 707
    move-result-object v2

    .line 708
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 709
    .line 710
    .line 711
    move-result-object v2

    .line 712
    move-object v15, v2

    .line 713
    check-cast v15, Ltr0/b;

    .line 714
    .line 715
    const-class v2, Lrs0/g;

    .line 716
    .line 717
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 718
    .line 719
    .line 720
    move-result-object v2

    .line 721
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 722
    .line 723
    .line 724
    move-result-object v2

    .line 725
    move-object/from16 v16, v2

    .line 726
    .line 727
    check-cast v16, Lrs0/g;

    .line 728
    .line 729
    const-class v2, Lks0/s;

    .line 730
    .line 731
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 732
    .line 733
    .line 734
    move-result-object v2

    .line 735
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 736
    .line 737
    .line 738
    move-result-object v2

    .line 739
    move-object/from16 v17, v2

    .line 740
    .line 741
    check-cast v17, Lks0/s;

    .line 742
    .line 743
    const-class v2, Lw20/b;

    .line 744
    .line 745
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 746
    .line 747
    .line 748
    move-result-object v2

    .line 749
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object v2

    .line 753
    move-object/from16 v18, v2

    .line 754
    .line 755
    check-cast v18, Lw20/b;

    .line 756
    .line 757
    const-class v2, Lw20/d;

    .line 758
    .line 759
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 760
    .line 761
    .line 762
    move-result-object v2

    .line 763
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 764
    .line 765
    .line 766
    move-result-object v2

    .line 767
    move-object/from16 v19, v2

    .line 768
    .line 769
    check-cast v19, Lw20/d;

    .line 770
    .line 771
    const-class v2, Lw20/e;

    .line 772
    .line 773
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 774
    .line 775
    .line 776
    move-result-object v2

    .line 777
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 778
    .line 779
    .line 780
    move-result-object v2

    .line 781
    move-object/from16 v20, v2

    .line 782
    .line 783
    check-cast v20, Lw20/e;

    .line 784
    .line 785
    const-class v2, Lgb0/c0;

    .line 786
    .line 787
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 788
    .line 789
    .line 790
    move-result-object v2

    .line 791
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v2

    .line 795
    move-object/from16 v21, v2

    .line 796
    .line 797
    check-cast v21, Lgb0/c0;

    .line 798
    .line 799
    const-class v2, Lug0/c;

    .line 800
    .line 801
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 802
    .line 803
    .line 804
    move-result-object v2

    .line 805
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 806
    .line 807
    .line 808
    move-result-object v2

    .line 809
    move-object/from16 v22, v2

    .line 810
    .line 811
    check-cast v22, Lug0/c;

    .line 812
    .line 813
    const-class v2, Lrq0/f;

    .line 814
    .line 815
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 816
    .line 817
    .line 818
    move-result-object v2

    .line 819
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 820
    .line 821
    .line 822
    move-result-object v2

    .line 823
    move-object/from16 v23, v2

    .line 824
    .line 825
    check-cast v23, Lrq0/f;

    .line 826
    .line 827
    const-class v2, Lws0/n;

    .line 828
    .line 829
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 830
    .line 831
    .line 832
    move-result-object v2

    .line 833
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 834
    .line 835
    .line 836
    move-result-object v2

    .line 837
    move-object/from16 v24, v2

    .line 838
    .line 839
    check-cast v24, Lws0/n;

    .line 840
    .line 841
    const-class v2, Lks0/r;

    .line 842
    .line 843
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 844
    .line 845
    .line 846
    move-result-object v2

    .line 847
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    move-result-object v2

    .line 851
    move-object/from16 v25, v2

    .line 852
    .line 853
    check-cast v25, Lks0/r;

    .line 854
    .line 855
    const-class v2, Lat0/o;

    .line 856
    .line 857
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 858
    .line 859
    .line 860
    move-result-object v2

    .line 861
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    move-result-object v2

    .line 865
    move-object/from16 v26, v2

    .line 866
    .line 867
    check-cast v26, Lat0/o;

    .line 868
    .line 869
    const-class v2, Lat0/a;

    .line 870
    .line 871
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 872
    .line 873
    .line 874
    move-result-object v2

    .line 875
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 876
    .line 877
    .line 878
    move-result-object v2

    .line 879
    move-object/from16 v27, v2

    .line 880
    .line 881
    check-cast v27, Lat0/a;

    .line 882
    .line 883
    const-class v2, Lhu0/b;

    .line 884
    .line 885
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 886
    .line 887
    .line 888
    move-result-object v2

    .line 889
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 890
    .line 891
    .line 892
    move-result-object v2

    .line 893
    move-object/from16 v28, v2

    .line 894
    .line 895
    check-cast v28, Lhu0/b;

    .line 896
    .line 897
    const-class v2, Lqf0/g;

    .line 898
    .line 899
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 900
    .line 901
    .line 902
    move-result-object v2

    .line 903
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 904
    .line 905
    .line 906
    move-result-object v2

    .line 907
    move-object/from16 v29, v2

    .line 908
    .line 909
    check-cast v29, Lqf0/g;

    .line 910
    .line 911
    const-class v2, Lqf0/f;

    .line 912
    .line 913
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 914
    .line 915
    .line 916
    move-result-object v2

    .line 917
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v2

    .line 921
    move-object/from16 v30, v2

    .line 922
    .line 923
    check-cast v30, Lqf0/f;

    .line 924
    .line 925
    const-class v2, Lgt0/d;

    .line 926
    .line 927
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 928
    .line 929
    .line 930
    move-result-object v2

    .line 931
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 932
    .line 933
    .line 934
    move-result-object v2

    .line 935
    move-object/from16 v31, v2

    .line 936
    .line 937
    check-cast v31, Lgt0/d;

    .line 938
    .line 939
    const-class v2, Lwr0/i;

    .line 940
    .line 941
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 942
    .line 943
    .line 944
    move-result-object v1

    .line 945
    invoke-virtual {v0, v1, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 946
    .line 947
    .line 948
    move-result-object v0

    .line 949
    move-object/from16 v32, v0

    .line 950
    .line 951
    check-cast v32, Lwr0/i;

    .line 952
    .line 953
    invoke-direct/range {v5 .. v32}, Ly20/m;-><init>(Lci0/h;Lij0/a;Lws0/c;Lci0/b;Lci0/d;Lug0/a;Lkf0/i;Lgn0/b;Lkf0/h;Ltr0/b;Lrs0/g;Lks0/s;Lw20/b;Lw20/d;Lw20/e;Lgb0/c0;Lug0/c;Lrq0/f;Lws0/n;Lks0/r;Lat0/o;Lat0/a;Lhu0/b;Lqf0/g;Lqf0/f;Lgt0/d;Lwr0/i;)V

    .line 954
    .line 955
    .line 956
    return-object v5

    .line 957
    :pswitch_7
    move-object/from16 v0, p1

    .line 958
    .line 959
    check-cast v0, Lk21/a;

    .line 960
    .line 961
    move-object/from16 v2, p2

    .line 962
    .line 963
    check-cast v2, Lg21/a;

    .line 964
    .line 965
    const-string v3, "$this$single"

    .line 966
    .line 967
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 968
    .line 969
    .line 970
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 971
    .line 972
    .line 973
    new-instance v1, Lu10/c;

    .line 974
    .line 975
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 976
    .line 977
    const-class v3, Lxl0/f;

    .line 978
    .line 979
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 980
    .line 981
    .line 982
    move-result-object v3

    .line 983
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 984
    .line 985
    .line 986
    move-result-object v3

    .line 987
    check-cast v3, Lxl0/f;

    .line 988
    .line 989
    const-class v5, Lcz/myskoda/api/bff/v1/DiscoverNewsApi;

    .line 990
    .line 991
    const-string v6, "null"

    .line 992
    .line 993
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 994
    .line 995
    .line 996
    move-result-object v5

    .line 997
    const-class v6, Lti0/a;

    .line 998
    .line 999
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v2

    .line 1003
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v0

    .line 1007
    check-cast v0, Lti0/a;

    .line 1008
    .line 1009
    invoke-direct {v1, v3, v0}, Lu10/c;-><init>(Lxl0/f;Lti0/a;)V

    .line 1010
    .line 1011
    .line 1012
    return-object v1

    .line 1013
    :pswitch_8
    move-object/from16 v0, p1

    .line 1014
    .line 1015
    check-cast v0, Ll2/o;

    .line 1016
    .line 1017
    move-object/from16 v1, p2

    .line 1018
    .line 1019
    check-cast v1, Ljava/lang/Integer;

    .line 1020
    .line 1021
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1022
    .line 1023
    .line 1024
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1025
    .line 1026
    .line 1027
    move-result v1

    .line 1028
    invoke-static {v0, v1}, Luz/k0;->a0(Ll2/o;I)V

    .line 1029
    .line 1030
    .line 1031
    return-object v8

    .line 1032
    :pswitch_9
    move-object/from16 v0, p1

    .line 1033
    .line 1034
    check-cast v0, Ll2/o;

    .line 1035
    .line 1036
    move-object/from16 v1, p2

    .line 1037
    .line 1038
    check-cast v1, Ljava/lang/Integer;

    .line 1039
    .line 1040
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1041
    .line 1042
    .line 1043
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1044
    .line 1045
    .line 1046
    move-result v1

    .line 1047
    invoke-static {v0, v1}, Luz/k0;->Z(Ll2/o;I)V

    .line 1048
    .line 1049
    .line 1050
    return-object v8

    .line 1051
    :pswitch_a
    move-object/from16 v0, p1

    .line 1052
    .line 1053
    check-cast v0, Ll2/o;

    .line 1054
    .line 1055
    move-object/from16 v1, p2

    .line 1056
    .line 1057
    check-cast v1, Ljava/lang/Integer;

    .line 1058
    .line 1059
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1060
    .line 1061
    .line 1062
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1063
    .line 1064
    .line 1065
    move-result v1

    .line 1066
    invoke-static {v0, v1}, Luz/k0;->J(Ll2/o;I)V

    .line 1067
    .line 1068
    .line 1069
    return-object v8

    .line 1070
    :pswitch_b
    move-object/from16 v0, p1

    .line 1071
    .line 1072
    check-cast v0, Ll2/o;

    .line 1073
    .line 1074
    move-object/from16 v1, p2

    .line 1075
    .line 1076
    check-cast v1, Ljava/lang/Integer;

    .line 1077
    .line 1078
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1079
    .line 1080
    .line 1081
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1082
    .line 1083
    .line 1084
    move-result v1

    .line 1085
    invoke-static {v0, v1}, Luz/k0;->W(Ll2/o;I)V

    .line 1086
    .line 1087
    .line 1088
    return-object v8

    .line 1089
    :pswitch_c
    move-object/from16 v0, p1

    .line 1090
    .line 1091
    check-cast v0, Ll2/o;

    .line 1092
    .line 1093
    move-object/from16 v1, p2

    .line 1094
    .line 1095
    check-cast v1, Ljava/lang/Integer;

    .line 1096
    .line 1097
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1098
    .line 1099
    .line 1100
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1101
    .line 1102
    .line 1103
    move-result v1

    .line 1104
    invoke-static {v0, v1}, Luz/k0;->U(Ll2/o;I)V

    .line 1105
    .line 1106
    .line 1107
    return-object v8

    .line 1108
    :pswitch_d
    move-object/from16 v0, p1

    .line 1109
    .line 1110
    check-cast v0, Ll2/o;

    .line 1111
    .line 1112
    move-object/from16 v1, p2

    .line 1113
    .line 1114
    check-cast v1, Ljava/lang/Integer;

    .line 1115
    .line 1116
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1117
    .line 1118
    .line 1119
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1120
    .line 1121
    .line 1122
    move-result v1

    .line 1123
    invoke-static {v0, v1}, Luz/k0;->U(Ll2/o;I)V

    .line 1124
    .line 1125
    .line 1126
    return-object v8

    .line 1127
    :pswitch_e
    move-object/from16 v0, p1

    .line 1128
    .line 1129
    check-cast v0, Ll2/o;

    .line 1130
    .line 1131
    move-object/from16 v1, p2

    .line 1132
    .line 1133
    check-cast v1, Ljava/lang/Integer;

    .line 1134
    .line 1135
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1136
    .line 1137
    .line 1138
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1139
    .line 1140
    .line 1141
    move-result v1

    .line 1142
    invoke-static {v0, v1}, Luz/k0;->S(Ll2/o;I)V

    .line 1143
    .line 1144
    .line 1145
    return-object v8

    .line 1146
    :pswitch_f
    move-object/from16 v0, p1

    .line 1147
    .line 1148
    check-cast v0, Ll2/o;

    .line 1149
    .line 1150
    move-object/from16 v1, p2

    .line 1151
    .line 1152
    check-cast v1, Ljava/lang/Integer;

    .line 1153
    .line 1154
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1155
    .line 1156
    .line 1157
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1158
    .line 1159
    .line 1160
    move-result v1

    .line 1161
    invoke-static {v0, v1}, Luz/k0;->Q(Ll2/o;I)V

    .line 1162
    .line 1163
    .line 1164
    return-object v8

    .line 1165
    :pswitch_10
    move-object/from16 v0, p1

    .line 1166
    .line 1167
    check-cast v0, Ll2/o;

    .line 1168
    .line 1169
    move-object/from16 v1, p2

    .line 1170
    .line 1171
    check-cast v1, Ljava/lang/Integer;

    .line 1172
    .line 1173
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1174
    .line 1175
    .line 1176
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1177
    .line 1178
    .line 1179
    move-result v1

    .line 1180
    invoke-static {v0, v1}, Luz/k0;->O(Ll2/o;I)V

    .line 1181
    .line 1182
    .line 1183
    return-object v8

    .line 1184
    :pswitch_11
    move-object/from16 v0, p1

    .line 1185
    .line 1186
    check-cast v0, Ll2/o;

    .line 1187
    .line 1188
    move-object/from16 v1, p2

    .line 1189
    .line 1190
    check-cast v1, Ljava/lang/Integer;

    .line 1191
    .line 1192
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1193
    .line 1194
    .line 1195
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1196
    .line 1197
    .line 1198
    move-result v1

    .line 1199
    invoke-static {v0, v1}, Luz/p0;->d(Ll2/o;I)V

    .line 1200
    .line 1201
    .line 1202
    return-object v8

    .line 1203
    :pswitch_12
    move-object/from16 v0, p1

    .line 1204
    .line 1205
    check-cast v0, Ll2/o;

    .line 1206
    .line 1207
    move-object/from16 v1, p2

    .line 1208
    .line 1209
    check-cast v1, Ljava/lang/Integer;

    .line 1210
    .line 1211
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1212
    .line 1213
    .line 1214
    invoke-static {v9}, Ll2/b;->x(I)I

    .line 1215
    .line 1216
    .line 1217
    move-result v1

    .line 1218
    invoke-static {v0, v1}, Luz/p0;->c(Ll2/o;I)V

    .line 1219
    .line 1220
    .line 1221
    return-object v8

    .line 1222
    :pswitch_13
    move-object/from16 v0, p1

    .line 1223
    .line 1224
    check-cast v0, Ll2/o;

    .line 1225
    .line 1226
    move-object/from16 v1, p2

    .line 1227
    .line 1228
    check-cast v1, Ljava/lang/Integer;

    .line 1229
    .line 1230
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1231
    .line 1232
    .line 1233
    move-result v1

    .line 1234
    and-int/lit8 v2, v1, 0x3

    .line 1235
    .line 1236
    if-eq v2, v10, :cond_1d

    .line 1237
    .line 1238
    move v2, v9

    .line 1239
    goto :goto_7

    .line 1240
    :cond_1d
    move v2, v7

    .line 1241
    :goto_7
    and-int/2addr v1, v9

    .line 1242
    check-cast v0, Ll2/t;

    .line 1243
    .line 1244
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1245
    .line 1246
    .line 1247
    move-result v1

    .line 1248
    if-eqz v1, :cond_1e

    .line 1249
    .line 1250
    invoke-static {v4, v4, v0, v7, v6}, Luz/k0;->Y(Lx2/s;Lay0/a;Ll2/o;II)V

    .line 1251
    .line 1252
    .line 1253
    goto :goto_8

    .line 1254
    :cond_1e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1255
    .line 1256
    .line 1257
    :goto_8
    return-object v8

    .line 1258
    :pswitch_14
    move-object/from16 v0, p1

    .line 1259
    .line 1260
    check-cast v0, Ll2/o;

    .line 1261
    .line 1262
    move-object/from16 v1, p2

    .line 1263
    .line 1264
    check-cast v1, Ljava/lang/Integer;

    .line 1265
    .line 1266
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1267
    .line 1268
    .line 1269
    move-result v1

    .line 1270
    and-int/lit8 v3, v1, 0x3

    .line 1271
    .line 1272
    if-eq v3, v10, :cond_1f

    .line 1273
    .line 1274
    move v3, v9

    .line 1275
    goto :goto_9

    .line 1276
    :cond_1f
    move v3, v7

    .line 1277
    :goto_9
    and-int/2addr v1, v9

    .line 1278
    move-object v15, v0

    .line 1279
    check-cast v15, Ll2/t;

    .line 1280
    .line 1281
    invoke-virtual {v15, v1, v3}, Ll2/t;->O(IZ)Z

    .line 1282
    .line 1283
    .line 1284
    move-result v0

    .line 1285
    if-eqz v0, :cond_20

    .line 1286
    .line 1287
    new-instance v11, Ltz/k4;

    .line 1288
    .line 1289
    new-instance v0, Ltz/z3;

    .line 1290
    .line 1291
    const-string v1, "Select a plan"

    .line 1292
    .line 1293
    const-string v3, "Active"

    .line 1294
    .line 1295
    const-string v4, "ChargingPlan"

    .line 1296
    .line 1297
    invoke-direct {v0, v4, v1, v3}, Ltz/z3;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1298
    .line 1299
    .line 1300
    new-instance v1, Ltz/j4;

    .line 1301
    .line 1302
    const-string v3, "Wallboxes"

    .line 1303
    .line 1304
    const-string v4, "Add Wallbox"

    .line 1305
    .line 1306
    invoke-direct {v1, v3, v4}, Ltz/j4;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1307
    .line 1308
    .line 1309
    new-array v3, v10, [Ltz/w3;

    .line 1310
    .line 1311
    aput-object v0, v3, v7

    .line 1312
    .line 1313
    aput-object v1, v3, v9

    .line 1314
    .line 1315
    invoke-static {v3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v0

    .line 1319
    new-instance v1, Ltz/y3;

    .line 1320
    .line 1321
    const-string v3, "Charging history"

    .line 1322
    .line 1323
    invoke-direct {v1, v3}, Ltz/y3;-><init>(Ljava/lang/String;)V

    .line 1324
    .line 1325
    .line 1326
    new-instance v3, Ltz/a4;

    .line 1327
    .line 1328
    const-string v4, "Charging statistics"

    .line 1329
    .line 1330
    invoke-direct {v3, v4, v9}, Ltz/a4;-><init>(Ljava/lang/String;Z)V

    .line 1331
    .line 1332
    .line 1333
    new-instance v4, Ltz/x3;

    .line 1334
    .line 1335
    const-string v5, "Charging cards"

    .line 1336
    .line 1337
    invoke-direct {v4, v5}, Ltz/x3;-><init>(Ljava/lang/String;)V

    .line 1338
    .line 1339
    .line 1340
    new-instance v5, Ltz/b4;

    .line 1341
    .line 1342
    const-string v12, "Vouchers"

    .line 1343
    .line 1344
    invoke-direct {v5, v12, v9}, Ltz/b4;-><init>(Ljava/lang/String;Z)V

    .line 1345
    .line 1346
    .line 1347
    new-instance v12, Ltz/d4;

    .line 1348
    .line 1349
    const-string v13, "Invoices"

    .line 1350
    .line 1351
    invoke-direct {v12, v13, v9}, Ltz/d4;-><init>(Ljava/lang/String;Z)V

    .line 1352
    .line 1353
    .line 1354
    new-instance v13, Ltz/f4;

    .line 1355
    .line 1356
    const-string v14, "Payment methods"

    .line 1357
    .line 1358
    invoke-direct {v13, v14, v9}, Ltz/f4;-><init>(Ljava/lang/String;Z)V

    .line 1359
    .line 1360
    .line 1361
    new-instance v14, Ltz/g4;

    .line 1362
    .line 1363
    move/from16 p0, v2

    .line 1364
    .line 1365
    const-string v2, "Plug & charge"

    .line 1366
    .line 1367
    move/from16 v16, v6

    .line 1368
    .line 1369
    const-string v6, "---"

    .line 1370
    .line 1371
    invoke-direct {v14, v2, v9, v6}, Ltz/g4;-><init>(Ljava/lang/String;ZLjava/lang/String;)V

    .line 1372
    .line 1373
    .line 1374
    new-instance v2, Ltz/c4;

    .line 1375
    .line 1376
    const-string v6, "Help and support"

    .line 1377
    .line 1378
    invoke-direct {v2, v6}, Ltz/c4;-><init>(Ljava/lang/String;)V

    .line 1379
    .line 1380
    .line 1381
    new-instance v6, Ltz/e4;

    .line 1382
    .line 1383
    move/from16 v17, v9

    .line 1384
    .line 1385
    const-string v9, "Legal notice"

    .line 1386
    .line 1387
    invoke-direct {v6, v9}, Ltz/e4;-><init>(Ljava/lang/String;)V

    .line 1388
    .line 1389
    .line 1390
    const/16 v9, 0x9

    .line 1391
    .line 1392
    new-array v9, v9, [Ltz/i4;

    .line 1393
    .line 1394
    aput-object v1, v9, v7

    .line 1395
    .line 1396
    aput-object v3, v9, v17

    .line 1397
    .line 1398
    aput-object v4, v9, v10

    .line 1399
    .line 1400
    aput-object v5, v9, v16

    .line 1401
    .line 1402
    const/4 v1, 0x4

    .line 1403
    aput-object v12, v9, v1

    .line 1404
    .line 1405
    const/4 v1, 0x5

    .line 1406
    aput-object v13, v9, v1

    .line 1407
    .line 1408
    aput-object v14, v9, p0

    .line 1409
    .line 1410
    const/4 v1, 0x7

    .line 1411
    aput-object v2, v9, v1

    .line 1412
    .line 1413
    const/16 v1, 0x8

    .line 1414
    .line 1415
    aput-object v6, v9, v1

    .line 1416
    .line 1417
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 1418
    .line 1419
    .line 1420
    move-result-object v1

    .line 1421
    const/16 v2, 0x18

    .line 1422
    .line 1423
    invoke-direct {v11, v0, v1, v2}, Ltz/k4;-><init>(Ljava/util/List;Ljava/util/List;I)V

    .line 1424
    .line 1425
    .line 1426
    const/16 v16, 0x0

    .line 1427
    .line 1428
    const/16 v17, 0xe

    .line 1429
    .line 1430
    const/4 v12, 0x0

    .line 1431
    const/4 v13, 0x0

    .line 1432
    const/4 v14, 0x0

    .line 1433
    invoke-static/range {v11 .. v17}, Luz/k0;->V(Ltz/k4;Lay0/a;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 1434
    .line 1435
    .line 1436
    goto :goto_a

    .line 1437
    :cond_20
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 1438
    .line 1439
    .line 1440
    :goto_a
    return-object v8

    .line 1441
    :pswitch_15
    move/from16 v17, v9

    .line 1442
    .line 1443
    move-object/from16 v0, p1

    .line 1444
    .line 1445
    check-cast v0, Ll2/o;

    .line 1446
    .line 1447
    move-object/from16 v1, p2

    .line 1448
    .line 1449
    check-cast v1, Ljava/lang/Integer;

    .line 1450
    .line 1451
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1452
    .line 1453
    .line 1454
    move-result v1

    .line 1455
    and-int/lit8 v2, v1, 0x3

    .line 1456
    .line 1457
    if-eq v2, v10, :cond_21

    .line 1458
    .line 1459
    move/from16 v7, v17

    .line 1460
    .line 1461
    :cond_21
    and-int/lit8 v1, v1, 0x1

    .line 1462
    .line 1463
    check-cast v0, Ll2/t;

    .line 1464
    .line 1465
    invoke-virtual {v0, v1, v7}, Ll2/t;->O(IZ)Z

    .line 1466
    .line 1467
    .line 1468
    move-result v1

    .line 1469
    if-eqz v1, :cond_22

    .line 1470
    .line 1471
    sget-object v9, Lh2/v;->a:Lh2/v;

    .line 1472
    .line 1473
    const-wide/16 v14, 0x0

    .line 1474
    .line 1475
    const/high16 v17, 0x30000

    .line 1476
    .line 1477
    const/4 v10, 0x0

    .line 1478
    const/4 v11, 0x0

    .line 1479
    const/4 v12, 0x0

    .line 1480
    const/4 v13, 0x0

    .line 1481
    move-object/from16 v16, v0

    .line 1482
    .line 1483
    invoke-virtual/range {v9 .. v17}, Lh2/v;->a(Lx2/s;FFLe3/n0;JLl2/o;I)V

    .line 1484
    .line 1485
    .line 1486
    goto :goto_b

    .line 1487
    :cond_22
    move-object/from16 v16, v0

    .line 1488
    .line 1489
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 1490
    .line 1491
    .line 1492
    :goto_b
    return-object v8

    .line 1493
    :pswitch_16
    move/from16 v17, v9

    .line 1494
    .line 1495
    move-object/from16 v0, p1

    .line 1496
    .line 1497
    check-cast v0, Ll2/o;

    .line 1498
    .line 1499
    move-object/from16 v1, p2

    .line 1500
    .line 1501
    check-cast v1, Ljava/lang/Integer;

    .line 1502
    .line 1503
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1504
    .line 1505
    .line 1506
    move-result v1

    .line 1507
    and-int/lit8 v2, v1, 0x3

    .line 1508
    .line 1509
    if-eq v2, v10, :cond_23

    .line 1510
    .line 1511
    move/from16 v2, v17

    .line 1512
    .line 1513
    goto :goto_c

    .line 1514
    :cond_23
    move v2, v7

    .line 1515
    :goto_c
    and-int/lit8 v1, v1, 0x1

    .line 1516
    .line 1517
    check-cast v0, Ll2/t;

    .line 1518
    .line 1519
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1520
    .line 1521
    .line 1522
    move-result v1

    .line 1523
    if-eqz v1, :cond_24

    .line 1524
    .line 1525
    invoke-static {v0, v7}, Luz/y;->d(Ll2/o;I)V

    .line 1526
    .line 1527
    .line 1528
    goto :goto_d

    .line 1529
    :cond_24
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1530
    .line 1531
    .line 1532
    :goto_d
    return-object v8

    .line 1533
    :pswitch_17
    move/from16 v17, v9

    .line 1534
    .line 1535
    move-object/from16 v0, p1

    .line 1536
    .line 1537
    check-cast v0, Ll2/o;

    .line 1538
    .line 1539
    move-object/from16 v1, p2

    .line 1540
    .line 1541
    check-cast v1, Ljava/lang/Integer;

    .line 1542
    .line 1543
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1544
    .line 1545
    .line 1546
    move-result v1

    .line 1547
    and-int/lit8 v2, v1, 0x3

    .line 1548
    .line 1549
    if-eq v2, v10, :cond_25

    .line 1550
    .line 1551
    move/from16 v2, v17

    .line 1552
    .line 1553
    goto :goto_e

    .line 1554
    :cond_25
    move v2, v7

    .line 1555
    :goto_e
    and-int/lit8 v1, v1, 0x1

    .line 1556
    .line 1557
    check-cast v0, Ll2/t;

    .line 1558
    .line 1559
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1560
    .line 1561
    .line 1562
    move-result v1

    .line 1563
    if-eqz v1, :cond_26

    .line 1564
    .line 1565
    invoke-static {v0, v7}, Luz/y;->c(Ll2/o;I)V

    .line 1566
    .line 1567
    .line 1568
    goto :goto_f

    .line 1569
    :cond_26
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1570
    .line 1571
    .line 1572
    :goto_f
    return-object v8

    .line 1573
    :pswitch_18
    move/from16 v17, v9

    .line 1574
    .line 1575
    move-object/from16 v0, p1

    .line 1576
    .line 1577
    check-cast v0, Ll2/o;

    .line 1578
    .line 1579
    move-object/from16 v1, p2

    .line 1580
    .line 1581
    check-cast v1, Ljava/lang/Integer;

    .line 1582
    .line 1583
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1584
    .line 1585
    .line 1586
    move-result v1

    .line 1587
    and-int/lit8 v2, v1, 0x3

    .line 1588
    .line 1589
    if-eq v2, v10, :cond_27

    .line 1590
    .line 1591
    move/from16 v2, v17

    .line 1592
    .line 1593
    goto :goto_10

    .line 1594
    :cond_27
    move v2, v7

    .line 1595
    :goto_10
    and-int/lit8 v1, v1, 0x1

    .line 1596
    .line 1597
    check-cast v0, Ll2/t;

    .line 1598
    .line 1599
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1600
    .line 1601
    .line 1602
    move-result v1

    .line 1603
    if-eqz v1, :cond_28

    .line 1604
    .line 1605
    invoke-static {v0, v7}, Luz/y;->b(Ll2/o;I)V

    .line 1606
    .line 1607
    .line 1608
    goto :goto_11

    .line 1609
    :cond_28
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1610
    .line 1611
    .line 1612
    :goto_11
    return-object v8

    .line 1613
    :pswitch_19
    move/from16 v17, v9

    .line 1614
    .line 1615
    move-object/from16 v0, p1

    .line 1616
    .line 1617
    check-cast v0, Ll2/o;

    .line 1618
    .line 1619
    move-object/from16 v1, p2

    .line 1620
    .line 1621
    check-cast v1, Ljava/lang/Integer;

    .line 1622
    .line 1623
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1624
    .line 1625
    .line 1626
    move-result v1

    .line 1627
    and-int/lit8 v2, v1, 0x3

    .line 1628
    .line 1629
    if-eq v2, v10, :cond_29

    .line 1630
    .line 1631
    move/from16 v2, v17

    .line 1632
    .line 1633
    goto :goto_12

    .line 1634
    :cond_29
    move v2, v7

    .line 1635
    :goto_12
    and-int/lit8 v1, v1, 0x1

    .line 1636
    .line 1637
    check-cast v0, Ll2/t;

    .line 1638
    .line 1639
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1640
    .line 1641
    .line 1642
    move-result v1

    .line 1643
    if-eqz v1, :cond_2a

    .line 1644
    .line 1645
    invoke-static {v0, v7}, Luz/y;->a(Ll2/o;I)V

    .line 1646
    .line 1647
    .line 1648
    goto :goto_13

    .line 1649
    :cond_2a
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 1650
    .line 1651
    .line 1652
    :goto_13
    return-object v8

    .line 1653
    :pswitch_1a
    move/from16 v17, v9

    .line 1654
    .line 1655
    move-object/from16 v0, p1

    .line 1656
    .line 1657
    check-cast v0, Ll2/o;

    .line 1658
    .line 1659
    move-object/from16 v1, p2

    .line 1660
    .line 1661
    check-cast v1, Ljava/lang/Integer;

    .line 1662
    .line 1663
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1664
    .line 1665
    .line 1666
    invoke-static/range {v17 .. v17}, Ll2/b;->x(I)I

    .line 1667
    .line 1668
    .line 1669
    move-result v1

    .line 1670
    invoke-static {v0, v1}, Luz/k0;->D(Ll2/o;I)V

    .line 1671
    .line 1672
    .line 1673
    return-object v8

    .line 1674
    :pswitch_1b
    move/from16 v17, v9

    .line 1675
    .line 1676
    move-object/from16 v0, p1

    .line 1677
    .line 1678
    check-cast v0, Ll2/o;

    .line 1679
    .line 1680
    move-object/from16 v1, p2

    .line 1681
    .line 1682
    check-cast v1, Ljava/lang/Integer;

    .line 1683
    .line 1684
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1685
    .line 1686
    .line 1687
    invoke-static/range {v17 .. v17}, Ll2/b;->x(I)I

    .line 1688
    .line 1689
    .line 1690
    move-result v1

    .line 1691
    invoke-static {v0, v1}, Luz/k0;->A(Ll2/o;I)V

    .line 1692
    .line 1693
    .line 1694
    return-object v8

    .line 1695
    :pswitch_1c
    move/from16 v17, v9

    .line 1696
    .line 1697
    move-object/from16 v0, p1

    .line 1698
    .line 1699
    check-cast v0, Ll2/o;

    .line 1700
    .line 1701
    move-object/from16 v1, p2

    .line 1702
    .line 1703
    check-cast v1, Ljava/lang/Integer;

    .line 1704
    .line 1705
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1706
    .line 1707
    .line 1708
    invoke-static/range {v17 .. v17}, Ll2/b;->x(I)I

    .line 1709
    .line 1710
    .line 1711
    move-result v1

    .line 1712
    invoke-static {v0, v1}, Luz/k0;->L(Ll2/o;I)V

    .line 1713
    .line 1714
    .line 1715
    return-object v8

    .line 1716
    nop

    .line 1717
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
