.class public abstract Lr11/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lr11/a;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 9
    .line 10
    const/16 v1, 0x19

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static a(Ljava/lang/String;)Lr11/b;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_26

    .line 8
    .line 9
    sget-object v1, Lr11/a;->a:Ljava/util/concurrent/ConcurrentHashMap;

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Lr11/b;

    .line 16
    .line 17
    if-nez v2, :cond_25

    .line 18
    .line 19
    new-instance v2, Lvp/y1;

    .line 20
    .line 21
    const/16 v3, 0x15

    .line 22
    .line 23
    invoke-direct {v2, v3}, Lvp/y1;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    const/4 v4, 0x1

    .line 31
    new-array v5, v4, [I

    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    move v7, v6

    .line 35
    :goto_0
    if-ge v7, v3, :cond_24

    .line 36
    .line 37
    aput v7, v5, v6

    .line 38
    .line 39
    invoke-static {v0, v5}, Lr11/a;->b(Ljava/lang/String;[I)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v7

    .line 43
    aget v8, v5, v6

    .line 44
    .line 45
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 46
    .line 47
    .line 48
    move-result v9

    .line 49
    if-nez v9, :cond_0

    .line 50
    .line 51
    goto/16 :goto_6

    .line 52
    .line 53
    :cond_0
    invoke-virtual {v7, v6}, Ljava/lang/String;->charAt(I)C

    .line 54
    .line 55
    .line 56
    move-result v10

    .line 57
    const/16 v11, 0x27

    .line 58
    .line 59
    if-eq v10, v11, :cond_22

    .line 60
    .line 61
    const/16 v11, 0x4b

    .line 62
    .line 63
    const/4 v12, 0x2

    .line 64
    if-eq v10, v11, :cond_21

    .line 65
    .line 66
    const/16 v11, 0x4d

    .line 67
    .line 68
    const/4 v13, 0x3

    .line 69
    const/4 v14, 0x4

    .line 70
    if-eq v10, v11, :cond_1e

    .line 71
    .line 72
    const/16 v11, 0x53

    .line 73
    .line 74
    if-eq v10, v11, :cond_1d

    .line 75
    .line 76
    const/16 v11, 0x61

    .line 77
    .line 78
    if-eq v10, v11, :cond_1c

    .line 79
    .line 80
    const/16 v11, 0x68

    .line 81
    .line 82
    if-eq v10, v11, :cond_1b

    .line 83
    .line 84
    const/16 v11, 0x6b

    .line 85
    .line 86
    if-eq v10, v11, :cond_1a

    .line 87
    .line 88
    const/16 v11, 0x6d

    .line 89
    .line 90
    if-eq v10, v11, :cond_19

    .line 91
    .line 92
    const/16 v11, 0x73

    .line 93
    .line 94
    if-eq v10, v11, :cond_18

    .line 95
    .line 96
    const/16 v11, 0x47

    .line 97
    .line 98
    if-eq v10, v11, :cond_17

    .line 99
    .line 100
    const/16 v11, 0x48

    .line 101
    .line 102
    if-eq v10, v11, :cond_16

    .line 103
    .line 104
    const/16 v11, 0x59

    .line 105
    .line 106
    if-eq v10, v11, :cond_8

    .line 107
    .line 108
    const/16 v15, 0x5a

    .line 109
    .line 110
    const/4 v11, 0x0

    .line 111
    if-eq v10, v15, :cond_5

    .line 112
    .line 113
    const/16 v15, 0x64

    .line 114
    .line 115
    if-eq v10, v15, :cond_4

    .line 116
    .line 117
    const/16 v15, 0x65

    .line 118
    .line 119
    if-eq v10, v15, :cond_3

    .line 120
    .line 121
    packed-switch v10, :pswitch_data_0

    .line 122
    .line 123
    .line 124
    packed-switch v10, :pswitch_data_1

    .line 125
    .line 126
    .line 127
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 128
    .line 129
    const-string v1, "Illegal pattern component: "

    .line 130
    .line 131
    invoke-virtual {v1, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw v0

    .line 139
    :pswitch_0
    if-lt v9, v14, :cond_1

    .line 140
    .line 141
    new-instance v7, Lr11/m;

    .line 142
    .line 143
    invoke-direct {v7, v6}, Lr11/m;-><init>(I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v2, v7, v11}, Lvp/y1;->D(Lr11/y;Lr11/w;)V

    .line 147
    .line 148
    .line 149
    goto/16 :goto_5

    .line 150
    .line 151
    :cond_1
    new-instance v7, Lr11/m;

    .line 152
    .line 153
    invoke-direct {v7, v4}, Lr11/m;-><init>(I)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v2, v7, v7}, Lvp/y1;->D(Lr11/y;Lr11/w;)V

    .line 157
    .line 158
    .line 159
    goto/16 :goto_5

    .line 160
    .line 161
    :pswitch_1
    sget-object v7, Ln11/b;->r:Ln11/b;

    .line 162
    .line 163
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 164
    .line 165
    .line 166
    goto/16 :goto_5

    .line 167
    .line 168
    :pswitch_2
    if-lt v9, v14, :cond_2

    .line 169
    .line 170
    sget-object v7, Ln11/b;->s:Ln11/b;

    .line 171
    .line 172
    invoke-virtual {v2, v7}, Lvp/y1;->L(Ln11/b;)V

    .line 173
    .line 174
    .line 175
    goto/16 :goto_5

    .line 176
    .line 177
    :cond_2
    sget-object v7, Ln11/b;->s:Ln11/b;

    .line 178
    .line 179
    new-instance v9, Lr11/k;

    .line 180
    .line 181
    invoke-direct {v9, v7, v4}, Lr11/k;-><init>(Ln11/b;Z)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v2, v9}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    goto/16 :goto_5

    .line 188
    .line 189
    :pswitch_3
    sget-object v7, Ln11/b;->m:Ln11/b;

    .line 190
    .line 191
    invoke-virtual {v2, v7, v9, v13}, Lvp/y1;->E(Ln11/b;II)V

    .line 192
    .line 193
    .line 194
    goto/16 :goto_5

    .line 195
    .line 196
    :pswitch_4
    sget-object v7, Ln11/b;->j:Ln11/b;

    .line 197
    .line 198
    invoke-virtual {v2, v7, v9, v9}, Lvp/y1;->K(Ln11/b;II)V

    .line 199
    .line 200
    .line 201
    goto/16 :goto_5

    .line 202
    .line 203
    :cond_3
    sget-object v7, Ln11/b;->s:Ln11/b;

    .line 204
    .line 205
    invoke-virtual {v2, v7, v9, v4}, Lvp/y1;->E(Ln11/b;II)V

    .line 206
    .line 207
    .line 208
    goto/16 :goto_5

    .line 209
    .line 210
    :cond_4
    sget-object v7, Ln11/b;->o:Ln11/b;

    .line 211
    .line 212
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 213
    .line 214
    .line 215
    goto/16 :goto_5

    .line 216
    .line 217
    :cond_5
    const-string v7, "Z"

    .line 218
    .line 219
    if-ne v9, v4, :cond_6

    .line 220
    .line 221
    new-instance v9, Lr11/n;

    .line 222
    .line 223
    invoke-direct {v9, v11, v12, v7, v6}, Lr11/n;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v2, v9}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    goto/16 :goto_5

    .line 230
    .line 231
    :cond_6
    if-ne v9, v12, :cond_7

    .line 232
    .line 233
    new-instance v9, Lr11/n;

    .line 234
    .line 235
    invoke-direct {v9, v11, v12, v7, v4}, Lr11/n;-><init>(Ljava/lang/String;ILjava/lang/String;Z)V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v2, v9}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 239
    .line 240
    .line 241
    goto/16 :goto_5

    .line 242
    .line 243
    :cond_7
    sget-object v7, Lr11/l;->d:Lr11/l;

    .line 244
    .line 245
    invoke-virtual {v2, v7, v7}, Lvp/y1;->D(Lr11/y;Lr11/w;)V

    .line 246
    .line 247
    .line 248
    goto/16 :goto_5

    .line 249
    .line 250
    :cond_8
    :pswitch_5
    const/16 v7, 0x78

    .line 251
    .line 252
    if-ne v9, v12, :cond_10

    .line 253
    .line 254
    add-int/lit8 v9, v8, 0x1

    .line 255
    .line 256
    if-ge v9, v3, :cond_a

    .line 257
    .line 258
    aget v9, v5, v6

    .line 259
    .line 260
    add-int/2addr v9, v4

    .line 261
    aput v9, v5, v6

    .line 262
    .line 263
    invoke-static {v0, v5}, Lr11/a;->b(Ljava/lang/String;[I)Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v9

    .line 267
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 268
    .line 269
    .line 270
    move-result v11

    .line 271
    if-lez v11, :cond_9

    .line 272
    .line 273
    invoke-virtual {v9, v6}, Ljava/lang/String;->charAt(I)C

    .line 274
    .line 275
    .line 276
    move-result v9

    .line 277
    sparse-switch v9, :sswitch_data_0

    .line 278
    .line 279
    .line 280
    goto :goto_1

    .line 281
    :sswitch_0
    if-gt v11, v12, :cond_9

    .line 282
    .line 283
    :sswitch_1
    move v9, v4

    .line 284
    goto :goto_2

    .line 285
    :cond_9
    :goto_1
    move v9, v6

    .line 286
    :goto_2
    xor-int/2addr v9, v4

    .line 287
    aget v11, v5, v6

    .line 288
    .line 289
    sub-int/2addr v11, v4

    .line 290
    aput v11, v5, v6

    .line 291
    .line 292
    goto :goto_3

    .line 293
    :cond_a
    move v9, v4

    .line 294
    :goto_3
    const-wide/high16 v13, -0x8000000000000000L

    .line 295
    .line 296
    if-eq v10, v7, :cond_d

    .line 297
    .line 298
    sget-object v7, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 299
    .line 300
    const-wide v15, 0x7fffffffffffffffL

    .line 301
    .line 302
    .line 303
    .line 304
    .line 305
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 306
    .line 307
    .line 308
    move-result-wide v11

    .line 309
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    cmp-long v10, v11, v13

    .line 314
    .line 315
    if-eqz v10, :cond_b

    .line 316
    .line 317
    cmp-long v10, v11, v15

    .line 318
    .line 319
    if-nez v10, :cond_c

    .line 320
    .line 321
    :cond_b
    sget-object v7, Lp11/n;->P:Lp11/n;

    .line 322
    .line 323
    :cond_c
    iget-object v7, v7, Lp11/b;->J:Ln11/a;

    .line 324
    .line 325
    invoke-virtual {v7, v11, v12}, Ln11/a;->b(J)I

    .line 326
    .line 327
    .line 328
    move-result v7

    .line 329
    add-int/lit8 v7, v7, -0x1e

    .line 330
    .line 331
    new-instance v10, Lr11/o;

    .line 332
    .line 333
    sget-object v11, Ln11/b;->l:Ln11/b;

    .line 334
    .line 335
    invoke-direct {v10, v11, v7, v9}, Lr11/o;-><init>(Ln11/b;IZ)V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v2, v10}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 339
    .line 340
    .line 341
    goto/16 :goto_5

    .line 342
    .line 343
    :cond_d
    const-wide v15, 0x7fffffffffffffffL

    .line 344
    .line 345
    .line 346
    .line 347
    .line 348
    sget-object v7, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 349
    .line 350
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 351
    .line 352
    .line 353
    move-result-wide v10

    .line 354
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 355
    .line 356
    .line 357
    move-result-object v7

    .line 358
    cmp-long v12, v10, v13

    .line 359
    .line 360
    if-eqz v12, :cond_e

    .line 361
    .line 362
    cmp-long v12, v10, v15

    .line 363
    .line 364
    if-nez v12, :cond_f

    .line 365
    .line 366
    :cond_e
    sget-object v7, Lp11/n;->P:Lp11/n;

    .line 367
    .line 368
    :cond_f
    iget-object v7, v7, Lp11/b;->G:Ln11/a;

    .line 369
    .line 370
    invoke-virtual {v7, v10, v11}, Ln11/a;->b(J)I

    .line 371
    .line 372
    .line 373
    move-result v7

    .line 374
    add-int/lit8 v7, v7, -0x1e

    .line 375
    .line 376
    new-instance v10, Lr11/o;

    .line 377
    .line 378
    sget-object v11, Ln11/b;->q:Ln11/b;

    .line 379
    .line 380
    invoke-direct {v10, v11, v7, v9}, Lr11/o;-><init>(Ln11/b;IZ)V

    .line 381
    .line 382
    .line 383
    invoke-virtual {v2, v10}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 384
    .line 385
    .line 386
    goto/16 :goto_5

    .line 387
    .line 388
    :cond_10
    add-int/lit8 v11, v8, 0x1

    .line 389
    .line 390
    const/16 v13, 0x9

    .line 391
    .line 392
    if-ge v11, v3, :cond_12

    .line 393
    .line 394
    aget v11, v5, v6

    .line 395
    .line 396
    add-int/2addr v11, v4

    .line 397
    aput v11, v5, v6

    .line 398
    .line 399
    invoke-static {v0, v5}, Lr11/a;->b(Ljava/lang/String;[I)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object v11

    .line 403
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 404
    .line 405
    .line 406
    move-result v14

    .line 407
    if-lez v14, :cond_11

    .line 408
    .line 409
    invoke-virtual {v11, v6}, Ljava/lang/String;->charAt(I)C

    .line 410
    .line 411
    .line 412
    move-result v11

    .line 413
    sparse-switch v11, :sswitch_data_1

    .line 414
    .line 415
    .line 416
    goto :goto_4

    .line 417
    :sswitch_2
    if-gt v14, v12, :cond_11

    .line 418
    .line 419
    :sswitch_3
    move v13, v9

    .line 420
    :cond_11
    :goto_4
    aget v11, v5, v6

    .line 421
    .line 422
    sub-int/2addr v11, v4

    .line 423
    aput v11, v5, v6

    .line 424
    .line 425
    :cond_12
    const/16 v11, 0x59

    .line 426
    .line 427
    if-eq v10, v11, :cond_15

    .line 428
    .line 429
    if-eq v10, v7, :cond_14

    .line 430
    .line 431
    const/16 v7, 0x79

    .line 432
    .line 433
    if-eq v10, v7, :cond_13

    .line 434
    .line 435
    goto/16 :goto_5

    .line 436
    .line 437
    :cond_13
    sget-object v7, Ln11/b;->l:Ln11/b;

    .line 438
    .line 439
    invoke-virtual {v2, v7, v9, v13}, Lvp/y1;->K(Ln11/b;II)V

    .line 440
    .line 441
    .line 442
    goto/16 :goto_5

    .line 443
    .line 444
    :cond_14
    sget-object v7, Ln11/b;->q:Ln11/b;

    .line 445
    .line 446
    invoke-virtual {v2, v7, v9, v13}, Lvp/y1;->K(Ln11/b;II)V

    .line 447
    .line 448
    .line 449
    goto/16 :goto_5

    .line 450
    .line 451
    :cond_15
    sget-object v7, Ln11/b;->i:Ln11/b;

    .line 452
    .line 453
    invoke-virtual {v2, v7, v9, v13}, Lvp/y1;->E(Ln11/b;II)V

    .line 454
    .line 455
    .line 456
    goto/16 :goto_5

    .line 457
    .line 458
    :cond_16
    sget-object v7, Ln11/b;->x:Ln11/b;

    .line 459
    .line 460
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 461
    .line 462
    .line 463
    goto/16 :goto_5

    .line 464
    .line 465
    :cond_17
    sget-object v7, Ln11/b;->h:Ln11/b;

    .line 466
    .line 467
    invoke-virtual {v2, v7}, Lvp/y1;->L(Ln11/b;)V

    .line 468
    .line 469
    .line 470
    goto :goto_5

    .line 471
    :cond_18
    sget-object v7, Ln11/b;->B:Ln11/b;

    .line 472
    .line 473
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 474
    .line 475
    .line 476
    goto :goto_5

    .line 477
    :cond_19
    sget-object v7, Ln11/b;->z:Ln11/b;

    .line 478
    .line 479
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 480
    .line 481
    .line 482
    goto :goto_5

    .line 483
    :cond_1a
    sget-object v7, Ln11/b;->w:Ln11/b;

    .line 484
    .line 485
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 486
    .line 487
    .line 488
    goto :goto_5

    .line 489
    :cond_1b
    sget-object v7, Ln11/b;->v:Ln11/b;

    .line 490
    .line 491
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 492
    .line 493
    .line 494
    goto :goto_5

    .line 495
    :cond_1c
    sget-object v7, Ln11/b;->t:Ln11/b;

    .line 496
    .line 497
    invoke-virtual {v2, v7}, Lvp/y1;->L(Ln11/b;)V

    .line 498
    .line 499
    .line 500
    goto :goto_5

    .line 501
    :cond_1d
    sget-object v7, Ln11/b;->A:Ln11/b;

    .line 502
    .line 503
    invoke-virtual {v2, v7, v9, v9}, Lvp/y1;->G(Ln11/b;II)V

    .line 504
    .line 505
    .line 506
    goto :goto_5

    .line 507
    :cond_1e
    if-lt v9, v13, :cond_20

    .line 508
    .line 509
    if-lt v9, v14, :cond_1f

    .line 510
    .line 511
    sget-object v7, Ln11/b;->n:Ln11/b;

    .line 512
    .line 513
    invoke-virtual {v2, v7}, Lvp/y1;->L(Ln11/b;)V

    .line 514
    .line 515
    .line 516
    goto :goto_5

    .line 517
    :cond_1f
    sget-object v7, Ln11/b;->n:Ln11/b;

    .line 518
    .line 519
    new-instance v9, Lr11/k;

    .line 520
    .line 521
    invoke-direct {v9, v7, v4}, Lr11/k;-><init>(Ln11/b;Z)V

    .line 522
    .line 523
    .line 524
    invoke-virtual {v2, v9}, Lvp/y1;->C(Ljava/lang/Object;)V

    .line 525
    .line 526
    .line 527
    goto :goto_5

    .line 528
    :cond_20
    sget-object v7, Ln11/b;->n:Ln11/b;

    .line 529
    .line 530
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 531
    .line 532
    .line 533
    goto :goto_5

    .line 534
    :cond_21
    sget-object v7, Ln11/b;->u:Ln11/b;

    .line 535
    .line 536
    invoke-virtual {v2, v7, v9, v12}, Lvp/y1;->E(Ln11/b;II)V

    .line 537
    .line 538
    .line 539
    goto :goto_5

    .line 540
    :cond_22
    invoke-virtual {v7, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 541
    .line 542
    .line 543
    move-result-object v7

    .line 544
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 545
    .line 546
    .line 547
    move-result v9

    .line 548
    if-ne v9, v4, :cond_23

    .line 549
    .line 550
    invoke-virtual {v7, v6}, Ljava/lang/String;->charAt(I)C

    .line 551
    .line 552
    .line 553
    move-result v7

    .line 554
    invoke-virtual {v2, v7}, Lvp/y1;->H(C)V

    .line 555
    .line 556
    .line 557
    goto :goto_5

    .line 558
    :cond_23
    new-instance v9, Ljava/lang/String;

    .line 559
    .line 560
    invoke-direct {v9, v7}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 561
    .line 562
    .line 563
    invoke-virtual {v2, v9}, Lvp/y1;->I(Ljava/lang/String;)V

    .line 564
    .line 565
    .line 566
    :goto_5
    add-int/lit8 v7, v8, 0x1

    .line 567
    .line 568
    goto/16 :goto_0

    .line 569
    .line 570
    :cond_24
    :goto_6
    invoke-virtual {v2}, Lvp/y1;->T()Lr11/b;

    .line 571
    .line 572
    .line 573
    move-result-object v2

    .line 574
    invoke-virtual {v1}, Ljava/util/concurrent/ConcurrentHashMap;->size()I

    .line 575
    .line 576
    .line 577
    move-result v3

    .line 578
    const/16 v4, 0x1f4

    .line 579
    .line 580
    if-ge v3, v4, :cond_25

    .line 581
    .line 582
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 583
    .line 584
    .line 585
    move-result-object v0

    .line 586
    check-cast v0, Lr11/b;

    .line 587
    .line 588
    if-eqz v0, :cond_25

    .line 589
    .line 590
    return-object v0

    .line 591
    :cond_25
    return-object v2

    .line 592
    :cond_26
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 593
    .line 594
    const-string v1, "Invalid pattern specification"

    .line 595
    .line 596
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    throw v0

    .line 600
    nop

    .line 601
    :pswitch_data_0
    .packed-switch 0x43
        :pswitch_4
        :pswitch_3
        :pswitch_2
    .end packed-switch

    .line 602
    .line 603
    .line 604
    .line 605
    .line 606
    .line 607
    .line 608
    .line 609
    .line 610
    .line 611
    :pswitch_data_1
    .packed-switch 0x77
        :pswitch_1
        :pswitch_5
        :pswitch_5
        :pswitch_0
    .end packed-switch

    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    .line 623
    :sswitch_data_0
    .sparse-switch
        0x43 -> :sswitch_1
        0x44 -> :sswitch_1
        0x46 -> :sswitch_1
        0x48 -> :sswitch_1
        0x4b -> :sswitch_1
        0x4d -> :sswitch_0
        0x53 -> :sswitch_1
        0x57 -> :sswitch_1
        0x59 -> :sswitch_1
        0x63 -> :sswitch_1
        0x64 -> :sswitch_1
        0x65 -> :sswitch_1
        0x68 -> :sswitch_1
        0x6b -> :sswitch_1
        0x6d -> :sswitch_1
        0x73 -> :sswitch_1
        0x77 -> :sswitch_1
        0x78 -> :sswitch_1
        0x79 -> :sswitch_1
    .end sparse-switch

    .line 624
    .line 625
    .line 626
    .line 627
    .line 628
    .line 629
    .line 630
    .line 631
    .line 632
    .line 633
    .line 634
    .line 635
    .line 636
    .line 637
    .line 638
    .line 639
    .line 640
    .line 641
    .line 642
    .line 643
    .line 644
    .line 645
    .line 646
    .line 647
    .line 648
    .line 649
    .line 650
    .line 651
    .line 652
    .line 653
    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    .line 663
    .line 664
    .line 665
    .line 666
    .line 667
    .line 668
    .line 669
    .line 670
    .line 671
    .line 672
    .line 673
    .line 674
    .line 675
    .line 676
    .line 677
    .line 678
    .line 679
    .line 680
    .line 681
    .line 682
    .line 683
    .line 684
    .line 685
    .line 686
    .line 687
    .line 688
    .line 689
    .line 690
    .line 691
    .line 692
    .line 693
    .line 694
    .line 695
    .line 696
    .line 697
    .line 698
    .line 699
    .line 700
    .line 701
    :sswitch_data_1
    .sparse-switch
        0x43 -> :sswitch_3
        0x44 -> :sswitch_3
        0x46 -> :sswitch_3
        0x48 -> :sswitch_3
        0x4b -> :sswitch_3
        0x4d -> :sswitch_2
        0x53 -> :sswitch_3
        0x57 -> :sswitch_3
        0x59 -> :sswitch_3
        0x63 -> :sswitch_3
        0x64 -> :sswitch_3
        0x65 -> :sswitch_3
        0x68 -> :sswitch_3
        0x6b -> :sswitch_3
        0x6d -> :sswitch_3
        0x73 -> :sswitch_3
        0x77 -> :sswitch_3
        0x78 -> :sswitch_3
        0x79 -> :sswitch_3
    .end sparse-switch
.end method

.method public static b(Ljava/lang/String;[I)Ljava/lang/String;
    .locals 13

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget v2, p1, v1

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    const/16 v5, 0x5a

    .line 18
    .line 19
    const/16 v6, 0x41

    .line 20
    .line 21
    if-lt v4, v6, :cond_0

    .line 22
    .line 23
    if-le v4, v5, :cond_1

    .line 24
    .line 25
    :cond_0
    const/16 v7, 0x7a

    .line 26
    .line 27
    const/16 v8, 0x61

    .line 28
    .line 29
    if-lt v4, v8, :cond_2

    .line 30
    .line 31
    if-gt v4, v7, :cond_2

    .line 32
    .line 33
    :cond_1
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    :goto_0
    add-int/lit8 v5, v2, 0x1

    .line 37
    .line 38
    if-ge v5, v3, :cond_8

    .line 39
    .line 40
    invoke-virtual {p0, v5}, Ljava/lang/String;->charAt(I)C

    .line 41
    .line 42
    .line 43
    move-result v6

    .line 44
    if-ne v6, v4, :cond_8

    .line 45
    .line 46
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    move v2, v5

    .line 50
    goto :goto_0

    .line 51
    :cond_2
    const/16 v4, 0x27

    .line 52
    .line 53
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    move v9, v1

    .line 57
    :goto_1
    if-ge v2, v3, :cond_8

    .line 58
    .line 59
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    if-ne v10, v4, :cond_4

    .line 64
    .line 65
    add-int/lit8 v11, v2, 0x1

    .line 66
    .line 67
    if-ge v11, v3, :cond_3

    .line 68
    .line 69
    invoke-virtual {p0, v11}, Ljava/lang/String;->charAt(I)C

    .line 70
    .line 71
    .line 72
    move-result v12

    .line 73
    if-ne v12, v4, :cond_3

    .line 74
    .line 75
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    move v2, v11

    .line 79
    goto :goto_2

    .line 80
    :cond_3
    xor-int/lit8 v9, v9, 0x1

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_4
    if-nez v9, :cond_7

    .line 84
    .line 85
    if-lt v10, v6, :cond_5

    .line 86
    .line 87
    if-le v10, v5, :cond_6

    .line 88
    .line 89
    :cond_5
    if-lt v10, v8, :cond_7

    .line 90
    .line 91
    if-gt v10, v7, :cond_7

    .line 92
    .line 93
    :cond_6
    add-int/lit8 v2, v2, -0x1

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_7
    invoke-virtual {v0, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_8
    :goto_3
    aput v2, p1, v1

    .line 103
    .line 104
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0
.end method
