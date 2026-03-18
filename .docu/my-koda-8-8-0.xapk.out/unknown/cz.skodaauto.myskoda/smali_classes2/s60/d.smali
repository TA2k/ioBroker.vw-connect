.class public final synthetic Ls60/d;
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
    iput p1, p0, Ls60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Ls60/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Ls60/d;->d:I

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v0, p1

    .line 9
    .line 10
    check-cast v0, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    and-int/lit8 v2, v1, 0x3

    .line 21
    .line 22
    const/4 v3, 0x2

    .line 23
    const/4 v4, 0x1

    .line 24
    if-eq v2, v3, :cond_0

    .line 25
    .line 26
    move v2, v4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x0

    .line 29
    :goto_0
    and-int/2addr v1, v4

    .line 30
    move-object v7, v0

    .line 31
    check-cast v7, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v7, v1, v2}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_4

    .line 38
    .line 39
    new-instance v3, Ls10/j;

    .line 40
    .line 41
    new-instance v8, Ls10/i;

    .line 42
    .line 43
    const-string v15, "22 \u00b0C"

    .line 44
    .line 45
    const-string v16, "80%"

    .line 46
    .line 47
    const-wide/16 v9, 0xb

    .line 48
    .line 49
    const/4 v11, 0x1

    .line 50
    const-string v12, "Plan 1"

    .line 51
    .line 52
    const-string v13, "08:00"

    .line 53
    .line 54
    const-string v14, "Once on Mon"

    .line 55
    .line 56
    invoke-direct/range {v8 .. v16}, Ls10/i;-><init>(JZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    new-instance v9, Ls10/i;

    .line 60
    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    const-string v17, "80%"

    .line 64
    .line 65
    const-wide/16 v10, 0x2

    .line 66
    .line 67
    const/4 v12, 0x0

    .line 68
    const-string v13, "Plan 2"

    .line 69
    .line 70
    const-string v14, "09:00"

    .line 71
    .line 72
    const-string v15, "Once on Fri"

    .line 73
    .line 74
    invoke-direct/range {v9 .. v17}, Ls10/i;-><init>(JZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    filled-new-array {v8, v9}, [Ls10/i;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    const/4 v1, 0x5

    .line 86
    invoke-direct {v3, v0, v1}, Ls10/j;-><init>(Ljava/util/List;I)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 94
    .line 95
    if-ne v0, v1, :cond_1

    .line 96
    .line 97
    new-instance v0, Lz81/g;

    .line 98
    .line 99
    const/4 v2, 0x2

    .line 100
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :cond_1
    move-object v4, v0

    .line 107
    check-cast v4, Lay0/a;

    .line 108
    .line 109
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    if-ne v0, v1, :cond_2

    .line 114
    .line 115
    new-instance v0, Lt10/b;

    .line 116
    .line 117
    const/4 v2, 0x0

    .line 118
    invoke-direct {v0, v2}, Lt10/b;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_2
    move-object v5, v0

    .line 125
    check-cast v5, Lay0/n;

    .line 126
    .line 127
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-ne v0, v1, :cond_3

    .line 132
    .line 133
    new-instance v0, Ldj/a;

    .line 134
    .line 135
    const/16 v1, 0xf

    .line 136
    .line 137
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_3
    move-object v6, v0

    .line 144
    check-cast v6, Lay0/k;

    .line 145
    .line 146
    const/16 v8, 0xdb0

    .line 147
    .line 148
    invoke-static/range {v3 .. v8}, Lt10/a;->k(Ls10/j;Lay0/a;Lay0/n;Lay0/k;Ll2/o;I)V

    .line 149
    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_4
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 153
    .line 154
    .line 155
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object v0

    .line 158
    :pswitch_0
    move-object/from16 v0, p1

    .line 159
    .line 160
    check-cast v0, Ll2/o;

    .line 161
    .line 162
    move-object/from16 v1, p2

    .line 163
    .line 164
    check-cast v1, Ljava/lang/Integer;

    .line 165
    .line 166
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v1

    .line 170
    and-int/lit8 v2, v1, 0x3

    .line 171
    .line 172
    const/4 v3, 0x2

    .line 173
    const/4 v4, 0x0

    .line 174
    const/4 v5, 0x1

    .line 175
    if-eq v2, v3, :cond_5

    .line 176
    .line 177
    move v2, v5

    .line 178
    goto :goto_2

    .line 179
    :cond_5
    move v2, v4

    .line 180
    :goto_2
    and-int/2addr v1, v5

    .line 181
    check-cast v0, Ll2/t;

    .line 182
    .line 183
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 184
    .line 185
    .line 186
    move-result v1

    .line 187
    if-eqz v1, :cond_6

    .line 188
    .line 189
    invoke-static {v0, v4}, Lt10/a;->j(Ll2/o;I)V

    .line 190
    .line 191
    .line 192
    goto :goto_3

    .line 193
    :cond_6
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 194
    .line 195
    .line 196
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    return-object v0

    .line 199
    :pswitch_1
    move-object/from16 v0, p1

    .line 200
    .line 201
    check-cast v0, Ll2/o;

    .line 202
    .line 203
    move-object/from16 v1, p2

    .line 204
    .line 205
    check-cast v1, Ljava/lang/Integer;

    .line 206
    .line 207
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    and-int/lit8 v2, v1, 0x3

    .line 212
    .line 213
    const/4 v3, 0x2

    .line 214
    const/4 v4, 0x0

    .line 215
    const/4 v5, 0x1

    .line 216
    if-eq v2, v3, :cond_7

    .line 217
    .line 218
    move v2, v5

    .line 219
    goto :goto_4

    .line 220
    :cond_7
    move v2, v4

    .line 221
    :goto_4
    and-int/2addr v1, v5

    .line 222
    check-cast v0, Ll2/t;

    .line 223
    .line 224
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 225
    .line 226
    .line 227
    move-result v1

    .line 228
    if-eqz v1, :cond_8

    .line 229
    .line 230
    invoke-static {v0, v4}, Lt10/a;->c(Ll2/o;I)V

    .line 231
    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_8
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 235
    .line 236
    .line 237
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 238
    .line 239
    return-object v0

    .line 240
    :pswitch_2
    move-object/from16 v0, p1

    .line 241
    .line 242
    check-cast v0, Ll2/o;

    .line 243
    .line 244
    move-object/from16 v1, p2

    .line 245
    .line 246
    check-cast v1, Ljava/lang/Integer;

    .line 247
    .line 248
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    and-int/lit8 v2, v1, 0x3

    .line 253
    .line 254
    const/4 v3, 0x2

    .line 255
    const/4 v4, 0x1

    .line 256
    if-eq v2, v3, :cond_9

    .line 257
    .line 258
    move v2, v4

    .line 259
    goto :goto_6

    .line 260
    :cond_9
    const/4 v2, 0x0

    .line 261
    :goto_6
    and-int/2addr v1, v4

    .line 262
    move-object v10, v0

    .line 263
    check-cast v10, Ll2/t;

    .line 264
    .line 265
    invoke-virtual {v10, v1, v2}, Ll2/t;->O(IZ)Z

    .line 266
    .line 267
    .line 268
    move-result v0

    .line 269
    if-eqz v0, :cond_10

    .line 270
    .line 271
    new-instance v3, Ls10/b;

    .line 272
    .line 273
    const/16 v0, 0xf5

    .line 274
    .line 275
    invoke-direct {v3, v0}, Ls10/b;-><init>(I)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 283
    .line 284
    if-ne v0, v1, :cond_a

    .line 285
    .line 286
    new-instance v0, Lz81/g;

    .line 287
    .line 288
    const/4 v2, 0x2

    .line 289
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    :cond_a
    move-object v4, v0

    .line 296
    check-cast v4, Lay0/a;

    .line 297
    .line 298
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    if-ne v0, v1, :cond_b

    .line 303
    .line 304
    new-instance v0, Lz81/g;

    .line 305
    .line 306
    const/4 v2, 0x2

    .line 307
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    :cond_b
    move-object v5, v0

    .line 314
    check-cast v5, Lay0/a;

    .line 315
    .line 316
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    if-ne v0, v1, :cond_c

    .line 321
    .line 322
    new-instance v0, Lsb/a;

    .line 323
    .line 324
    const/16 v2, 0x19

    .line 325
    .line 326
    invoke-direct {v0, v2}, Lsb/a;-><init>(I)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    :cond_c
    move-object v6, v0

    .line 333
    check-cast v6, Lay0/k;

    .line 334
    .line 335
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v0

    .line 339
    if-ne v0, v1, :cond_d

    .line 340
    .line 341
    new-instance v0, Lz81/g;

    .line 342
    .line 343
    const/4 v2, 0x2

    .line 344
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    :cond_d
    move-object v7, v0

    .line 351
    check-cast v7, Lay0/a;

    .line 352
    .line 353
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    if-ne v0, v1, :cond_e

    .line 358
    .line 359
    new-instance v0, Lz81/g;

    .line 360
    .line 361
    const/4 v2, 0x2

    .line 362
    invoke-direct {v0, v2}, Lz81/g;-><init>(I)V

    .line 363
    .line 364
    .line 365
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 366
    .line 367
    .line 368
    :cond_e
    move-object v8, v0

    .line 369
    check-cast v8, Lay0/a;

    .line 370
    .line 371
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    if-ne v0, v1, :cond_f

    .line 376
    .line 377
    new-instance v0, Lz81/g;

    .line 378
    .line 379
    const/4 v1, 0x2

    .line 380
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 381
    .line 382
    .line 383
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 384
    .line 385
    .line 386
    :cond_f
    move-object v9, v0

    .line 387
    check-cast v9, Lay0/a;

    .line 388
    .line 389
    const v11, 0x1b6db0

    .line 390
    .line 391
    .line 392
    invoke-static/range {v3 .. v11}, Lt10/a;->d(Ls10/b;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 393
    .line 394
    .line 395
    goto :goto_7

    .line 396
    :cond_10
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 397
    .line 398
    .line 399
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 400
    .line 401
    return-object v0

    .line 402
    :pswitch_3
    move-object/from16 v0, p1

    .line 403
    .line 404
    check-cast v0, Lu2/b;

    .line 405
    .line 406
    move-object/from16 v0, p2

    .line 407
    .line 408
    check-cast v0, Lt1/h1;

    .line 409
    .line 410
    iget-object v1, v0, Lt1/h1;->a:Ll2/f1;

    .line 411
    .line 412
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 413
    .line 414
    .line 415
    move-result v1

    .line 416
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    iget-object v0, v0, Lt1/h1;->f:Ll2/j1;

    .line 421
    .line 422
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v0

    .line 426
    check-cast v0, Lg1/w1;

    .line 427
    .line 428
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 429
    .line 430
    if-ne v0, v2, :cond_11

    .line 431
    .line 432
    const/4 v0, 0x1

    .line 433
    goto :goto_8

    .line 434
    :cond_11
    const/4 v0, 0x0

    .line 435
    :goto_8
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    filled-new-array {v1, v0}, [Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v0

    .line 443
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 444
    .line 445
    .line 446
    move-result-object v0

    .line 447
    return-object v0

    .line 448
    :pswitch_4
    move-object/from16 v0, p1

    .line 449
    .line 450
    check-cast v0, Lk21/a;

    .line 451
    .line 452
    move-object/from16 v1, p2

    .line 453
    .line 454
    check-cast v1, Lg21/a;

    .line 455
    .line 456
    const-string v2, "$this$single"

    .line 457
    .line 458
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 459
    .line 460
    .line 461
    const-string v2, "it"

    .line 462
    .line 463
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 464
    .line 465
    .line 466
    new-instance v1, Lry/q;

    .line 467
    .line 468
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 469
    .line 470
    const-class v3, Lry/e;

    .line 471
    .line 472
    const-string v4, "null"

    .line 473
    .line 474
    invoke-static {v2, v3, v4}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 475
    .line 476
    .line 477
    move-result-object v3

    .line 478
    const-class v5, Lti0/a;

    .line 479
    .line 480
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 481
    .line 482
    .line 483
    move-result-object v6

    .line 484
    const/4 v7, 0x0

    .line 485
    invoke-virtual {v0, v6, v3, v7}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v3

    .line 489
    check-cast v3, Lti0/a;

    .line 490
    .line 491
    const-class v6, Lry/b;

    .line 492
    .line 493
    invoke-static {v2, v6, v4}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 494
    .line 495
    .line 496
    move-result-object v6

    .line 497
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 498
    .line 499
    .line 500
    move-result-object v8

    .line 501
    invoke-virtual {v0, v8, v6, v7}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 502
    .line 503
    .line 504
    move-result-object v6

    .line 505
    check-cast v6, Lti0/a;

    .line 506
    .line 507
    const-class v8, Lry/f;

    .line 508
    .line 509
    invoke-static {v2, v8, v4}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 510
    .line 511
    .line 512
    move-result-object v4

    .line 513
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 514
    .line 515
    .line 516
    move-result-object v5

    .line 517
    invoke-virtual {v0, v5, v4, v7}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v4

    .line 521
    check-cast v4, Lti0/a;

    .line 522
    .line 523
    const-class v5, Lwe0/a;

    .line 524
    .line 525
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    invoke-virtual {v0, v2, v7, v7}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object v0

    .line 533
    check-cast v0, Lwe0/a;

    .line 534
    .line 535
    invoke-direct {v1, v3, v6, v4, v0}, Lry/q;-><init>(Lti0/a;Lti0/a;Lti0/a;Lwe0/a;)V

    .line 536
    .line 537
    .line 538
    return-object v1

    .line 539
    :pswitch_5
    move-object/from16 v0, p1

    .line 540
    .line 541
    check-cast v0, Lk21/a;

    .line 542
    .line 543
    move-object/from16 v1, p2

    .line 544
    .line 545
    check-cast v1, Lg21/a;

    .line 546
    .line 547
    const-string v2, "$this$single"

    .line 548
    .line 549
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 550
    .line 551
    .line 552
    const-string v2, "it"

    .line 553
    .line 554
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    new-instance v1, Lry/k;

    .line 558
    .line 559
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 560
    .line 561
    const-class v3, Lxl0/f;

    .line 562
    .line 563
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 564
    .line 565
    .line 566
    move-result-object v3

    .line 567
    const/4 v4, 0x0

    .line 568
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 569
    .line 570
    .line 571
    move-result-object v3

    .line 572
    check-cast v3, Lxl0/f;

    .line 573
    .line 574
    const-class v5, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 575
    .line 576
    const-string v6, "null"

    .line 577
    .line 578
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 579
    .line 580
    .line 581
    move-result-object v5

    .line 582
    const-class v6, Lti0/a;

    .line 583
    .line 584
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 585
    .line 586
    .line 587
    move-result-object v2

    .line 588
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    check-cast v0, Lti0/a;

    .line 593
    .line 594
    invoke-direct {v1, v3, v0}, Lry/k;-><init>(Lxl0/f;Lti0/a;)V

    .line 595
    .line 596
    .line 597
    return-object v1

    .line 598
    :pswitch_6
    move-object/from16 v0, p1

    .line 599
    .line 600
    check-cast v0, Ll2/o;

    .line 601
    .line 602
    move-object/from16 v1, p2

    .line 603
    .line 604
    check-cast v1, Ljava/lang/Integer;

    .line 605
    .line 606
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 607
    .line 608
    .line 609
    const/4 v1, 0x1

    .line 610
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 611
    .line 612
    .line 613
    move-result v1

    .line 614
    invoke-static {v0, v1}, Lsm0/a;->a(Ll2/o;I)V

    .line 615
    .line 616
    .line 617
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 618
    .line 619
    return-object v0

    .line 620
    :pswitch_7
    move-object/from16 v0, p1

    .line 621
    .line 622
    check-cast v0, Ll2/o;

    .line 623
    .line 624
    move-object/from16 v1, p2

    .line 625
    .line 626
    check-cast v1, Ljava/lang/Integer;

    .line 627
    .line 628
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 629
    .line 630
    .line 631
    move-result v1

    .line 632
    and-int/lit8 v2, v1, 0x3

    .line 633
    .line 634
    const/4 v3, 0x2

    .line 635
    const/4 v4, 0x1

    .line 636
    if-eq v2, v3, :cond_12

    .line 637
    .line 638
    move v2, v4

    .line 639
    goto :goto_9

    .line 640
    :cond_12
    const/4 v2, 0x0

    .line 641
    :goto_9
    and-int/2addr v1, v4

    .line 642
    check-cast v0, Ll2/t;

    .line 643
    .line 644
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 645
    .line 646
    .line 647
    move-result v1

    .line 648
    if-eqz v1, :cond_13

    .line 649
    .line 650
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 651
    .line 652
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    move-result-object v1

    .line 656
    check-cast v1, Lj91/f;

    .line 657
    .line 658
    invoke-virtual {v1}, Lj91/f;->j()Lg4/p0;

    .line 659
    .line 660
    .line 661
    move-result-object v4

    .line 662
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 663
    .line 664
    const/high16 v2, 0x3f800000    # 1.0f

    .line 665
    .line 666
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 667
    .line 668
    .line 669
    move-result-object v5

    .line 670
    new-instance v14, Lr4/k;

    .line 671
    .line 672
    const/4 v1, 0x3

    .line 673
    invoke-direct {v14, v1}, Lr4/k;-><init>(I)V

    .line 674
    .line 675
    .line 676
    const/16 v23, 0x0

    .line 677
    .line 678
    const v24, 0xfbf8

    .line 679
    .line 680
    .line 681
    const-string v3, "Page 3"

    .line 682
    .line 683
    const-wide/16 v6, 0x0

    .line 684
    .line 685
    const-wide/16 v8, 0x0

    .line 686
    .line 687
    const/4 v10, 0x0

    .line 688
    const-wide/16 v11, 0x0

    .line 689
    .line 690
    const/4 v13, 0x0

    .line 691
    const-wide/16 v15, 0x0

    .line 692
    .line 693
    const/16 v17, 0x0

    .line 694
    .line 695
    const/16 v18, 0x0

    .line 696
    .line 697
    const/16 v19, 0x0

    .line 698
    .line 699
    const/16 v20, 0x0

    .line 700
    .line 701
    const/16 v22, 0x186

    .line 702
    .line 703
    move-object/from16 v21, v0

    .line 704
    .line 705
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 706
    .line 707
    .line 708
    goto :goto_a

    .line 709
    :cond_13
    move-object/from16 v21, v0

    .line 710
    .line 711
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 712
    .line 713
    .line 714
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 715
    .line 716
    return-object v0

    .line 717
    :pswitch_8
    move-object/from16 v0, p1

    .line 718
    .line 719
    check-cast v0, Ll2/o;

    .line 720
    .line 721
    move-object/from16 v1, p2

    .line 722
    .line 723
    check-cast v1, Ljava/lang/Integer;

    .line 724
    .line 725
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 726
    .line 727
    .line 728
    move-result v1

    .line 729
    and-int/lit8 v2, v1, 0x3

    .line 730
    .line 731
    const/4 v3, 0x2

    .line 732
    const/4 v4, 0x1

    .line 733
    if-eq v2, v3, :cond_14

    .line 734
    .line 735
    move v2, v4

    .line 736
    goto :goto_b

    .line 737
    :cond_14
    const/4 v2, 0x0

    .line 738
    :goto_b
    and-int/2addr v1, v4

    .line 739
    check-cast v0, Ll2/t;

    .line 740
    .line 741
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 742
    .line 743
    .line 744
    move-result v1

    .line 745
    if-eqz v1, :cond_15

    .line 746
    .line 747
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 748
    .line 749
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object v1

    .line 753
    check-cast v1, Lj91/f;

    .line 754
    .line 755
    invoke-virtual {v1}, Lj91/f;->j()Lg4/p0;

    .line 756
    .line 757
    .line 758
    move-result-object v4

    .line 759
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 760
    .line 761
    const/high16 v2, 0x3f800000    # 1.0f

    .line 762
    .line 763
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 764
    .line 765
    .line 766
    move-result-object v5

    .line 767
    new-instance v14, Lr4/k;

    .line 768
    .line 769
    const/4 v1, 0x3

    .line 770
    invoke-direct {v14, v1}, Lr4/k;-><init>(I)V

    .line 771
    .line 772
    .line 773
    const/16 v23, 0x0

    .line 774
    .line 775
    const v24, 0xfbf8

    .line 776
    .line 777
    .line 778
    const-string v3, "Page 2"

    .line 779
    .line 780
    const-wide/16 v6, 0x0

    .line 781
    .line 782
    const-wide/16 v8, 0x0

    .line 783
    .line 784
    const/4 v10, 0x0

    .line 785
    const-wide/16 v11, 0x0

    .line 786
    .line 787
    const/4 v13, 0x0

    .line 788
    const-wide/16 v15, 0x0

    .line 789
    .line 790
    const/16 v17, 0x0

    .line 791
    .line 792
    const/16 v18, 0x0

    .line 793
    .line 794
    const/16 v19, 0x0

    .line 795
    .line 796
    const/16 v20, 0x0

    .line 797
    .line 798
    const/16 v22, 0x186

    .line 799
    .line 800
    move-object/from16 v21, v0

    .line 801
    .line 802
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 803
    .line 804
    .line 805
    goto :goto_c

    .line 806
    :cond_15
    move-object/from16 v21, v0

    .line 807
    .line 808
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 809
    .line 810
    .line 811
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 812
    .line 813
    return-object v0

    .line 814
    :pswitch_9
    move-object/from16 v0, p1

    .line 815
    .line 816
    check-cast v0, Ll2/o;

    .line 817
    .line 818
    move-object/from16 v1, p2

    .line 819
    .line 820
    check-cast v1, Ljava/lang/Integer;

    .line 821
    .line 822
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 823
    .line 824
    .line 825
    move-result v1

    .line 826
    and-int/lit8 v2, v1, 0x3

    .line 827
    .line 828
    const/4 v3, 0x2

    .line 829
    const/4 v4, 0x1

    .line 830
    if-eq v2, v3, :cond_16

    .line 831
    .line 832
    move v2, v4

    .line 833
    goto :goto_d

    .line 834
    :cond_16
    const/4 v2, 0x0

    .line 835
    :goto_d
    and-int/2addr v1, v4

    .line 836
    check-cast v0, Ll2/t;

    .line 837
    .line 838
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 839
    .line 840
    .line 841
    move-result v1

    .line 842
    if-eqz v1, :cond_17

    .line 843
    .line 844
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 845
    .line 846
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 847
    .line 848
    .line 849
    move-result-object v1

    .line 850
    check-cast v1, Lj91/f;

    .line 851
    .line 852
    invoke-virtual {v1}, Lj91/f;->j()Lg4/p0;

    .line 853
    .line 854
    .line 855
    move-result-object v4

    .line 856
    const/16 v23, 0x0

    .line 857
    .line 858
    const v24, 0xfffc

    .line 859
    .line 860
    .line 861
    const-string v3, "Page 1"

    .line 862
    .line 863
    const/4 v5, 0x0

    .line 864
    const-wide/16 v6, 0x0

    .line 865
    .line 866
    const-wide/16 v8, 0x0

    .line 867
    .line 868
    const/4 v10, 0x0

    .line 869
    const-wide/16 v11, 0x0

    .line 870
    .line 871
    const/4 v13, 0x0

    .line 872
    const/4 v14, 0x0

    .line 873
    const-wide/16 v15, 0x0

    .line 874
    .line 875
    const/16 v17, 0x0

    .line 876
    .line 877
    const/16 v18, 0x0

    .line 878
    .line 879
    const/16 v19, 0x0

    .line 880
    .line 881
    const/16 v20, 0x0

    .line 882
    .line 883
    const/16 v22, 0x6

    .line 884
    .line 885
    move-object/from16 v21, v0

    .line 886
    .line 887
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 888
    .line 889
    .line 890
    goto :goto_e

    .line 891
    :cond_17
    move-object/from16 v21, v0

    .line 892
    .line 893
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 894
    .line 895
    .line 896
    :goto_e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 897
    .line 898
    return-object v0

    .line 899
    :pswitch_a
    move-object/from16 v0, p1

    .line 900
    .line 901
    check-cast v0, Lk21/a;

    .line 902
    .line 903
    move-object/from16 v1, p2

    .line 904
    .line 905
    check-cast v1, Lg21/a;

    .line 906
    .line 907
    const-string v2, "$this$viewModel"

    .line 908
    .line 909
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 910
    .line 911
    .line 912
    const-string v2, "it"

    .line 913
    .line 914
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 915
    .line 916
    .line 917
    new-instance v1, Lvl0/b;

    .line 918
    .line 919
    const-class v2, Ltl0/b;

    .line 920
    .line 921
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 922
    .line 923
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 924
    .line 925
    .line 926
    move-result-object v2

    .line 927
    const/4 v3, 0x0

    .line 928
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 929
    .line 930
    .line 931
    move-result-object v0

    .line 932
    check-cast v0, Ltl0/b;

    .line 933
    .line 934
    invoke-direct {v1, v0}, Lvl0/b;-><init>(Ltl0/b;)V

    .line 935
    .line 936
    .line 937
    return-object v1

    .line 938
    :pswitch_b
    move-object/from16 v0, p1

    .line 939
    .line 940
    check-cast v0, Lk21/a;

    .line 941
    .line 942
    move-object/from16 v1, p2

    .line 943
    .line 944
    check-cast v1, Lg21/a;

    .line 945
    .line 946
    const-string v2, "$this$factory"

    .line 947
    .line 948
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 949
    .line 950
    .line 951
    const-string v2, "it"

    .line 952
    .line 953
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 954
    .line 955
    .line 956
    new-instance v1, Ltl0/b;

    .line 957
    .line 958
    const-class v2, Ltl0/a;

    .line 959
    .line 960
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 961
    .line 962
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 963
    .line 964
    .line 965
    move-result-object v2

    .line 966
    const/4 v3, 0x0

    .line 967
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 968
    .line 969
    .line 970
    move-result-object v0

    .line 971
    check-cast v0, Ltl0/a;

    .line 972
    .line 973
    invoke-direct {v1, v0}, Ltl0/b;-><init>(Ltl0/a;)V

    .line 974
    .line 975
    .line 976
    return-object v1

    .line 977
    :pswitch_c
    move-object/from16 v0, p1

    .line 978
    .line 979
    check-cast v0, Lk21/a;

    .line 980
    .line 981
    move-object/from16 v1, p2

    .line 982
    .line 983
    check-cast v1, Lg21/a;

    .line 984
    .line 985
    const-string v2, "$this$factory"

    .line 986
    .line 987
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 988
    .line 989
    .line 990
    const-string v2, "it"

    .line 991
    .line 992
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 993
    .line 994
    .line 995
    new-instance v1, Lrj0/a;

    .line 996
    .line 997
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 998
    .line 999
    const-class v3, Lxl0/f;

    .line 1000
    .line 1001
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v3

    .line 1005
    const/4 v4, 0x0

    .line 1006
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v3

    .line 1010
    check-cast v3, Lxl0/f;

    .line 1011
    .line 1012
    const-class v5, Lcz/myskoda/api/bff_manuals/v2/ManualsApi;

    .line 1013
    .line 1014
    const-string v6, "null"

    .line 1015
    .line 1016
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v5

    .line 1020
    const-class v6, Lti0/a;

    .line 1021
    .line 1022
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1023
    .line 1024
    .line 1025
    move-result-object v2

    .line 1026
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v0

    .line 1030
    check-cast v0, Lti0/a;

    .line 1031
    .line 1032
    invoke-direct {v1, v3, v0}, Lrj0/a;-><init>(Lxl0/f;Lti0/a;)V

    .line 1033
    .line 1034
    .line 1035
    return-object v1

    .line 1036
    :pswitch_d
    move-object/from16 v0, p1

    .line 1037
    .line 1038
    check-cast v0, Lk21/a;

    .line 1039
    .line 1040
    move-object/from16 v1, p2

    .line 1041
    .line 1042
    check-cast v1, Lg21/a;

    .line 1043
    .line 1044
    const-string v2, "$this$single"

    .line 1045
    .line 1046
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1047
    .line 1048
    .line 1049
    const-string v2, "it"

    .line 1050
    .line 1051
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1052
    .line 1053
    .line 1054
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1055
    .line 1056
    const-class v2, Lve0/d;

    .line 1057
    .line 1058
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v2

    .line 1062
    const/4 v3, 0x0

    .line 1063
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1064
    .line 1065
    .line 1066
    move-result-object v2

    .line 1067
    check-cast v2, Lve0/d;

    .line 1068
    .line 1069
    new-instance v4, Lve0/c;

    .line 1070
    .line 1071
    invoke-direct {v4, v2}, Lve0/c;-><init>(Lve0/d;)V

    .line 1072
    .line 1073
    .line 1074
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v2

    .line 1078
    new-instance v4, Lb3/g;

    .line 1079
    .line 1080
    new-instance v5, Lpg/m;

    .line 1081
    .line 1082
    const/16 v6, 0xc

    .line 1083
    .line 1084
    invoke-direct {v5, v0, v6}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 1085
    .line 1086
    .line 1087
    invoke-direct {v4, v5}, Lb3/g;-><init>(Lay0/k;)V

    .line 1088
    .line 1089
    .line 1090
    new-instance v5, Lsc0/a;

    .line 1091
    .line 1092
    const/4 v6, 0x1

    .line 1093
    invoke-direct {v5, v0, v6}, Lsc0/a;-><init>(Lk21/a;I)V

    .line 1094
    .line 1095
    .line 1096
    const/4 v6, 0x4

    .line 1097
    invoke-static {v4, v2, v5, v6}, Lq6/d;->d(Lb3/g;Ljava/util/List;Lay0/a;I)Lq6/c;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v2

    .line 1101
    new-instance v4, Lve0/u;

    .line 1102
    .line 1103
    const-class v5, Lte0/b;

    .line 1104
    .line 1105
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v5

    .line 1109
    invoke-virtual {v0, v5, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v5

    .line 1113
    check-cast v5, Lte0/b;

    .line 1114
    .line 1115
    const-class v6, Lte0/a;

    .line 1116
    .line 1117
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1118
    .line 1119
    .line 1120
    move-result-object v1

    .line 1121
    invoke-virtual {v0, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v0

    .line 1125
    check-cast v0, Lte0/a;

    .line 1126
    .line 1127
    invoke-direct {v4, v2, v5, v0}, Lve0/u;-><init>(Lq6/c;Lte0/b;Lte0/a;)V

    .line 1128
    .line 1129
    .line 1130
    return-object v4

    .line 1131
    :pswitch_e
    move-object/from16 v0, p1

    .line 1132
    .line 1133
    check-cast v0, Lk21/a;

    .line 1134
    .line 1135
    move-object/from16 v1, p2

    .line 1136
    .line 1137
    check-cast v1, Lg21/a;

    .line 1138
    .line 1139
    const-string v2, "$this$single"

    .line 1140
    .line 1141
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1142
    .line 1143
    .line 1144
    const-string v2, "it"

    .line 1145
    .line 1146
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1147
    .line 1148
    .line 1149
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1150
    .line 1151
    const-class v2, Lyl/l;

    .line 1152
    .line 1153
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v2

    .line 1157
    const/4 v3, 0x0

    .line 1158
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1159
    .line 1160
    .line 1161
    move-result-object v2

    .line 1162
    check-cast v2, Lyl/l;

    .line 1163
    .line 1164
    check-cast v2, Lyl/r;

    .line 1165
    .line 1166
    new-instance v3, Lcom/google/android/material/datepicker/d;

    .line 1167
    .line 1168
    iget-object v2, v2, Lyl/r;->a:Lyl/o;

    .line 1169
    .line 1170
    invoke-direct {v3, v2}, Lcom/google/android/material/datepicker/d;-><init>(Lyl/o;)V

    .line 1171
    .line 1172
    .line 1173
    new-instance v2, Ljava/util/ArrayList;

    .line 1174
    .line 1175
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1176
    .line 1177
    .line 1178
    new-instance v4, Ljava/util/ArrayList;

    .line 1179
    .line 1180
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1181
    .line 1182
    .line 1183
    new-instance v5, Ljava/util/ArrayList;

    .line 1184
    .line 1185
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1186
    .line 1187
    .line 1188
    new-instance v6, Ljava/util/ArrayList;

    .line 1189
    .line 1190
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 1191
    .line 1192
    .line 1193
    new-instance v7, Ljava/util/ArrayList;

    .line 1194
    .line 1195
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 1196
    .line 1197
    .line 1198
    new-instance v8, Lsc0/a;

    .line 1199
    .line 1200
    const/4 v9, 0x0

    .line 1201
    invoke-direct {v8, v0, v9}, Lsc0/a;-><init>(Lk21/a;I)V

    .line 1202
    .line 1203
    .line 1204
    new-instance v0, Lim/j;

    .line 1205
    .line 1206
    new-instance v9, Lha0/f;

    .line 1207
    .line 1208
    const/16 v10, 0xa

    .line 1209
    .line 1210
    invoke-direct {v9, v8, v10}, Lha0/f;-><init>(Lay0/a;I)V

    .line 1211
    .line 1212
    .line 1213
    invoke-direct {v0, v9}, Lim/j;-><init>(Lay0/a;)V

    .line 1214
    .line 1215
    .line 1216
    const-class v8, Lyl/t;

    .line 1217
    .line 1218
    invoke-virtual {v1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1219
    .line 1220
    .line 1221
    move-result-object v1

    .line 1222
    new-instance v8, Lyj/b;

    .line 1223
    .line 1224
    const/4 v9, 0x4

    .line 1225
    invoke-direct {v8, v9, v0, v1}, Lyj/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1226
    .line 1227
    .line 1228
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1229
    .line 1230
    .line 1231
    new-instance v10, Lyl/d;

    .line 1232
    .line 1233
    invoke-static {v2}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 1234
    .line 1235
    .line 1236
    move-result-object v11

    .line 1237
    invoke-static {v4}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 1238
    .line 1239
    .line 1240
    move-result-object v12

    .line 1241
    invoke-static {v5}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v13

    .line 1245
    invoke-static {v6}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v14

    .line 1249
    invoke-static {v7}, Lkp/g8;->c(Ljava/util/List;)Ljava/util/List;

    .line 1250
    .line 1251
    .line 1252
    move-result-object v15

    .line 1253
    invoke-direct/range {v10 .. v15}, Lyl/d;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 1254
    .line 1255
    .line 1256
    iput-object v10, v3, Lcom/google/android/material/datepicker/d;->g:Ljava/lang/Object;

    .line 1257
    .line 1258
    invoke-virtual {v3}, Lcom/google/android/material/datepicker/d;->f()Lyl/r;

    .line 1259
    .line 1260
    .line 1261
    move-result-object v0

    .line 1262
    return-object v0

    .line 1263
    :pswitch_f
    move-object/from16 v1, p1

    .line 1264
    .line 1265
    check-cast v1, Lk21/a;

    .line 1266
    .line 1267
    move-object/from16 v0, p2

    .line 1268
    .line 1269
    check-cast v0, Lg21/a;

    .line 1270
    .line 1271
    const-string v2, "$this$single"

    .line 1272
    .line 1273
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1274
    .line 1275
    .line 1276
    const-string v2, "it"

    .line 1277
    .line 1278
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1279
    .line 1280
    .line 1281
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1282
    .line 1283
    const-class v2, Lnc0/r;

    .line 1284
    .line 1285
    invoke-virtual {v0, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1286
    .line 1287
    .line 1288
    move-result-object v2

    .line 1289
    const/4 v3, 0x0

    .line 1290
    invoke-virtual {v1, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1291
    .line 1292
    .line 1293
    move-result-object v2

    .line 1294
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 1295
    .line 1296
    .line 1297
    move-result-object v2

    .line 1298
    const-class v4, Luc0/a;

    .line 1299
    .line 1300
    invoke-virtual {v0, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1301
    .line 1302
    .line 1303
    move-result-object v4

    .line 1304
    invoke-virtual {v1, v4, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1305
    .line 1306
    .line 1307
    move-result-object v4

    .line 1308
    check-cast v4, Ld01/c;

    .line 1309
    .line 1310
    const-class v5, Ldm0/o;

    .line 1311
    .line 1312
    invoke-virtual {v0, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v0

    .line 1316
    invoke-virtual {v1, v0, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1317
    .line 1318
    .line 1319
    move-result-object v0

    .line 1320
    move-object v7, v0

    .line 1321
    check-cast v7, Ldm0/o;

    .line 1322
    .line 1323
    const/16 v8, 0x51

    .line 1324
    .line 1325
    move-object v3, v2

    .line 1326
    const/4 v2, 0x0

    .line 1327
    const-string v5, "bff-api-auth"

    .line 1328
    .line 1329
    const/4 v6, 0x0

    .line 1330
    invoke-static/range {v1 .. v8}, Lzl0/b;->b(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;I)Ld01/h0;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v0

    .line 1334
    return-object v0

    .line 1335
    :pswitch_10
    move-object/from16 v0, p1

    .line 1336
    .line 1337
    check-cast v0, Ll2/o;

    .line 1338
    .line 1339
    move-object/from16 v1, p2

    .line 1340
    .line 1341
    check-cast v1, Ljava/lang/Integer;

    .line 1342
    .line 1343
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1344
    .line 1345
    .line 1346
    const/4 v1, 0x1

    .line 1347
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1348
    .line 1349
    .line 1350
    move-result v1

    .line 1351
    invoke-static {v0, v1}, Ls80/a;->h(Ll2/o;I)V

    .line 1352
    .line 1353
    .line 1354
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1355
    .line 1356
    return-object v0

    .line 1357
    :pswitch_11
    move-object/from16 v0, p1

    .line 1358
    .line 1359
    check-cast v0, Ll2/o;

    .line 1360
    .line 1361
    move-object/from16 v1, p2

    .line 1362
    .line 1363
    check-cast v1, Ljava/lang/Integer;

    .line 1364
    .line 1365
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1366
    .line 1367
    .line 1368
    const/4 v1, 0x1

    .line 1369
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1370
    .line 1371
    .line 1372
    move-result v1

    .line 1373
    invoke-static {v0, v1}, Ls80/a;->c(Ll2/o;I)V

    .line 1374
    .line 1375
    .line 1376
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1377
    .line 1378
    return-object v0

    .line 1379
    :pswitch_12
    move-object/from16 v0, p1

    .line 1380
    .line 1381
    check-cast v0, Ll2/o;

    .line 1382
    .line 1383
    move-object/from16 v1, p2

    .line 1384
    .line 1385
    check-cast v1, Ljava/lang/Integer;

    .line 1386
    .line 1387
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1388
    .line 1389
    .line 1390
    const/4 v1, 0x1

    .line 1391
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1392
    .line 1393
    .line 1394
    move-result v1

    .line 1395
    invoke-static {v0, v1}, Ls80/a;->d(Ll2/o;I)V

    .line 1396
    .line 1397
    .line 1398
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1399
    .line 1400
    return-object v0

    .line 1401
    :pswitch_13
    move-object/from16 v0, p1

    .line 1402
    .line 1403
    check-cast v0, Ll2/o;

    .line 1404
    .line 1405
    move-object/from16 v1, p2

    .line 1406
    .line 1407
    check-cast v1, Ljava/lang/Integer;

    .line 1408
    .line 1409
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1410
    .line 1411
    .line 1412
    move-result v1

    .line 1413
    and-int/lit8 v2, v1, 0x3

    .line 1414
    .line 1415
    const/4 v3, 0x2

    .line 1416
    const/4 v4, 0x1

    .line 1417
    if-eq v2, v3, :cond_18

    .line 1418
    .line 1419
    move v2, v4

    .line 1420
    goto :goto_f

    .line 1421
    :cond_18
    const/4 v2, 0x0

    .line 1422
    :goto_f
    and-int/2addr v1, v4

    .line 1423
    move-object v7, v0

    .line 1424
    check-cast v7, Ll2/t;

    .line 1425
    .line 1426
    invoke-virtual {v7, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1427
    .line 1428
    .line 1429
    move-result v0

    .line 1430
    if-eqz v0, :cond_19

    .line 1431
    .line 1432
    new-instance v3, Lr80/a;

    .line 1433
    .line 1434
    const-string v0, "1 expiring"

    .line 1435
    .line 1436
    invoke-direct {v3, v0}, Lr80/a;-><init>(Ljava/lang/String;)V

    .line 1437
    .line 1438
    .line 1439
    const/4 v8, 0x0

    .line 1440
    const/16 v9, 0xe

    .line 1441
    .line 1442
    const/4 v4, 0x0

    .line 1443
    const/4 v5, 0x0

    .line 1444
    const/4 v6, 0x0

    .line 1445
    invoke-static/range {v3 .. v9}, Ls80/a;->g(Lr80/a;Lx2/s;ZLay0/a;Ll2/o;II)V

    .line 1446
    .line 1447
    .line 1448
    goto :goto_10

    .line 1449
    :cond_19
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 1450
    .line 1451
    .line 1452
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1453
    .line 1454
    return-object v0

    .line 1455
    :pswitch_14
    move-object/from16 v0, p1

    .line 1456
    .line 1457
    check-cast v0, Ll2/o;

    .line 1458
    .line 1459
    move-object/from16 v1, p2

    .line 1460
    .line 1461
    check-cast v1, Ljava/lang/Integer;

    .line 1462
    .line 1463
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1464
    .line 1465
    .line 1466
    const/4 v1, 0x1

    .line 1467
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1468
    .line 1469
    .line 1470
    move-result v1

    .line 1471
    invoke-static {v0, v1}, Ls60/a;->D(Ll2/o;I)V

    .line 1472
    .line 1473
    .line 1474
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1475
    .line 1476
    return-object v0

    .line 1477
    :pswitch_15
    move-object/from16 v0, p1

    .line 1478
    .line 1479
    check-cast v0, Ll2/o;

    .line 1480
    .line 1481
    move-object/from16 v1, p2

    .line 1482
    .line 1483
    check-cast v1, Ljava/lang/Integer;

    .line 1484
    .line 1485
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1486
    .line 1487
    .line 1488
    const/4 v1, 0x1

    .line 1489
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1490
    .line 1491
    .line 1492
    move-result v1

    .line 1493
    invoke-static {v0, v1}, Ls60/a;->C(Ll2/o;I)V

    .line 1494
    .line 1495
    .line 1496
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1497
    .line 1498
    return-object v0

    .line 1499
    :pswitch_16
    move-object/from16 v0, p1

    .line 1500
    .line 1501
    check-cast v0, Ll2/o;

    .line 1502
    .line 1503
    move-object/from16 v1, p2

    .line 1504
    .line 1505
    check-cast v1, Ljava/lang/Integer;

    .line 1506
    .line 1507
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1508
    .line 1509
    .line 1510
    const/4 v1, 0x1

    .line 1511
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1512
    .line 1513
    .line 1514
    move-result v1

    .line 1515
    invoke-static {v0, v1}, Ls60/a;->y(Ll2/o;I)V

    .line 1516
    .line 1517
    .line 1518
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1519
    .line 1520
    return-object v0

    .line 1521
    :pswitch_17
    move-object/from16 v0, p1

    .line 1522
    .line 1523
    check-cast v0, Ll2/o;

    .line 1524
    .line 1525
    move-object/from16 v1, p2

    .line 1526
    .line 1527
    check-cast v1, Ljava/lang/Integer;

    .line 1528
    .line 1529
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1530
    .line 1531
    .line 1532
    const/4 v1, 0x1

    .line 1533
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1534
    .line 1535
    .line 1536
    move-result v1

    .line 1537
    invoke-static {v0, v1}, Ls60/a;->w(Ll2/o;I)V

    .line 1538
    .line 1539
    .line 1540
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1541
    .line 1542
    return-object v0

    .line 1543
    :pswitch_18
    move-object/from16 v0, p1

    .line 1544
    .line 1545
    check-cast v0, Ll2/o;

    .line 1546
    .line 1547
    move-object/from16 v1, p2

    .line 1548
    .line 1549
    check-cast v1, Ljava/lang/Integer;

    .line 1550
    .line 1551
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1552
    .line 1553
    .line 1554
    const/4 v1, 0x1

    .line 1555
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1556
    .line 1557
    .line 1558
    move-result v1

    .line 1559
    invoke-static {v0, v1}, Ls60/a;->u(Ll2/o;I)V

    .line 1560
    .line 1561
    .line 1562
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1563
    .line 1564
    return-object v0

    .line 1565
    :pswitch_19
    move-object/from16 v0, p1

    .line 1566
    .line 1567
    check-cast v0, Ll2/o;

    .line 1568
    .line 1569
    move-object/from16 v1, p2

    .line 1570
    .line 1571
    check-cast v1, Ljava/lang/Integer;

    .line 1572
    .line 1573
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1574
    .line 1575
    .line 1576
    const/4 v1, 0x1

    .line 1577
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1578
    .line 1579
    .line 1580
    move-result v1

    .line 1581
    invoke-static {v0, v1}, Ls60/a;->s(Ll2/o;I)V

    .line 1582
    .line 1583
    .line 1584
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1585
    .line 1586
    return-object v0

    .line 1587
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1588
    .line 1589
    check-cast v0, Ll2/o;

    .line 1590
    .line 1591
    move-object/from16 v1, p2

    .line 1592
    .line 1593
    check-cast v1, Ljava/lang/Integer;

    .line 1594
    .line 1595
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1596
    .line 1597
    .line 1598
    const/4 v1, 0x1

    .line 1599
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1600
    .line 1601
    .line 1602
    move-result v1

    .line 1603
    invoke-static {v0, v1}, Ls60/a;->q(Ll2/o;I)V

    .line 1604
    .line 1605
    .line 1606
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1607
    .line 1608
    return-object v0

    .line 1609
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1610
    .line 1611
    check-cast v0, Ll2/o;

    .line 1612
    .line 1613
    move-object/from16 v1, p2

    .line 1614
    .line 1615
    check-cast v1, Ljava/lang/Integer;

    .line 1616
    .line 1617
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1618
    .line 1619
    .line 1620
    const/4 v1, 0x1

    .line 1621
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1622
    .line 1623
    .line 1624
    move-result v1

    .line 1625
    invoke-static {v0, v1}, Ls60/a;->o(Ll2/o;I)V

    .line 1626
    .line 1627
    .line 1628
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1629
    .line 1630
    return-object v0

    .line 1631
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1632
    .line 1633
    check-cast v0, Ll2/o;

    .line 1634
    .line 1635
    move-object/from16 v1, p2

    .line 1636
    .line 1637
    check-cast v1, Ljava/lang/Integer;

    .line 1638
    .line 1639
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1640
    .line 1641
    .line 1642
    const/4 v1, 0x1

    .line 1643
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1644
    .line 1645
    .line 1646
    move-result v1

    .line 1647
    invoke-static {v0, v1}, Ls60/j;->g(Ll2/o;I)V

    .line 1648
    .line 1649
    .line 1650
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1651
    .line 1652
    return-object v0

    .line 1653
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
