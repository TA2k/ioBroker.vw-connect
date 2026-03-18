.class public final synthetic Lb71/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;


# direct methods
.method public synthetic constructor <init>(Lx2/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb71/j;->d:I

    iput-object p1, p0, Lb71/j;->e:Lx2/s;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;II)V
    .locals 0

    .line 2
    iput p3, p0, Lb71/j;->d:I

    iput-object p1, p0, Lb71/j;->e:Lx2/s;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb71/j;->d:I

    .line 4
    .line 5
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x2

    .line 9
    const/4 v5, 0x7

    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v7, v0, Lb71/j;->e:Lx2/s;

    .line 12
    .line 13
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    move-object/from16 v0, p1

    .line 19
    .line 20
    check-cast v0, Ll2/o;

    .line 21
    .line 22
    move-object/from16 v1, p2

    .line 23
    .line 24
    check-cast v1, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    invoke-static {v7, v0, v1}, Lkl0/e;->a(Lx2/s;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    return-object v8

    .line 37
    :pswitch_0
    move-object/from16 v0, p1

    .line 38
    .line 39
    check-cast v0, Ll2/o;

    .line 40
    .line 41
    move-object/from16 v1, p2

    .line 42
    .line 43
    check-cast v1, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    invoke-static {v7, v0, v1}, Li91/j0;->e0(Lx2/s;Ll2/o;I)V

    .line 53
    .line 54
    .line 55
    return-object v8

    .line 56
    :pswitch_1
    move-object/from16 v0, p1

    .line 57
    .line 58
    check-cast v0, Ll2/o;

    .line 59
    .line 60
    move-object/from16 v1, p2

    .line 61
    .line 62
    check-cast v1, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    invoke-static {v7, v0, v1}, Li91/j0;->G(Lx2/s;Ll2/o;I)V

    .line 72
    .line 73
    .line 74
    return-object v8

    .line 75
    :pswitch_2
    move-object/from16 v0, p1

    .line 76
    .line 77
    check-cast v0, Ll2/o;

    .line 78
    .line 79
    move-object/from16 v1, p2

    .line 80
    .line 81
    check-cast v1, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    invoke-static {v7, v0, v1}, Li91/j0;->o(Lx2/s;Ll2/o;I)V

    .line 91
    .line 92
    .line 93
    return-object v8

    .line 94
    :pswitch_3
    move-object/from16 v1, p1

    .line 95
    .line 96
    check-cast v1, Ll2/o;

    .line 97
    .line 98
    move-object/from16 v2, p2

    .line 99
    .line 100
    check-cast v2, Ljava/lang/Integer;

    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    and-int/lit8 v5, v2, 0x3

    .line 107
    .line 108
    if-eq v5, v4, :cond_0

    .line 109
    .line 110
    move v3, v6

    .line 111
    :cond_0
    and-int/2addr v2, v6

    .line 112
    move-object v12, v1

    .line 113
    check-cast v12, Ll2/t;

    .line 114
    .line 115
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 116
    .line 117
    .line 118
    move-result v1

    .line 119
    if-eqz v1, :cond_1

    .line 120
    .line 121
    new-instance v9, Lh40/l4;

    .line 122
    .line 123
    invoke-direct {v9, v4}, Lh40/l4;-><init>(I)V

    .line 124
    .line 125
    .line 126
    const/4 v13, 0x0

    .line 127
    const/4 v14, 0x4

    .line 128
    iget-object v10, v0, Lb71/j;->e:Lx2/s;

    .line 129
    .line 130
    const/4 v11, 0x0

    .line 131
    invoke-static/range {v9 .. v14}, Li40/l1;->s0(Lh40/l4;Lx2/s;Ld01/h0;Ll2/o;II)V

    .line 132
    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_1
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 136
    .line 137
    .line 138
    :goto_0
    return-object v8

    .line 139
    :pswitch_4
    move-object/from16 v0, p1

    .line 140
    .line 141
    check-cast v0, Ll2/o;

    .line 142
    .line 143
    move-object/from16 v1, p2

    .line 144
    .line 145
    check-cast v1, Ljava/lang/Integer;

    .line 146
    .line 147
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    invoke-static {v7, v0, v1}, Li40/l1;->k0(Lx2/s;Ll2/o;I)V

    .line 155
    .line 156
    .line 157
    return-object v8

    .line 158
    :pswitch_5
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
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    invoke-static {v7, v0, v1}, Li40/l1;->j0(Lx2/s;Ll2/o;I)V

    .line 174
    .line 175
    .line 176
    return-object v8

    .line 177
    :pswitch_6
    move-object/from16 v0, p1

    .line 178
    .line 179
    check-cast v0, Ll2/o;

    .line 180
    .line 181
    move-object/from16 v1, p2

    .line 182
    .line 183
    check-cast v1, Ljava/lang/Integer;

    .line 184
    .line 185
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 186
    .line 187
    .line 188
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    invoke-static {v7, v0, v1}, Li40/l1;->F(Lx2/s;Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    return-object v8

    .line 196
    :pswitch_7
    move-object/from16 v0, p1

    .line 197
    .line 198
    check-cast v0, Ll2/o;

    .line 199
    .line 200
    move-object/from16 v1, p2

    .line 201
    .line 202
    check-cast v1, Ljava/lang/Integer;

    .line 203
    .line 204
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    invoke-static {v7, v0, v1}, Li40/l1;->F(Lx2/s;Ll2/o;I)V

    .line 212
    .line 213
    .line 214
    return-object v8

    .line 215
    :pswitch_8
    move-object/from16 v0, p1

    .line 216
    .line 217
    check-cast v0, Ll2/o;

    .line 218
    .line 219
    move-object/from16 v1, p2

    .line 220
    .line 221
    check-cast v1, Ljava/lang/Integer;

    .line 222
    .line 223
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 224
    .line 225
    .line 226
    move-result v1

    .line 227
    and-int/lit8 v5, v1, 0x3

    .line 228
    .line 229
    if-eq v5, v4, :cond_2

    .line 230
    .line 231
    move v3, v6

    .line 232
    :cond_2
    and-int/2addr v1, v6

    .line 233
    check-cast v0, Ll2/t;

    .line 234
    .line 235
    invoke-virtual {v0, v1, v3}, Ll2/t;->O(IZ)Z

    .line 236
    .line 237
    .line 238
    move-result v1

    .line 239
    if-eqz v1, :cond_4

    .line 240
    .line 241
    new-instance v9, Lga0/i;

    .line 242
    .line 243
    sget-object v1, Lga0/e;->d:Lga0/e;

    .line 244
    .line 245
    new-instance v1, Lga0/h;

    .line 246
    .line 247
    sget-object v3, Lga0/g;->d:Lga0/g;

    .line 248
    .line 249
    sget-object v4, Lga0/f;->d:Lga0/f;

    .line 250
    .line 251
    invoke-direct {v1, v3, v4}, Lga0/h;-><init>(Lga0/g;Lga0/f;)V

    .line 252
    .line 253
    .line 254
    new-instance v3, Lga0/h;

    .line 255
    .line 256
    sget-object v5, Lga0/g;->g:Lga0/g;

    .line 257
    .line 258
    invoke-direct {v3, v5, v4}, Lga0/h;-><init>(Lga0/g;Lga0/f;)V

    .line 259
    .line 260
    .line 261
    new-instance v4, Lga0/h;

    .line 262
    .line 263
    sget-object v5, Lga0/g;->f:Lga0/g;

    .line 264
    .line 265
    sget-object v6, Lga0/f;->e:Lga0/f;

    .line 266
    .line 267
    invoke-direct {v4, v5, v6}, Lga0/h;-><init>(Lga0/g;Lga0/f;)V

    .line 268
    .line 269
    .line 270
    new-instance v5, Lga0/h;

    .line 271
    .line 272
    sget-object v6, Lga0/g;->e:Lga0/g;

    .line 273
    .line 274
    sget-object v10, Lga0/f;->f:Lga0/f;

    .line 275
    .line 276
    invoke-direct {v5, v6, v10}, Lga0/h;-><init>(Lga0/g;Lga0/f;)V

    .line 277
    .line 278
    .line 279
    filled-new-array {v1, v3, v4, v5}, [Lga0/h;

    .line 280
    .line 281
    .line 282
    move-result-object v1

    .line 283
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    const/16 v3, 0x1e5

    .line 288
    .line 289
    invoke-direct {v9, v1, v3}, Lga0/i;-><init>(Ljava/util/List;I)V

    .line 290
    .line 291
    .line 292
    const/4 v1, 0x3

    .line 293
    invoke-static {v7, v1}, Landroidx/compose/foundation/layout/d;->u(Lx2/s;I)Lx2/s;

    .line 294
    .line 295
    .line 296
    move-result-object v10

    .line 297
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    if-ne v1, v2, :cond_3

    .line 302
    .line 303
    new-instance v1, Lh50/p;

    .line 304
    .line 305
    const/16 v2, 0x14

    .line 306
    .line 307
    invoke-direct {v1, v2}, Lh50/p;-><init>(I)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v0, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    :cond_3
    move-object v11, v1

    .line 314
    check-cast v11, Lay0/a;

    .line 315
    .line 316
    const/16 v17, 0x180

    .line 317
    .line 318
    const/16 v18, 0x78

    .line 319
    .line 320
    const/4 v12, 0x0

    .line 321
    const/4 v13, 0x0

    .line 322
    const/4 v14, 0x0

    .line 323
    const/4 v15, 0x0

    .line 324
    move-object/from16 v16, v0

    .line 325
    .line 326
    invoke-static/range {v9 .. v18}, Lha0/b;->h(Lga0/i;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 327
    .line 328
    .line 329
    goto :goto_1

    .line 330
    :cond_4
    move-object/from16 v16, v0

    .line 331
    .line 332
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 333
    .line 334
    .line 335
    :goto_1
    return-object v8

    .line 336
    :pswitch_9
    move-object/from16 v0, p1

    .line 337
    .line 338
    check-cast v0, Ll2/o;

    .line 339
    .line 340
    move-object/from16 v1, p2

    .line 341
    .line 342
    check-cast v1, Ljava/lang/Integer;

    .line 343
    .line 344
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 345
    .line 346
    .line 347
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 348
    .line 349
    .line 350
    move-result v1

    .line 351
    invoke-static {v7, v0, v1}, Lh90/a;->e(Lx2/s;Ll2/o;I)V

    .line 352
    .line 353
    .line 354
    return-object v8

    .line 355
    :pswitch_a
    move-object/from16 v0, p1

    .line 356
    .line 357
    check-cast v0, Ll2/o;

    .line 358
    .line 359
    move-object/from16 v1, p2

    .line 360
    .line 361
    check-cast v1, Ljava/lang/Integer;

    .line 362
    .line 363
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 364
    .line 365
    .line 366
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 367
    .line 368
    .line 369
    move-result v1

    .line 370
    invoke-static {v7, v0, v1}, Lh90/a;->e(Lx2/s;Ll2/o;I)V

    .line 371
    .line 372
    .line 373
    return-object v8

    .line 374
    :pswitch_b
    move-object/from16 v0, p1

    .line 375
    .line 376
    check-cast v0, Ll2/o;

    .line 377
    .line 378
    move-object/from16 v1, p2

    .line 379
    .line 380
    check-cast v1, Ljava/lang/Integer;

    .line 381
    .line 382
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 383
    .line 384
    .line 385
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 386
    .line 387
    .line 388
    move-result v1

    .line 389
    invoke-static {v7, v0, v1}, Lh90/a;->b(Lx2/s;Ll2/o;I)V

    .line 390
    .line 391
    .line 392
    return-object v8

    .line 393
    :pswitch_c
    move-object/from16 v0, p1

    .line 394
    .line 395
    check-cast v0, Ll2/o;

    .line 396
    .line 397
    move-object/from16 v1, p2

    .line 398
    .line 399
    check-cast v1, Ljava/lang/Integer;

    .line 400
    .line 401
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 402
    .line 403
    .line 404
    invoke-static {v5}, Ll2/b;->x(I)I

    .line 405
    .line 406
    .line 407
    move-result v1

    .line 408
    invoke-static {v7, v0, v1}, Lh90/a;->b(Lx2/s;Ll2/o;I)V

    .line 409
    .line 410
    .line 411
    return-object v8

    .line 412
    :pswitch_d
    move-object/from16 v0, p1

    .line 413
    .line 414
    check-cast v0, Ll2/o;

    .line 415
    .line 416
    move-object/from16 v1, p2

    .line 417
    .line 418
    check-cast v1, Ljava/lang/Integer;

    .line 419
    .line 420
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 421
    .line 422
    .line 423
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 424
    .line 425
    .line 426
    move-result v1

    .line 427
    invoke-static {v7, v0, v1}, Lh10/a;->d(Lx2/s;Ll2/o;I)V

    .line 428
    .line 429
    .line 430
    return-object v8

    .line 431
    :pswitch_e
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
    and-int/lit8 v5, v1, 0x3

    .line 444
    .line 445
    if-eq v5, v4, :cond_5

    .line 446
    .line 447
    move v5, v6

    .line 448
    goto :goto_2

    .line 449
    :cond_5
    move v5, v3

    .line 450
    :goto_2
    and-int/2addr v1, v6

    .line 451
    check-cast v0, Ll2/t;

    .line 452
    .line 453
    invoke-virtual {v0, v1, v5}, Ll2/t;->O(IZ)Z

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    if-eqz v1, :cond_7

    .line 458
    .line 459
    new-instance v1, Lg10/a;

    .line 460
    .line 461
    const/4 v5, 0x0

    .line 462
    const-string v6, "Auto Skoda"

    .line 463
    .line 464
    invoke-direct {v1, v5, v3, v6}, Lg10/a;-><init>(Lql0/g;ZLjava/lang/String;)V

    .line 465
    .line 466
    .line 467
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object v3

    .line 471
    if-ne v3, v2, :cond_6

    .line 472
    .line 473
    new-instance v3, Lz81/g;

    .line 474
    .line 475
    invoke-direct {v3, v4}, Lz81/g;-><init>(I)V

    .line 476
    .line 477
    .line 478
    invoke-virtual {v0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 479
    .line 480
    .line 481
    :cond_6
    check-cast v3, Lay0/a;

    .line 482
    .line 483
    const/16 v2, 0x30

    .line 484
    .line 485
    invoke-static {v1, v3, v7, v0, v2}, Lh10/a;->c(Lg10/a;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 486
    .line 487
    .line 488
    goto :goto_3

    .line 489
    :cond_7
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 490
    .line 491
    .line 492
    :goto_3
    return-object v8

    .line 493
    :pswitch_f
    move-object/from16 v0, p1

    .line 494
    .line 495
    check-cast v0, Ll2/o;

    .line 496
    .line 497
    move-object/from16 v1, p2

    .line 498
    .line 499
    check-cast v1, Ljava/lang/Integer;

    .line 500
    .line 501
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 502
    .line 503
    .line 504
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 505
    .line 506
    .line 507
    move-result v1

    .line 508
    invoke-static {v7, v0, v1}, Lh10/a;->b(Lx2/s;Ll2/o;I)V

    .line 509
    .line 510
    .line 511
    return-object v8

    .line 512
    :pswitch_10
    move-object/from16 v0, p1

    .line 513
    .line 514
    check-cast v0, Ll2/o;

    .line 515
    .line 516
    move-object/from16 v1, p2

    .line 517
    .line 518
    check-cast v1, Ljava/lang/Integer;

    .line 519
    .line 520
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 521
    .line 522
    .line 523
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 524
    .line 525
    .line 526
    move-result v1

    .line 527
    invoke-static {v7, v0, v1}, Lh10/a;->b(Lx2/s;Ll2/o;I)V

    .line 528
    .line 529
    .line 530
    return-object v8

    .line 531
    :pswitch_11
    move-object/from16 v0, p1

    .line 532
    .line 533
    check-cast v0, Ll2/o;

    .line 534
    .line 535
    move-object/from16 v1, p2

    .line 536
    .line 537
    check-cast v1, Ljava/lang/Integer;

    .line 538
    .line 539
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 540
    .line 541
    .line 542
    const/16 v1, 0x37

    .line 543
    .line 544
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 545
    .line 546
    .line 547
    move-result v1

    .line 548
    invoke-static {v7, v0, v1}, Ldl0/e;->a(Lx2/s;Ll2/o;I)V

    .line 549
    .line 550
    .line 551
    return-object v8

    .line 552
    :pswitch_12
    move-object/from16 v0, p1

    .line 553
    .line 554
    check-cast v0, Ll2/o;

    .line 555
    .line 556
    move-object/from16 v1, p2

    .line 557
    .line 558
    check-cast v1, Ljava/lang/Integer;

    .line 559
    .line 560
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 561
    .line 562
    .line 563
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 564
    .line 565
    .line 566
    move-result v1

    .line 567
    invoke-static {v7, v0, v1}, Ld80/b;->G(Lx2/s;Ll2/o;I)V

    .line 568
    .line 569
    .line 570
    return-object v8

    .line 571
    :pswitch_13
    move-object/from16 v0, p1

    .line 572
    .line 573
    check-cast v0, Ll2/o;

    .line 574
    .line 575
    move-object/from16 v1, p2

    .line 576
    .line 577
    check-cast v1, Ljava/lang/Integer;

    .line 578
    .line 579
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 580
    .line 581
    .line 582
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 583
    .line 584
    .line 585
    move-result v1

    .line 586
    invoke-static {v7, v0, v1}, Ld80/b;->C(Lx2/s;Ll2/o;I)V

    .line 587
    .line 588
    .line 589
    return-object v8

    .line 590
    :pswitch_14
    move-object/from16 v0, p1

    .line 591
    .line 592
    check-cast v0, Ll2/o;

    .line 593
    .line 594
    move-object/from16 v1, p2

    .line 595
    .line 596
    check-cast v1, Ljava/lang/Integer;

    .line 597
    .line 598
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 599
    .line 600
    .line 601
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 602
    .line 603
    .line 604
    move-result v1

    .line 605
    invoke-static {v7, v0, v1}, Ld80/b;->v(Lx2/s;Ll2/o;I)V

    .line 606
    .line 607
    .line 608
    return-object v8

    .line 609
    :pswitch_15
    move-object/from16 v0, p1

    .line 610
    .line 611
    check-cast v0, Ll2/o;

    .line 612
    .line 613
    move-object/from16 v1, p2

    .line 614
    .line 615
    check-cast v1, Ljava/lang/Integer;

    .line 616
    .line 617
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 618
    .line 619
    .line 620
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 621
    .line 622
    .line 623
    move-result v1

    .line 624
    invoke-static {v7, v0, v1}, Ld80/b;->h(Lx2/s;Ll2/o;I)V

    .line 625
    .line 626
    .line 627
    return-object v8

    .line 628
    :pswitch_16
    move-object/from16 v0, p1

    .line 629
    .line 630
    check-cast v0, Ll2/o;

    .line 631
    .line 632
    move-object/from16 v1, p2

    .line 633
    .line 634
    check-cast v1, Ljava/lang/Integer;

    .line 635
    .line 636
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 637
    .line 638
    .line 639
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 640
    .line 641
    .line 642
    move-result v1

    .line 643
    invoke-static {v7, v0, v1}, Ljp/tf;->d(Lx2/s;Ll2/o;I)V

    .line 644
    .line 645
    .line 646
    return-object v8

    .line 647
    :pswitch_17
    move-object/from16 v1, p1

    .line 648
    .line 649
    check-cast v1, Ll2/o;

    .line 650
    .line 651
    move-object/from16 v2, p2

    .line 652
    .line 653
    check-cast v2, Ljava/lang/Integer;

    .line 654
    .line 655
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 656
    .line 657
    .line 658
    move-result v2

    .line 659
    and-int/lit8 v5, v2, 0x3

    .line 660
    .line 661
    if-eq v5, v4, :cond_8

    .line 662
    .line 663
    move v3, v6

    .line 664
    :cond_8
    and-int/2addr v2, v6

    .line 665
    move-object v12, v1

    .line 666
    check-cast v12, Ll2/t;

    .line 667
    .line 668
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 669
    .line 670
    .line 671
    move-result v1

    .line 672
    if-eqz v1, :cond_9

    .line 673
    .line 674
    sget-object v1, Llf0/i;->j:Llf0/i;

    .line 675
    .line 676
    sget-object v2, Lvf0/k;->d:Lvf0/k;

    .line 677
    .line 678
    sget-object v2, Lvf0/l;->d:Lvf0/l;

    .line 679
    .line 680
    new-instance v9, Lc70/d;

    .line 681
    .line 682
    const-string v2, "Range"

    .line 683
    .line 684
    const/16 v3, 0x55d0

    .line 685
    .line 686
    invoke-direct {v9, v3, v2, v1}, Lc70/d;-><init>(ILjava/lang/String;Llf0/i;)V

    .line 687
    .line 688
    .line 689
    const/4 v13, 0x0

    .line 690
    const/4 v14, 0x4

    .line 691
    iget-object v10, v0, Lb71/j;->e:Lx2/s;

    .line 692
    .line 693
    const/4 v11, 0x0

    .line 694
    invoke-static/range {v9 .. v14}, Ljp/sf;->c(Lc70/d;Lx2/s;Lay0/a;Ll2/o;II)V

    .line 695
    .line 696
    .line 697
    goto :goto_4

    .line 698
    :cond_9
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 699
    .line 700
    .line 701
    :goto_4
    return-object v8

    .line 702
    :pswitch_18
    move-object/from16 v0, p1

    .line 703
    .line 704
    check-cast v0, Ll2/o;

    .line 705
    .line 706
    move-object/from16 v1, p2

    .line 707
    .line 708
    check-cast v1, Ljava/lang/Integer;

    .line 709
    .line 710
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 711
    .line 712
    .line 713
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 714
    .line 715
    .line 716
    move-result v1

    .line 717
    invoke-static {v7, v0, v1}, Ld00/o;->r(Lx2/s;Ll2/o;I)V

    .line 718
    .line 719
    .line 720
    return-object v8

    .line 721
    :pswitch_19
    move-object/from16 v0, p1

    .line 722
    .line 723
    check-cast v0, Ll2/o;

    .line 724
    .line 725
    move-object/from16 v1, p2

    .line 726
    .line 727
    check-cast v1, Ljava/lang/Integer;

    .line 728
    .line 729
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 730
    .line 731
    .line 732
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 733
    .line 734
    .line 735
    move-result v1

    .line 736
    invoke-static {v7, v0, v1}, Ld00/o;->p(Lx2/s;Ll2/o;I)V

    .line 737
    .line 738
    .line 739
    return-object v8

    .line 740
    :pswitch_1a
    move-object/from16 v0, p1

    .line 741
    .line 742
    check-cast v0, Ll2/o;

    .line 743
    .line 744
    move-object/from16 v1, p2

    .line 745
    .line 746
    check-cast v1, Ljava/lang/Integer;

    .line 747
    .line 748
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 749
    .line 750
    .line 751
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 752
    .line 753
    .line 754
    move-result v1

    .line 755
    invoke-static {v7, v0, v1}, Ld00/o;->n(Lx2/s;Ll2/o;I)V

    .line 756
    .line 757
    .line 758
    return-object v8

    .line 759
    :pswitch_1b
    move-object/from16 v0, p1

    .line 760
    .line 761
    check-cast v0, Ll2/o;

    .line 762
    .line 763
    move-object/from16 v1, p2

    .line 764
    .line 765
    check-cast v1, Ljava/lang/Integer;

    .line 766
    .line 767
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 768
    .line 769
    .line 770
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 771
    .line 772
    .line 773
    move-result v1

    .line 774
    invoke-static {v7, v0, v1}, Ld00/o;->l(Lx2/s;Ll2/o;I)V

    .line 775
    .line 776
    .line 777
    return-object v8

    .line 778
    :pswitch_1c
    move-object/from16 v0, p1

    .line 779
    .line 780
    check-cast v0, Ll2/o;

    .line 781
    .line 782
    move-object/from16 v1, p2

    .line 783
    .line 784
    check-cast v1, Ljava/lang/Integer;

    .line 785
    .line 786
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 787
    .line 788
    .line 789
    invoke-static {v6}, Ll2/b;->x(I)I

    .line 790
    .line 791
    .line 792
    move-result v1

    .line 793
    invoke-static {v7, v0, v1}, Lb71/a;->b(Lx2/s;Ll2/o;I)V

    .line 794
    .line 795
    .line 796
    return-object v8

    .line 797
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
