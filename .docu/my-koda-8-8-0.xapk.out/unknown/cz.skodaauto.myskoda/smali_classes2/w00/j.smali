.class public final synthetic Lw00/j;
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
    iput p1, p0, Lw00/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Lw00/j;->d:I

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
    iget v0, v0, Lw00/j;->d:I

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
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v0, v1}, Lx40/a;->m(Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object v0

    .line 30
    :pswitch_0
    move-object/from16 v0, p1

    .line 31
    .line 32
    check-cast v0, Ll2/o;

    .line 33
    .line 34
    move-object/from16 v1, p2

    .line 35
    .line 36
    check-cast v1, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 v1, 0x1

    .line 42
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-static {v0, v1}, Lx40/d;->c(Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_1
    move-object/from16 v0, p1

    .line 51
    .line 52
    check-cast v0, Ll2/o;

    .line 53
    .line 54
    move-object/from16 v1, p2

    .line 55
    .line 56
    check-cast v1, Ljava/lang/Integer;

    .line 57
    .line 58
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    and-int/lit8 v2, v1, 0x3

    .line 63
    .line 64
    const/4 v3, 0x2

    .line 65
    const/4 v4, 0x1

    .line 66
    if-eq v2, v3, :cond_0

    .line 67
    .line 68
    move v2, v4

    .line 69
    goto :goto_1

    .line 70
    :cond_0
    const/4 v2, 0x0

    .line 71
    :goto_1
    and-int/2addr v1, v4

    .line 72
    check-cast v0, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    if-eqz v1, :cond_1

    .line 79
    .line 80
    const/16 v1, 0x14

    .line 81
    .line 82
    int-to-float v1, v1

    .line 83
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 84
    .line 85
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    const/16 v2, 0x18

    .line 90
    .line 91
    int-to-float v2, v2

    .line 92
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 97
    .line 98
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    check-cast v1, Lj91/f;

    .line 103
    .line 104
    invoke-virtual {v1}, Lj91/f;->m()Lg4/p0;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    new-instance v14, Lr4/k;

    .line 109
    .line 110
    const/4 v1, 0x3

    .line 111
    invoke-direct {v14, v1}, Lr4/k;-><init>(I)V

    .line 112
    .line 113
    .line 114
    const/16 v23, 0x0

    .line 115
    .line 116
    const v24, 0xfbf8

    .line 117
    .line 118
    .line 119
    const-string v3, ":"

    .line 120
    .line 121
    const-wide/16 v6, 0x0

    .line 122
    .line 123
    const-wide/16 v8, 0x0

    .line 124
    .line 125
    const/4 v10, 0x0

    .line 126
    const-wide/16 v11, 0x0

    .line 127
    .line 128
    const/4 v13, 0x0

    .line 129
    const-wide/16 v15, 0x0

    .line 130
    .line 131
    const/16 v17, 0x0

    .line 132
    .line 133
    const/16 v18, 0x0

    .line 134
    .line 135
    const/16 v19, 0x0

    .line 136
    .line 137
    const/16 v20, 0x0

    .line 138
    .line 139
    const/16 v22, 0x186

    .line 140
    .line 141
    move-object/from16 v21, v0

    .line 142
    .line 143
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 144
    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_1
    move-object/from16 v21, v0

    .line 148
    .line 149
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 150
    .line 151
    .line 152
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 153
    .line 154
    return-object v0

    .line 155
    :pswitch_2
    move-object/from16 v0, p1

    .line 156
    .line 157
    check-cast v0, Ll2/o;

    .line 158
    .line 159
    move-object/from16 v1, p2

    .line 160
    .line 161
    check-cast v1, Ljava/lang/Integer;

    .line 162
    .line 163
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    const/4 v1, 0x1

    .line 167
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    invoke-static {v0, v1}, Lx30/b;->L(Ll2/o;I)V

    .line 172
    .line 173
    .line 174
    goto/16 :goto_0

    .line 175
    .line 176
    :pswitch_3
    move-object/from16 v0, p1

    .line 177
    .line 178
    check-cast v0, Ll2/o;

    .line 179
    .line 180
    move-object/from16 v1, p2

    .line 181
    .line 182
    check-cast v1, Ljava/lang/Integer;

    .line 183
    .line 184
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 185
    .line 186
    .line 187
    const/4 v1, 0x1

    .line 188
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    invoke-static {v0, v1}, Lx30/b;->J(Ll2/o;I)V

    .line 193
    .line 194
    .line 195
    goto/16 :goto_0

    .line 196
    .line 197
    :pswitch_4
    move-object/from16 v0, p1

    .line 198
    .line 199
    check-cast v0, Ll2/o;

    .line 200
    .line 201
    move-object/from16 v1, p2

    .line 202
    .line 203
    check-cast v1, Ljava/lang/Integer;

    .line 204
    .line 205
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    const/4 v1, 0x1

    .line 209
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 210
    .line 211
    .line 212
    move-result v1

    .line 213
    invoke-static {v0, v1}, Lx30/b;->H(Ll2/o;I)V

    .line 214
    .line 215
    .line 216
    goto/16 :goto_0

    .line 217
    .line 218
    :pswitch_5
    move-object/from16 v0, p1

    .line 219
    .line 220
    check-cast v0, Ll2/o;

    .line 221
    .line 222
    move-object/from16 v1, p2

    .line 223
    .line 224
    check-cast v1, Ljava/lang/Integer;

    .line 225
    .line 226
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    const/4 v1, 0x1

    .line 230
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 231
    .line 232
    .line 233
    move-result v1

    .line 234
    invoke-static {v0, v1}, Lx30/b;->F(Ll2/o;I)V

    .line 235
    .line 236
    .line 237
    goto/16 :goto_0

    .line 238
    .line 239
    :pswitch_6
    move-object/from16 v0, p1

    .line 240
    .line 241
    check-cast v0, Ll2/o;

    .line 242
    .line 243
    move-object/from16 v1, p2

    .line 244
    .line 245
    check-cast v1, Ljava/lang/Integer;

    .line 246
    .line 247
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 248
    .line 249
    .line 250
    const/4 v1, 0x1

    .line 251
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 252
    .line 253
    .line 254
    move-result v1

    .line 255
    invoke-static {v0, v1}, Lx30/b;->E(Ll2/o;I)V

    .line 256
    .line 257
    .line 258
    goto/16 :goto_0

    .line 259
    .line 260
    :pswitch_7
    move-object/from16 v0, p1

    .line 261
    .line 262
    check-cast v0, Ll2/o;

    .line 263
    .line 264
    move-object/from16 v1, p2

    .line 265
    .line 266
    check-cast v1, Ljava/lang/Integer;

    .line 267
    .line 268
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 269
    .line 270
    .line 271
    const/4 v1, 0x1

    .line 272
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 273
    .line 274
    .line 275
    move-result v1

    .line 276
    invoke-static {v0, v1}, Lx30/b;->A(Ll2/o;I)V

    .line 277
    .line 278
    .line 279
    goto/16 :goto_0

    .line 280
    .line 281
    :pswitch_8
    move-object/from16 v0, p1

    .line 282
    .line 283
    check-cast v0, Ll2/o;

    .line 284
    .line 285
    move-object/from16 v1, p2

    .line 286
    .line 287
    check-cast v1, Ljava/lang/Integer;

    .line 288
    .line 289
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 290
    .line 291
    .line 292
    const/4 v1, 0x1

    .line 293
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 294
    .line 295
    .line 296
    move-result v1

    .line 297
    invoke-static {v0, v1}, Lx30/b;->y(Ll2/o;I)V

    .line 298
    .line 299
    .line 300
    goto/16 :goto_0

    .line 301
    .line 302
    :pswitch_9
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
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 311
    .line 312
    .line 313
    const/4 v1, 0x1

    .line 314
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 315
    .line 316
    .line 317
    move-result v1

    .line 318
    invoke-static {v0, v1}, Lx30/b;->t(Ll2/o;I)V

    .line 319
    .line 320
    .line 321
    goto/16 :goto_0

    .line 322
    .line 323
    :pswitch_a
    move-object/from16 v0, p1

    .line 324
    .line 325
    check-cast v0, Ll2/o;

    .line 326
    .line 327
    move-object/from16 v1, p2

    .line 328
    .line 329
    check-cast v1, Ljava/lang/Integer;

    .line 330
    .line 331
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 332
    .line 333
    .line 334
    const/4 v1, 0x1

    .line 335
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 336
    .line 337
    .line 338
    move-result v1

    .line 339
    invoke-static {v0, v1}, Lx30/b;->r(Ll2/o;I)V

    .line 340
    .line 341
    .line 342
    goto/16 :goto_0

    .line 343
    .line 344
    :pswitch_b
    move-object/from16 v0, p1

    .line 345
    .line 346
    check-cast v0, Ll2/o;

    .line 347
    .line 348
    move-object/from16 v1, p2

    .line 349
    .line 350
    check-cast v1, Ljava/lang/Integer;

    .line 351
    .line 352
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 353
    .line 354
    .line 355
    const/4 v1, 0x1

    .line 356
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 357
    .line 358
    .line 359
    move-result v1

    .line 360
    invoke-static {v0, v1}, Lx30/b;->p(Ll2/o;I)V

    .line 361
    .line 362
    .line 363
    goto/16 :goto_0

    .line 364
    .line 365
    :pswitch_c
    move-object/from16 v0, p1

    .line 366
    .line 367
    check-cast v0, Ll2/o;

    .line 368
    .line 369
    move-object/from16 v1, p2

    .line 370
    .line 371
    check-cast v1, Ljava/lang/Integer;

    .line 372
    .line 373
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 374
    .line 375
    .line 376
    const/4 v1, 0x1

    .line 377
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 378
    .line 379
    .line 380
    move-result v1

    .line 381
    invoke-static {v0, v1}, Lx30/b;->n(Ll2/o;I)V

    .line 382
    .line 383
    .line 384
    goto/16 :goto_0

    .line 385
    .line 386
    :pswitch_d
    move-object/from16 v0, p1

    .line 387
    .line 388
    check-cast v0, Ll2/o;

    .line 389
    .line 390
    move-object/from16 v1, p2

    .line 391
    .line 392
    check-cast v1, Ljava/lang/Integer;

    .line 393
    .line 394
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 395
    .line 396
    .line 397
    const/4 v1, 0x1

    .line 398
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    invoke-static {v0, v1}, Lx30/b;->k(Ll2/o;I)V

    .line 403
    .line 404
    .line 405
    goto/16 :goto_0

    .line 406
    .line 407
    :pswitch_e
    move-object/from16 v0, p1

    .line 408
    .line 409
    check-cast v0, Ll2/o;

    .line 410
    .line 411
    move-object/from16 v1, p2

    .line 412
    .line 413
    check-cast v1, Ljava/lang/Integer;

    .line 414
    .line 415
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 416
    .line 417
    .line 418
    const/4 v1, 0x1

    .line 419
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 420
    .line 421
    .line 422
    move-result v1

    .line 423
    invoke-static {v0, v1}, Lx30/b;->j(Ll2/o;I)V

    .line 424
    .line 425
    .line 426
    goto/16 :goto_0

    .line 427
    .line 428
    :pswitch_f
    move-object/from16 v0, p1

    .line 429
    .line 430
    check-cast v0, Ll2/o;

    .line 431
    .line 432
    move-object/from16 v1, p2

    .line 433
    .line 434
    check-cast v1, Ljava/lang/Integer;

    .line 435
    .line 436
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 437
    .line 438
    .line 439
    const/4 v1, 0x1

    .line 440
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 441
    .line 442
    .line 443
    move-result v1

    .line 444
    invoke-static {v0, v1}, Lx30/b;->f(Ll2/o;I)V

    .line 445
    .line 446
    .line 447
    goto/16 :goto_0

    .line 448
    .line 449
    :pswitch_10
    move-object/from16 v0, p1

    .line 450
    .line 451
    check-cast v0, Ll2/o;

    .line 452
    .line 453
    move-object/from16 v1, p2

    .line 454
    .line 455
    check-cast v1, Ljava/lang/Integer;

    .line 456
    .line 457
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 458
    .line 459
    .line 460
    const/4 v1, 0x1

    .line 461
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 462
    .line 463
    .line 464
    move-result v1

    .line 465
    invoke-static {v0, v1}, Lx30/b;->e(Ll2/o;I)V

    .line 466
    .line 467
    .line 468
    goto/16 :goto_0

    .line 469
    .line 470
    :pswitch_11
    move-object/from16 v0, p1

    .line 471
    .line 472
    check-cast v0, Ll2/o;

    .line 473
    .line 474
    move-object/from16 v1, p2

    .line 475
    .line 476
    check-cast v1, Ljava/lang/Integer;

    .line 477
    .line 478
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 479
    .line 480
    .line 481
    const/4 v1, 0x1

    .line 482
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 483
    .line 484
    .line 485
    move-result v1

    .line 486
    invoke-static {v0, v1}, Lx30/b;->b(Ll2/o;I)V

    .line 487
    .line 488
    .line 489
    goto/16 :goto_0

    .line 490
    .line 491
    :pswitch_12
    move-object/from16 v0, p1

    .line 492
    .line 493
    check-cast v0, Ll2/o;

    .line 494
    .line 495
    move-object/from16 v1, p2

    .line 496
    .line 497
    check-cast v1, Ljava/lang/Integer;

    .line 498
    .line 499
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 500
    .line 501
    .line 502
    move-result v1

    .line 503
    and-int/lit8 v2, v1, 0x3

    .line 504
    .line 505
    const/4 v3, 0x2

    .line 506
    const/4 v4, 0x1

    .line 507
    if-eq v2, v3, :cond_2

    .line 508
    .line 509
    move v2, v4

    .line 510
    goto :goto_3

    .line 511
    :cond_2
    const/4 v2, 0x0

    .line 512
    :goto_3
    and-int/2addr v1, v4

    .line 513
    move-object v9, v0

    .line 514
    check-cast v9, Ll2/t;

    .line 515
    .line 516
    invoke-virtual {v9, v1, v2}, Ll2/t;->O(IZ)Z

    .line 517
    .line 518
    .line 519
    move-result v0

    .line 520
    if-eqz v0, :cond_3

    .line 521
    .line 522
    new-instance v3, Lw30/a;

    .line 523
    .line 524
    const/16 v0, 0x203

    .line 525
    .line 526
    invoke-direct {v3, v0}, Lw30/a;-><init>(I)V

    .line 527
    .line 528
    .line 529
    const/4 v10, 0x0

    .line 530
    const/16 v11, 0x3e

    .line 531
    .line 532
    const/4 v4, 0x0

    .line 533
    const/4 v5, 0x0

    .line 534
    const/4 v6, 0x0

    .line 535
    const/4 v7, 0x0

    .line 536
    const/4 v8, 0x0

    .line 537
    invoke-static/range {v3 .. v11}, Lx30/b;->d(Lw30/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 538
    .line 539
    .line 540
    goto :goto_4

    .line 541
    :cond_3
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 542
    .line 543
    .line 544
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 545
    .line 546
    return-object v0

    .line 547
    :pswitch_13
    move-object/from16 v0, p1

    .line 548
    .line 549
    check-cast v0, Ll2/o;

    .line 550
    .line 551
    move-object/from16 v1, p2

    .line 552
    .line 553
    check-cast v1, Ljava/lang/Integer;

    .line 554
    .line 555
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 556
    .line 557
    .line 558
    const/4 v1, 0x1

    .line 559
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 560
    .line 561
    .line 562
    move-result v1

    .line 563
    invoke-static {v0, v1}, Lwk/a;->r(Ll2/o;I)V

    .line 564
    .line 565
    .line 566
    goto/16 :goto_0

    .line 567
    .line 568
    :pswitch_14
    move-object/from16 v0, p1

    .line 569
    .line 570
    check-cast v0, Ll2/o;

    .line 571
    .line 572
    move-object/from16 v1, p2

    .line 573
    .line 574
    check-cast v1, Ljava/lang/Integer;

    .line 575
    .line 576
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 577
    .line 578
    .line 579
    move-result v1

    .line 580
    and-int/lit8 v2, v1, 0x3

    .line 581
    .line 582
    const/4 v3, 0x2

    .line 583
    const/4 v4, 0x0

    .line 584
    const/4 v5, 0x1

    .line 585
    if-eq v2, v3, :cond_4

    .line 586
    .line 587
    move v2, v5

    .line 588
    goto :goto_5

    .line 589
    :cond_4
    move v2, v4

    .line 590
    :goto_5
    and-int/2addr v1, v5

    .line 591
    check-cast v0, Ll2/t;

    .line 592
    .line 593
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 594
    .line 595
    .line 596
    move-result v1

    .line 597
    if-eqz v1, :cond_5

    .line 598
    .line 599
    const/4 v1, 0x6

    .line 600
    invoke-static {v1, v4, v0, v5}, Ldk/b;->e(IILl2/o;Z)V

    .line 601
    .line 602
    .line 603
    goto :goto_6

    .line 604
    :cond_5
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 605
    .line 606
    .line 607
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 608
    .line 609
    return-object v0

    .line 610
    :pswitch_15
    move-object/from16 v0, p1

    .line 611
    .line 612
    check-cast v0, Ll2/o;

    .line 613
    .line 614
    move-object/from16 v1, p2

    .line 615
    .line 616
    check-cast v1, Ljava/lang/Integer;

    .line 617
    .line 618
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 619
    .line 620
    .line 621
    move-result v1

    .line 622
    and-int/lit8 v2, v1, 0x3

    .line 623
    .line 624
    const/4 v3, 0x1

    .line 625
    const/4 v4, 0x2

    .line 626
    if-eq v2, v4, :cond_6

    .line 627
    .line 628
    move v2, v3

    .line 629
    goto :goto_7

    .line 630
    :cond_6
    const/4 v2, 0x0

    .line 631
    :goto_7
    and-int/2addr v1, v3

    .line 632
    move-object v9, v0

    .line 633
    check-cast v9, Ll2/t;

    .line 634
    .line 635
    invoke-virtual {v9, v1, v2}, Ll2/t;->O(IZ)Z

    .line 636
    .line 637
    .line 638
    move-result v0

    .line 639
    if-eqz v0, :cond_7

    .line 640
    .line 641
    new-instance v7, Li91/x2;

    .line 642
    .line 643
    invoke-static {v9}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 644
    .line 645
    .line 646
    move-result-object v0

    .line 647
    invoke-direct {v7, v0, v4}, Li91/x2;-><init>(Lay0/a;I)V

    .line 648
    .line 649
    .line 650
    const/4 v10, 0x6

    .line 651
    const/16 v11, 0xa

    .line 652
    .line 653
    const-string v5, ""

    .line 654
    .line 655
    const/4 v6, 0x0

    .line 656
    const/4 v8, 0x0

    .line 657
    invoke-static/range {v5 .. v11}, Ldk/l;->a(Ljava/lang/String;Lx2/s;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;Ll2/o;II)V

    .line 658
    .line 659
    .line 660
    goto :goto_8

    .line 661
    :cond_7
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 662
    .line 663
    .line 664
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 665
    .line 666
    return-object v0

    .line 667
    :pswitch_16
    move-object/from16 v0, p1

    .line 668
    .line 669
    check-cast v0, Ll2/o;

    .line 670
    .line 671
    move-object/from16 v1, p2

    .line 672
    .line 673
    check-cast v1, Ljava/lang/Integer;

    .line 674
    .line 675
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 676
    .line 677
    .line 678
    move-result v1

    .line 679
    and-int/lit8 v2, v1, 0x3

    .line 680
    .line 681
    const/4 v3, 0x2

    .line 682
    const/4 v4, 0x0

    .line 683
    const/4 v5, 0x1

    .line 684
    if-eq v2, v3, :cond_8

    .line 685
    .line 686
    move v2, v5

    .line 687
    goto :goto_9

    .line 688
    :cond_8
    move v2, v4

    .line 689
    :goto_9
    and-int/2addr v1, v5

    .line 690
    check-cast v0, Ll2/t;

    .line 691
    .line 692
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 693
    .line 694
    .line 695
    move-result v1

    .line 696
    if-eqz v1, :cond_9

    .line 697
    .line 698
    const/4 v1, 0x6

    .line 699
    invoke-static {v1, v4, v0, v5}, Ldk/b;->e(IILl2/o;Z)V

    .line 700
    .line 701
    .line 702
    goto :goto_a

    .line 703
    :cond_9
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 704
    .line 705
    .line 706
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 707
    .line 708
    return-object v0

    .line 709
    :pswitch_17
    move-object/from16 v0, p1

    .line 710
    .line 711
    check-cast v0, Ll2/o;

    .line 712
    .line 713
    move-object/from16 v1, p2

    .line 714
    .line 715
    check-cast v1, Ljava/lang/Integer;

    .line 716
    .line 717
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 718
    .line 719
    .line 720
    const/4 v1, 0x1

    .line 721
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 722
    .line 723
    .line 724
    move-result v1

    .line 725
    invoke-static {v0, v1}, Lwj/c;->c(Ll2/o;I)V

    .line 726
    .line 727
    .line 728
    goto/16 :goto_0

    .line 729
    .line 730
    :pswitch_18
    move-object/from16 v0, p1

    .line 731
    .line 732
    check-cast v0, Ll2/o;

    .line 733
    .line 734
    move-object/from16 v1, p2

    .line 735
    .line 736
    check-cast v1, Ljava/lang/Integer;

    .line 737
    .line 738
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 739
    .line 740
    .line 741
    const/4 v1, 0x1

    .line 742
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 743
    .line 744
    .line 745
    move-result v1

    .line 746
    invoke-static {v0, v1}, Lwj/c;->d(Ll2/o;I)V

    .line 747
    .line 748
    .line 749
    goto/16 :goto_0

    .line 750
    .line 751
    :pswitch_19
    move-object/from16 v0, p1

    .line 752
    .line 753
    check-cast v0, Ll2/o;

    .line 754
    .line 755
    move-object/from16 v1, p2

    .line 756
    .line 757
    check-cast v1, Ljava/lang/Integer;

    .line 758
    .line 759
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 760
    .line 761
    .line 762
    const/4 v1, 0x1

    .line 763
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 764
    .line 765
    .line 766
    move-result v1

    .line 767
    invoke-static {v0, v1}, Llp/ed;->a(Ll2/o;I)V

    .line 768
    .line 769
    .line 770
    goto/16 :goto_0

    .line 771
    .line 772
    :pswitch_1a
    move-object/from16 v0, p1

    .line 773
    .line 774
    check-cast v0, Ll2/o;

    .line 775
    .line 776
    move-object/from16 v1, p2

    .line 777
    .line 778
    check-cast v1, Ljava/lang/Integer;

    .line 779
    .line 780
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 781
    .line 782
    .line 783
    const/4 v1, 0x7

    .line 784
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 785
    .line 786
    .line 787
    move-result v1

    .line 788
    invoke-static {v0, v1}, Lw00/a;->o(Ll2/o;I)V

    .line 789
    .line 790
    .line 791
    goto/16 :goto_0

    .line 792
    .line 793
    :pswitch_1b
    move-object/from16 v0, p1

    .line 794
    .line 795
    check-cast v0, Ll2/o;

    .line 796
    .line 797
    move-object/from16 v1, p2

    .line 798
    .line 799
    check-cast v1, Ljava/lang/Integer;

    .line 800
    .line 801
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 802
    .line 803
    .line 804
    const/4 v1, 0x7

    .line 805
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 806
    .line 807
    .line 808
    move-result v1

    .line 809
    invoke-static {v0, v1}, Lw00/a;->i(Ll2/o;I)V

    .line 810
    .line 811
    .line 812
    goto/16 :goto_0

    .line 813
    .line 814
    :pswitch_1c
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
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 823
    .line 824
    .line 825
    const/4 v1, 0x7

    .line 826
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 827
    .line 828
    .line 829
    move-result v1

    .line 830
    invoke-static {v0, v1}, Lw00/a;->b(Ll2/o;I)V

    .line 831
    .line 832
    .line 833
    goto/16 :goto_0

    .line 834
    .line 835
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
