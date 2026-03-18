.class public final Ldl/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldl/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ldl/i;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p2, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Ldl/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    check-cast p3, Ll2/o;

    .line 15
    .line 16
    check-cast p4, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p4

    .line 22
    and-int/lit8 v0, p4, 0x6

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    move-object v0, p3

    .line 27
    check-cast v0, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_0

    .line 34
    .line 35
    const/4 p1, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p1, 0x2

    .line 38
    :goto_0
    or-int/2addr p1, p4

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move p1, p4

    .line 41
    :goto_1
    and-int/lit8 p4, p4, 0x30

    .line 42
    .line 43
    if-nez p4, :cond_3

    .line 44
    .line 45
    move-object p4, p3

    .line 46
    check-cast p4, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 49
    .line 50
    .line 51
    move-result p4

    .line 52
    if-eqz p4, :cond_2

    .line 53
    .line 54
    const/16 p4, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 p4, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr p1, p4

    .line 60
    :cond_3
    and-int/lit16 p4, p1, 0x93

    .line 61
    .line 62
    const/16 v0, 0x92

    .line 63
    .line 64
    const/4 v1, 0x0

    .line 65
    if-eq p4, v0, :cond_4

    .line 66
    .line 67
    const/4 p4, 0x1

    .line 68
    goto :goto_3

    .line 69
    :cond_4
    move p4, v1

    .line 70
    :goto_3
    and-int/lit8 v0, p1, 0x1

    .line 71
    .line 72
    check-cast p3, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {p3, v0, p4}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result p4

    .line 78
    if-eqz p4, :cond_7

    .line 79
    .line 80
    iget-object p4, p0, Ldl/i;->e:Ljava/util/List;

    .line 81
    .line 82
    check-cast p4, Lnx0/c;

    .line 83
    .line 84
    invoke-virtual {p4, p2}, Lnx0/c;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p4

    .line 88
    check-cast p4, Lhe/c;

    .line 89
    .line 90
    const v0, 0x74bcc92

    .line 91
    .line 92
    .line 93
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 94
    .line 95
    .line 96
    instance-of v0, p4, Lhe/b;

    .line 97
    .line 98
    if-eqz v0, :cond_5

    .line 99
    .line 100
    const p0, 0x52d0ebfe

    .line 101
    .line 102
    .line 103
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    check-cast p4, Lhe/b;

    .line 107
    .line 108
    iget-object p0, p4, Lhe/b;->a:Ljava/lang/String;

    .line 109
    .line 110
    and-int/lit8 p1, p1, 0x70

    .line 111
    .line 112
    invoke-static {p2, p1, p0, p3}, Ljk/a;->c(IILjava/lang/String;Ll2/o;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p3, v1}, Ll2/t;->q(Z)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_5
    instance-of v0, p4, Lhe/a;

    .line 120
    .line 121
    if-eqz v0, :cond_6

    .line 122
    .line 123
    const v0, 0x52d0f74c

    .line 124
    .line 125
    .line 126
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 127
    .line 128
    .line 129
    check-cast p4, Lhe/a;

    .line 130
    .line 131
    iget-object p0, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast p0, Lay0/k;

    .line 134
    .line 135
    and-int/lit8 p1, p1, 0x70

    .line 136
    .line 137
    invoke-static {p4, p2, p0, p3, p1}, Ljk/a;->b(Lhe/a;ILay0/k;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p3, v1}, Ll2/t;->q(Z)V

    .line 141
    .line 142
    .line 143
    :goto_4
    invoke-virtual {p3, v1}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_6
    const p0, 0x52d0e591

    .line 148
    .line 149
    .line 150
    invoke-static {p0, p3, v1}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    throw p0

    .line 155
    :cond_7
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 156
    .line 157
    .line 158
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 159
    .line 160
    return-object p0

    .line 161
    :pswitch_0
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 162
    .line 163
    check-cast p2, Ljava/lang/Number;

    .line 164
    .line 165
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    check-cast p3, Ll2/o;

    .line 170
    .line 171
    check-cast p4, Ljava/lang/Number;

    .line 172
    .line 173
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 174
    .line 175
    .line 176
    move-result p4

    .line 177
    and-int/lit8 v0, p4, 0x6

    .line 178
    .line 179
    if-nez v0, :cond_9

    .line 180
    .line 181
    move-object v0, p3

    .line 182
    check-cast v0, Ll2/t;

    .line 183
    .line 184
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result p1

    .line 188
    if-eqz p1, :cond_8

    .line 189
    .line 190
    const/4 p1, 0x4

    .line 191
    goto :goto_6

    .line 192
    :cond_8
    const/4 p1, 0x2

    .line 193
    :goto_6
    or-int/2addr p1, p4

    .line 194
    goto :goto_7

    .line 195
    :cond_9
    move p1, p4

    .line 196
    :goto_7
    and-int/lit8 p4, p4, 0x30

    .line 197
    .line 198
    if-nez p4, :cond_b

    .line 199
    .line 200
    move-object p4, p3

    .line 201
    check-cast p4, Ll2/t;

    .line 202
    .line 203
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 204
    .line 205
    .line 206
    move-result p4

    .line 207
    if-eqz p4, :cond_a

    .line 208
    .line 209
    const/16 p4, 0x20

    .line 210
    .line 211
    goto :goto_8

    .line 212
    :cond_a
    const/16 p4, 0x10

    .line 213
    .line 214
    :goto_8
    or-int/2addr p1, p4

    .line 215
    :cond_b
    and-int/lit16 p4, p1, 0x93

    .line 216
    .line 217
    const/16 v0, 0x92

    .line 218
    .line 219
    const/4 v1, 0x0

    .line 220
    const/4 v2, 0x1

    .line 221
    if-eq p4, v0, :cond_c

    .line 222
    .line 223
    move p4, v2

    .line 224
    goto :goto_9

    .line 225
    :cond_c
    move p4, v1

    .line 226
    :goto_9
    and-int/2addr p1, v2

    .line 227
    move-object v7, p3

    .line 228
    check-cast v7, Ll2/t;

    .line 229
    .line 230
    invoke-virtual {v7, p1, p4}, Ll2/t;->O(IZ)Z

    .line 231
    .line 232
    .line 233
    move-result p1

    .line 234
    if-eqz p1, :cond_f

    .line 235
    .line 236
    iget-object p1, p0, Ldl/i;->e:Ljava/util/List;

    .line 237
    .line 238
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    move-object v3, p1

    .line 243
    check-cast v3, Lh50/i;

    .line 244
    .line 245
    const p1, 0xb0d03

    .line 246
    .line 247
    .line 248
    invoke-virtual {v7, p1}, Ll2/t;->Y(I)V

    .line 249
    .line 250
    .line 251
    if-nez p2, :cond_d

    .line 252
    .line 253
    move v4, v2

    .line 254
    goto :goto_a

    .line 255
    :cond_d
    move v4, v1

    .line 256
    :goto_a
    iget-object p0, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p0, Lh50/c;

    .line 259
    .line 260
    iget-object p0, p0, Lh50/c;->b:Ljava/util/List;

    .line 261
    .line 262
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 263
    .line 264
    .line 265
    move-result p0

    .line 266
    if-ne p2, p0, :cond_e

    .line 267
    .line 268
    move v5, v2

    .line 269
    goto :goto_b

    .line 270
    :cond_e
    move v5, v1

    .line 271
    :goto_b
    const-string p0, "active_route_stop_"

    .line 272
    .line 273
    invoke-static {p2, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v6

    .line 277
    const/4 v8, 0x0

    .line 278
    invoke-static/range {v3 .. v8}, Li50/c;->m(Lh50/i;ZZLjava/lang/String;Ll2/o;I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v7, v1}, Ll2/t;->q(Z)V

    .line 282
    .line 283
    .line 284
    goto :goto_c

    .line 285
    :cond_f
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 286
    .line 287
    .line 288
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 289
    .line 290
    return-object p0

    .line 291
    :pswitch_1
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 292
    .line 293
    check-cast p2, Ljava/lang/Number;

    .line 294
    .line 295
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 296
    .line 297
    .line 298
    move-result p2

    .line 299
    check-cast p3, Ll2/o;

    .line 300
    .line 301
    check-cast p4, Ljava/lang/Number;

    .line 302
    .line 303
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 304
    .line 305
    .line 306
    move-result p4

    .line 307
    iget-object v0, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 308
    .line 309
    check-cast v0, Ll2/g1;

    .line 310
    .line 311
    and-int/lit8 v1, p4, 0x6

    .line 312
    .line 313
    if-nez v1, :cond_11

    .line 314
    .line 315
    move-object v1, p3

    .line 316
    check-cast v1, Ll2/t;

    .line 317
    .line 318
    invoke-virtual {v1, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 319
    .line 320
    .line 321
    move-result p1

    .line 322
    if-eqz p1, :cond_10

    .line 323
    .line 324
    const/4 p1, 0x4

    .line 325
    goto :goto_d

    .line 326
    :cond_10
    const/4 p1, 0x2

    .line 327
    :goto_d
    or-int/2addr p1, p4

    .line 328
    goto :goto_e

    .line 329
    :cond_11
    move p1, p4

    .line 330
    :goto_e
    and-int/lit8 p4, p4, 0x30

    .line 331
    .line 332
    if-nez p4, :cond_13

    .line 333
    .line 334
    move-object p4, p3

    .line 335
    check-cast p4, Ll2/t;

    .line 336
    .line 337
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 338
    .line 339
    .line 340
    move-result p4

    .line 341
    if-eqz p4, :cond_12

    .line 342
    .line 343
    const/16 p4, 0x20

    .line 344
    .line 345
    goto :goto_f

    .line 346
    :cond_12
    const/16 p4, 0x10

    .line 347
    .line 348
    :goto_f
    or-int/2addr p1, p4

    .line 349
    :cond_13
    and-int/lit16 p4, p1, 0x93

    .line 350
    .line 351
    const/16 v1, 0x92

    .line 352
    .line 353
    const/4 v2, 0x0

    .line 354
    const/4 v3, 0x1

    .line 355
    if-eq p4, v1, :cond_14

    .line 356
    .line 357
    move p4, v3

    .line 358
    goto :goto_10

    .line 359
    :cond_14
    move p4, v2

    .line 360
    :goto_10
    and-int/2addr p1, v3

    .line 361
    move-object v8, p3

    .line 362
    check-cast v8, Ll2/t;

    .line 363
    .line 364
    invoke-virtual {v8, p1, p4}, Ll2/t;->O(IZ)Z

    .line 365
    .line 366
    .line 367
    move-result p1

    .line 368
    if-eqz p1, :cond_17

    .line 369
    .line 370
    iget-object p0, p0, Ldl/i;->e:Ljava/util/List;

    .line 371
    .line 372
    invoke-interface {p0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    move-object v4, p0

    .line 377
    check-cast v4, Lh40/h3;

    .line 378
    .line 379
    const p0, 0x61dc977

    .line 380
    .line 381
    .line 382
    invoke-virtual {v8, p0}, Ll2/t;->Y(I)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 386
    .line 387
    .line 388
    move-result p0

    .line 389
    if-ne p2, p0, :cond_15

    .line 390
    .line 391
    move v5, v3

    .line 392
    goto :goto_11

    .line 393
    :cond_15
    move v5, v2

    .line 394
    :goto_11
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 395
    .line 396
    .line 397
    move-result p0

    .line 398
    if-ge p2, p0, :cond_16

    .line 399
    .line 400
    move v6, v3

    .line 401
    goto :goto_12

    .line 402
    :cond_16
    move v6, v2

    .line 403
    :goto_12
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 404
    .line 405
    const/high16 p1, 0x3f800000    # 1.0f

    .line 406
    .line 407
    invoke-static {p0, p1}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 408
    .line 409
    .line 410
    move-result-object v7

    .line 411
    const/16 v9, 0xc00

    .line 412
    .line 413
    invoke-static/range {v4 .. v9}, Li40/y1;->a(Lh40/h3;ZZLx2/s;Ll2/o;I)V

    .line 414
    .line 415
    .line 416
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 417
    .line 418
    .line 419
    goto :goto_13

    .line 420
    :cond_17
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 421
    .line 422
    .line 423
    :goto_13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 424
    .line 425
    return-object p0

    .line 426
    :pswitch_2
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 427
    .line 428
    check-cast p2, Ljava/lang/Number;

    .line 429
    .line 430
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 431
    .line 432
    .line 433
    move-result p2

    .line 434
    check-cast p3, Ll2/o;

    .line 435
    .line 436
    check-cast p4, Ljava/lang/Number;

    .line 437
    .line 438
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 439
    .line 440
    .line 441
    move-result p4

    .line 442
    and-int/lit8 v0, p4, 0x6

    .line 443
    .line 444
    if-nez v0, :cond_19

    .line 445
    .line 446
    move-object v0, p3

    .line 447
    check-cast v0, Ll2/t;

    .line 448
    .line 449
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 450
    .line 451
    .line 452
    move-result p1

    .line 453
    if-eqz p1, :cond_18

    .line 454
    .line 455
    const/4 p1, 0x4

    .line 456
    goto :goto_14

    .line 457
    :cond_18
    const/4 p1, 0x2

    .line 458
    :goto_14
    or-int/2addr p1, p4

    .line 459
    goto :goto_15

    .line 460
    :cond_19
    move p1, p4

    .line 461
    :goto_15
    and-int/lit8 p4, p4, 0x30

    .line 462
    .line 463
    if-nez p4, :cond_1b

    .line 464
    .line 465
    move-object p4, p3

    .line 466
    check-cast p4, Ll2/t;

    .line 467
    .line 468
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 469
    .line 470
    .line 471
    move-result p4

    .line 472
    if-eqz p4, :cond_1a

    .line 473
    .line 474
    const/16 p4, 0x20

    .line 475
    .line 476
    goto :goto_16

    .line 477
    :cond_1a
    const/16 p4, 0x10

    .line 478
    .line 479
    :goto_16
    or-int/2addr p1, p4

    .line 480
    :cond_1b
    and-int/lit16 p4, p1, 0x93

    .line 481
    .line 482
    const/16 v0, 0x92

    .line 483
    .line 484
    const/4 v1, 0x1

    .line 485
    const/4 v2, 0x0

    .line 486
    if-eq p4, v0, :cond_1c

    .line 487
    .line 488
    move p4, v1

    .line 489
    goto :goto_17

    .line 490
    :cond_1c
    move p4, v2

    .line 491
    :goto_17
    and-int/2addr p1, v1

    .line 492
    check-cast p3, Ll2/t;

    .line 493
    .line 494
    invoke-virtual {p3, p1, p4}, Ll2/t;->O(IZ)Z

    .line 495
    .line 496
    .line 497
    move-result p1

    .line 498
    if-eqz p1, :cond_1e

    .line 499
    .line 500
    iget-object p1, p0, Ldl/i;->e:Ljava/util/List;

    .line 501
    .line 502
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 503
    .line 504
    .line 505
    move-result-object p1

    .line 506
    check-cast p1, Lay0/n;

    .line 507
    .line 508
    const p4, -0x5af11b8f

    .line 509
    .line 510
    .line 511
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 512
    .line 513
    .line 514
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 515
    .line 516
    .line 517
    move-result-object p4

    .line 518
    invoke-interface {p1, p3, p4}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    iget-object p0, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast p0, Ljava/util/List;

    .line 524
    .line 525
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 526
    .line 527
    .line 528
    move-result p0

    .line 529
    if-ge p2, p0, :cond_1d

    .line 530
    .line 531
    const p0, 0x686bdc7b

    .line 532
    .line 533
    .line 534
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 535
    .line 536
    .line 537
    const/4 p0, 0x0

    .line 538
    invoke-static {v2, v1, p3, p0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 539
    .line 540
    .line 541
    :goto_18
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 542
    .line 543
    .line 544
    goto :goto_19

    .line 545
    :cond_1d
    const p0, -0x5b3a5882

    .line 546
    .line 547
    .line 548
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 549
    .line 550
    .line 551
    goto :goto_18

    .line 552
    :goto_19
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 553
    .line 554
    .line 555
    goto :goto_1a

    .line 556
    :cond_1e
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 557
    .line 558
    .line 559
    :goto_1a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 560
    .line 561
    return-object p0

    .line 562
    :pswitch_3
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 563
    .line 564
    check-cast p2, Ljava/lang/Number;

    .line 565
    .line 566
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 567
    .line 568
    .line 569
    move-result p2

    .line 570
    check-cast p3, Ll2/o;

    .line 571
    .line 572
    check-cast p4, Ljava/lang/Number;

    .line 573
    .line 574
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 575
    .line 576
    .line 577
    move-result p4

    .line 578
    and-int/lit8 v0, p4, 0x6

    .line 579
    .line 580
    if-nez v0, :cond_20

    .line 581
    .line 582
    move-object v0, p3

    .line 583
    check-cast v0, Ll2/t;

    .line 584
    .line 585
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 586
    .line 587
    .line 588
    move-result p1

    .line 589
    if-eqz p1, :cond_1f

    .line 590
    .line 591
    const/4 p1, 0x4

    .line 592
    goto :goto_1b

    .line 593
    :cond_1f
    const/4 p1, 0x2

    .line 594
    :goto_1b
    or-int/2addr p1, p4

    .line 595
    goto :goto_1c

    .line 596
    :cond_20
    move p1, p4

    .line 597
    :goto_1c
    and-int/lit8 p4, p4, 0x30

    .line 598
    .line 599
    if-nez p4, :cond_22

    .line 600
    .line 601
    move-object p4, p3

    .line 602
    check-cast p4, Ll2/t;

    .line 603
    .line 604
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 605
    .line 606
    .line 607
    move-result p4

    .line 608
    if-eqz p4, :cond_21

    .line 609
    .line 610
    const/16 p4, 0x20

    .line 611
    .line 612
    goto :goto_1d

    .line 613
    :cond_21
    const/16 p4, 0x10

    .line 614
    .line 615
    :goto_1d
    or-int/2addr p1, p4

    .line 616
    :cond_22
    and-int/lit16 p4, p1, 0x93

    .line 617
    .line 618
    const/16 v0, 0x92

    .line 619
    .line 620
    const/4 v1, 0x0

    .line 621
    if-eq p4, v0, :cond_23

    .line 622
    .line 623
    const/4 p4, 0x1

    .line 624
    goto :goto_1e

    .line 625
    :cond_23
    move p4, v1

    .line 626
    :goto_1e
    and-int/lit8 v0, p1, 0x1

    .line 627
    .line 628
    check-cast p3, Ll2/t;

    .line 629
    .line 630
    invoke-virtual {p3, v0, p4}, Ll2/t;->O(IZ)Z

    .line 631
    .line 632
    .line 633
    move-result p4

    .line 634
    if-eqz p4, :cond_24

    .line 635
    .line 636
    iget-object p4, p0, Ldl/i;->e:Ljava/util/List;

    .line 637
    .line 638
    invoke-interface {p4, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 639
    .line 640
    .line 641
    move-result-object p4

    .line 642
    check-cast p4, Lrh/d;

    .line 643
    .line 644
    const v0, -0x18b37965

    .line 645
    .line 646
    .line 647
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 648
    .line 649
    .line 650
    iget-object p0, p0, Ldl/i;->f:Ljava/lang/Object;

    .line 651
    .line 652
    check-cast p0, Lt2/b;

    .line 653
    .line 654
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 655
    .line 656
    .line 657
    move-result-object p2

    .line 658
    and-int/lit8 p1, p1, 0x70

    .line 659
    .line 660
    const/16 v0, 0x8

    .line 661
    .line 662
    or-int/2addr p1, v0

    .line 663
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 664
    .line 665
    .line 666
    move-result-object p1

    .line 667
    invoke-virtual {p0, p4, p2, p3, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 668
    .line 669
    .line 670
    const/16 p0, 0x18

    .line 671
    .line 672
    int-to-float p0, p0

    .line 673
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 674
    .line 675
    invoke-static {p1, p0, p3, v1}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 676
    .line 677
    .line 678
    goto :goto_1f

    .line 679
    :cond_24
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 680
    .line 681
    .line 682
    :goto_1f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 683
    .line 684
    return-object p0

    .line 685
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
