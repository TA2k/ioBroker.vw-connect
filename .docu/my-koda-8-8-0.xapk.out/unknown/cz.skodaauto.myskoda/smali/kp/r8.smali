.class public abstract Lkp/r8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lj11/s;Luv/q;Luv/q;)Luv/q;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    new-instance v1, Luv/r;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p1, v1, Luv/r;->a:Luv/q;

    .line 11
    .line 12
    iput-object v0, v1, Luv/r;->b:Luv/q;

    .line 13
    .line 14
    iput-object v0, v1, Luv/r;->c:Luv/q;

    .line 15
    .line 16
    iput-object p2, v1, Luv/r;->d:Luv/q;

    .line 17
    .line 18
    iput-object v0, v1, Luv/r;->e:Luv/q;

    .line 19
    .line 20
    instance-of p2, p0, Lj11/b;

    .line 21
    .line 22
    if-eqz p2, :cond_1

    .line 23
    .line 24
    sget-object p2, Luv/a;->a:Luv/a;

    .line 25
    .line 26
    goto/16 :goto_8

    .line 27
    .line 28
    :cond_1
    instance-of p2, p0, Lj11/c;

    .line 29
    .line 30
    if-eqz p2, :cond_2

    .line 31
    .line 32
    new-instance p2, Luv/f0;

    .line 33
    .line 34
    move-object v2, p0

    .line 35
    check-cast v2, Lj11/c;

    .line 36
    .line 37
    iget-char v2, v2, Lj11/c;->g:C

    .line 38
    .line 39
    invoke-direct {p2, v2}, Luv/f0;-><init>(C)V

    .line 40
    .line 41
    .line 42
    goto/16 :goto_8

    .line 43
    .line 44
    :cond_2
    instance-of p2, p0, Lj11/d;

    .line 45
    .line 46
    const-string v2, "getLiteral(...)"

    .line 47
    .line 48
    if-eqz p2, :cond_3

    .line 49
    .line 50
    new-instance p2, Luv/b;

    .line 51
    .line 52
    move-object v3, p0

    .line 53
    check-cast v3, Lj11/d;

    .line 54
    .line 55
    iget-object v3, v3, Lj11/d;->g:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-direct {p2, v3}, Luv/b;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_8

    .line 64
    .line 65
    :cond_3
    instance-of p2, p0, Lj11/f;

    .line 66
    .line 67
    if-eqz p2, :cond_4

    .line 68
    .line 69
    sget-object p2, Luv/d;->a:Luv/d;

    .line 70
    .line 71
    goto/16 :goto_8

    .line 72
    .line 73
    :cond_4
    instance-of p2, p0, Lj11/g;

    .line 74
    .line 75
    const-string v3, "getOpeningDelimiter(...)"

    .line 76
    .line 77
    if-eqz p2, :cond_5

    .line 78
    .line 79
    new-instance p2, Luv/e;

    .line 80
    .line 81
    move-object v2, p0

    .line 82
    check-cast v2, Lj11/g;

    .line 83
    .line 84
    iget-object v2, v2, Lj11/g;->g:Ljava/lang/String;

    .line 85
    .line 86
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-direct {p2, v2}, Luv/e;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    goto/16 :goto_8

    .line 93
    .line 94
    :cond_5
    instance-of p2, p0, Lj11/h;

    .line 95
    .line 96
    if-eqz p2, :cond_6

    .line 97
    .line 98
    move-object p2, p0

    .line 99
    check-cast p2, Lj11/h;

    .line 100
    .line 101
    iget-object v7, p2, Lj11/h;->k:Ljava/lang/String;

    .line 102
    .line 103
    iget-char v3, p2, Lj11/h;->g:C

    .line 104
    .line 105
    iget v5, p2, Lj11/h;->i:I

    .line 106
    .line 107
    iget v4, p2, Lj11/h;->h:I

    .line 108
    .line 109
    iget-object v6, p2, Lj11/h;->j:Ljava/lang/String;

    .line 110
    .line 111
    new-instance v2, Luv/f;

    .line 112
    .line 113
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    invoke-direct/range {v2 .. v7}, Luv/f;-><init>(CIILjava/lang/String;Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    :goto_0
    move-object p2, v2

    .line 123
    goto/16 :goto_8

    .line 124
    .line 125
    :cond_6
    instance-of p2, p0, Lj11/i;

    .line 126
    .line 127
    if-eqz p2, :cond_7

    .line 128
    .line 129
    sget-object p2, Luv/g;->a:Luv/g;

    .line 130
    .line 131
    goto/16 :goto_8

    .line 132
    .line 133
    :cond_7
    instance-of p2, p0, Lj11/j;

    .line 134
    .line 135
    if-eqz p2, :cond_8

    .line 136
    .line 137
    new-instance p2, Luv/h;

    .line 138
    .line 139
    move-object v2, p0

    .line 140
    check-cast v2, Lj11/j;

    .line 141
    .line 142
    iget v2, v2, Lj11/j;->g:I

    .line 143
    .line 144
    invoke-direct {p2, v2}, Luv/h;-><init>(I)V

    .line 145
    .line 146
    .line 147
    goto/16 :goto_8

    .line 148
    .line 149
    :cond_8
    instance-of p2, p0, Lj11/z;

    .line 150
    .line 151
    if-eqz p2, :cond_9

    .line 152
    .line 153
    sget-object p2, Luv/e0;->a:Luv/e0;

    .line 154
    .line 155
    goto/16 :goto_8

    .line 156
    .line 157
    :cond_9
    instance-of p2, p0, Lj11/l;

    .line 158
    .line 159
    if-eqz p2, :cond_a

    .line 160
    .line 161
    new-instance p2, Luv/j;

    .line 162
    .line 163
    move-object v3, p0

    .line 164
    check-cast v3, Lj11/l;

    .line 165
    .line 166
    iget-object v3, v3, Lj11/l;->g:Ljava/lang/String;

    .line 167
    .line 168
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    invoke-direct {p2, v3}, Luv/j;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    goto/16 :goto_8

    .line 175
    .line 176
    :cond_a
    instance-of p2, p0, Lj11/k;

    .line 177
    .line 178
    if-eqz p2, :cond_b

    .line 179
    .line 180
    new-instance p2, Luv/i;

    .line 181
    .line 182
    move-object v3, p0

    .line 183
    check-cast v3, Lj11/k;

    .line 184
    .line 185
    iget-object v3, v3, Lj11/k;->g:Ljava/lang/String;

    .line 186
    .line 187
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-direct {p2, v3}, Luv/i;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    goto/16 :goto_8

    .line 194
    .line 195
    :cond_b
    instance-of p2, p0, Lj11/m;

    .line 196
    .line 197
    const-string v4, ""

    .line 198
    .line 199
    if-eqz p2, :cond_e

    .line 200
    .line 201
    move-object p2, p0

    .line 202
    check-cast p2, Lj11/m;

    .line 203
    .line 204
    iget-object v2, p2, Lj11/m;->g:Ljava/lang/String;

    .line 205
    .line 206
    if-nez v2, :cond_c

    .line 207
    .line 208
    goto/16 :goto_7

    .line 209
    .line 210
    :cond_c
    new-instance v3, Luv/k;

    .line 211
    .line 212
    iget-object p2, p2, Lj11/m;->h:Ljava/lang/String;

    .line 213
    .line 214
    if-nez p2, :cond_d

    .line 215
    .line 216
    goto :goto_1

    .line 217
    :cond_d
    move-object v4, p2

    .line 218
    :goto_1
    invoke-direct {v3, v4, v2}, Luv/k;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    goto/16 :goto_4

    .line 222
    .line 223
    :cond_e
    instance-of p2, p0, Lj11/n;

    .line 224
    .line 225
    if-eqz p2, :cond_f

    .line 226
    .line 227
    new-instance p2, Luv/l;

    .line 228
    .line 229
    move-object v3, p0

    .line 230
    check-cast v3, Lj11/n;

    .line 231
    .line 232
    iget-object v3, v3, Lj11/n;->g:Ljava/lang/String;

    .line 233
    .line 234
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-direct {p2, v3}, Luv/l;-><init>(Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_8

    .line 241
    .line 242
    :cond_f
    instance-of p2, p0, Lj11/o;

    .line 243
    .line 244
    if-eqz p2, :cond_11

    .line 245
    .line 246
    move-object p2, p0

    .line 247
    check-cast p2, Lj11/o;

    .line 248
    .line 249
    iget-object v2, p2, Lj11/o;->h:Ljava/lang/String;

    .line 250
    .line 251
    if-nez v2, :cond_10

    .line 252
    .line 253
    goto :goto_2

    .line 254
    :cond_10
    move-object v4, v2

    .line 255
    :goto_2
    iget-object p2, p2, Lj11/o;->g:Ljava/lang/String;

    .line 256
    .line 257
    new-instance v2, Luv/n;

    .line 258
    .line 259
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    invoke-direct {v2, p2, v4}, Luv/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 263
    .line 264
    .line 265
    goto/16 :goto_0

    .line 266
    .line 267
    :cond_11
    instance-of p2, p0, Lj11/r;

    .line 268
    .line 269
    if-eqz p2, :cond_12

    .line 270
    .line 271
    sget-object p2, Luv/p;->a:Luv/p;

    .line 272
    .line 273
    goto/16 :goto_8

    .line 274
    .line 275
    :cond_12
    instance-of p2, p0, Lj11/t;

    .line 276
    .line 277
    if-eqz p2, :cond_13

    .line 278
    .line 279
    new-instance p2, Luv/s;

    .line 280
    .line 281
    move-object v2, p0

    .line 282
    check-cast v2, Lj11/t;

    .line 283
    .line 284
    iget v3, v2, Lj11/t;->g:I

    .line 285
    .line 286
    iget-char v2, v2, Lj11/t;->h:C

    .line 287
    .line 288
    invoke-direct {p2, v2, v3}, Luv/s;-><init>(CI)V

    .line 289
    .line 290
    .line 291
    goto/16 :goto_8

    .line 292
    .line 293
    :cond_13
    instance-of p2, p0, Lj11/u;

    .line 294
    .line 295
    if-eqz p2, :cond_14

    .line 296
    .line 297
    sget-object p2, Luv/t;->a:Luv/t;

    .line 298
    .line 299
    goto/16 :goto_8

    .line 300
    .line 301
    :cond_14
    instance-of p2, p0, Lj11/v;

    .line 302
    .line 303
    if-eqz p2, :cond_15

    .line 304
    .line 305
    sget-object p2, Luv/u;->a:Luv/u;

    .line 306
    .line 307
    goto/16 :goto_8

    .line 308
    .line 309
    :cond_15
    instance-of p2, p0, Lj11/x;

    .line 310
    .line 311
    if-eqz p2, :cond_16

    .line 312
    .line 313
    new-instance p2, Luv/w;

    .line 314
    .line 315
    move-object v2, p0

    .line 316
    check-cast v2, Lj11/x;

    .line 317
    .line 318
    iget-object v2, v2, Lj11/x;->g:Ljava/lang/String;

    .line 319
    .line 320
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    invoke-direct {p2, v2}, Luv/w;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    goto/16 :goto_8

    .line 327
    .line 328
    :cond_16
    instance-of p2, p0, Lj11/y;

    .line 329
    .line 330
    if-eqz p2, :cond_17

    .line 331
    .line 332
    new-instance p2, Luv/d0;

    .line 333
    .line 334
    move-object v3, p0

    .line 335
    check-cast v3, Lj11/y;

    .line 336
    .line 337
    iget-object v3, v3, Lj11/y;->g:Ljava/lang/String;

    .line 338
    .line 339
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    invoke-direct {p2, v3}, Luv/d0;-><init>(Ljava/lang/String;)V

    .line 343
    .line 344
    .line 345
    goto/16 :goto_8

    .line 346
    .line 347
    :cond_17
    instance-of p2, p0, Lj11/p;

    .line 348
    .line 349
    if-eqz p2, :cond_19

    .line 350
    .line 351
    move-object p2, p0

    .line 352
    check-cast p2, Lj11/p;

    .line 353
    .line 354
    iget-object v2, p2, Lj11/p;->i:Ljava/lang/String;

    .line 355
    .line 356
    if-nez v2, :cond_18

    .line 357
    .line 358
    goto :goto_3

    .line 359
    :cond_18
    move-object v4, v2

    .line 360
    :goto_3
    iget-object v2, p2, Lj11/p;->h:Ljava/lang/String;

    .line 361
    .line 362
    iget-object p2, p2, Lj11/p;->g:Ljava/lang/String;

    .line 363
    .line 364
    new-instance v3, Luv/o;

    .line 365
    .line 366
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 367
    .line 368
    .line 369
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 370
    .line 371
    .line 372
    invoke-direct {v3, p2, v2, v4}, Luv/o;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    :goto_4
    move-object p2, v3

    .line 376
    goto/16 :goto_8

    .line 377
    .line 378
    :cond_19
    instance-of p2, p0, Le11/a;

    .line 379
    .line 380
    if-eqz p2, :cond_1a

    .line 381
    .line 382
    sget-object p2, Luv/b0;->a:Luv/b0;

    .line 383
    .line 384
    goto :goto_8

    .line 385
    :cond_1a
    instance-of p2, p0, Le11/e;

    .line 386
    .line 387
    if-eqz p2, :cond_1b

    .line 388
    .line 389
    sget-object p2, Luv/a0;->a:Luv/a0;

    .line 390
    .line 391
    goto :goto_8

    .line 392
    :cond_1b
    instance-of p2, p0, Le11/b;

    .line 393
    .line 394
    if-eqz p2, :cond_1c

    .line 395
    .line 396
    sget-object p2, Luv/x;->a:Luv/x;

    .line 397
    .line 398
    goto :goto_8

    .line 399
    :cond_1c
    instance-of p2, p0, Le11/f;

    .line 400
    .line 401
    if-eqz p2, :cond_1d

    .line 402
    .line 403
    sget-object p2, Luv/c0;->a:Luv/c0;

    .line 404
    .line 405
    goto :goto_8

    .line 406
    :cond_1d
    instance-of p2, p0, Le11/d;

    .line 407
    .line 408
    if-eqz p2, :cond_23

    .line 409
    .line 410
    new-instance p2, Luv/y;

    .line 411
    .line 412
    move-object v2, p0

    .line 413
    check-cast v2, Le11/d;

    .line 414
    .line 415
    iget-boolean v3, v2, Le11/d;->g:Z

    .line 416
    .line 417
    iget-object v2, v2, Le11/d;->h:Le11/c;

    .line 418
    .line 419
    const/4 v4, -0x1

    .line 420
    if-nez v2, :cond_1e

    .line 421
    .line 422
    move v2, v4

    .line 423
    goto :goto_5

    .line 424
    :cond_1e
    sget-object v5, Lsv/a;->a:[I

    .line 425
    .line 426
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 427
    .line 428
    .line 429
    move-result v2

    .line 430
    aget v2, v5, v2

    .line 431
    .line 432
    :goto_5
    if-eq v2, v4, :cond_22

    .line 433
    .line 434
    const/4 v4, 0x1

    .line 435
    if-eq v2, v4, :cond_21

    .line 436
    .line 437
    const/4 v4, 0x2

    .line 438
    if-eq v2, v4, :cond_20

    .line 439
    .line 440
    const/4 v4, 0x3

    .line 441
    if-eq v2, v4, :cond_1f

    .line 442
    .line 443
    sget-object v2, Luv/z;->d:Luv/z;

    .line 444
    .line 445
    goto :goto_6

    .line 446
    :cond_1f
    sget-object v2, Luv/z;->f:Luv/z;

    .line 447
    .line 448
    goto :goto_6

    .line 449
    :cond_20
    sget-object v2, Luv/z;->e:Luv/z;

    .line 450
    .line 451
    goto :goto_6

    .line 452
    :cond_21
    sget-object v2, Luv/z;->d:Luv/z;

    .line 453
    .line 454
    goto :goto_6

    .line 455
    :cond_22
    sget-object v2, Luv/z;->d:Luv/z;

    .line 456
    .line 457
    :goto_6
    invoke-direct {p2, v3, v2}, Luv/y;-><init>(ZLuv/z;)V

    .line 458
    .line 459
    .line 460
    goto :goto_8

    .line 461
    :cond_23
    instance-of p2, p0, Lc11/a;

    .line 462
    .line 463
    if-eqz p2, :cond_24

    .line 464
    .line 465
    new-instance p2, Luv/v;

    .line 466
    .line 467
    move-object v2, p0

    .line 468
    check-cast v2, Lc11/a;

    .line 469
    .line 470
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 471
    .line 472
    .line 473
    goto :goto_8

    .line 474
    :cond_24
    :goto_7
    move-object p2, v0

    .line 475
    :goto_8
    if-eqz p2, :cond_25

    .line 476
    .line 477
    new-instance v2, Luv/q;

    .line 478
    .line 479
    invoke-direct {v2, p2, v1}, Luv/q;-><init>(Llp/la;Luv/r;)V

    .line 480
    .line 481
    .line 482
    goto :goto_9

    .line 483
    :cond_25
    move-object v2, v0

    .line 484
    :goto_9
    if-eqz v2, :cond_26

    .line 485
    .line 486
    iget-object p2, v2, Luv/q;->b:Luv/r;

    .line 487
    .line 488
    iget-object v1, p0, Lj11/s;->b:Lj11/s;

    .line 489
    .line 490
    invoke-static {v1, v2, v0}, Lkp/r8;->a(Lj11/s;Luv/q;Luv/q;)Luv/q;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    iput-object v1, p2, Luv/r;->b:Luv/q;

    .line 495
    .line 496
    iget-object v1, p0, Lj11/s;->e:Lj11/s;

    .line 497
    .line 498
    invoke-static {v1, p1, v2}, Lkp/r8;->a(Lj11/s;Luv/q;Luv/q;)Luv/q;

    .line 499
    .line 500
    .line 501
    move-result-object v1

    .line 502
    iput-object v1, p2, Luv/r;->e:Luv/q;

    .line 503
    .line 504
    :cond_26
    iget-object p0, p0, Lj11/s;->e:Lj11/s;

    .line 505
    .line 506
    if-nez p0, :cond_29

    .line 507
    .line 508
    if-eqz p1, :cond_27

    .line 509
    .line 510
    iget-object v0, p1, Luv/q;->b:Luv/r;

    .line 511
    .line 512
    :cond_27
    if-nez v0, :cond_28

    .line 513
    .line 514
    goto :goto_a

    .line 515
    :cond_28
    iput-object v2, v0, Luv/r;->c:Luv/q;

    .line 516
    .line 517
    :cond_29
    :goto_a
    return-object v2
.end method
