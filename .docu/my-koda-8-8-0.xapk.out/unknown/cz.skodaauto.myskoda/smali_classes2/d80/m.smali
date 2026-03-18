.class public final synthetic Ld80/m;
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
    iput p1, p0, Ld80/m;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Ld80/m;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget p0, p0, Ld80/m;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p1, p0}, Ldl0/e;->k(Ll2/o;I)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 25
    .line 26
    check-cast p2, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p1, p0}, Ldl0/e;->h(Ll2/o;I)V

    .line 37
    .line 38
    .line 39
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 43
    .line 44
    check-cast p2, Ljava/lang/Integer;

    .line 45
    .line 46
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    const/4 p0, 0x1

    .line 50
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    invoke-static {p1, p0}, Ldl0/e;->e(Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_2
    check-cast p1, Ll2/o;

    .line 61
    .line 62
    check-cast p2, Ljava/lang/Integer;

    .line 63
    .line 64
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const/16 p0, 0x37

    .line 68
    .line 69
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 74
    .line 75
    invoke-static {p2, p1, p0}, Ldl0/e;->a(Lx2/s;Ll2/o;I)V

    .line 76
    .line 77
    .line 78
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    return-object p0

    .line 81
    :pswitch_3
    check-cast p1, Ll2/o;

    .line 82
    .line 83
    check-cast p2, Ljava/lang/Integer;

    .line 84
    .line 85
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    and-int/lit8 p2, p0, 0x3

    .line 90
    .line 91
    const/4 v0, 0x2

    .line 92
    const/4 v1, 0x1

    .line 93
    if-eq p2, v0, :cond_0

    .line 94
    .line 95
    move p2, v1

    .line 96
    goto :goto_0

    .line 97
    :cond_0
    const/4 p2, 0x0

    .line 98
    :goto_0
    and-int/2addr p0, v1

    .line 99
    move-object v7, p1

    .line 100
    check-cast v7, Ll2/t;

    .line 101
    .line 102
    invoke-virtual {v7, p0, p2}, Ll2/t;->O(IZ)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_4

    .line 107
    .line 108
    new-instance v0, Lcl0/r;

    .line 109
    .line 110
    invoke-direct {v0}, Lcl0/r;-><init>()V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 118
    .line 119
    if-ne p0, p1, :cond_1

    .line 120
    .line 121
    new-instance p0, Lz81/g;

    .line 122
    .line 123
    const/4 p2, 0x2

    .line 124
    invoke-direct {p0, p2}, Lz81/g;-><init>(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v7, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_1
    move-object v2, p0

    .line 131
    check-cast v2, Lay0/a;

    .line 132
    .line 133
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    if-ne p0, p1, :cond_2

    .line 138
    .line 139
    new-instance p0, Ldj/a;

    .line 140
    .line 141
    const/4 p2, 0x6

    .line 142
    invoke-direct {p0, p2}, Ldj/a;-><init>(I)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v7, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_2
    move-object v3, p0

    .line 149
    check-cast v3, Lay0/k;

    .line 150
    .line 151
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    if-ne p0, p1, :cond_3

    .line 156
    .line 157
    new-instance p0, Lz81/g;

    .line 158
    .line 159
    const/4 p1, 0x2

    .line 160
    invoke-direct {p0, p1}, Lz81/g;-><init>(I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v7, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    :cond_3
    move-object v4, p0

    .line 167
    check-cast v4, Lay0/a;

    .line 168
    .line 169
    const/16 v8, 0x6d80

    .line 170
    .line 171
    const/16 v9, 0x60

    .line 172
    .line 173
    const v1, 0x7f120627

    .line 174
    .line 175
    .line 176
    const/4 v5, 0x0

    .line 177
    const/4 v6, 0x0

    .line 178
    invoke-static/range {v0 .. v9}, Ldl0/e;->j(Lcl0/r;ILay0/a;Lay0/k;Lay0/a;Lx2/s;ZLl2/o;II)V

    .line 179
    .line 180
    .line 181
    goto :goto_1

    .line 182
    :cond_4
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_4
    check-cast p1, Ll2/o;

    .line 189
    .line 190
    check-cast p2, Ljava/lang/Integer;

    .line 191
    .line 192
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    and-int/lit8 p2, p0, 0x3

    .line 197
    .line 198
    const/4 v0, 0x2

    .line 199
    const/4 v1, 0x1

    .line 200
    if-eq p2, v0, :cond_5

    .line 201
    .line 202
    move p2, v1

    .line 203
    goto :goto_2

    .line 204
    :cond_5
    const/4 p2, 0x0

    .line 205
    :goto_2
    and-int/2addr p0, v1

    .line 206
    move-object v3, p1

    .line 207
    check-cast v3, Ll2/t;

    .line 208
    .line 209
    invoke-virtual {v3, p0, p2}, Ll2/t;->O(IZ)Z

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    if-eqz p0, :cond_7

    .line 214
    .line 215
    new-instance v0, Lcl0/o;

    .line 216
    .line 217
    const/4 p0, 0x0

    .line 218
    invoke-direct {v0, p0}, Lcl0/o;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 226
    .line 227
    if-ne p0, p1, :cond_6

    .line 228
    .line 229
    new-instance p0, Lz81/g;

    .line 230
    .line 231
    const/4 p1, 0x2

    .line 232
    invoke-direct {p0, p1}, Lz81/g;-><init>(I)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v3, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    :cond_6
    move-object v1, p0

    .line 239
    check-cast v1, Lay0/a;

    .line 240
    .line 241
    const/16 v4, 0x1b0

    .line 242
    .line 243
    const/16 v5, 0x8

    .line 244
    .line 245
    const/4 v2, 0x0

    .line 246
    invoke-static/range {v0 .. v5}, Ldl0/e;->g(Lcl0/o;Lay0/a;ZLl2/o;II)V

    .line 247
    .line 248
    .line 249
    goto :goto_3

    .line 250
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 251
    .line 252
    .line 253
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 254
    .line 255
    return-object p0

    .line 256
    :pswitch_5
    check-cast p1, Ll2/o;

    .line 257
    .line 258
    check-cast p2, Ljava/lang/Integer;

    .line 259
    .line 260
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 261
    .line 262
    .line 263
    move-result p0

    .line 264
    and-int/lit8 p2, p0, 0x3

    .line 265
    .line 266
    const/4 v0, 0x2

    .line 267
    const/4 v1, 0x0

    .line 268
    const/4 v2, 0x1

    .line 269
    if-eq p2, v0, :cond_8

    .line 270
    .line 271
    move p2, v2

    .line 272
    goto :goto_4

    .line 273
    :cond_8
    move p2, v1

    .line 274
    :goto_4
    and-int/2addr p0, v2

    .line 275
    move-object v6, p1

    .line 276
    check-cast v6, Ll2/t;

    .line 277
    .line 278
    invoke-virtual {v6, p0, p2}, Ll2/t;->O(IZ)Z

    .line 279
    .line 280
    .line 281
    move-result p0

    .line 282
    if-eqz p0, :cond_a

    .line 283
    .line 284
    new-instance v2, Lcl0/m;

    .line 285
    .line 286
    invoke-direct {v2, v1}, Lcl0/m;-><init>(Z)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 294
    .line 295
    if-ne p0, p1, :cond_9

    .line 296
    .line 297
    new-instance p0, Lz81/g;

    .line 298
    .line 299
    const/4 p1, 0x2

    .line 300
    invoke-direct {p0, p1}, Lz81/g;-><init>(I)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v6, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    :cond_9
    move-object v3, p0

    .line 307
    check-cast v3, Lay0/a;

    .line 308
    .line 309
    const/16 v7, 0x30

    .line 310
    .line 311
    const/16 v8, 0xc

    .line 312
    .line 313
    const/4 v4, 0x0

    .line 314
    const/4 v5, 0x0

    .line 315
    invoke-static/range {v2 .. v8}, Ldl0/e;->d(Lcl0/m;Lay0/a;Lx2/s;ZLl2/o;II)V

    .line 316
    .line 317
    .line 318
    goto :goto_5

    .line 319
    :cond_a
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 320
    .line 321
    .line 322
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 323
    .line 324
    return-object p0

    .line 325
    :pswitch_6
    check-cast p1, Ll2/o;

    .line 326
    .line 327
    check-cast p2, Ljava/lang/Integer;

    .line 328
    .line 329
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    const/4 p0, 0x1

    .line 333
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 334
    .line 335
    .line 336
    move-result p0

    .line 337
    invoke-static {p1, p0}, Ldl0/d;->b(Ll2/o;I)V

    .line 338
    .line 339
    .line 340
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 341
    .line 342
    return-object p0

    .line 343
    :pswitch_7
    check-cast p1, Ll2/o;

    .line 344
    .line 345
    check-cast p2, Ljava/lang/Integer;

    .line 346
    .line 347
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 348
    .line 349
    .line 350
    const/4 p0, 0x1

    .line 351
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 352
    .line 353
    .line 354
    move-result p0

    .line 355
    invoke-static {p1, p0}, Ldl/d;->c(Ll2/o;I)V

    .line 356
    .line 357
    .line 358
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 359
    .line 360
    return-object p0

    .line 361
    :pswitch_8
    check-cast p1, Ll2/o;

    .line 362
    .line 363
    check-cast p2, Ljava/lang/Integer;

    .line 364
    .line 365
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 366
    .line 367
    .line 368
    const/4 p0, 0x1

    .line 369
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 370
    .line 371
    .line 372
    move-result p0

    .line 373
    invoke-static {p1, p0}, Ldl/d;->b(Ll2/o;I)V

    .line 374
    .line 375
    .line 376
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 377
    .line 378
    return-object p0

    .line 379
    :pswitch_9
    check-cast p1, Ll2/o;

    .line 380
    .line 381
    check-cast p2, Ljava/lang/Integer;

    .line 382
    .line 383
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 384
    .line 385
    .line 386
    move-result p0

    .line 387
    and-int/lit8 p2, p0, 0x3

    .line 388
    .line 389
    const/4 v0, 0x2

    .line 390
    const/4 v1, 0x0

    .line 391
    const/4 v2, 0x1

    .line 392
    if-eq p2, v0, :cond_b

    .line 393
    .line 394
    move p2, v2

    .line 395
    goto :goto_6

    .line 396
    :cond_b
    move p2, v1

    .line 397
    :goto_6
    and-int/2addr p0, v2

    .line 398
    check-cast p1, Ll2/t;

    .line 399
    .line 400
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 401
    .line 402
    .line 403
    move-result p0

    .line 404
    if-eqz p0, :cond_c

    .line 405
    .line 406
    const/4 p0, 0x6

    .line 407
    invoke-static {p0, v1, p1, v2}, Ldk/b;->e(IILl2/o;Z)V

    .line 408
    .line 409
    .line 410
    goto :goto_7

    .line 411
    :cond_c
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 412
    .line 413
    .line 414
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 415
    .line 416
    return-object p0

    .line 417
    :pswitch_a
    check-cast p1, Ll2/o;

    .line 418
    .line 419
    check-cast p2, Ljava/lang/Integer;

    .line 420
    .line 421
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 422
    .line 423
    .line 424
    move-result p0

    .line 425
    and-int/lit8 p2, p0, 0x3

    .line 426
    .line 427
    const/4 v0, 0x2

    .line 428
    const/4 v1, 0x1

    .line 429
    if-eq p2, v0, :cond_d

    .line 430
    .line 431
    move p2, v1

    .line 432
    goto :goto_8

    .line 433
    :cond_d
    const/4 p2, 0x0

    .line 434
    :goto_8
    and-int/2addr p0, v1

    .line 435
    move-object v3, p1

    .line 436
    check-cast v3, Ll2/t;

    .line 437
    .line 438
    invoke-virtual {v3, p0, p2}, Ll2/t;->O(IZ)Z

    .line 439
    .line 440
    .line 441
    move-result p0

    .line 442
    if-eqz p0, :cond_e

    .line 443
    .line 444
    invoke-static {v3}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    const/4 v4, 0x6

    .line 449
    const/4 v5, 0x2

    .line 450
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 451
    .line 452
    const/4 v1, 0x0

    .line 453
    invoke-static/range {v0 .. v5}, Ljp/nd;->a(Lx2/s;Ljava/lang/String;Lay0/a;Ll2/o;II)V

    .line 454
    .line 455
    .line 456
    goto :goto_9

    .line 457
    :cond_e
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 458
    .line 459
    .line 460
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 461
    .line 462
    return-object p0

    .line 463
    :pswitch_b
    check-cast p1, Ll2/o;

    .line 464
    .line 465
    check-cast p2, Ljava/lang/Integer;

    .line 466
    .line 467
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 468
    .line 469
    .line 470
    move-result p0

    .line 471
    and-int/lit8 p2, p0, 0x3

    .line 472
    .line 473
    const/4 v0, 0x2

    .line 474
    const/4 v1, 0x1

    .line 475
    if-eq p2, v0, :cond_f

    .line 476
    .line 477
    move p2, v1

    .line 478
    goto :goto_a

    .line 479
    :cond_f
    const/4 p2, 0x0

    .line 480
    :goto_a
    and-int/2addr p0, v1

    .line 481
    check-cast p1, Ll2/t;

    .line 482
    .line 483
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 484
    .line 485
    .line 486
    move-result p0

    .line 487
    if-eqz p0, :cond_10

    .line 488
    .line 489
    const p0, 0x7f120b9e

    .line 490
    .line 491
    .line 492
    invoke-static {p1, p0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object p0

    .line 496
    const/4 p2, 0x6

    .line 497
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 498
    .line 499
    invoke-static {p2, p0, p1, v0}, Ljp/nd;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 500
    .line 501
    .line 502
    goto :goto_b

    .line 503
    :cond_10
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 504
    .line 505
    .line 506
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 507
    .line 508
    return-object p0

    .line 509
    :pswitch_c
    check-cast p1, Ll2/o;

    .line 510
    .line 511
    check-cast p2, Ljava/lang/Integer;

    .line 512
    .line 513
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 514
    .line 515
    .line 516
    move-result p0

    .line 517
    and-int/lit8 p2, p0, 0x3

    .line 518
    .line 519
    const/4 v0, 0x2

    .line 520
    const/4 v1, 0x1

    .line 521
    const/4 v2, 0x0

    .line 522
    if-eq p2, v0, :cond_11

    .line 523
    .line 524
    move p2, v1

    .line 525
    goto :goto_c

    .line 526
    :cond_11
    move p2, v2

    .line 527
    :goto_c
    and-int/2addr p0, v1

    .line 528
    move-object v10, p1

    .line 529
    check-cast v10, Ll2/t;

    .line 530
    .line 531
    invoke-virtual {v10, p0, p2}, Ll2/t;->O(IZ)Z

    .line 532
    .line 533
    .line 534
    move-result p0

    .line 535
    if-eqz p0, :cond_12

    .line 536
    .line 537
    const p0, 0x7f080359

    .line 538
    .line 539
    .line 540
    invoke-static {p0, v2, v10}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 541
    .line 542
    .line 543
    move-result-object v3

    .line 544
    sget-wide p0, Le3/s;->e:J

    .line 545
    .line 546
    new-instance v9, Le3/m;

    .line 547
    .line 548
    const/4 p2, 0x5

    .line 549
    invoke-direct {v9, p0, p1, p2}, Le3/m;-><init>(JI)V

    .line 550
    .line 551
    .line 552
    const v11, 0x180030

    .line 553
    .line 554
    .line 555
    const/16 v12, 0x3c

    .line 556
    .line 557
    const/4 v4, 0x0

    .line 558
    const/4 v5, 0x0

    .line 559
    const/4 v6, 0x0

    .line 560
    const/4 v7, 0x0

    .line 561
    const/4 v8, 0x0

    .line 562
    invoke-static/range {v3 .. v12}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 563
    .line 564
    .line 565
    goto :goto_d

    .line 566
    :cond_12
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 567
    .line 568
    .line 569
    :goto_d
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 570
    .line 571
    return-object p0

    .line 572
    :pswitch_d
    check-cast p1, Ll2/o;

    .line 573
    .line 574
    check-cast p2, Ljava/lang/Integer;

    .line 575
    .line 576
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 577
    .line 578
    .line 579
    const/4 p0, 0x1

    .line 580
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 581
    .line 582
    .line 583
    move-result p0

    .line 584
    invoke-static {p1, p0}, Ldk/b;->g(Ll2/o;I)V

    .line 585
    .line 586
    .line 587
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 588
    .line 589
    return-object p0

    .line 590
    :pswitch_e
    check-cast p1, Ll2/o;

    .line 591
    .line 592
    check-cast p2, Ljava/lang/Integer;

    .line 593
    .line 594
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 595
    .line 596
    .line 597
    const/4 p0, 0x1

    .line 598
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 599
    .line 600
    .line 601
    move-result p0

    .line 602
    invoke-static {p1, p0}, Ldk/b;->f(Ll2/o;I)V

    .line 603
    .line 604
    .line 605
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 606
    .line 607
    return-object p0

    .line 608
    :pswitch_f
    check-cast p1, Ll2/o;

    .line 609
    .line 610
    check-cast p2, Ljava/lang/Integer;

    .line 611
    .line 612
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 613
    .line 614
    .line 615
    const/4 p0, 0x1

    .line 616
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 617
    .line 618
    .line 619
    move-result p0

    .line 620
    invoke-static {p1, p0}, Ldk/b;->h(Ll2/o;I)V

    .line 621
    .line 622
    .line 623
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 624
    .line 625
    return-object p0

    .line 626
    :pswitch_10
    check-cast p1, Lk21/a;

    .line 627
    .line 628
    check-cast p2, Lg21/a;

    .line 629
    .line 630
    const-string p0, "$this$single"

    .line 631
    .line 632
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 633
    .line 634
    .line 635
    const-string p0, "it"

    .line 636
    .line 637
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 638
    .line 639
    .line 640
    new-instance p0, Lce0/d;

    .line 641
    .line 642
    sget-object p2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 643
    .line 644
    const-class v0, Lxl0/f;

    .line 645
    .line 646
    invoke-virtual {p2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 647
    .line 648
    .line 649
    move-result-object v0

    .line 650
    const/4 v1, 0x0

    .line 651
    invoke-virtual {p1, v0, v1, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v0

    .line 655
    check-cast v0, Lxl0/f;

    .line 656
    .line 657
    const-class v2, Lcz/myskoda/api/bff_consents/v2/ConsentsApi;

    .line 658
    .line 659
    const-string v3, "null"

    .line 660
    .line 661
    invoke-static {p2, v2, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 662
    .line 663
    .line 664
    move-result-object v2

    .line 665
    const-class v3, Lti0/a;

    .line 666
    .line 667
    invoke-virtual {p2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 668
    .line 669
    .line 670
    move-result-object p2

    .line 671
    invoke-virtual {p1, p2, v2, v1}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    move-result-object p1

    .line 675
    check-cast p1, Lti0/a;

    .line 676
    .line 677
    invoke-direct {p0, v0, p1}, Lce0/d;-><init>(Lxl0/f;Lti0/a;)V

    .line 678
    .line 679
    .line 680
    return-object p0

    .line 681
    :pswitch_11
    check-cast p1, Ll2/o;

    .line 682
    .line 683
    check-cast p2, Ljava/lang/Integer;

    .line 684
    .line 685
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 686
    .line 687
    .line 688
    const/4 p0, 0x1

    .line 689
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 690
    .line 691
    .line 692
    move-result p0

    .line 693
    invoke-static {p1, p0}, Ld90/v;->j(Ll2/o;I)V

    .line 694
    .line 695
    .line 696
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 697
    .line 698
    return-object p0

    .line 699
    :pswitch_12
    check-cast p1, Ll2/o;

    .line 700
    .line 701
    check-cast p2, Ljava/lang/Integer;

    .line 702
    .line 703
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 704
    .line 705
    .line 706
    const/4 p0, 0x1

    .line 707
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 708
    .line 709
    .line 710
    move-result p0

    .line 711
    invoke-static {p1, p0}, Ld90/v;->g(Ll2/o;I)V

    .line 712
    .line 713
    .line 714
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 715
    .line 716
    return-object p0

    .line 717
    :pswitch_13
    check-cast p1, Ll2/o;

    .line 718
    .line 719
    check-cast p2, Ljava/lang/Integer;

    .line 720
    .line 721
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 722
    .line 723
    .line 724
    const/4 p0, 0x1

    .line 725
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 726
    .line 727
    .line 728
    move-result p0

    .line 729
    invoke-static {p1, p0}, Ljp/cg;->a(Ll2/o;I)V

    .line 730
    .line 731
    .line 732
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 733
    .line 734
    return-object p0

    .line 735
    :pswitch_14
    check-cast p1, Ll2/o;

    .line 736
    .line 737
    check-cast p2, Ljava/lang/Integer;

    .line 738
    .line 739
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 740
    .line 741
    .line 742
    const/4 p0, 0x1

    .line 743
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 744
    .line 745
    .line 746
    move-result p0

    .line 747
    invoke-static {p1, p0}, Ld90/l;->a(Ll2/o;I)V

    .line 748
    .line 749
    .line 750
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 751
    .line 752
    return-object p0

    .line 753
    :pswitch_15
    check-cast p1, Ll2/o;

    .line 754
    .line 755
    check-cast p2, Ljava/lang/Integer;

    .line 756
    .line 757
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 758
    .line 759
    .line 760
    const/4 p0, 0x1

    .line 761
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 762
    .line 763
    .line 764
    move-result p0

    .line 765
    invoke-static {p1, p0}, Ljp/bg;->c(Ll2/o;I)V

    .line 766
    .line 767
    .line 768
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 769
    .line 770
    return-object p0

    .line 771
    :pswitch_16
    check-cast p1, Ll2/o;

    .line 772
    .line 773
    check-cast p2, Ljava/lang/Integer;

    .line 774
    .line 775
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 776
    .line 777
    .line 778
    const/4 p0, 0x1

    .line 779
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 780
    .line 781
    .line 782
    move-result p0

    .line 783
    invoke-static {p1, p0}, Ljp/ag;->e(Ll2/o;I)V

    .line 784
    .line 785
    .line 786
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 787
    .line 788
    return-object p0

    .line 789
    :pswitch_17
    check-cast p1, Ll2/o;

    .line 790
    .line 791
    check-cast p2, Ljava/lang/Integer;

    .line 792
    .line 793
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 794
    .line 795
    .line 796
    const/4 p0, 0x1

    .line 797
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 798
    .line 799
    .line 800
    move-result p0

    .line 801
    invoke-static {p1, p0}, Ljp/ag;->c(Ll2/o;I)V

    .line 802
    .line 803
    .line 804
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 805
    .line 806
    return-object p0

    .line 807
    :pswitch_18
    check-cast p1, Ll2/o;

    .line 808
    .line 809
    check-cast p2, Ljava/lang/Integer;

    .line 810
    .line 811
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 812
    .line 813
    .line 814
    const/4 p0, 0x1

    .line 815
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 816
    .line 817
    .line 818
    move-result p0

    .line 819
    invoke-static {p1, p0}, Ljp/ag;->f(Ll2/o;I)V

    .line 820
    .line 821
    .line 822
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 823
    .line 824
    return-object p0

    .line 825
    :pswitch_19
    check-cast p1, Ll2/o;

    .line 826
    .line 827
    check-cast p2, Ljava/lang/Integer;

    .line 828
    .line 829
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 830
    .line 831
    .line 832
    const/4 p0, 0x1

    .line 833
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 834
    .line 835
    .line 836
    move-result p0

    .line 837
    invoke-static {p1, p0}, Ljp/ag;->h(Ll2/o;I)V

    .line 838
    .line 839
    .line 840
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 841
    .line 842
    return-object p0

    .line 843
    :pswitch_1a
    check-cast p1, Ll2/o;

    .line 844
    .line 845
    check-cast p2, Ljava/lang/Integer;

    .line 846
    .line 847
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 848
    .line 849
    .line 850
    const/4 p0, 0x1

    .line 851
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 852
    .line 853
    .line 854
    move-result p0

    .line 855
    invoke-static {p1, p0}, Ljp/zf;->a(Ll2/o;I)V

    .line 856
    .line 857
    .line 858
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 859
    .line 860
    return-object p0

    .line 861
    :pswitch_1b
    check-cast p1, Ll2/o;

    .line 862
    .line 863
    check-cast p2, Ljava/lang/Integer;

    .line 864
    .line 865
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 866
    .line 867
    .line 868
    const/4 p0, 0x1

    .line 869
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 870
    .line 871
    .line 872
    move-result p0

    .line 873
    invoke-static {p1, p0}, Ljp/yf;->i(Ll2/o;I)V

    .line 874
    .line 875
    .line 876
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 877
    .line 878
    return-object p0

    .line 879
    :pswitch_1c
    check-cast p1, Ll2/o;

    .line 880
    .line 881
    check-cast p2, Ljava/lang/Integer;

    .line 882
    .line 883
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 884
    .line 885
    .line 886
    const/4 p0, 0x1

    .line 887
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 888
    .line 889
    .line 890
    move-result p0

    .line 891
    invoke-static {p1, p0}, Ld80/b;->I(Ll2/o;I)V

    .line 892
    .line 893
    .line 894
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 895
    .line 896
    return-object p0

    .line 897
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
