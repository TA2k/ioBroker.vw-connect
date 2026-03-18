.class public final synthetic Ld80/a;
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
    iput p1, p0, Ld80/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Ld80/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget p0, p0, Ld80/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch p0, :pswitch_data_0

    .line 8
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
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 19
    .line 20
    invoke-static {p2, p1, p0}, Ld80/b;->G(Lx2/s;Ll2/o;I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    invoke-static {p1, p0}, Ld80/b;->J(Ll2/o;I)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x1

    .line 42
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    invoke-static {p1, p0}, Ld80/b;->E(Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    const/4 p0, 0x1

    .line 54
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    invoke-static {p1, p0}, Ld80/b;->E(Ll2/o;I)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    const/4 p0, 0x1

    .line 66
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    invoke-static {p1, p0}, Ld80/b;->L(Ll2/o;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    const/4 p0, 0x1

    .line 78
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 83
    .line 84
    invoke-static {p2, p1, p0}, Ld80/b;->C(Lx2/s;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :pswitch_5
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    const/4 p0, 0x1

    .line 92
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    invoke-static {p1, p0}, Ld80/b;->B(Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    goto :goto_0

    .line 100
    :pswitch_6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    const/4 p0, 0x1

    .line 104
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 105
    .line 106
    .line 107
    move-result p0

    .line 108
    invoke-static {p1, p0}, Ld80/b;->z(Ll2/o;I)V

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :pswitch_7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    const/4 p0, 0x1

    .line 116
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 117
    .line 118
    .line 119
    move-result p0

    .line 120
    invoke-static {p1, p0}, Ld80/b;->z(Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    goto :goto_0

    .line 124
    :pswitch_8
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    const/4 p0, 0x1

    .line 128
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-static {p1, p0}, Ld80/b;->x(Ll2/o;I)V

    .line 133
    .line 134
    .line 135
    goto :goto_0

    .line 136
    :pswitch_9
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    const/4 p0, 0x1

    .line 140
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 145
    .line 146
    invoke-static {p2, p1, p0}, Ld80/b;->v(Lx2/s;Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    goto :goto_0

    .line 150
    :pswitch_a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    const/4 p0, 0x1

    .line 154
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    invoke-static {p1, p0}, Ld80/b;->r(Ll2/o;I)V

    .line 159
    .line 160
    .line 161
    goto/16 :goto_0

    .line 162
    .line 163
    :pswitch_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    const/4 p0, 0x1

    .line 167
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    invoke-static {p1, p0}, Ld80/b;->p(Ll2/o;I)V

    .line 172
    .line 173
    .line 174
    goto/16 :goto_0

    .line 175
    .line 176
    :pswitch_c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    const/4 p0, 0x1

    .line 180
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 181
    .line 182
    .line 183
    move-result p0

    .line 184
    invoke-static {p1, p0}, Ld80/b;->p(Ll2/o;I)V

    .line 185
    .line 186
    .line 187
    goto/16 :goto_0

    .line 188
    .line 189
    :pswitch_d
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    const/4 p0, 0x1

    .line 193
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 194
    .line 195
    .line 196
    move-result p0

    .line 197
    invoke-static {p1, p0}, Ld80/b;->o(Ll2/o;I)V

    .line 198
    .line 199
    .line 200
    goto/16 :goto_0

    .line 201
    .line 202
    :pswitch_e
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 203
    .line 204
    .line 205
    const/4 p0, 0x1

    .line 206
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 207
    .line 208
    .line 209
    move-result p0

    .line 210
    invoke-static {p1, p0}, Ld80/b;->m(Ll2/o;I)V

    .line 211
    .line 212
    .line 213
    goto/16 :goto_0

    .line 214
    .line 215
    :pswitch_f
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    const/4 p0, 0x1

    .line 219
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    invoke-static {p1, p0}, Ld80/b;->m(Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    goto/16 :goto_0

    .line 227
    .line 228
    :pswitch_10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 229
    .line 230
    .line 231
    const/4 p0, 0x1

    .line 232
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 233
    .line 234
    .line 235
    move-result p0

    .line 236
    invoke-static {p1, p0}, Ld80/b;->j(Ll2/o;I)V

    .line 237
    .line 238
    .line 239
    goto/16 :goto_0

    .line 240
    .line 241
    :pswitch_11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 242
    .line 243
    .line 244
    const/4 p0, 0x1

    .line 245
    invoke-static {p0}, Ll2/b;->x(I)I

    .line 246
    .line 247
    .line 248
    move-result p0

    .line 249
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 250
    .line 251
    invoke-static {p2, p1, p0}, Ld80/b;->h(Lx2/s;Ll2/o;I)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_0

    .line 255
    .line 256
    :pswitch_12
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 257
    .line 258
    .line 259
    move-result p0

    .line 260
    and-int/lit8 p2, p0, 0x3

    .line 261
    .line 262
    const/4 v0, 0x2

    .line 263
    const/4 v1, 0x1

    .line 264
    if-eq p2, v0, :cond_0

    .line 265
    .line 266
    move p2, v1

    .line 267
    goto :goto_1

    .line 268
    :cond_0
    const/4 p2, 0x0

    .line 269
    :goto_1
    and-int/2addr p0, v1

    .line 270
    move-object v7, p1

    .line 271
    check-cast v7, Ll2/t;

    .line 272
    .line 273
    invoke-virtual {v7, p0, p2}, Ll2/t;->O(IZ)Z

    .line 274
    .line 275
    .line 276
    move-result p0

    .line 277
    if-eqz p0, :cond_1

    .line 278
    .line 279
    new-instance v2, Lc80/f0;

    .line 280
    .line 281
    const-string p0, "Your car will lock. Please ensure that it is empty."

    .line 282
    .line 283
    invoke-direct {v2, p0, p0, v1}, Lc80/f0;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 284
    .line 285
    .line 286
    const/4 v8, 0x0

    .line 287
    const/16 v9, 0x1e

    .line 288
    .line 289
    const/4 v3, 0x0

    .line 290
    const/4 v4, 0x0

    .line 291
    const/4 v5, 0x0

    .line 292
    const/4 v6, 0x0

    .line 293
    invoke-static/range {v2 .. v9}, Ld80/b;->H(Lc80/f0;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 294
    .line 295
    .line 296
    goto :goto_2

    .line 297
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 298
    .line 299
    .line 300
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_13
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 304
    .line 305
    .line 306
    move-result p0

    .line 307
    and-int/lit8 p2, p0, 0x3

    .line 308
    .line 309
    const/4 v0, 0x2

    .line 310
    const/4 v1, 0x1

    .line 311
    if-eq p2, v0, :cond_2

    .line 312
    .line 313
    move p2, v1

    .line 314
    goto :goto_3

    .line 315
    :cond_2
    const/4 p2, 0x0

    .line 316
    :goto_3
    and-int/2addr p0, v1

    .line 317
    check-cast p1, Ll2/t;

    .line 318
    .line 319
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 320
    .line 321
    .line 322
    move-result p0

    .line 323
    if-eqz p0, :cond_5

    .line 324
    .line 325
    new-instance p0, Lc80/b0;

    .line 326
    .line 327
    const/4 p2, 0x5

    .line 328
    invoke-direct {p0, p2}, Lc80/b0;-><init>(I)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object p2

    .line 335
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 336
    .line 337
    if-ne p2, v0, :cond_3

    .line 338
    .line 339
    new-instance p2, Lz81/g;

    .line 340
    .line 341
    const/4 v1, 0x2

    .line 342
    invoke-direct {p2, v1}, Lz81/g;-><init>(I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {p1, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    :cond_3
    check-cast p2, Lay0/a;

    .line 349
    .line 350
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    if-ne v1, v0, :cond_4

    .line 355
    .line 356
    new-instance v1, Lz81/g;

    .line 357
    .line 358
    const/4 v0, 0x2

    .line 359
    invoke-direct {v1, v0}, Lz81/g;-><init>(I)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    :cond_4
    check-cast v1, Lay0/a;

    .line 366
    .line 367
    const/16 v0, 0x1b0

    .line 368
    .line 369
    invoke-static {p0, p2, v1, p1, v0}, Ld80/b;->F(Lc80/b0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 370
    .line 371
    .line 372
    goto :goto_4

    .line 373
    :cond_5
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 374
    .line 375
    .line 376
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 377
    .line 378
    return-object p0

    .line 379
    :pswitch_14
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 380
    .line 381
    .line 382
    move-result p0

    .line 383
    and-int/lit8 p2, p0, 0x3

    .line 384
    .line 385
    const/4 v0, 0x2

    .line 386
    const/4 v1, 0x1

    .line 387
    if-eq p2, v0, :cond_6

    .line 388
    .line 389
    move p2, v1

    .line 390
    goto :goto_5

    .line 391
    :cond_6
    const/4 p2, 0x0

    .line 392
    :goto_5
    and-int/2addr p0, v1

    .line 393
    move-object v3, p1

    .line 394
    check-cast v3, Ll2/t;

    .line 395
    .line 396
    invoke-virtual {v3, p0, p2}, Ll2/t;->O(IZ)Z

    .line 397
    .line 398
    .line 399
    move-result p0

    .line 400
    if-eqz p0, :cond_7

    .line 401
    .line 402
    const/4 v4, 0x0

    .line 403
    const/4 v5, 0x7

    .line 404
    const/4 v0, 0x0

    .line 405
    const/4 v1, 0x0

    .line 406
    const/4 v2, 0x0

    .line 407
    invoke-static/range {v0 .. v5}, Ld80/b;->D(Lx2/s;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 408
    .line 409
    .line 410
    goto :goto_6

    .line 411
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 412
    .line 413
    .line 414
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 415
    .line 416
    return-object p0

    .line 417
    :pswitch_15
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 418
    .line 419
    .line 420
    move-result p0

    .line 421
    and-int/lit8 p2, p0, 0x3

    .line 422
    .line 423
    const/4 v0, 0x2

    .line 424
    const/4 v1, 0x1

    .line 425
    if-eq p2, v0, :cond_8

    .line 426
    .line 427
    move p2, v1

    .line 428
    goto :goto_7

    .line 429
    :cond_8
    const/4 p2, 0x0

    .line 430
    :goto_7
    and-int/2addr p0, v1

    .line 431
    move-object v10, p1

    .line 432
    check-cast v10, Ll2/t;

    .line 433
    .line 434
    invoke-virtual {v10, p0, p2}, Ll2/t;->O(IZ)Z

    .line 435
    .line 436
    .line 437
    move-result p0

    .line 438
    if-eqz p0, :cond_9

    .line 439
    .line 440
    new-instance v2, Lc80/w;

    .line 441
    .line 442
    const-string p0, "Your S-PIN is now active and can be used to manage services in My\u0160koda."

    .line 443
    .line 444
    const/16 p1, 0x31

    .line 445
    .line 446
    invoke-direct {v2, v1, p0, p1}, Lc80/w;-><init>(ZLjava/lang/String;I)V

    .line 447
    .line 448
    .line 449
    const/4 v11, 0x0

    .line 450
    const/16 v12, 0xfe

    .line 451
    .line 452
    const/4 v3, 0x0

    .line 453
    const/4 v4, 0x0

    .line 454
    const/4 v5, 0x0

    .line 455
    const/4 v6, 0x0

    .line 456
    const/4 v7, 0x0

    .line 457
    const/4 v8, 0x0

    .line 458
    const/4 v9, 0x0

    .line 459
    invoke-static/range {v2 .. v12}, Ld80/b;->A(Lc80/w;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 460
    .line 461
    .line 462
    goto :goto_8

    .line 463
    :cond_9
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 464
    .line 465
    .line 466
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 467
    .line 468
    return-object p0

    .line 469
    :pswitch_16
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 470
    .line 471
    .line 472
    move-result p0

    .line 473
    and-int/lit8 p2, p0, 0x3

    .line 474
    .line 475
    const/4 v0, 0x2

    .line 476
    const/4 v1, 0x1

    .line 477
    if-eq p2, v0, :cond_a

    .line 478
    .line 479
    move p2, v1

    .line 480
    goto :goto_9

    .line 481
    :cond_a
    const/4 p2, 0x0

    .line 482
    :goto_9
    and-int/2addr p0, v1

    .line 483
    move-object v8, p1

    .line 484
    check-cast v8, Ll2/t;

    .line 485
    .line 486
    invoke-virtual {v8, p0, p2}, Ll2/t;->O(IZ)Z

    .line 487
    .line 488
    .line 489
    move-result p0

    .line 490
    if-eqz p0, :cond_b

    .line 491
    .line 492
    new-instance v0, Lc80/r;

    .line 493
    .line 494
    const/4 p0, 0x0

    .line 495
    const/16 p1, 0x3f7

    .line 496
    .line 497
    invoke-direct {v0, p0, p1}, Lc80/r;-><init>(Ljava/lang/String;I)V

    .line 498
    .line 499
    .line 500
    const/4 v9, 0x0

    .line 501
    const/16 v10, 0xfe

    .line 502
    .line 503
    const/4 v1, 0x0

    .line 504
    const/4 v2, 0x0

    .line 505
    const/4 v3, 0x0

    .line 506
    const/4 v4, 0x0

    .line 507
    const/4 v5, 0x0

    .line 508
    const/4 v6, 0x0

    .line 509
    const/4 v7, 0x0

    .line 510
    invoke-static/range {v0 .. v10}, Ld80/b;->w(Lc80/r;Lx2/s;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Ll2/o;II)V

    .line 511
    .line 512
    .line 513
    goto :goto_a

    .line 514
    :cond_b
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 515
    .line 516
    .line 517
    :goto_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 518
    .line 519
    return-object p0

    .line 520
    :pswitch_17
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 521
    .line 522
    .line 523
    move-result p0

    .line 524
    and-int/lit8 p2, p0, 0x3

    .line 525
    .line 526
    const/4 v0, 0x2

    .line 527
    const/4 v1, 0x0

    .line 528
    const/4 v2, 0x1

    .line 529
    if-eq p2, v0, :cond_c

    .line 530
    .line 531
    move p2, v2

    .line 532
    goto :goto_b

    .line 533
    :cond_c
    move p2, v1

    .line 534
    :goto_b
    and-int/2addr p0, v2

    .line 535
    check-cast p1, Ll2/t;

    .line 536
    .line 537
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 538
    .line 539
    .line 540
    move-result p0

    .line 541
    if-eqz p0, :cond_d

    .line 542
    .line 543
    new-instance p0, Lc80/p;

    .line 544
    .line 545
    sget-object p2, Lyq0/h;->a:Lyq0/h;

    .line 546
    .line 547
    invoke-direct {p0, p2}, Lc80/p;-><init>(Lyq0/m;)V

    .line 548
    .line 549
    .line 550
    invoke-static {p0, p1, v1}, Ld80/b;->q(Lc80/p;Ll2/o;I)V

    .line 551
    .line 552
    .line 553
    goto :goto_c

    .line 554
    :cond_d
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 555
    .line 556
    .line 557
    :goto_c
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 558
    .line 559
    return-object p0

    .line 560
    :pswitch_18
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 561
    .line 562
    .line 563
    move-result p0

    .line 564
    and-int/lit8 p2, p0, 0x3

    .line 565
    .line 566
    const/4 v0, 0x2

    .line 567
    const/4 v1, 0x0

    .line 568
    const/4 v2, 0x1

    .line 569
    if-eq p2, v0, :cond_e

    .line 570
    .line 571
    move p2, v2

    .line 572
    goto :goto_d

    .line 573
    :cond_e
    move p2, v1

    .line 574
    :goto_d
    and-int/2addr p0, v2

    .line 575
    check-cast p1, Ll2/t;

    .line 576
    .line 577
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 578
    .line 579
    .line 580
    move-result p0

    .line 581
    if-eqz p0, :cond_f

    .line 582
    .line 583
    const/4 p0, 0x0

    .line 584
    const/4 p2, 0x3

    .line 585
    invoke-static {p0, p0, p1, v1, p2}, Ld80/b;->n(Lay0/a;Lay0/a;Ll2/o;II)V

    .line 586
    .line 587
    .line 588
    goto :goto_e

    .line 589
    :cond_f
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 590
    .line 591
    .line 592
    :goto_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 593
    .line 594
    return-object p0

    .line 595
    :pswitch_19
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 596
    .line 597
    .line 598
    move-result p0

    .line 599
    and-int/lit8 p2, p0, 0x3

    .line 600
    .line 601
    const/4 v0, 0x2

    .line 602
    const/4 v1, 0x1

    .line 603
    if-eq p2, v0, :cond_10

    .line 604
    .line 605
    move p2, v1

    .line 606
    goto :goto_f

    .line 607
    :cond_10
    const/4 p2, 0x0

    .line 608
    :goto_f
    and-int/2addr p0, v1

    .line 609
    move-object v7, p1

    .line 610
    check-cast v7, Ll2/t;

    .line 611
    .line 612
    invoke-virtual {v7, p0, p2}, Ll2/t;->O(IZ)Z

    .line 613
    .line 614
    .line 615
    move-result p0

    .line 616
    if-eqz p0, :cond_11

    .line 617
    .line 618
    new-instance v0, Lc80/k;

    .line 619
    .line 620
    invoke-direct {v0}, Lc80/k;-><init>()V

    .line 621
    .line 622
    .line 623
    const/4 v8, 0x0

    .line 624
    const/16 v9, 0x7e

    .line 625
    .line 626
    const/4 v1, 0x0

    .line 627
    const/4 v2, 0x0

    .line 628
    const/4 v3, 0x0

    .line 629
    const/4 v4, 0x0

    .line 630
    const/4 v5, 0x0

    .line 631
    const/4 v6, 0x0

    .line 632
    invoke-static/range {v0 .. v9}, Ld80/b;->i(Lc80/k;Lx2/s;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;Ll2/o;II)V

    .line 633
    .line 634
    .line 635
    goto :goto_10

    .line 636
    :cond_11
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 637
    .line 638
    .line 639
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 640
    .line 641
    return-object p0

    .line 642
    :pswitch_1a
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 643
    .line 644
    .line 645
    move-result p0

    .line 646
    and-int/lit8 p2, p0, 0x3

    .line 647
    .line 648
    const/4 v0, 0x0

    .line 649
    const/4 v1, 0x1

    .line 650
    const/4 v2, 0x2

    .line 651
    if-eq p2, v2, :cond_12

    .line 652
    .line 653
    move p2, v1

    .line 654
    goto :goto_11

    .line 655
    :cond_12
    move p2, v0

    .line 656
    :goto_11
    and-int/2addr p0, v1

    .line 657
    check-cast p1, Ll2/t;

    .line 658
    .line 659
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 660
    .line 661
    .line 662
    move-result p0

    .line 663
    if-eqz p0, :cond_13

    .line 664
    .line 665
    new-instance p0, Lc80/i;

    .line 666
    .line 667
    sget-object p2, Lc80/h;->f:Lc80/h;

    .line 668
    .line 669
    const/16 v1, 0xe

    .line 670
    .line 671
    invoke-direct {p0, p2, v1}, Lc80/i;-><init>(Lc80/h;I)V

    .line 672
    .line 673
    .line 674
    const/4 p2, 0x0

    .line 675
    invoke-static {p0, p2, p1, v0, v2}, Ld80/b;->f(Lc80/i;Lay0/a;Ll2/o;II)V

    .line 676
    .line 677
    .line 678
    goto :goto_12

    .line 679
    :cond_13
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 680
    .line 681
    .line 682
    :goto_12
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 683
    .line 684
    return-object p0

    .line 685
    :pswitch_1b
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 686
    .line 687
    .line 688
    move-result p0

    .line 689
    and-int/lit8 p2, p0, 0x3

    .line 690
    .line 691
    const/4 v0, 0x2

    .line 692
    const/4 v1, 0x1

    .line 693
    if-eq p2, v0, :cond_14

    .line 694
    .line 695
    move p2, v1

    .line 696
    goto :goto_13

    .line 697
    :cond_14
    const/4 p2, 0x0

    .line 698
    :goto_13
    and-int/2addr p0, v1

    .line 699
    move-object v4, p1

    .line 700
    check-cast v4, Ll2/t;

    .line 701
    .line 702
    invoke-virtual {v4, p0, p2}, Ll2/t;->O(IZ)Z

    .line 703
    .line 704
    .line 705
    move-result p0

    .line 706
    if-eqz p0, :cond_15

    .line 707
    .line 708
    new-instance v0, Lc80/c;

    .line 709
    .line 710
    const/4 p0, 0x6

    .line 711
    const/4 p1, 0x0

    .line 712
    invoke-direct {v0, p1, p1, p0}, Lc80/c;-><init>(Lc80/b;Lc80/a;I)V

    .line 713
    .line 714
    .line 715
    const/4 v5, 0x0

    .line 716
    const/16 v6, 0xe

    .line 717
    .line 718
    const/4 v1, 0x0

    .line 719
    const/4 v2, 0x0

    .line 720
    const/4 v3, 0x0

    .line 721
    invoke-static/range {v0 .. v6}, Ld80/b;->b(Lc80/c;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 722
    .line 723
    .line 724
    goto :goto_14

    .line 725
    :cond_15
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 726
    .line 727
    .line 728
    :goto_14
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 729
    .line 730
    return-object p0

    .line 731
    :pswitch_1c
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 732
    .line 733
    .line 734
    move-result p0

    .line 735
    and-int/lit8 p2, p0, 0x3

    .line 736
    .line 737
    const/4 v0, 0x2

    .line 738
    const/4 v1, 0x1

    .line 739
    if-eq p2, v0, :cond_16

    .line 740
    .line 741
    move p2, v1

    .line 742
    goto :goto_15

    .line 743
    :cond_16
    const/4 p2, 0x0

    .line 744
    :goto_15
    and-int/2addr p0, v1

    .line 745
    move-object v7, p1

    .line 746
    check-cast v7, Ll2/t;

    .line 747
    .line 748
    invoke-virtual {v7, p0, p2}, Ll2/t;->O(IZ)Z

    .line 749
    .line 750
    .line 751
    move-result p0

    .line 752
    if-eqz p0, :cond_18

    .line 753
    .line 754
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 755
    .line 756
    .line 757
    move-result-object p0

    .line 758
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 759
    .line 760
    if-ne p0, p1, :cond_17

    .line 761
    .line 762
    new-instance p0, Lz81/g;

    .line 763
    .line 764
    const/4 p1, 0x2

    .line 765
    invoke-direct {p0, p1}, Lz81/g;-><init>(I)V

    .line 766
    .line 767
    .line 768
    invoke-virtual {v7, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 769
    .line 770
    .line 771
    :cond_17
    check-cast p0, Lay0/a;

    .line 772
    .line 773
    new-instance v3, Li91/x2;

    .line 774
    .line 775
    const/4 p1, 0x3

    .line 776
    invoke-direct {v3, p0, p1}, Li91/x2;-><init>(Lay0/a;I)V

    .line 777
    .line 778
    .line 779
    const/4 v8, 0x0

    .line 780
    const/16 v9, 0x3bf

    .line 781
    .line 782
    const/4 v0, 0x0

    .line 783
    const/4 v1, 0x0

    .line 784
    const/4 v2, 0x0

    .line 785
    const/4 v4, 0x0

    .line 786
    const/4 v5, 0x0

    .line 787
    const/4 v6, 0x0

    .line 788
    invoke-static/range {v0 .. v9}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 789
    .line 790
    .line 791
    goto :goto_16

    .line 792
    :cond_18
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 793
    .line 794
    .line 795
    :goto_16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 796
    .line 797
    return-object p0

    .line 798
    nop

    .line 799
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
