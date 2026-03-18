.class public final synthetic Lt61/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lt61/g;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lt61/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lt61/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 66

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lt61/g;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0xa

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x1

    .line 10
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v7, v0, Lt61/g;->f:Ljava/lang/Object;

    .line 13
    .line 14
    iget-object v0, v0, Lt61/g;->e:Ljava/lang/Object;

    .line 15
    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    check-cast v0, Lay0/k;

    .line 20
    .line 21
    check-cast v7, Lwc/f;

    .line 22
    .line 23
    new-instance v1, Lwc/d;

    .line 24
    .line 25
    iget-boolean v2, v7, Lwc/f;->e:Z

    .line 26
    .line 27
    xor-int/2addr v2, v5

    .line 28
    invoke-direct {v1, v2}, Lwc/d;-><init>(Z)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    return-object v6

    .line 35
    :pswitch_0
    check-cast v0, Ljava/lang/String;

    .line 36
    .line 37
    check-cast v7, Luz0/y;

    .line 38
    .line 39
    sget-object v1, Lsz0/k;->e:Lsz0/k;

    .line 40
    .line 41
    new-array v2, v4, [Lsz0/g;

    .line 42
    .line 43
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 44
    .line 45
    invoke-direct {v4, v7, v3}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    invoke-static {v0, v1, v2, v4}, Lkp/x8;->d(Ljava/lang/String;Lkp/y8;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    return-object v0

    .line 53
    :pswitch_1
    check-cast v0, Luz0/y;

    .line 54
    .line 55
    check-cast v7, Ljava/lang/String;

    .line 56
    .line 57
    iget-object v1, v0, Luz0/y;->c:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v1, Luz0/x;

    .line 60
    .line 61
    if-nez v1, :cond_0

    .line 62
    .line 63
    new-instance v1, Luz0/x;

    .line 64
    .line 65
    iget-object v0, v0, Luz0/y;->b:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, [Ljava/lang/Enum;

    .line 68
    .line 69
    array-length v2, v0

    .line 70
    invoke-direct {v1, v7, v2}, Luz0/x;-><init>(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    array-length v2, v0

    .line 74
    move v3, v4

    .line 75
    :goto_0
    if-ge v3, v2, :cond_0

    .line 76
    .line 77
    aget-object v5, v0, v3

    .line 78
    .line 79
    invoke-virtual {v5}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-virtual {v1, v5, v4}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 84
    .line 85
    .line 86
    add-int/lit8 v3, v3, 0x1

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_0
    return-object v1

    .line 90
    :pswitch_2
    check-cast v0, Lay0/k;

    .line 91
    .line 92
    check-cast v7, Ltz/i4;

    .line 93
    .line 94
    invoke-interface {v0, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    return-object v6

    .line 98
    :pswitch_3
    check-cast v0, Lay0/k;

    .line 99
    .line 100
    check-cast v7, Ltz/w3;

    .line 101
    .line 102
    invoke-interface {v0, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    return-object v6

    .line 106
    :pswitch_4
    check-cast v0, Lay0/k;

    .line 107
    .line 108
    check-cast v7, Ltz/m3;

    .line 109
    .line 110
    invoke-interface {v0, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    return-object v6

    .line 114
    :pswitch_5
    check-cast v0, Lay0/k;

    .line 115
    .line 116
    check-cast v7, Ltz/e3;

    .line 117
    .line 118
    invoke-interface {v0, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    return-object v6

    .line 122
    :pswitch_6
    check-cast v0, Lay0/k;

    .line 123
    .line 124
    check-cast v7, Ltz/l2;

    .line 125
    .line 126
    iget-wide v1, v7, Ltz/l2;->a:J

    .line 127
    .line 128
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    return-object v6

    .line 136
    :pswitch_7
    check-cast v0, Lay0/k;

    .line 137
    .line 138
    check-cast v7, Ltz/v1;

    .line 139
    .line 140
    iget-wide v1, v7, Ltz/v1;->a:J

    .line 141
    .line 142
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    return-object v6

    .line 150
    :pswitch_8
    check-cast v0, Lay0/k;

    .line 151
    .line 152
    check-cast v7, Lsg/f;

    .line 153
    .line 154
    new-instance v1, Lsg/m;

    .line 155
    .line 156
    invoke-direct {v1, v7}, Lsg/m;-><init>(Lsg/f;)V

    .line 157
    .line 158
    .line 159
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    return-object v6

    .line 163
    :pswitch_9
    check-cast v0, Lu/c1;

    .line 164
    .line 165
    check-cast v7, Ljava/util/List;

    .line 166
    .line 167
    iget-object v0, v0, Lu/c1;->m:Lv/b;

    .line 168
    .line 169
    sget-object v1, Lu/b1;->a:Lh0/g;

    .line 170
    .line 171
    const-string v1, "characteristicsCompat"

    .line 172
    .line 173
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 177
    .line 178
    const/16 v2, 0x21

    .line 179
    .line 180
    if-ge v1, v2, :cond_1

    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_1
    invoke-static {}, Lu/a1;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    invoke-virtual {v0, v1}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    check-cast v0, [J

    .line 192
    .line 193
    if-eqz v0, :cond_6

    .line 194
    .line 195
    array-length v1, v0

    .line 196
    if-nez v1, :cond_2

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_2
    new-instance v1, Ljava/util/HashSet;

    .line 200
    .line 201
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 202
    .line 203
    .line 204
    array-length v2, v0

    .line 205
    move v3, v4

    .line 206
    :goto_1
    if-ge v3, v2, :cond_3

    .line 207
    .line 208
    aget-wide v8, v0, v3

    .line 209
    .line 210
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    invoke-virtual {v1, v6}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    add-int/lit8 v3, v3, 0x1

    .line 218
    .line 219
    goto :goto_1

    .line 220
    :cond_3
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    :cond_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    if-eqz v2, :cond_5

    .line 229
    .line 230
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    check-cast v2, Lh0/h2;

    .line 235
    .line 236
    iget-object v2, v2, Lh0/h2;->c:Lh0/c2;

    .line 237
    .line 238
    iget-wide v2, v2, Lh0/c2;->d:J

    .line 239
    .line 240
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 241
    .line 242
    .line 243
    move-result-object v2

    .line 244
    invoke-virtual {v1, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    if-nez v2, :cond_4

    .line 249
    .line 250
    goto :goto_2

    .line 251
    :cond_5
    move v4, v5

    .line 252
    :cond_6
    :goto_2
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    return-object v0

    .line 257
    :pswitch_a
    check-cast v0, Ltz/a3;

    .line 258
    .line 259
    check-cast v7, Lcn0/c;

    .line 260
    .line 261
    invoke-virtual {v0, v7, v5}, Ltz/a3;->q(Lcn0/c;Z)V

    .line 262
    .line 263
    .line 264
    return-object v6

    .line 265
    :pswitch_b
    check-cast v0, Ltz/p2;

    .line 266
    .line 267
    check-cast v7, Lcn0/c;

    .line 268
    .line 269
    iget-object v1, v7, Lcn0/c;->e:Lcn0/a;

    .line 270
    .line 271
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    move-object v7, v5

    .line 276
    check-cast v7, Ltz/n2;

    .line 277
    .line 278
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 279
    .line 280
    .line 281
    move-result-object v5

    .line 282
    check-cast v5, Ltz/n2;

    .line 283
    .line 284
    iget-object v5, v5, Ltz/n2;->a:Ljava/util/List;

    .line 285
    .line 286
    check-cast v5, Ljava/lang/Iterable;

    .line 287
    .line 288
    new-instance v8, Ljava/util/ArrayList;

    .line 289
    .line 290
    invoke-static {v5, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 291
    .line 292
    .line 293
    move-result v3

    .line 294
    invoke-direct {v8, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 295
    .line 296
    .line 297
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 298
    .line 299
    .line 300
    move-result-object v3

    .line 301
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 302
    .line 303
    .line 304
    move-result v5

    .line 305
    if-eqz v5, :cond_7

    .line 306
    .line 307
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v5

    .line 311
    check-cast v5, Ltz/l2;

    .line 312
    .line 313
    iget-wide v10, v5, Ltz/l2;->a:J

    .line 314
    .line 315
    iget-object v12, v5, Ltz/l2;->b:Ljava/lang/String;

    .line 316
    .line 317
    iget-object v13, v5, Ltz/l2;->c:Ljava/lang/String;

    .line 318
    .line 319
    iget-boolean v15, v5, Ltz/l2;->e:Z

    .line 320
    .line 321
    const-string v5, "name"

    .line 322
    .line 323
    invoke-static {v12, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    new-instance v9, Ltz/l2;

    .line 327
    .line 328
    const/4 v14, 0x0

    .line 329
    invoke-direct/range {v9 .. v15}, Ltz/l2;-><init>(JLjava/lang/String;Ljava/lang/String;ZZ)V

    .line 330
    .line 331
    .line 332
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 333
    .line 334
    .line 335
    goto :goto_3

    .line 336
    :cond_7
    iget-object v3, v0, Ltz/p2;->r:Lij0/a;

    .line 337
    .line 338
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 339
    .line 340
    .line 341
    move-result v1

    .line 342
    packed-switch v1, :pswitch_data_1

    .line 343
    .line 344
    .line 345
    :goto_4
    move-object v11, v2

    .line 346
    goto :goto_5

    .line 347
    :pswitch_c
    new-array v1, v4, [Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v3, Ljj0/f;

    .line 350
    .line 351
    const v2, 0x7f120f90

    .line 352
    .line 353
    .line 354
    invoke-virtual {v3, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    goto :goto_4

    .line 359
    :pswitch_d
    new-array v1, v4, [Ljava/lang/Object;

    .line 360
    .line 361
    check-cast v3, Ljj0/f;

    .line 362
    .line 363
    const v2, 0x7f120fad

    .line 364
    .line 365
    .line 366
    invoke-virtual {v3, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    goto :goto_4

    .line 371
    :goto_5
    const/4 v15, 0x0

    .line 372
    const/16 v16, 0xf6

    .line 373
    .line 374
    const/4 v9, 0x0

    .line 375
    const/4 v10, 0x0

    .line 376
    const/4 v12, 0x0

    .line 377
    const/4 v13, 0x0

    .line 378
    const/4 v14, 0x0

    .line 379
    invoke-static/range {v7 .. v16}, Ltz/n2;->a(Ltz/n2;Ljava/util/List;ZZLjava/lang/String;Ltz/m2;Ler0/g;Llf0/i;ZI)Ltz/n2;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 384
    .line 385
    .line 386
    return-object v6

    .line 387
    :pswitch_e
    check-cast v0, Ltz/n0;

    .line 388
    .line 389
    check-cast v7, Lcn0/c;

    .line 390
    .line 391
    iget-object v1, v7, Lcn0/c;->e:Lcn0/a;

    .line 392
    .line 393
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 394
    .line 395
    .line 396
    move-result v7

    .line 397
    const/16 v8, 0x15

    .line 398
    .line 399
    const/16 v9, 0xd

    .line 400
    .line 401
    if-eq v7, v3, :cond_8

    .line 402
    .line 403
    if-eq v7, v9, :cond_8

    .line 404
    .line 405
    if-eq v7, v8, :cond_8

    .line 406
    .line 407
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    check-cast v1, Ltz/f0;

    .line 412
    .line 413
    goto/16 :goto_a

    .line 414
    .line 415
    :cond_8
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 416
    .line 417
    .line 418
    move-result-object v7

    .line 419
    move-object v10, v7

    .line 420
    check-cast v10, Ltz/f0;

    .line 421
    .line 422
    iget-object v7, v0, Ltz/n0;->v:Lij0/a;

    .line 423
    .line 424
    const-string v11, "<this>"

    .line 425
    .line 426
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 427
    .line 428
    .line 429
    const-string v11, "stringResource"

    .line 430
    .line 431
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 432
    .line 433
    .line 434
    sget-object v11, Ltz/o0;->a:[I

    .line 435
    .line 436
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 437
    .line 438
    .line 439
    move-result v12

    .line 440
    aget v11, v11, v12

    .line 441
    .line 442
    if-ne v11, v5, :cond_9

    .line 443
    .line 444
    new-array v5, v4, [Ljava/lang/Object;

    .line 445
    .line 446
    check-cast v7, Ljj0/f;

    .line 447
    .line 448
    const v11, 0x7f12043b

    .line 449
    .line 450
    .line 451
    invoke-virtual {v7, v11, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v5

    .line 455
    :goto_6
    move-object/from16 v16, v5

    .line 456
    .line 457
    goto :goto_7

    .line 458
    :cond_9
    new-array v5, v4, [Ljava/lang/Object;

    .line 459
    .line 460
    check-cast v7, Ljj0/f;

    .line 461
    .line 462
    const v11, 0x7f12045b

    .line 463
    .line 464
    .line 465
    invoke-virtual {v7, v11, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object v5

    .line 469
    goto :goto_6

    .line 470
    :goto_7
    const/16 v36, 0x0

    .line 471
    .line 472
    const v37, 0xfffff3f

    .line 473
    .line 474
    .line 475
    const/4 v11, 0x0

    .line 476
    const/4 v12, 0x0

    .line 477
    const/4 v13, 0x0

    .line 478
    const/4 v14, 0x0

    .line 479
    const/4 v15, 0x0

    .line 480
    const/16 v17, 0x0

    .line 481
    .line 482
    const/16 v18, 0x0

    .line 483
    .line 484
    const/16 v19, 0x0

    .line 485
    .line 486
    const/16 v20, 0x0

    .line 487
    .line 488
    const/16 v21, 0x0

    .line 489
    .line 490
    const/16 v22, 0x0

    .line 491
    .line 492
    const/16 v23, 0x0

    .line 493
    .line 494
    const/16 v24, 0x0

    .line 495
    .line 496
    const/16 v25, 0x0

    .line 497
    .line 498
    const/16 v26, 0x0

    .line 499
    .line 500
    const/16 v27, 0x0

    .line 501
    .line 502
    const/16 v28, 0x0

    .line 503
    .line 504
    const/16 v29, 0x0

    .line 505
    .line 506
    const/16 v30, 0x0

    .line 507
    .line 508
    const/16 v31, 0x0

    .line 509
    .line 510
    const/16 v32, 0x0

    .line 511
    .line 512
    const/16 v33, 0x0

    .line 513
    .line 514
    const/16 v34, 0x0

    .line 515
    .line 516
    const/16 v35, 0x0

    .line 517
    .line 518
    invoke-static/range {v10 .. v37}, Ltz/f0;->a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;

    .line 519
    .line 520
    .line 521
    move-result-object v5

    .line 522
    iget-object v7, v5, Ltz/f0;->n:Ltz/z;

    .line 523
    .line 524
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 525
    .line 526
    .line 527
    move-result v1

    .line 528
    if-eq v1, v3, :cond_11

    .line 529
    .line 530
    if-eq v1, v9, :cond_f

    .line 531
    .line 532
    if-eq v1, v8, :cond_a

    .line 533
    .line 534
    move-object v1, v5

    .line 535
    goto/16 :goto_a

    .line 536
    .line 537
    :cond_a
    iget-object v1, v5, Ltz/f0;->o:Ltz/x;

    .line 538
    .line 539
    if-eqz v1, :cond_b

    .line 540
    .line 541
    new-instance v1, Ltz/x;

    .line 542
    .line 543
    invoke-direct {v1, v4}, Ltz/x;-><init>(Z)V

    .line 544
    .line 545
    .line 546
    move-object/from16 v51, v1

    .line 547
    .line 548
    goto :goto_8

    .line 549
    :cond_b
    move-object/from16 v51, v2

    .line 550
    .line 551
    :goto_8
    iget-object v1, v5, Ltz/f0;->p:Ltz/y;

    .line 552
    .line 553
    if-eqz v1, :cond_c

    .line 554
    .line 555
    new-instance v1, Ltz/y;

    .line 556
    .line 557
    invoke-direct {v1, v4}, Ltz/y;-><init>(Z)V

    .line 558
    .line 559
    .line 560
    move-object/from16 v52, v1

    .line 561
    .line 562
    goto :goto_9

    .line 563
    :cond_c
    move-object/from16 v52, v2

    .line 564
    .line 565
    :goto_9
    new-instance v1, Ltz/v;

    .line 566
    .line 567
    invoke-direct {v1, v4}, Ltz/v;-><init>(Z)V

    .line 568
    .line 569
    .line 570
    iget-object v3, v10, Ltz/f0;->q:Llp/p0;

    .line 571
    .line 572
    instance-of v7, v3, Ltz/c0;

    .line 573
    .line 574
    if-eqz v7, :cond_d

    .line 575
    .line 576
    move-object v2, v3

    .line 577
    check-cast v2, Ltz/c0;

    .line 578
    .line 579
    :cond_d
    if-eqz v2, :cond_e

    .line 580
    .line 581
    const-string v3, "Saving limit\u2026"

    .line 582
    .line 583
    const/16 v7, 0x77e

    .line 584
    .line 585
    invoke-static {v2, v3, v4, v7}, Ltz/c0;->b(Ltz/c0;Ljava/lang/String;II)Ltz/c0;

    .line 586
    .line 587
    .line 588
    move-result-object v3

    .line 589
    :cond_e
    move-object/from16 v53, v3

    .line 590
    .line 591
    const/16 v64, 0x0

    .line 592
    .line 593
    const v65, 0xffe1fff

    .line 594
    .line 595
    .line 596
    const/16 v39, 0x0

    .line 597
    .line 598
    const/16 v40, 0x0

    .line 599
    .line 600
    const/16 v41, 0x0

    .line 601
    .line 602
    const/16 v42, 0x0

    .line 603
    .line 604
    const/16 v43, 0x0

    .line 605
    .line 606
    const/16 v44, 0x0

    .line 607
    .line 608
    const/16 v45, 0x0

    .line 609
    .line 610
    const/16 v46, 0x0

    .line 611
    .line 612
    const/16 v47, 0x0

    .line 613
    .line 614
    const/16 v48, 0x0

    .line 615
    .line 616
    const/16 v49, 0x0

    .line 617
    .line 618
    const/16 v54, 0x0

    .line 619
    .line 620
    const/16 v55, 0x0

    .line 621
    .line 622
    const/16 v56, 0x0

    .line 623
    .line 624
    const/16 v57, 0x0

    .line 625
    .line 626
    const/16 v58, 0x0

    .line 627
    .line 628
    const/16 v59, 0x0

    .line 629
    .line 630
    const/16 v60, 0x0

    .line 631
    .line 632
    const/16 v61, 0x0

    .line 633
    .line 634
    const/16 v62, 0x0

    .line 635
    .line 636
    const/16 v63, 0x0

    .line 637
    .line 638
    move-object/from16 v50, v1

    .line 639
    .line 640
    move-object/from16 v38, v5

    .line 641
    .line 642
    invoke-static/range {v38 .. v65}, Ltz/f0;->a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;

    .line 643
    .line 644
    .line 645
    move-result-object v1

    .line 646
    goto/16 :goto_a

    .line 647
    .line 648
    :cond_f
    move-object/from16 v38, v5

    .line 649
    .line 650
    new-instance v1, Ltz/y;

    .line 651
    .line 652
    invoke-direct {v1, v4}, Ltz/y;-><init>(Z)V

    .line 653
    .line 654
    .line 655
    if-eqz v7, :cond_10

    .line 656
    .line 657
    new-instance v2, Ltz/v;

    .line 658
    .line 659
    invoke-direct {v2, v4}, Ltz/v;-><init>(Z)V

    .line 660
    .line 661
    .line 662
    :cond_10
    move-object/from16 v50, v2

    .line 663
    .line 664
    const/16 v64, 0x0

    .line 665
    .line 666
    const v65, 0xfff1fff

    .line 667
    .line 668
    .line 669
    const/16 v39, 0x0

    .line 670
    .line 671
    const/16 v40, 0x0

    .line 672
    .line 673
    const/16 v41, 0x0

    .line 674
    .line 675
    const/16 v42, 0x0

    .line 676
    .line 677
    const/16 v43, 0x0

    .line 678
    .line 679
    const/16 v44, 0x0

    .line 680
    .line 681
    const/16 v45, 0x0

    .line 682
    .line 683
    const/16 v46, 0x0

    .line 684
    .line 685
    const/16 v47, 0x0

    .line 686
    .line 687
    const/16 v48, 0x0

    .line 688
    .line 689
    const/16 v49, 0x0

    .line 690
    .line 691
    const/16 v51, 0x0

    .line 692
    .line 693
    const/16 v53, 0x0

    .line 694
    .line 695
    const/16 v54, 0x0

    .line 696
    .line 697
    const/16 v55, 0x0

    .line 698
    .line 699
    const/16 v56, 0x0

    .line 700
    .line 701
    const/16 v57, 0x0

    .line 702
    .line 703
    const/16 v58, 0x0

    .line 704
    .line 705
    const/16 v59, 0x0

    .line 706
    .line 707
    const/16 v60, 0x0

    .line 708
    .line 709
    const/16 v61, 0x0

    .line 710
    .line 711
    const/16 v62, 0x0

    .line 712
    .line 713
    const/16 v63, 0x0

    .line 714
    .line 715
    move-object/from16 v52, v1

    .line 716
    .line 717
    invoke-static/range {v38 .. v65}, Ltz/f0;->a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    goto :goto_a

    .line 722
    :cond_11
    move-object/from16 v38, v5

    .line 723
    .line 724
    new-instance v1, Ltz/x;

    .line 725
    .line 726
    invoke-direct {v1, v4}, Ltz/x;-><init>(Z)V

    .line 727
    .line 728
    .line 729
    if-eqz v7, :cond_12

    .line 730
    .line 731
    new-instance v2, Ltz/v;

    .line 732
    .line 733
    invoke-direct {v2, v4}, Ltz/v;-><init>(Z)V

    .line 734
    .line 735
    .line 736
    :cond_12
    move-object/from16 v50, v2

    .line 737
    .line 738
    const/16 v64, 0x0

    .line 739
    .line 740
    const v65, 0xfff1fff

    .line 741
    .line 742
    .line 743
    const/16 v39, 0x0

    .line 744
    .line 745
    const/16 v40, 0x0

    .line 746
    .line 747
    const/16 v41, 0x0

    .line 748
    .line 749
    const/16 v42, 0x0

    .line 750
    .line 751
    const/16 v43, 0x0

    .line 752
    .line 753
    const/16 v44, 0x0

    .line 754
    .line 755
    const/16 v45, 0x0

    .line 756
    .line 757
    const/16 v46, 0x0

    .line 758
    .line 759
    const/16 v47, 0x0

    .line 760
    .line 761
    const/16 v48, 0x0

    .line 762
    .line 763
    const/16 v49, 0x0

    .line 764
    .line 765
    const/16 v52, 0x0

    .line 766
    .line 767
    const/16 v53, 0x0

    .line 768
    .line 769
    const/16 v54, 0x0

    .line 770
    .line 771
    const/16 v55, 0x0

    .line 772
    .line 773
    const/16 v56, 0x0

    .line 774
    .line 775
    const/16 v57, 0x0

    .line 776
    .line 777
    const/16 v58, 0x0

    .line 778
    .line 779
    const/16 v59, 0x0

    .line 780
    .line 781
    const/16 v60, 0x0

    .line 782
    .line 783
    const/16 v61, 0x0

    .line 784
    .line 785
    const/16 v62, 0x0

    .line 786
    .line 787
    const/16 v63, 0x0

    .line 788
    .line 789
    move-object/from16 v51, v1

    .line 790
    .line 791
    invoke-static/range {v38 .. v65}, Ltz/f0;->a(Ltz/f0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ltz/e0;ZLtz/z;Ltz/x;Ltz/y;Llp/p0;Ltz/a0;Lne0/c;ZZZZZLjava/lang/String;Ljava/lang/String;ZLjava/lang/String;I)Ltz/f0;

    .line 792
    .line 793
    .line 794
    move-result-object v1

    .line 795
    :goto_a
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 796
    .line 797
    .line 798
    return-object v6

    .line 799
    :pswitch_f
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 800
    .line 801
    check-cast v7, Ltechnology/cariad/cat/genx/InternalVehicle;

    .line 802
    .line 803
    invoke-static {v0, v7}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->w(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/InternalVehicle;)Llx0/b0;

    .line 804
    .line 805
    .line 806
    move-result-object v0

    .line 807
    return-object v0

    .line 808
    :pswitch_10
    check-cast v0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;

    .line 809
    .line 810
    check-cast v7, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 811
    .line 812
    invoke-static {v0, v7}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->Y(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp;Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;)Llx0/b0;

    .line 813
    .line 814
    .line 815
    move-result-object v0

    .line 816
    return-object v0

    .line 817
    :pswitch_11
    check-cast v0, Ltechnology/cariad/cat/genx/QRCode;

    .line 818
    .line 819
    check-cast v7, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 820
    .line 821
    invoke-static {v0, v7}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->I(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;)Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object v0

    .line 825
    return-object v0

    .line 826
    :pswitch_12
    check-cast v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 827
    .line 828
    check-cast v7, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 829
    .line 830
    invoke-static {v0, v7}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->x(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)Ljava/lang/String;

    .line 831
    .line 832
    .line 833
    move-result-object v0

    .line 834
    return-object v0

    .line 835
    :pswitch_13
    check-cast v0, Lay0/k;

    .line 836
    .line 837
    check-cast v7, Lsa0/j;

    .line 838
    .line 839
    iget-boolean v1, v7, Lsa0/j;->b:Z

    .line 840
    .line 841
    xor-int/2addr v1, v5

    .line 842
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 843
    .line 844
    .line 845
    move-result-object v1

    .line 846
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 847
    .line 848
    .line 849
    return-object v6

    .line 850
    :pswitch_14
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;

    .line 851
    .line 852
    check-cast v7, Lh91/c;

    .line 853
    .line 854
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->B(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;

    .line 855
    .line 856
    .line 857
    move-result-object v0

    .line 858
    return-object v0

    .line 859
    :pswitch_15
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;

    .line 860
    .line 861
    check-cast v7, Lh91/c;

    .line 862
    .line 863
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->M(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;

    .line 864
    .line 865
    .line 866
    move-result-object v0

    .line 867
    return-object v0

    .line 868
    :pswitch_16
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;

    .line 869
    .line 870
    check-cast v7, Lh91/c;

    .line 871
    .line 872
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->j(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;

    .line 873
    .line 874
    .line 875
    move-result-object v0

    .line 876
    return-object v0

    .line 877
    :pswitch_17
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 878
    .line 879
    check-cast v7, Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;

    .line 880
    .line 881
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$onSoftwareStackIncompatibilityEncountered(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)V

    .line 882
    .line 883
    .line 884
    return-object v6

    .line 885
    :pswitch_18
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 886
    .line 887
    check-cast v7, Ljava/lang/String;

    .line 888
    .line 889
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 890
    .line 891
    .line 892
    move-result-object v0

    .line 893
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 894
    .line 895
    .line 896
    move-result-object v0

    .line 897
    const-string v1, "onVehicleReceivedLinkParameters() for vehicle "

    .line 898
    .line 899
    const-string v2, ": "

    .line 900
    .line 901
    invoke-static {v1, v0, v2, v7}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 902
    .line 903
    .line 904
    move-result-object v0

    .line 905
    return-object v0

    .line 906
    :pswitch_19
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 907
    .line 908
    check-cast v7, Llx0/l;

    .line 909
    .line 910
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$onConnectionErrorEncountered(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Llx0/l;)V

    .line 911
    .line 912
    .line 913
    return-object v6

    .line 914
    :pswitch_1a
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 915
    .line 916
    check-cast v7, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 917
    .line 918
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$onCar2PhoneModeReceived(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ltechnology/cariad/cat/genx/Car2PhoneMode;)V

    .line 919
    .line 920
    .line 921
    return-object v6

    .line 922
    :pswitch_1b
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 923
    .line 924
    check-cast v7, Lt71/f;

    .line 925
    .line 926
    invoke-static {v0, v7}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$onSendWindowStatusReceived(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lt71/f;)V

    .line 927
    .line 928
    .line 929
    return-object v6

    .line 930
    :pswitch_1c
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 931
    .line 932
    check-cast v7, Ltechnology/cariad/cat/genx/GenXError;

    .line 933
    .line 934
    new-instance v1, Ljava/lang/StringBuilder;

    .line 935
    .line 936
    const-string v2, "onConnectionDropped(): connection = "

    .line 937
    .line 938
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 939
    .line 940
    .line 941
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 942
    .line 943
    .line 944
    const-string v0, ", error = "

    .line 945
    .line 946
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 947
    .line 948
    .line 949
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 950
    .line 951
    .line 952
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 953
    .line 954
    .line 955
    move-result-object v0

    .line 956
    return-object v0

    .line 957
    :pswitch_1d
    check-cast v0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 958
    .line 959
    check-cast v7, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 960
    .line 961
    new-instance v1, Ljava/lang/StringBuilder;

    .line 962
    .line 963
    const-string v2, "onConnectionReceived(): connection = "

    .line 964
    .line 965
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 966
    .line 967
    .line 968
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 969
    .line 970
    .line 971
    const-string v0, ", message = "

    .line 972
    .line 973
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 974
    .line 975
    .line 976
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 977
    .line 978
    .line 979
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 980
    .line 981
    .line 982
    move-result-object v0

    .line 983
    return-object v0

    .line 984
    :pswitch_1e
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 985
    .line 986
    check-cast v7, Ljava/lang/Throwable;

    .line 987
    .line 988
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 989
    .line 990
    .line 991
    move-result-object v0

    .line 992
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getVin(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ljava/lang/String;

    .line 993
    .line 994
    .line 995
    move-result-object v0

    .line 996
    new-instance v1, Ljava/lang/StringBuilder;

    .line 997
    .line 998
    const-string v2, "Failed to connect to \'"

    .line 999
    .line 1000
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1001
    .line 1002
    .line 1003
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1004
    .line 1005
    .line 1006
    const-string v0, "\' - error = "

    .line 1007
    .line 1008
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1009
    .line 1010
    .line 1011
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1012
    .line 1013
    .line 1014
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1015
    .line 1016
    .line 1017
    move-result-object v0

    .line 1018
    return-object v0

    .line 1019
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1e
        :pswitch_1d
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

    .line 1020
    .line 1021
    .line 1022
    .line 1023
    .line 1024
    .line 1025
    .line 1026
    .line 1027
    .line 1028
    .line 1029
    .line 1030
    .line 1031
    .line 1032
    .line 1033
    .line 1034
    .line 1035
    .line 1036
    .line 1037
    .line 1038
    .line 1039
    .line 1040
    .line 1041
    .line 1042
    .line 1043
    .line 1044
    .line 1045
    .line 1046
    .line 1047
    .line 1048
    .line 1049
    .line 1050
    .line 1051
    .line 1052
    .line 1053
    .line 1054
    .line 1055
    .line 1056
    .line 1057
    .line 1058
    .line 1059
    .line 1060
    .line 1061
    .line 1062
    .line 1063
    .line 1064
    .line 1065
    .line 1066
    .line 1067
    .line 1068
    .line 1069
    .line 1070
    .line 1071
    .line 1072
    .line 1073
    .line 1074
    .line 1075
    .line 1076
    .line 1077
    .line 1078
    .line 1079
    .line 1080
    .line 1081
    :pswitch_data_1
    .packed-switch 0x16
        :pswitch_d
        :pswitch_c
        :pswitch_d
    .end packed-switch
.end method
