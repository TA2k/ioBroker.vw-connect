.class public final synthetic Lvj0/b;
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
    iput p1, p0, Lvj0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    iput p2, p0, Lvj0/b;->d:I

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
    iget v0, v0, Lvj0/b;->d:I

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
    invoke-static {v0, v1}, Lw00/a;->l(Ll2/o;I)V

    .line 25
    .line 26
    .line 27
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
    invoke-static {v0, v1}, Lw00/a;->h(Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object v0

    .line 52
    :pswitch_1
    move-object/from16 v0, p1

    .line 53
    .line 54
    check-cast v0, Ll2/o;

    .line 55
    .line 56
    move-object/from16 v1, p2

    .line 57
    .line 58
    check-cast v1, Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    and-int/lit8 v2, v1, 0x3

    .line 65
    .line 66
    const/4 v3, 0x2

    .line 67
    const/4 v4, 0x1

    .line 68
    if-eq v2, v3, :cond_0

    .line 69
    .line 70
    move v2, v4

    .line 71
    goto :goto_0

    .line 72
    :cond_0
    const/4 v2, 0x0

    .line 73
    :goto_0
    and-int/2addr v1, v4

    .line 74
    check-cast v0, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-eqz v1, :cond_1

    .line 81
    .line 82
    const v1, 0x7f120327

    .line 83
    .line 84
    .line 85
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 90
    .line 91
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Lj91/f;

    .line 96
    .line 97
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    invoke-static {v2, v1}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    const/16 v23, 0x0

    .line 108
    .line 109
    const v24, 0xfff8

    .line 110
    .line 111
    .line 112
    const-wide/16 v6, 0x0

    .line 113
    .line 114
    const-wide/16 v8, 0x0

    .line 115
    .line 116
    const/4 v10, 0x0

    .line 117
    const-wide/16 v11, 0x0

    .line 118
    .line 119
    const/4 v13, 0x0

    .line 120
    const/4 v14, 0x0

    .line 121
    const-wide/16 v15, 0x0

    .line 122
    .line 123
    const/16 v17, 0x0

    .line 124
    .line 125
    const/16 v18, 0x0

    .line 126
    .line 127
    const/16 v19, 0x0

    .line 128
    .line 129
    const/16 v20, 0x0

    .line 130
    .line 131
    const/16 v22, 0x0

    .line 132
    .line 133
    move-object/from16 v21, v0

    .line 134
    .line 135
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_1
    move-object/from16 v21, v0

    .line 140
    .line 141
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 142
    .line 143
    .line 144
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    return-object v0

    .line 147
    :pswitch_2
    move-object/from16 v0, p1

    .line 148
    .line 149
    check-cast v0, Ll2/o;

    .line 150
    .line 151
    move-object/from16 v1, p2

    .line 152
    .line 153
    check-cast v1, Ljava/lang/Integer;

    .line 154
    .line 155
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 156
    .line 157
    .line 158
    move-result v1

    .line 159
    and-int/lit8 v2, v1, 0x3

    .line 160
    .line 161
    const/4 v3, 0x2

    .line 162
    const/4 v4, 0x1

    .line 163
    if-eq v2, v3, :cond_2

    .line 164
    .line 165
    move v2, v4

    .line 166
    goto :goto_2

    .line 167
    :cond_2
    const/4 v2, 0x0

    .line 168
    :goto_2
    and-int/2addr v1, v4

    .line 169
    check-cast v0, Ll2/t;

    .line 170
    .line 171
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-eqz v1, :cond_3

    .line 176
    .line 177
    const v1, 0x7f120328

    .line 178
    .line 179
    .line 180
    invoke-static {v0, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 185
    .line 186
    invoke-virtual {v0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    check-cast v2, Lj91/f;

    .line 191
    .line 192
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 197
    .line 198
    invoke-static {v2, v1}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    const/16 v23, 0x0

    .line 203
    .line 204
    const v24, 0xfff8

    .line 205
    .line 206
    .line 207
    const-wide/16 v6, 0x0

    .line 208
    .line 209
    const-wide/16 v8, 0x0

    .line 210
    .line 211
    const/4 v10, 0x0

    .line 212
    const-wide/16 v11, 0x0

    .line 213
    .line 214
    const/4 v13, 0x0

    .line 215
    const/4 v14, 0x0

    .line 216
    const-wide/16 v15, 0x0

    .line 217
    .line 218
    const/16 v17, 0x0

    .line 219
    .line 220
    const/16 v18, 0x0

    .line 221
    .line 222
    const/16 v19, 0x0

    .line 223
    .line 224
    const/16 v20, 0x0

    .line 225
    .line 226
    const/16 v22, 0x0

    .line 227
    .line 228
    move-object/from16 v21, v0

    .line 229
    .line 230
    invoke-static/range {v3 .. v24}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 231
    .line 232
    .line 233
    goto :goto_3

    .line 234
    :cond_3
    move-object/from16 v21, v0

    .line 235
    .line 236
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 237
    .line 238
    .line 239
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    return-object v0

    .line 242
    :pswitch_3
    move-object/from16 v0, p1

    .line 243
    .line 244
    check-cast v0, Ll2/o;

    .line 245
    .line 246
    move-object/from16 v1, p2

    .line 247
    .line 248
    check-cast v1, Ljava/lang/Integer;

    .line 249
    .line 250
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 251
    .line 252
    .line 253
    move-result v1

    .line 254
    and-int/lit8 v2, v1, 0x3

    .line 255
    .line 256
    const/4 v3, 0x2

    .line 257
    const/4 v4, 0x1

    .line 258
    if-eq v2, v3, :cond_4

    .line 259
    .line 260
    move v2, v4

    .line 261
    goto :goto_4

    .line 262
    :cond_4
    const/4 v2, 0x0

    .line 263
    :goto_4
    and-int/2addr v1, v4

    .line 264
    check-cast v0, Ll2/t;

    .line 265
    .line 266
    invoke-virtual {v0, v1, v2}, Ll2/t;->O(IZ)Z

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    if-eqz v1, :cond_5

    .line 271
    .line 272
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 273
    .line 274
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v1

    .line 278
    check-cast v1, Lj91/c;

    .line 279
    .line 280
    iget v1, v1, Lj91/c;->h:F

    .line 281
    .line 282
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 283
    .line 284
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 285
    .line 286
    .line 287
    move-result-object v1

    .line 288
    invoke-static {v0, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 289
    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_5
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 293
    .line 294
    .line 295
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object v0

    .line 298
    :pswitch_4
    move-object/from16 v0, p1

    .line 299
    .line 300
    check-cast v0, Lpx0/g;

    .line 301
    .line 302
    move-object/from16 v1, p2

    .line 303
    .line 304
    check-cast v1, Lpx0/e;

    .line 305
    .line 306
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    return-object v0

    .line 311
    :pswitch_5
    move-object/from16 v0, p1

    .line 312
    .line 313
    check-cast v0, Lpx0/g;

    .line 314
    .line 315
    move-object/from16 v1, p2

    .line 316
    .line 317
    check-cast v1, Lpx0/e;

    .line 318
    .line 319
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    return-object v0

    .line 324
    :pswitch_6
    move-object/from16 v0, p1

    .line 325
    .line 326
    check-cast v0, Ljava/lang/Boolean;

    .line 327
    .line 328
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 329
    .line 330
    .line 331
    move-object/from16 v1, p2

    .line 332
    .line 333
    check-cast v1, Lpx0/e;

    .line 334
    .line 335
    return-object v0

    .line 336
    :pswitch_7
    move-object/from16 v0, p1

    .line 337
    .line 338
    check-cast v0, Lk21/a;

    .line 339
    .line 340
    move-object/from16 v1, p2

    .line 341
    .line 342
    check-cast v1, Lg21/a;

    .line 343
    .line 344
    const-string v2, "$this$factory"

    .line 345
    .line 346
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    const-string v2, "it"

    .line 350
    .line 351
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    new-instance v1, Lus0/b;

    .line 355
    .line 356
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 357
    .line 358
    const-class v3, Lxl0/f;

    .line 359
    .line 360
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 361
    .line 362
    .line 363
    move-result-object v3

    .line 364
    const/4 v4, 0x0

    .line 365
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v3

    .line 369
    check-cast v3, Lxl0/f;

    .line 370
    .line 371
    const-class v5, Lcz/myskoda/api/bff/v1/VehicleServicesBackupApi;

    .line 372
    .line 373
    const-string v6, "null"

    .line 374
    .line 375
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 376
    .line 377
    .line 378
    move-result-object v5

    .line 379
    const-class v6, Lti0/a;

    .line 380
    .line 381
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 382
    .line 383
    .line 384
    move-result-object v2

    .line 385
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 386
    .line 387
    .line 388
    move-result-object v0

    .line 389
    check-cast v0, Lti0/a;

    .line 390
    .line 391
    invoke-direct {v1, v3, v0}, Lus0/b;-><init>(Lxl0/f;Lti0/a;)V

    .line 392
    .line 393
    .line 394
    return-object v1

    .line 395
    :pswitch_8
    move-object/from16 v0, p1

    .line 396
    .line 397
    check-cast v0, Lk21/a;

    .line 398
    .line 399
    move-object/from16 v1, p2

    .line 400
    .line 401
    check-cast v1, Lg21/a;

    .line 402
    .line 403
    const-string v2, "$this$single"

    .line 404
    .line 405
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    const-string v2, "it"

    .line 409
    .line 410
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 411
    .line 412
    .line 413
    new-instance v1, Lus0/g;

    .line 414
    .line 415
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 416
    .line 417
    const-string v3, "null"

    .line 418
    .line 419
    const-class v4, Lus0/h;

    .line 420
    .line 421
    invoke-static {v2, v4, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 422
    .line 423
    .line 424
    move-result-object v3

    .line 425
    const-class v4, Lti0/a;

    .line 426
    .line 427
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 428
    .line 429
    .line 430
    move-result-object v2

    .line 431
    const/4 v4, 0x0

    .line 432
    invoke-virtual {v0, v2, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    check-cast v0, Lti0/a;

    .line 437
    .line 438
    invoke-direct {v1, v0}, Lus0/g;-><init>(Lti0/a;)V

    .line 439
    .line 440
    .line 441
    return-object v1

    .line 442
    :pswitch_9
    move-object/from16 v0, p1

    .line 443
    .line 444
    check-cast v0, Lk21/a;

    .line 445
    .line 446
    move-object/from16 v1, p2

    .line 447
    .line 448
    check-cast v1, Lg21/a;

    .line 449
    .line 450
    const-string v2, "$this$single"

    .line 451
    .line 452
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 453
    .line 454
    .line 455
    const-string v2, "it"

    .line 456
    .line 457
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    new-instance v1, Lzr0/a;

    .line 461
    .line 462
    const-class v2, Lur0/g;

    .line 463
    .line 464
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 465
    .line 466
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 467
    .line 468
    .line 469
    move-result-object v2

    .line 470
    const/4 v3, 0x0

    .line 471
    invoke-virtual {v0, v2, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v0

    .line 475
    check-cast v0, Lur0/g;

    .line 476
    .line 477
    invoke-direct {v1, v0}, Lzr0/a;-><init>(Lur0/g;)V

    .line 478
    .line 479
    .line 480
    return-object v1

    .line 481
    :pswitch_a
    move-object/from16 v0, p1

    .line 482
    .line 483
    check-cast v0, Lk21/a;

    .line 484
    .line 485
    move-object/from16 v1, p2

    .line 486
    .line 487
    check-cast v1, Lg21/a;

    .line 488
    .line 489
    const-string v2, "$this$single"

    .line 490
    .line 491
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 492
    .line 493
    .line 494
    const-string v2, "it"

    .line 495
    .line 496
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 497
    .line 498
    .line 499
    new-instance v1, Lur0/b;

    .line 500
    .line 501
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 502
    .line 503
    const-class v3, Lxl0/f;

    .line 504
    .line 505
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 506
    .line 507
    .line 508
    move-result-object v3

    .line 509
    const/4 v4, 0x0

    .line 510
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 511
    .line 512
    .line 513
    move-result-object v3

    .line 514
    check-cast v3, Lxl0/f;

    .line 515
    .line 516
    const-class v5, Lcz/myskoda/api/bff/v1/UserApi;

    .line 517
    .line 518
    const-string v6, "null"

    .line 519
    .line 520
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 521
    .line 522
    .line 523
    move-result-object v5

    .line 524
    const-class v6, Lti0/a;

    .line 525
    .line 526
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 527
    .line 528
    .line 529
    move-result-object v2

    .line 530
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v0

    .line 534
    check-cast v0, Lti0/a;

    .line 535
    .line 536
    invoke-direct {v1, v3, v0}, Lur0/b;-><init>(Lxl0/f;Lti0/a;)V

    .line 537
    .line 538
    .line 539
    return-object v1

    .line 540
    :pswitch_b
    move-object/from16 v0, p1

    .line 541
    .line 542
    check-cast v0, Lk21/a;

    .line 543
    .line 544
    move-object/from16 v1, p2

    .line 545
    .line 546
    check-cast v1, Lg21/a;

    .line 547
    .line 548
    const-string v2, "$this$single"

    .line 549
    .line 550
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    const-string v2, "it"

    .line 554
    .line 555
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 556
    .line 557
    .line 558
    new-instance v1, Lur0/g;

    .line 559
    .line 560
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 561
    .line 562
    const-string v3, "null"

    .line 563
    .line 564
    const-class v4, Lur0/h;

    .line 565
    .line 566
    invoke-static {v2, v4, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 567
    .line 568
    .line 569
    move-result-object v3

    .line 570
    const-class v4, Lti0/a;

    .line 571
    .line 572
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 573
    .line 574
    .line 575
    move-result-object v4

    .line 576
    const/4 v5, 0x0

    .line 577
    invoke-virtual {v0, v4, v3, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v3

    .line 581
    check-cast v3, Lti0/a;

    .line 582
    .line 583
    const-class v4, Lwe0/a;

    .line 584
    .line 585
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 586
    .line 587
    .line 588
    move-result-object v2

    .line 589
    invoke-virtual {v0, v2, v5, v5}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    check-cast v0, Lwe0/a;

    .line 594
    .line 595
    invoke-direct {v1, v3, v0}, Lur0/g;-><init>(Lti0/a;Lwe0/a;)V

    .line 596
    .line 597
    .line 598
    return-object v1

    .line 599
    :pswitch_c
    move-object/from16 v0, p1

    .line 600
    .line 601
    check-cast v0, Lk21/a;

    .line 602
    .line 603
    move-object/from16 v1, p2

    .line 604
    .line 605
    check-cast v1, Lg21/a;

    .line 606
    .line 607
    const-string v2, "$this$single"

    .line 608
    .line 609
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 610
    .line 611
    .line 612
    const-string v2, "it"

    .line 613
    .line 614
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    new-instance v1, Ltq0/k;

    .line 618
    .line 619
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 620
    .line 621
    const-class v3, Lxl0/f;

    .line 622
    .line 623
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 624
    .line 625
    .line 626
    move-result-object v3

    .line 627
    const/4 v4, 0x0

    .line 628
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 629
    .line 630
    .line 631
    move-result-object v3

    .line 632
    check-cast v3, Lxl0/f;

    .line 633
    .line 634
    const-class v5, Lcz/myskoda/api/bff/v1/SpinApi;

    .line 635
    .line 636
    const-string v6, "null"

    .line 637
    .line 638
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 639
    .line 640
    .line 641
    move-result-object v5

    .line 642
    const-class v6, Lti0/a;

    .line 643
    .line 644
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 645
    .line 646
    .line 647
    move-result-object v2

    .line 648
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 649
    .line 650
    .line 651
    move-result-object v0

    .line 652
    check-cast v0, Lti0/a;

    .line 653
    .line 654
    invoke-direct {v1, v3, v0}, Ltq0/k;-><init>(Lxl0/f;Lti0/a;)V

    .line 655
    .line 656
    .line 657
    return-object v1

    .line 658
    :pswitch_d
    move-object/from16 v0, p1

    .line 659
    .line 660
    check-cast v0, Lk21/a;

    .line 661
    .line 662
    move-object/from16 v1, p2

    .line 663
    .line 664
    check-cast v1, Lg21/a;

    .line 665
    .line 666
    const-string v2, "$this$factory"

    .line 667
    .line 668
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 669
    .line 670
    .line 671
    const-string v2, "it"

    .line 672
    .line 673
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    new-instance v3, Lwq0/i0;

    .line 677
    .line 678
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 679
    .line 680
    const-class v2, Lkf0/e;

    .line 681
    .line 682
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 683
    .line 684
    .line 685
    move-result-object v2

    .line 686
    const/4 v4, 0x0

    .line 687
    invoke-virtual {v0, v2, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 688
    .line 689
    .line 690
    move-result-object v2

    .line 691
    check-cast v2, Lkf0/e;

    .line 692
    .line 693
    const-class v5, Lwq0/g0;

    .line 694
    .line 695
    invoke-virtual {v1, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 696
    .line 697
    .line 698
    move-result-object v5

    .line 699
    invoke-virtual {v0, v5, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 700
    .line 701
    .line 702
    move-result-object v5

    .line 703
    check-cast v5, Lwq0/g0;

    .line 704
    .line 705
    const-class v6, Ltq0/k;

    .line 706
    .line 707
    invoke-virtual {v1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 708
    .line 709
    .line 710
    move-result-object v6

    .line 711
    invoke-virtual {v0, v6, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 712
    .line 713
    .line 714
    move-result-object v6

    .line 715
    check-cast v6, Ltq0/k;

    .line 716
    .line 717
    const-class v7, Lwq0/r;

    .line 718
    .line 719
    invoke-virtual {v1, v7}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 720
    .line 721
    .line 722
    move-result-object v7

    .line 723
    invoke-virtual {v0, v7, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v4

    .line 727
    move-object v7, v4

    .line 728
    check-cast v7, Lwq0/r;

    .line 729
    .line 730
    const-class v4, Lme0/b;

    .line 731
    .line 732
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 733
    .line 734
    .line 735
    move-result-object v1

    .line 736
    invoke-virtual {v0, v1}, Lk21/a;->b(Lhy0/d;)Ljava/util/ArrayList;

    .line 737
    .line 738
    .line 739
    move-result-object v8

    .line 740
    move-object v4, v2

    .line 741
    invoke-direct/range {v3 .. v8}, Lwq0/i0;-><init>(Lkf0/e;Lwq0/g0;Ltq0/k;Lwq0/r;Ljava/util/ArrayList;)V

    .line 742
    .line 743
    .line 744
    return-object v3

    .line 745
    :pswitch_e
    move-object/from16 v0, p1

    .line 746
    .line 747
    check-cast v0, Lk21/a;

    .line 748
    .line 749
    move-object/from16 v1, p2

    .line 750
    .line 751
    check-cast v1, Lg21/a;

    .line 752
    .line 753
    const-string v2, "$this$single"

    .line 754
    .line 755
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 756
    .line 757
    .line 758
    const-string v2, "it"

    .line 759
    .line 760
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 761
    .line 762
    .line 763
    new-instance v1, Ltp0/b;

    .line 764
    .line 765
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 766
    .line 767
    const-class v3, Lxl0/f;

    .line 768
    .line 769
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 770
    .line 771
    .line 772
    move-result-object v3

    .line 773
    const/4 v4, 0x0

    .line 774
    invoke-virtual {v0, v3, v4, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 775
    .line 776
    .line 777
    move-result-object v3

    .line 778
    check-cast v3, Lxl0/f;

    .line 779
    .line 780
    const-class v5, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 781
    .line 782
    const-string v6, "null"

    .line 783
    .line 784
    invoke-static {v2, v5, v6}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 785
    .line 786
    .line 787
    move-result-object v5

    .line 788
    const-class v6, Lti0/a;

    .line 789
    .line 790
    invoke-virtual {v2, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 791
    .line 792
    .line 793
    move-result-object v2

    .line 794
    invoke-virtual {v0, v2, v5, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 795
    .line 796
    .line 797
    move-result-object v0

    .line 798
    check-cast v0, Lti0/a;

    .line 799
    .line 800
    invoke-direct {v1, v3, v0}, Ltp0/b;-><init>(Lxl0/f;Lti0/a;)V

    .line 801
    .line 802
    .line 803
    return-object v1

    .line 804
    :pswitch_f
    move-object/from16 v0, p1

    .line 805
    .line 806
    check-cast v0, Ll2/o;

    .line 807
    .line 808
    move-object/from16 v1, p2

    .line 809
    .line 810
    check-cast v1, Ljava/lang/Integer;

    .line 811
    .line 812
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 813
    .line 814
    .line 815
    const/4 v1, 0x1

    .line 816
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 817
    .line 818
    .line 819
    move-result v1

    .line 820
    invoke-static {v0, v1}, Llp/ac;->a(Ll2/o;I)V

    .line 821
    .line 822
    .line 823
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 824
    .line 825
    return-object v0

    .line 826
    :pswitch_10
    move-object/from16 v0, p1

    .line 827
    .line 828
    check-cast v0, Ll2/o;

    .line 829
    .line 830
    move-object/from16 v1, p2

    .line 831
    .line 832
    check-cast v1, Ljava/lang/Integer;

    .line 833
    .line 834
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 835
    .line 836
    .line 837
    const/4 v1, 0x1

    .line 838
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 839
    .line 840
    .line 841
    move-result v1

    .line 842
    invoke-static {v0, v1}, Llp/zb;->f(Ll2/o;I)V

    .line 843
    .line 844
    .line 845
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 846
    .line 847
    return-object v0

    .line 848
    :pswitch_11
    move-object/from16 v0, p1

    .line 849
    .line 850
    check-cast v0, Ll2/o;

    .line 851
    .line 852
    move-object/from16 v1, p2

    .line 853
    .line 854
    check-cast v1, Ljava/lang/Integer;

    .line 855
    .line 856
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 857
    .line 858
    .line 859
    const/4 v1, 0x1

    .line 860
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 861
    .line 862
    .line 863
    move-result v1

    .line 864
    invoke-static {v0, v1}, Llp/zb;->c(Ll2/o;I)V

    .line 865
    .line 866
    .line 867
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 868
    .line 869
    return-object v0

    .line 870
    :pswitch_12
    move-object/from16 v0, p1

    .line 871
    .line 872
    check-cast v0, Ll2/o;

    .line 873
    .line 874
    move-object/from16 v1, p2

    .line 875
    .line 876
    check-cast v1, Ljava/lang/Integer;

    .line 877
    .line 878
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 879
    .line 880
    .line 881
    const/4 v1, 0x1

    .line 882
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 883
    .line 884
    .line 885
    move-result v1

    .line 886
    invoke-static {v0, v1}, Llp/zb;->j(Ll2/o;I)V

    .line 887
    .line 888
    .line 889
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 890
    .line 891
    return-object v0

    .line 892
    :pswitch_13
    move-object/from16 v0, p1

    .line 893
    .line 894
    check-cast v0, Ll2/o;

    .line 895
    .line 896
    move-object/from16 v1, p2

    .line 897
    .line 898
    check-cast v1, Ljava/lang/Integer;

    .line 899
    .line 900
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 901
    .line 902
    .line 903
    const/4 v1, 0x1

    .line 904
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 905
    .line 906
    .line 907
    move-result v1

    .line 908
    invoke-static {v0, v1}, Llp/zb;->g(Ll2/o;I)V

    .line 909
    .line 910
    .line 911
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 912
    .line 913
    return-object v0

    .line 914
    :pswitch_14
    move-object/from16 v0, p1

    .line 915
    .line 916
    check-cast v0, Ll2/o;

    .line 917
    .line 918
    move-object/from16 v1, p2

    .line 919
    .line 920
    check-cast v1, Ljava/lang/Integer;

    .line 921
    .line 922
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 923
    .line 924
    .line 925
    const/4 v1, 0x1

    .line 926
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 927
    .line 928
    .line 929
    move-result v1

    .line 930
    invoke-static {v0, v1}, Llp/zb;->d(Ll2/o;I)V

    .line 931
    .line 932
    .line 933
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 934
    .line 935
    return-object v0

    .line 936
    :pswitch_15
    move-object/from16 v0, p1

    .line 937
    .line 938
    check-cast v0, Ll2/o;

    .line 939
    .line 940
    move-object/from16 v1, p2

    .line 941
    .line 942
    check-cast v1, Ljava/lang/Integer;

    .line 943
    .line 944
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 945
    .line 946
    .line 947
    const/4 v1, 0x1

    .line 948
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 949
    .line 950
    .line 951
    move-result v1

    .line 952
    invoke-static {v0, v1}, Llp/zb;->l(Ll2/o;I)V

    .line 953
    .line 954
    .line 955
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 956
    .line 957
    return-object v0

    .line 958
    :pswitch_16
    move-object/from16 v0, p1

    .line 959
    .line 960
    check-cast v0, Ll2/o;

    .line 961
    .line 962
    move-object/from16 v1, p2

    .line 963
    .line 964
    check-cast v1, Ljava/lang/Integer;

    .line 965
    .line 966
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 967
    .line 968
    .line 969
    const/4 v1, 0x1

    .line 970
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 971
    .line 972
    .line 973
    move-result v1

    .line 974
    invoke-static {v0, v1}, Llp/zb;->k(Ll2/o;I)V

    .line 975
    .line 976
    .line 977
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 978
    .line 979
    return-object v0

    .line 980
    :pswitch_17
    move-object/from16 v0, p1

    .line 981
    .line 982
    check-cast v0, Ll2/o;

    .line 983
    .line 984
    move-object/from16 v1, p2

    .line 985
    .line 986
    check-cast v1, Ljava/lang/Integer;

    .line 987
    .line 988
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 989
    .line 990
    .line 991
    const/4 v1, 0x1

    .line 992
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 993
    .line 994
    .line 995
    move-result v1

    .line 996
    invoke-static {v0, v1}, Llp/zb;->e(Ll2/o;I)V

    .line 997
    .line 998
    .line 999
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1000
    .line 1001
    return-object v0

    .line 1002
    :pswitch_18
    move-object/from16 v0, p1

    .line 1003
    .line 1004
    check-cast v0, Ll2/o;

    .line 1005
    .line 1006
    move-object/from16 v1, p2

    .line 1007
    .line 1008
    check-cast v1, Ljava/lang/Integer;

    .line 1009
    .line 1010
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1011
    .line 1012
    .line 1013
    const/4 v1, 0x1

    .line 1014
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1015
    .line 1016
    .line 1017
    move-result v1

    .line 1018
    invoke-static {v0, v1}, Llp/zb;->h(Ll2/o;I)V

    .line 1019
    .line 1020
    .line 1021
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1022
    .line 1023
    return-object v0

    .line 1024
    :pswitch_19
    move-object/from16 v0, p1

    .line 1025
    .line 1026
    check-cast v0, Ll2/o;

    .line 1027
    .line 1028
    move-object/from16 v1, p2

    .line 1029
    .line 1030
    check-cast v1, Ljava/lang/Integer;

    .line 1031
    .line 1032
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1033
    .line 1034
    .line 1035
    const/4 v1, 0x1

    .line 1036
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1037
    .line 1038
    .line 1039
    move-result v1

    .line 1040
    invoke-static {v0, v1}, Llp/zb;->b(Ll2/o;I)V

    .line 1041
    .line 1042
    .line 1043
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1044
    .line 1045
    return-object v0

    .line 1046
    :pswitch_1a
    move-object/from16 v0, p1

    .line 1047
    .line 1048
    check-cast v0, Ll2/o;

    .line 1049
    .line 1050
    move-object/from16 v1, p2

    .line 1051
    .line 1052
    check-cast v1, Ljava/lang/Integer;

    .line 1053
    .line 1054
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1055
    .line 1056
    .line 1057
    const/4 v1, 0x1

    .line 1058
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1059
    .line 1060
    .line 1061
    move-result v1

    .line 1062
    invoke-static {v0, v1}, Llp/zb;->i(Ll2/o;I)V

    .line 1063
    .line 1064
    .line 1065
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1066
    .line 1067
    return-object v0

    .line 1068
    :pswitch_1b
    move-object/from16 v0, p1

    .line 1069
    .line 1070
    check-cast v0, Ll2/o;

    .line 1071
    .line 1072
    move-object/from16 v1, p2

    .line 1073
    .line 1074
    check-cast v1, Ljava/lang/Integer;

    .line 1075
    .line 1076
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1077
    .line 1078
    .line 1079
    const/4 v1, 0x1

    .line 1080
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1081
    .line 1082
    .line 1083
    move-result v1

    .line 1084
    invoke-static {v0, v1}, Llp/zb;->a(Ll2/o;I)V

    .line 1085
    .line 1086
    .line 1087
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1088
    .line 1089
    return-object v0

    .line 1090
    :pswitch_1c
    move-object/from16 v0, p1

    .line 1091
    .line 1092
    check-cast v0, Lk21/a;

    .line 1093
    .line 1094
    move-object/from16 v1, p2

    .line 1095
    .line 1096
    check-cast v1, Lg21/a;

    .line 1097
    .line 1098
    const-string v2, "$this$single"

    .line 1099
    .line 1100
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1101
    .line 1102
    .line 1103
    const-string v2, "it"

    .line 1104
    .line 1105
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1106
    .line 1107
    .line 1108
    new-instance v1, Luj0/n;

    .line 1109
    .line 1110
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1111
    .line 1112
    const-string v3, "null"

    .line 1113
    .line 1114
    const-class v4, Luj0/a;

    .line 1115
    .line 1116
    invoke-static {v2, v4, v3}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 1117
    .line 1118
    .line 1119
    move-result-object v3

    .line 1120
    const-class v4, Lti0/a;

    .line 1121
    .line 1122
    invoke-virtual {v2, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1123
    .line 1124
    .line 1125
    move-result-object v2

    .line 1126
    const/4 v4, 0x0

    .line 1127
    invoke-virtual {v0, v2, v3, v4}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v0

    .line 1131
    check-cast v0, Lti0/a;

    .line 1132
    .line 1133
    invoke-direct {v1, v0}, Luj0/n;-><init>(Lti0/a;)V

    .line 1134
    .line 1135
    .line 1136
    return-object v1

    .line 1137
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
