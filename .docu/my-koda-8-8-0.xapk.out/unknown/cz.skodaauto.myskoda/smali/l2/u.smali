.class public final synthetic Ll2/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(IILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p2, p0, Ll2/u;->d:I

    iput-object p3, p0, Ll2/u;->e:Ljava/lang/Object;

    iput-object p4, p0, Ll2/u;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 2
    iput p1, p0, Ll2/u;->d:I

    iput-object p2, p0, Ll2/u;->e:Ljava/lang/Object;

    iput-object p3, p0, Ll2/u;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Ll2/u;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v2, Lo1/a0;

    .line 13
    .line 14
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lo1/c0;

    .line 17
    .line 18
    move-object/from16 v3, p1

    .line 19
    .line 20
    check-cast v3, Lt3/p1;

    .line 21
    .line 22
    check-cast v1, Lt4/a;

    .line 23
    .line 24
    new-instance v4, Lo1/d0;

    .line 25
    .line 26
    invoke-direct {v4, v2, v3}, Lo1/d0;-><init>(Lo1/a0;Lt3/p1;)V

    .line 27
    .line 28
    .line 29
    iget-wide v1, v1, Lt4/a;->a:J

    .line 30
    .line 31
    invoke-interface {v0, v4, v1, v2}, Lo1/c0;->a(Lo1/d0;J)Lt3/r0;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    return-object v0

    .line 36
    :pswitch_0
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Lz9/y;

    .line 39
    .line 40
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lx2/s;

    .line 43
    .line 44
    move-object/from16 v3, p1

    .line 45
    .line 46
    check-cast v3, Ll2/o;

    .line 47
    .line 48
    check-cast v1, Ljava/lang/Integer;

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    const/16 v1, 0x31

    .line 54
    .line 55
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    invoke-static {v2, v0, v3, v1}, Lny/j;->j(Lz9/y;Lx2/s;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_1
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 66
    .line 67
    move-object v5, v2

    .line 68
    check-cast v5, Lmy/t;

    .line 69
    .line 70
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Ll2/t2;

    .line 73
    .line 74
    move-object/from16 v2, p1

    .line 75
    .line 76
    check-cast v2, Ll2/o;

    .line 77
    .line 78
    check-cast v1, Ljava/lang/Integer;

    .line 79
    .line 80
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    and-int/lit8 v3, v1, 0x3

    .line 85
    .line 86
    const/4 v4, 0x2

    .line 87
    const/4 v6, 0x1

    .line 88
    if-eq v3, v4, :cond_0

    .line 89
    .line 90
    move v3, v6

    .line 91
    goto :goto_0

    .line 92
    :cond_0
    const/4 v3, 0x0

    .line 93
    :goto_0
    and-int/2addr v1, v6

    .line 94
    move-object v12, v2

    .line 95
    check-cast v12, Ll2/t;

    .line 96
    .line 97
    invoke-virtual {v12, v1, v3}, Ll2/t;->O(IZ)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-eqz v1, :cond_b

    .line 102
    .line 103
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    check-cast v0, Lmy/p;

    .line 108
    .line 109
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 118
    .line 119
    if-nez v1, :cond_1

    .line 120
    .line 121
    if-ne v2, v11, :cond_2

    .line 122
    .line 123
    :cond_1
    new-instance v3, Ln70/x;

    .line 124
    .line 125
    const/4 v9, 0x0

    .line 126
    const/16 v10, 0xe

    .line 127
    .line 128
    const/4 v4, 0x1

    .line 129
    const-class v6, Lmy/t;

    .line 130
    .line 131
    const-string v7, "onSelectBottomNavigationItem"

    .line 132
    .line 133
    const-string v8, "onSelectBottomNavigationItem(Lcz/skodaauto/myskoda/app/main/presentation/MainViewModel$State$BottomNavigationItem;)V"

    .line 134
    .line 135
    invoke-direct/range {v3 .. v10}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    move-object v2, v3

    .line 142
    :cond_2
    check-cast v2, Lhy0/g;

    .line 143
    .line 144
    check-cast v2, Lay0/k;

    .line 145
    .line 146
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v3

    .line 154
    if-nez v1, :cond_3

    .line 155
    .line 156
    if-ne v3, v11, :cond_4

    .line 157
    .line 158
    :cond_3
    new-instance v3, Ln70/x;

    .line 159
    .line 160
    const/4 v9, 0x0

    .line 161
    const/16 v10, 0xf

    .line 162
    .line 163
    const/4 v4, 0x1

    .line 164
    const-class v6, Lmy/t;

    .line 165
    .line 166
    const-string v7, "onCurrentRouteChanged"

    .line 167
    .line 168
    const-string v8, "onCurrentRouteChanged(Ljava/lang/String;)V"

    .line 169
    .line 170
    invoke-direct/range {v3 .. v10}, Ln70/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    :cond_4
    check-cast v3, Lhy0/g;

    .line 177
    .line 178
    move-object v1, v3

    .line 179
    check-cast v1, Lay0/k;

    .line 180
    .line 181
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v4

    .line 189
    if-nez v3, :cond_5

    .line 190
    .line 191
    if-ne v4, v11, :cond_6

    .line 192
    .line 193
    :cond_5
    new-instance v3, Ln80/d;

    .line 194
    .line 195
    const/4 v9, 0x0

    .line 196
    const/16 v10, 0x19

    .line 197
    .line 198
    const/4 v4, 0x0

    .line 199
    const-class v6, Lmy/t;

    .line 200
    .line 201
    const-string v7, "onSnackBarAction"

    .line 202
    .line 203
    const-string v8, "onSnackBarAction()V"

    .line 204
    .line 205
    invoke-direct/range {v3 .. v10}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    move-object v4, v3

    .line 212
    :cond_6
    check-cast v4, Lhy0/g;

    .line 213
    .line 214
    move-object v13, v4

    .line 215
    check-cast v13, Lay0/a;

    .line 216
    .line 217
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    if-nez v3, :cond_7

    .line 226
    .line 227
    if-ne v4, v11, :cond_8

    .line 228
    .line 229
    :cond_7
    new-instance v3, Ln80/d;

    .line 230
    .line 231
    const/4 v9, 0x0

    .line 232
    const/16 v10, 0x1a

    .line 233
    .line 234
    const/4 v4, 0x0

    .line 235
    const-class v6, Lmy/t;

    .line 236
    .line 237
    const-string v7, "onSnackBarDismiss"

    .line 238
    .line 239
    const-string v8, "onSnackBarDismiss()V"

    .line 240
    .line 241
    invoke-direct/range {v3 .. v10}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    move-object v4, v3

    .line 248
    :cond_8
    check-cast v4, Lhy0/g;

    .line 249
    .line 250
    move-object v14, v4

    .line 251
    check-cast v14, Lay0/a;

    .line 252
    .line 253
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v3

    .line 257
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v4

    .line 261
    if-nez v3, :cond_9

    .line 262
    .line 263
    if-ne v4, v11, :cond_a

    .line 264
    .line 265
    :cond_9
    new-instance v3, Ln80/d;

    .line 266
    .line 267
    const/4 v9, 0x0

    .line 268
    const/16 v10, 0x1b

    .line 269
    .line 270
    const/4 v4, 0x0

    .line 271
    const-class v6, Lmy/t;

    .line 272
    .line 273
    const-string v7, "onOverlayErrorDismiss"

    .line 274
    .line 275
    const-string v8, "onOverlayErrorDismiss()V"

    .line 276
    .line 277
    invoke-direct/range {v3 .. v10}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 281
    .line 282
    .line 283
    move-object v4, v3

    .line 284
    :cond_a
    check-cast v4, Lhy0/g;

    .line 285
    .line 286
    move-object v11, v4

    .line 287
    check-cast v11, Lay0/a;

    .line 288
    .line 289
    move-object v9, v13

    .line 290
    const/4 v13, 0x0

    .line 291
    move-object v6, v0

    .line 292
    move-object v8, v1

    .line 293
    move-object v7, v2

    .line 294
    move-object v10, v14

    .line 295
    invoke-static/range {v6 .. v13}, Lny/j;->g(Lmy/p;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 296
    .line 297
    .line 298
    goto :goto_1

    .line 299
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 300
    .line 301
    .line 302
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 303
    .line 304
    return-object v0

    .line 305
    :pswitch_2
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v2, Llu0/a;

    .line 308
    .line 309
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v0, Lx2/s;

    .line 312
    .line 313
    move-object/from16 v3, p1

    .line 314
    .line 315
    check-cast v3, Ll2/o;

    .line 316
    .line 317
    check-cast v1, Ljava/lang/Integer;

    .line 318
    .line 319
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 320
    .line 321
    .line 322
    const/4 v1, 0x1

    .line 323
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 324
    .line 325
    .line 326
    move-result v1

    .line 327
    invoke-static {v2, v0, v3, v1}, Ljp/wa;->f(Llu0/a;Lx2/s;Ll2/o;I)V

    .line 328
    .line 329
    .line 330
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 331
    .line 332
    return-object v0

    .line 333
    :pswitch_3
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast v2, Llc/l;

    .line 336
    .line 337
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v0, Lay0/k;

    .line 340
    .line 341
    move-object/from16 v3, p1

    .line 342
    .line 343
    check-cast v3, Ll2/o;

    .line 344
    .line 345
    check-cast v1, Ljava/lang/Integer;

    .line 346
    .line 347
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 348
    .line 349
    .line 350
    const/4 v1, 0x1

    .line 351
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 352
    .line 353
    .line 354
    move-result v1

    .line 355
    invoke-static {v2, v0, v3, v1}, Ljp/ra;->c(Llc/l;Lay0/k;Ll2/o;I)V

    .line 356
    .line 357
    .line 358
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 359
    .line 360
    return-object v0

    .line 361
    :pswitch_4
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v2, Lig/e;

    .line 364
    .line 365
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 366
    .line 367
    check-cast v0, Lay0/k;

    .line 368
    .line 369
    move-object/from16 v3, p1

    .line 370
    .line 371
    check-cast v3, Ll2/o;

    .line 372
    .line 373
    check-cast v1, Ljava/lang/Integer;

    .line 374
    .line 375
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 376
    .line 377
    .line 378
    const/4 v1, 0x1

    .line 379
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 380
    .line 381
    .line 382
    move-result v1

    .line 383
    invoke-static {v2, v0, v3, v1}, Ljp/ra;->g(Lig/e;Lay0/k;Ll2/o;I)V

    .line 384
    .line 385
    .line 386
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 387
    .line 388
    return-object v0

    .line 389
    :pswitch_5
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast v2, Llf0/i;

    .line 392
    .line 393
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 394
    .line 395
    check-cast v0, Lx2/s;

    .line 396
    .line 397
    move-object/from16 v3, p1

    .line 398
    .line 399
    check-cast v3, Ll2/o;

    .line 400
    .line 401
    check-cast v1, Ljava/lang/Integer;

    .line 402
    .line 403
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 404
    .line 405
    .line 406
    const/4 v1, 0x1

    .line 407
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 408
    .line 409
    .line 410
    move-result v1

    .line 411
    invoke-static {v2, v0, v3, v1}, Lnf0/a;->a(Llf0/i;Lx2/s;Ll2/o;I)V

    .line 412
    .line 413
    .line 414
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 415
    .line 416
    return-object v0

    .line 417
    :pswitch_6
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 418
    .line 419
    check-cast v2, Lmc0/e;

    .line 420
    .line 421
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 422
    .line 423
    check-cast v0, Lay0/a;

    .line 424
    .line 425
    move-object/from16 v3, p1

    .line 426
    .line 427
    check-cast v3, Ll2/o;

    .line 428
    .line 429
    check-cast v1, Ljava/lang/Integer;

    .line 430
    .line 431
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 432
    .line 433
    .line 434
    const/4 v1, 0x1

    .line 435
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 436
    .line 437
    .line 438
    move-result v1

    .line 439
    invoke-static {v2, v0, v3, v1}, Lnc0/e;->g(Lmc0/e;Lay0/a;Ll2/o;I)V

    .line 440
    .line 441
    .line 442
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 443
    .line 444
    return-object v0

    .line 445
    :pswitch_7
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast v2, Lma0/e;

    .line 448
    .line 449
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 450
    .line 451
    move-object v4, v0

    .line 452
    check-cast v4, Lay0/k;

    .line 453
    .line 454
    move-object/from16 v0, p1

    .line 455
    .line 456
    check-cast v0, Ll2/o;

    .line 457
    .line 458
    check-cast v1, Ljava/lang/Integer;

    .line 459
    .line 460
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 461
    .line 462
    .line 463
    move-result v1

    .line 464
    and-int/lit8 v3, v1, 0x3

    .line 465
    .line 466
    const/4 v5, 0x2

    .line 467
    const/4 v6, 0x0

    .line 468
    const/4 v11, 0x1

    .line 469
    if-eq v3, v5, :cond_c

    .line 470
    .line 471
    move v3, v11

    .line 472
    goto :goto_2

    .line 473
    :cond_c
    move v3, v6

    .line 474
    :goto_2
    and-int/2addr v1, v11

    .line 475
    move-object v8, v0

    .line 476
    check-cast v8, Ll2/t;

    .line 477
    .line 478
    invoke-virtual {v8, v1, v3}, Ll2/t;->O(IZ)Z

    .line 479
    .line 480
    .line 481
    move-result v0

    .line 482
    if-eqz v0, :cond_10

    .line 483
    .line 484
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 485
    .line 486
    sget-object v1, Lx2/c;->p:Lx2/h;

    .line 487
    .line 488
    invoke-static {v0, v1, v8, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    iget-wide v5, v8, Ll2/t;->T:J

    .line 493
    .line 494
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 495
    .line 496
    .line 497
    move-result v1

    .line 498
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 499
    .line 500
    .line 501
    move-result-object v3

    .line 502
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 503
    .line 504
    invoke-static {v8, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 505
    .line 506
    .line 507
    move-result-object v6

    .line 508
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 509
    .line 510
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 511
    .line 512
    .line 513
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 514
    .line 515
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 516
    .line 517
    .line 518
    iget-boolean v9, v8, Ll2/t;->S:Z

    .line 519
    .line 520
    if-eqz v9, :cond_d

    .line 521
    .line 522
    invoke-virtual {v8, v7}, Ll2/t;->l(Lay0/a;)V

    .line 523
    .line 524
    .line 525
    goto :goto_3

    .line 526
    :cond_d
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 527
    .line 528
    .line 529
    :goto_3
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 530
    .line 531
    invoke-static {v7, v0, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 532
    .line 533
    .line 534
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 535
    .line 536
    invoke-static {v0, v3, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 537
    .line 538
    .line 539
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 540
    .line 541
    iget-boolean v3, v8, Ll2/t;->S:Z

    .line 542
    .line 543
    if-nez v3, :cond_e

    .line 544
    .line 545
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v3

    .line 549
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 550
    .line 551
    .line 552
    move-result-object v7

    .line 553
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 554
    .line 555
    .line 556
    move-result v3

    .line 557
    if-nez v3, :cond_f

    .line 558
    .line 559
    :cond_e
    invoke-static {v1, v8, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 560
    .line 561
    .line 562
    :cond_f
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 563
    .line 564
    invoke-static {v0, v6, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 565
    .line 566
    .line 567
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 568
    .line 569
    invoke-virtual {v8, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 570
    .line 571
    .line 572
    move-result-object v0

    .line 573
    check-cast v0, Lj91/c;

    .line 574
    .line 575
    iget v0, v0, Lj91/c;->c:F

    .line 576
    .line 577
    const/high16 v1, 0x3f800000    # 1.0f

    .line 578
    .line 579
    invoke-static {v5, v0, v8, v5, v1}, Lp3/m;->v(Lx2/p;FLl2/t;Lx2/p;F)Lx2/s;

    .line 580
    .line 581
    .line 582
    move-result-object v0

    .line 583
    iget-object v1, v2, Lma0/e;->d:Ljava/lang/String;

    .line 584
    .line 585
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 586
    .line 587
    .line 588
    move-result-object v5

    .line 589
    iget-object v3, v2, Lma0/e;->b:Ljava/lang/String;

    .line 590
    .line 591
    const/4 v9, 0x0

    .line 592
    const/16 v10, 0x18

    .line 593
    .line 594
    const/4 v6, 0x0

    .line 595
    const/4 v7, 0x0

    .line 596
    invoke-static/range {v3 .. v10}, Lxf0/i0;->A(Ljava/lang/String;Lay0/k;Lx2/s;Lg4/p0;Lg4/p0;Ll2/o;II)V

    .line 597
    .line 598
    .line 599
    invoke-virtual {v8, v11}, Ll2/t;->q(Z)V

    .line 600
    .line 601
    .line 602
    goto :goto_4

    .line 603
    :cond_10
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 604
    .line 605
    .line 606
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 607
    .line 608
    return-object v0

    .line 609
    :pswitch_8
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast v2, Lm80/b;

    .line 612
    .line 613
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 614
    .line 615
    check-cast v0, Ll80/c;

    .line 616
    .line 617
    move-object/from16 v3, p1

    .line 618
    .line 619
    check-cast v3, Ll2/o;

    .line 620
    .line 621
    check-cast v1, Ljava/lang/Integer;

    .line 622
    .line 623
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 624
    .line 625
    .line 626
    const/4 v1, 0x1

    .line 627
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 628
    .line 629
    .line 630
    move-result v1

    .line 631
    invoke-static {v2, v0, v3, v1}, Ln80/a;->p(Lm80/b;Ll80/c;Ll2/o;I)V

    .line 632
    .line 633
    .line 634
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 635
    .line 636
    return-object v0

    .line 637
    :pswitch_9
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 638
    .line 639
    check-cast v2, Ll2/b1;

    .line 640
    .line 641
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 642
    .line 643
    check-cast v0, Lm70/y0;

    .line 644
    .line 645
    move-object/from16 v3, p1

    .line 646
    .line 647
    check-cast v3, Ll2/o;

    .line 648
    .line 649
    check-cast v1, Ljava/lang/Integer;

    .line 650
    .line 651
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 652
    .line 653
    .line 654
    move-result v1

    .line 655
    and-int/lit8 v4, v1, 0x3

    .line 656
    .line 657
    const/4 v5, 0x2

    .line 658
    const/4 v6, 0x1

    .line 659
    if-eq v4, v5, :cond_11

    .line 660
    .line 661
    move v4, v6

    .line 662
    goto :goto_5

    .line 663
    :cond_11
    const/4 v4, 0x0

    .line 664
    :goto_5
    and-int/2addr v1, v6

    .line 665
    move-object v12, v3

    .line 666
    check-cast v12, Ll2/t;

    .line 667
    .line 668
    invoke-virtual {v12, v1, v4}, Ll2/t;->O(IZ)Z

    .line 669
    .line 670
    .line 671
    move-result v1

    .line 672
    if-eqz v1, :cond_1d

    .line 673
    .line 674
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 675
    .line 676
    sget-object v3, Lk1/j;->f:Lk1/f;

    .line 677
    .line 678
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 679
    .line 680
    const/high16 v5, 0x3f800000    # 1.0f

    .line 681
    .line 682
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 683
    .line 684
    .line 685
    move-result-object v7

    .line 686
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 687
    .line 688
    .line 689
    move-result-object v8

    .line 690
    iget v8, v8, Lj91/c;->d:F

    .line 691
    .line 692
    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 693
    .line 694
    .line 695
    move-result-object v7

    .line 696
    const/16 v8, 0x36

    .line 697
    .line 698
    invoke-static {v3, v1, v12, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    iget-wide v9, v12, Ll2/t;->T:J

    .line 703
    .line 704
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 705
    .line 706
    .line 707
    move-result v3

    .line 708
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 709
    .line 710
    .line 711
    move-result-object v9

    .line 712
    invoke-static {v12, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 713
    .line 714
    .line 715
    move-result-object v7

    .line 716
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 717
    .line 718
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 719
    .line 720
    .line 721
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 722
    .line 723
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 724
    .line 725
    .line 726
    iget-boolean v11, v12, Ll2/t;->S:Z

    .line 727
    .line 728
    if-eqz v11, :cond_12

    .line 729
    .line 730
    invoke-virtual {v12, v10}, Ll2/t;->l(Lay0/a;)V

    .line 731
    .line 732
    .line 733
    goto :goto_6

    .line 734
    :cond_12
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 735
    .line 736
    .line 737
    :goto_6
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 738
    .line 739
    invoke-static {v11, v1, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 740
    .line 741
    .line 742
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 743
    .line 744
    invoke-static {v1, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 745
    .line 746
    .line 747
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 748
    .line 749
    iget-boolean v13, v12, Ll2/t;->S:Z

    .line 750
    .line 751
    if-nez v13, :cond_13

    .line 752
    .line 753
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 754
    .line 755
    .line 756
    move-result-object v13

    .line 757
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 758
    .line 759
    .line 760
    move-result-object v14

    .line 761
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 762
    .line 763
    .line 764
    move-result v13

    .line 765
    if-nez v13, :cond_14

    .line 766
    .line 767
    :cond_13
    invoke-static {v3, v12, v3, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 768
    .line 769
    .line 770
    :cond_14
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 771
    .line 772
    invoke-static {v3, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 773
    .line 774
    .line 775
    sget-object v7, Lx2/c;->r:Lx2/h;

    .line 776
    .line 777
    sget-object v13, Lk1/j;->g:Lk1/f;

    .line 778
    .line 779
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 780
    .line 781
    .line 782
    move-result-object v14

    .line 783
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 784
    .line 785
    .line 786
    move-result-object v15

    .line 787
    check-cast v15, Ljava/lang/Number;

    .line 788
    .line 789
    invoke-virtual {v15}, Ljava/lang/Number;->intValue()I

    .line 790
    .line 791
    .line 792
    move-result v15

    .line 793
    if-lez v15, :cond_15

    .line 794
    .line 795
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    move-result-object v2

    .line 799
    check-cast v2, Ljava/lang/Number;

    .line 800
    .line 801
    invoke-static {v2}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 802
    .line 803
    .line 804
    move-result v2

    .line 805
    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 806
    .line 807
    .line 808
    move-result-object v2

    .line 809
    goto :goto_7

    .line 810
    :cond_15
    move-object v2, v4

    .line 811
    :goto_7
    invoke-interface {v14, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 812
    .line 813
    .line 814
    move-result-object v2

    .line 815
    invoke-static {v13, v7, v12, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 816
    .line 817
    .line 818
    move-result-object v7

    .line 819
    iget-wide v14, v12, Ll2/t;->T:J

    .line 820
    .line 821
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 822
    .line 823
    .line 824
    move-result v14

    .line 825
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 826
    .line 827
    .line 828
    move-result-object v15

    .line 829
    invoke-static {v12, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 830
    .line 831
    .line 832
    move-result-object v2

    .line 833
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 834
    .line 835
    .line 836
    iget-boolean v8, v12, Ll2/t;->S:Z

    .line 837
    .line 838
    if-eqz v8, :cond_16

    .line 839
    .line 840
    invoke-virtual {v12, v10}, Ll2/t;->l(Lay0/a;)V

    .line 841
    .line 842
    .line 843
    goto :goto_8

    .line 844
    :cond_16
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 845
    .line 846
    .line 847
    :goto_8
    invoke-static {v11, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 848
    .line 849
    .line 850
    invoke-static {v1, v15, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 851
    .line 852
    .line 853
    iget-boolean v7, v12, Ll2/t;->S:Z

    .line 854
    .line 855
    if-nez v7, :cond_17

    .line 856
    .line 857
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 858
    .line 859
    .line 860
    move-result-object v7

    .line 861
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 862
    .line 863
    .line 864
    move-result-object v8

    .line 865
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 866
    .line 867
    .line 868
    move-result v7

    .line 869
    if-nez v7, :cond_18

    .line 870
    .line 871
    :cond_17
    invoke-static {v14, v12, v14, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 872
    .line 873
    .line 874
    :cond_18
    invoke-static {v3, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 875
    .line 876
    .line 877
    iget-object v7, v0, Lm70/y0;->b:Ljava/lang/String;

    .line 878
    .line 879
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 880
    .line 881
    .line 882
    move-result-object v2

    .line 883
    invoke-virtual {v2}, Lj91/f;->a()Lg4/p0;

    .line 884
    .line 885
    .line 886
    move-result-object v8

    .line 887
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 888
    .line 889
    .line 890
    move-result-object v2

    .line 891
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 892
    .line 893
    .line 894
    move-result-wide v14

    .line 895
    const-string v2, "trip_history_item_time_start"

    .line 896
    .line 897
    invoke-static {v4, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 898
    .line 899
    .line 900
    move-result-object v2

    .line 901
    const/16 v27, 0x0

    .line 902
    .line 903
    const v28, 0xfff0

    .line 904
    .line 905
    .line 906
    move-object/from16 v25, v12

    .line 907
    .line 908
    move-object/from16 v16, v13

    .line 909
    .line 910
    const-wide/16 v12, 0x0

    .line 911
    .line 912
    move-object/from16 v17, v11

    .line 913
    .line 914
    move-wide/from16 v35, v14

    .line 915
    .line 916
    move-object v15, v10

    .line 917
    move-wide/from16 v10, v35

    .line 918
    .line 919
    const/4 v14, 0x0

    .line 920
    move-object/from16 v18, v15

    .line 921
    .line 922
    move-object/from16 v19, v16

    .line 923
    .line 924
    const-wide/16 v15, 0x0

    .line 925
    .line 926
    move-object/from16 v20, v17

    .line 927
    .line 928
    const/16 v17, 0x0

    .line 929
    .line 930
    move-object/from16 v21, v18

    .line 931
    .line 932
    const/16 v18, 0x0

    .line 933
    .line 934
    move-object/from16 v23, v19

    .line 935
    .line 936
    move-object/from16 v22, v20

    .line 937
    .line 938
    const-wide/16 v19, 0x0

    .line 939
    .line 940
    move-object/from16 v24, v21

    .line 941
    .line 942
    const/16 v21, 0x0

    .line 943
    .line 944
    move-object/from16 v26, v22

    .line 945
    .line 946
    const/16 v22, 0x0

    .line 947
    .line 948
    move-object/from16 v29, v23

    .line 949
    .line 950
    const/16 v23, 0x0

    .line 951
    .line 952
    move-object/from16 v30, v24

    .line 953
    .line 954
    const/16 v24, 0x0

    .line 955
    .line 956
    move-object/from16 v31, v26

    .line 957
    .line 958
    const/16 v26, 0x180

    .line 959
    .line 960
    move-object/from16 v33, v9

    .line 961
    .line 962
    move-object/from16 v34, v29

    .line 963
    .line 964
    move-object/from16 v32, v31

    .line 965
    .line 966
    move-object v9, v2

    .line 967
    move-object/from16 v2, v30

    .line 968
    .line 969
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 970
    .line 971
    .line 972
    move-object/from16 v12, v25

    .line 973
    .line 974
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 975
    .line 976
    .line 977
    move-result-object v7

    .line 978
    iget v7, v7, Lj91/c;->a:F

    .line 979
    .line 980
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 981
    .line 982
    .line 983
    move-result-object v7

    .line 984
    invoke-static {v12, v7}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 985
    .line 986
    .line 987
    iget-object v7, v0, Lm70/y0;->c:Ljava/lang/String;

    .line 988
    .line 989
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 990
    .line 991
    .line 992
    move-result-object v8

    .line 993
    invoke-virtual {v8}, Lj91/f;->a()Lg4/p0;

    .line 994
    .line 995
    .line 996
    move-result-object v8

    .line 997
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 998
    .line 999
    .line 1000
    move-result-object v9

    .line 1001
    invoke-virtual {v9}, Lj91/e;->q()J

    .line 1002
    .line 1003
    .line 1004
    move-result-wide v10

    .line 1005
    const-string v9, "trip_history_item_time_end"

    .line 1006
    .line 1007
    invoke-static {v4, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v9

    .line 1011
    const-wide/16 v12, 0x0

    .line 1012
    .line 1013
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1014
    .line 1015
    .line 1016
    move-object/from16 v12, v25

    .line 1017
    .line 1018
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 1019
    .line 1020
    .line 1021
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v7

    .line 1025
    iget v11, v7, Lj91/c;->d:F

    .line 1026
    .line 1027
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v7

    .line 1031
    iget v7, v7, Lj91/c;->a:F

    .line 1032
    .line 1033
    const/4 v8, 0x0

    .line 1034
    invoke-static {v4, v8, v7, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v7

    .line 1038
    const/4 v13, 0x0

    .line 1039
    const/4 v14, 0x6

    .line 1040
    const-wide/16 v8, 0x0

    .line 1041
    .line 1042
    const/4 v10, 0x0

    .line 1043
    invoke-static/range {v7 .. v14}, Lxf0/y1;->r(Lx2/s;JFFLl2/o;II)V

    .line 1044
    .line 1045
    .line 1046
    sget-object v7, Lx2/c;->p:Lx2/h;

    .line 1047
    .line 1048
    invoke-static {v4, v5}, Landroidx/compose/foundation/layout/d;->c(Lx2/s;F)Lx2/s;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v8

    .line 1052
    float-to-double v9, v5

    .line 1053
    const-wide/16 v13, 0x0

    .line 1054
    .line 1055
    cmpl-double v9, v9, v13

    .line 1056
    .line 1057
    if-lez v9, :cond_19

    .line 1058
    .line 1059
    goto :goto_9

    .line 1060
    :cond_19
    const-string v9, "invalid weight; must be greater than zero"

    .line 1061
    .line 1062
    invoke-static {v9}, Ll1/a;->a(Ljava/lang/String;)V

    .line 1063
    .line 1064
    .line 1065
    :goto_9
    new-instance v9, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 1066
    .line 1067
    invoke-direct {v9, v5, v6}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 1068
    .line 1069
    .line 1070
    invoke-interface {v8, v9}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 1071
    .line 1072
    .line 1073
    move-result-object v5

    .line 1074
    move-object/from16 v8, v34

    .line 1075
    .line 1076
    const/16 v9, 0x36

    .line 1077
    .line 1078
    invoke-static {v8, v7, v12, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v7

    .line 1082
    iget-wide v8, v12, Ll2/t;->T:J

    .line 1083
    .line 1084
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 1085
    .line 1086
    .line 1087
    move-result v8

    .line 1088
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v9

    .line 1092
    invoke-static {v12, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v5

    .line 1096
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 1097
    .line 1098
    .line 1099
    iget-boolean v10, v12, Ll2/t;->S:Z

    .line 1100
    .line 1101
    if-eqz v10, :cond_1a

    .line 1102
    .line 1103
    invoke-virtual {v12, v2}, Ll2/t;->l(Lay0/a;)V

    .line 1104
    .line 1105
    .line 1106
    :goto_a
    move-object/from16 v2, v32

    .line 1107
    .line 1108
    goto :goto_b

    .line 1109
    :cond_1a
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 1110
    .line 1111
    .line 1112
    goto :goto_a

    .line 1113
    :goto_b
    invoke-static {v2, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1114
    .line 1115
    .line 1116
    invoke-static {v1, v9, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1117
    .line 1118
    .line 1119
    iget-boolean v1, v12, Ll2/t;->S:Z

    .line 1120
    .line 1121
    if-nez v1, :cond_1b

    .line 1122
    .line 1123
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 1124
    .line 1125
    .line 1126
    move-result-object v1

    .line 1127
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v2

    .line 1131
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1132
    .line 1133
    .line 1134
    move-result v1

    .line 1135
    if-nez v1, :cond_1c

    .line 1136
    .line 1137
    :cond_1b
    move-object/from16 v1, v33

    .line 1138
    .line 1139
    invoke-static {v8, v12, v8, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1140
    .line 1141
    .line 1142
    :cond_1c
    invoke-static {v3, v5, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1143
    .line 1144
    .line 1145
    iget-object v7, v0, Lm70/y0;->d:Ljava/lang/String;

    .line 1146
    .line 1147
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v1

    .line 1151
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v8

    .line 1155
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1156
    .line 1157
    .line 1158
    move-result-object v1

    .line 1159
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 1160
    .line 1161
    .line 1162
    move-result-wide v10

    .line 1163
    const-string v1, "trip_history_item_locations_start"

    .line 1164
    .line 1165
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v9

    .line 1169
    const/16 v27, 0x6180

    .line 1170
    .line 1171
    const v28, 0xaff0

    .line 1172
    .line 1173
    .line 1174
    move-object/from16 v25, v12

    .line 1175
    .line 1176
    const-wide/16 v12, 0x0

    .line 1177
    .line 1178
    const/4 v14, 0x0

    .line 1179
    const-wide/16 v15, 0x0

    .line 1180
    .line 1181
    const/16 v17, 0x0

    .line 1182
    .line 1183
    const/16 v18, 0x0

    .line 1184
    .line 1185
    const-wide/16 v19, 0x0

    .line 1186
    .line 1187
    const/16 v21, 0x2

    .line 1188
    .line 1189
    const/16 v22, 0x0

    .line 1190
    .line 1191
    const/16 v23, 0x1

    .line 1192
    .line 1193
    const/16 v24, 0x0

    .line 1194
    .line 1195
    const/16 v26, 0x180

    .line 1196
    .line 1197
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1198
    .line 1199
    .line 1200
    iget-object v7, v0, Lm70/y0;->e:Ljava/lang/String;

    .line 1201
    .line 1202
    invoke-static/range {v25 .. v25}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v1

    .line 1206
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 1207
    .line 1208
    .line 1209
    move-result-object v8

    .line 1210
    invoke-static/range {v25 .. v25}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v1

    .line 1214
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 1215
    .line 1216
    .line 1217
    move-result-wide v10

    .line 1218
    const-string v1, "trip_history_item_locations_end"

    .line 1219
    .line 1220
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v9

    .line 1224
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1225
    .line 1226
    .line 1227
    move-object/from16 v12, v25

    .line 1228
    .line 1229
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 1230
    .line 1231
    .line 1232
    invoke-static {v12}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v1

    .line 1236
    iget v1, v1, Lj91/c;->d:F

    .line 1237
    .line 1238
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v1

    .line 1242
    invoke-static {v12, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 1243
    .line 1244
    .line 1245
    iget-object v0, v0, Lm70/y0;->f:Ljava/lang/String;

    .line 1246
    .line 1247
    invoke-static {v0}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v7

    .line 1251
    invoke-static {v12}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 1252
    .line 1253
    .line 1254
    move-result-object v0

    .line 1255
    invoke-virtual {v0}, Lj91/f;->a()Lg4/p0;

    .line 1256
    .line 1257
    .line 1258
    move-result-object v9

    .line 1259
    invoke-static {v12}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 1260
    .line 1261
    .line 1262
    move-result-object v0

    .line 1263
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 1264
    .line 1265
    .line 1266
    move-result-wide v10

    .line 1267
    const-string v0, "trip_history_item_distance"

    .line 1268
    .line 1269
    invoke-static {v4, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v8

    .line 1273
    const/16 v25, 0x0

    .line 1274
    .line 1275
    const v26, 0xfff0

    .line 1276
    .line 1277
    .line 1278
    move-object/from16 v23, v12

    .line 1279
    .line 1280
    const-wide/16 v12, 0x0

    .line 1281
    .line 1282
    const-wide/16 v14, 0x0

    .line 1283
    .line 1284
    const/16 v16, 0x0

    .line 1285
    .line 1286
    const-wide/16 v17, 0x0

    .line 1287
    .line 1288
    const/16 v19, 0x0

    .line 1289
    .line 1290
    const/16 v20, 0x0

    .line 1291
    .line 1292
    const/16 v21, 0x0

    .line 1293
    .line 1294
    const/16 v22, 0x0

    .line 1295
    .line 1296
    const/16 v24, 0x30

    .line 1297
    .line 1298
    invoke-static/range {v7 .. v26}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 1299
    .line 1300
    .line 1301
    move-object/from16 v12, v23

    .line 1302
    .line 1303
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 1304
    .line 1305
    .line 1306
    goto :goto_c

    .line 1307
    :cond_1d
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 1308
    .line 1309
    .line 1310
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1311
    .line 1312
    return-object v0

    .line 1313
    :pswitch_a
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1314
    .line 1315
    check-cast v2, Lm70/z0;

    .line 1316
    .line 1317
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1318
    .line 1319
    check-cast v0, Lay0/k;

    .line 1320
    .line 1321
    move-object/from16 v3, p1

    .line 1322
    .line 1323
    check-cast v3, Ll2/o;

    .line 1324
    .line 1325
    check-cast v1, Ljava/lang/Integer;

    .line 1326
    .line 1327
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1328
    .line 1329
    .line 1330
    const/4 v1, 0x1

    .line 1331
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1332
    .line 1333
    .line 1334
    move-result v1

    .line 1335
    invoke-static {v2, v0, v3, v1}, Ln70/a;->l0(Lm70/z0;Lay0/k;Ll2/o;I)V

    .line 1336
    .line 1337
    .line 1338
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1339
    .line 1340
    return-object v0

    .line 1341
    :pswitch_b
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1342
    .line 1343
    check-cast v2, Lm70/c1;

    .line 1344
    .line 1345
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1346
    .line 1347
    move-object v5, v0

    .line 1348
    check-cast v5, Lay0/a;

    .line 1349
    .line 1350
    move-object/from16 v0, p1

    .line 1351
    .line 1352
    check-cast v0, Ll2/o;

    .line 1353
    .line 1354
    check-cast v1, Ljava/lang/Integer;

    .line 1355
    .line 1356
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1357
    .line 1358
    .line 1359
    move-result v1

    .line 1360
    and-int/lit8 v3, v1, 0x3

    .line 1361
    .line 1362
    const/4 v4, 0x2

    .line 1363
    const/4 v6, 0x1

    .line 1364
    const/4 v7, 0x0

    .line 1365
    if-eq v3, v4, :cond_1e

    .line 1366
    .line 1367
    move v3, v6

    .line 1368
    goto :goto_d

    .line 1369
    :cond_1e
    move v3, v7

    .line 1370
    :goto_d
    and-int/2addr v1, v6

    .line 1371
    move-object v13, v0

    .line 1372
    check-cast v13, Ll2/t;

    .line 1373
    .line 1374
    invoke-virtual {v13, v1, v3}, Ll2/t;->O(IZ)Z

    .line 1375
    .line 1376
    .line 1377
    move-result v0

    .line 1378
    if-eqz v0, :cond_21

    .line 1379
    .line 1380
    iget-object v0, v2, Lm70/c1;->i:Ljava/lang/String;

    .line 1381
    .line 1382
    if-nez v0, :cond_1f

    .line 1383
    .line 1384
    const v0, -0x5bf2ac90

    .line 1385
    .line 1386
    .line 1387
    const v1, 0x7f121464

    .line 1388
    .line 1389
    .line 1390
    invoke-static {v0, v1, v13, v13, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v0

    .line 1394
    :goto_e
    move-object v3, v0

    .line 1395
    goto :goto_f

    .line 1396
    :cond_1f
    const v1, -0x5bf2aff4

    .line 1397
    .line 1398
    .line 1399
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 1400
    .line 1401
    .line 1402
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 1403
    .line 1404
    .line 1405
    goto :goto_e

    .line 1406
    :goto_f
    iget-object v0, v2, Lm70/c1;->i:Ljava/lang/String;

    .line 1407
    .line 1408
    if-eqz v0, :cond_20

    .line 1409
    .line 1410
    goto :goto_10

    .line 1411
    :cond_20
    move v6, v7

    .line 1412
    :goto_10
    const v0, 0x7f080333

    .line 1413
    .line 1414
    .line 1415
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1416
    .line 1417
    .line 1418
    move-result-object v11

    .line 1419
    const/16 v15, 0xc00

    .line 1420
    .line 1421
    const/16 v16, 0x1ef2

    .line 1422
    .line 1423
    const/4 v4, 0x0

    .line 1424
    const/4 v7, 0x0

    .line 1425
    const/4 v8, 0x0

    .line 1426
    const/4 v9, 0x0

    .line 1427
    const/4 v10, 0x0

    .line 1428
    const-string v12, "triphistory_date"

    .line 1429
    .line 1430
    const/4 v14, 0x0

    .line 1431
    invoke-static/range {v3 .. v16}, Li91/h0;->a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V

    .line 1432
    .line 1433
    .line 1434
    goto :goto_11

    .line 1435
    :cond_21
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 1436
    .line 1437
    .line 1438
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1439
    .line 1440
    return-object v0

    .line 1441
    :pswitch_c
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1442
    .line 1443
    check-cast v2, Ll2/b1;

    .line 1444
    .line 1445
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1446
    .line 1447
    check-cast v0, Lay0/k;

    .line 1448
    .line 1449
    move-object/from16 v3, p1

    .line 1450
    .line 1451
    check-cast v3, Ljava/time/LocalDate;

    .line 1452
    .line 1453
    check-cast v1, Ljava/time/LocalDate;

    .line 1454
    .line 1455
    const-string v4, "from"

    .line 1456
    .line 1457
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1458
    .line 1459
    .line 1460
    const-string v4, "to"

    .line 1461
    .line 1462
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1463
    .line 1464
    .line 1465
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 1466
    .line 1467
    invoke-interface {v2, v4}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1468
    .line 1469
    .line 1470
    new-instance v2, Ll70/b;

    .line 1471
    .line 1472
    invoke-direct {v2, v3, v1}, Ll70/b;-><init>(Ljava/time/LocalDate;Ljava/time/LocalDate;)V

    .line 1473
    .line 1474
    .line 1475
    invoke-interface {v0, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1476
    .line 1477
    .line 1478
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1479
    .line 1480
    return-object v0

    .line 1481
    :pswitch_d
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1482
    .line 1483
    check-cast v2, Lm70/g0;

    .line 1484
    .line 1485
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1486
    .line 1487
    check-cast v0, Lay0/k;

    .line 1488
    .line 1489
    move-object/from16 v3, p1

    .line 1490
    .line 1491
    check-cast v3, Ll2/o;

    .line 1492
    .line 1493
    check-cast v1, Ljava/lang/Integer;

    .line 1494
    .line 1495
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1496
    .line 1497
    .line 1498
    const/4 v1, 0x1

    .line 1499
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1500
    .line 1501
    .line 1502
    move-result v1

    .line 1503
    invoke-static {v2, v0, v3, v1}, Ln70/a;->u(Lm70/g0;Lay0/k;Ll2/o;I)V

    .line 1504
    .line 1505
    .line 1506
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1507
    .line 1508
    return-object v0

    .line 1509
    :pswitch_e
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1510
    .line 1511
    move-object v3, v2

    .line 1512
    check-cast v3, Lx2/s;

    .line 1513
    .line 1514
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1515
    .line 1516
    move-object v4, v0

    .line 1517
    check-cast v4, Lm70/b0;

    .line 1518
    .line 1519
    move-object/from16 v0, p1

    .line 1520
    .line 1521
    check-cast v0, Ll2/o;

    .line 1522
    .line 1523
    check-cast v1, Ljava/lang/Integer;

    .line 1524
    .line 1525
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1526
    .line 1527
    .line 1528
    move-result v1

    .line 1529
    and-int/lit8 v2, v1, 0x3

    .line 1530
    .line 1531
    const/4 v5, 0x2

    .line 1532
    const/4 v6, 0x1

    .line 1533
    if-eq v2, v5, :cond_22

    .line 1534
    .line 1535
    move v2, v6

    .line 1536
    goto :goto_12

    .line 1537
    :cond_22
    const/4 v2, 0x0

    .line 1538
    :goto_12
    and-int/2addr v1, v6

    .line 1539
    move-object v8, v0

    .line 1540
    check-cast v8, Ll2/t;

    .line 1541
    .line 1542
    invoke-virtual {v8, v1, v2}, Ll2/t;->O(IZ)Z

    .line 1543
    .line 1544
    .line 1545
    move-result v0

    .line 1546
    if-eqz v0, :cond_23

    .line 1547
    .line 1548
    sget-object v6, Ll70/q;->e:Ll70/q;

    .line 1549
    .line 1550
    const/4 v7, 0x0

    .line 1551
    const/16 v9, 0x6d80

    .line 1552
    .line 1553
    const/4 v5, 0x0

    .line 1554
    invoke-static/range {v3 .. v9}, Ln70/a;->Y(Lx2/s;Lm70/b0;Ljava/lang/Integer;Ll70/q;Lay0/k;Ll2/o;I)V

    .line 1555
    .line 1556
    .line 1557
    goto :goto_13

    .line 1558
    :cond_23
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 1559
    .line 1560
    .line 1561
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1562
    .line 1563
    return-object v0

    .line 1564
    :pswitch_f
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1565
    .line 1566
    check-cast v2, Lm70/q;

    .line 1567
    .line 1568
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1569
    .line 1570
    check-cast v0, Ljava/lang/String;

    .line 1571
    .line 1572
    move-object/from16 v3, p1

    .line 1573
    .line 1574
    check-cast v3, Ll2/o;

    .line 1575
    .line 1576
    check-cast v1, Ljava/lang/Integer;

    .line 1577
    .line 1578
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1579
    .line 1580
    .line 1581
    const/4 v1, 0x1

    .line 1582
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1583
    .line 1584
    .line 1585
    move-result v1

    .line 1586
    invoke-static {v2, v0, v3, v1}, Ln70/r;->a(Lm70/q;Ljava/lang/String;Ll2/o;I)V

    .line 1587
    .line 1588
    .line 1589
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1590
    .line 1591
    return-object v0

    .line 1592
    :pswitch_10
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1593
    .line 1594
    check-cast v2, Lm70/r;

    .line 1595
    .line 1596
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1597
    .line 1598
    check-cast v0, Lay0/a;

    .line 1599
    .line 1600
    move-object/from16 v3, p1

    .line 1601
    .line 1602
    check-cast v3, Ll2/o;

    .line 1603
    .line 1604
    check-cast v1, Ljava/lang/Integer;

    .line 1605
    .line 1606
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1607
    .line 1608
    .line 1609
    const/4 v1, 0x1

    .line 1610
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1611
    .line 1612
    .line 1613
    move-result v1

    .line 1614
    invoke-static {v2, v0, v3, v1}, Ln70/a;->H(Lm70/r;Lay0/a;Ll2/o;I)V

    .line 1615
    .line 1616
    .line 1617
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1618
    .line 1619
    return-object v0

    .line 1620
    :pswitch_11
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1621
    .line 1622
    check-cast v2, Lm70/j;

    .line 1623
    .line 1624
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1625
    .line 1626
    check-cast v0, Lay0/k;

    .line 1627
    .line 1628
    move-object/from16 v3, p1

    .line 1629
    .line 1630
    check-cast v3, Ll2/o;

    .line 1631
    .line 1632
    check-cast v1, Ljava/lang/Integer;

    .line 1633
    .line 1634
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1635
    .line 1636
    .line 1637
    const/4 v1, 0x1

    .line 1638
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1639
    .line 1640
    .line 1641
    move-result v1

    .line 1642
    invoke-static {v2, v0, v3, v1}, Ln70/a;->S(Lm70/j;Lay0/k;Ll2/o;I)V

    .line 1643
    .line 1644
    .line 1645
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1646
    .line 1647
    return-object v0

    .line 1648
    :pswitch_12
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1649
    .line 1650
    check-cast v2, Lm70/b;

    .line 1651
    .line 1652
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1653
    .line 1654
    check-cast v0, Lay0/a;

    .line 1655
    .line 1656
    move-object/from16 v3, p1

    .line 1657
    .line 1658
    check-cast v3, Ll2/o;

    .line 1659
    .line 1660
    check-cast v1, Ljava/lang/Integer;

    .line 1661
    .line 1662
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1663
    .line 1664
    .line 1665
    const/4 v1, 0x1

    .line 1666
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1667
    .line 1668
    .line 1669
    move-result v1

    .line 1670
    invoke-static {v2, v0, v3, v1}, Ln70/a;->h(Lm70/b;Lay0/a;Ll2/o;I)V

    .line 1671
    .line 1672
    .line 1673
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1674
    .line 1675
    return-object v0

    .line 1676
    :pswitch_13
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1677
    .line 1678
    check-cast v2, Lhg/b;

    .line 1679
    .line 1680
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1681
    .line 1682
    check-cast v0, Lay0/k;

    .line 1683
    .line 1684
    move-object/from16 v3, p1

    .line 1685
    .line 1686
    check-cast v3, Ll2/o;

    .line 1687
    .line 1688
    check-cast v1, Ljava/lang/Integer;

    .line 1689
    .line 1690
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1691
    .line 1692
    .line 1693
    const/16 v1, 0x9

    .line 1694
    .line 1695
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1696
    .line 1697
    .line 1698
    move-result v1

    .line 1699
    invoke-static {v2, v0, v3, v1}, Lmk/a;->e(Lhg/b;Lay0/k;Ll2/o;I)V

    .line 1700
    .line 1701
    .line 1702
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1703
    .line 1704
    return-object v0

    .line 1705
    :pswitch_14
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1706
    .line 1707
    check-cast v2, Lhg/m;

    .line 1708
    .line 1709
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1710
    .line 1711
    check-cast v0, Lay0/k;

    .line 1712
    .line 1713
    move-object/from16 v3, p1

    .line 1714
    .line 1715
    check-cast v3, Ll2/o;

    .line 1716
    .line 1717
    check-cast v1, Ljava/lang/Integer;

    .line 1718
    .line 1719
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1720
    .line 1721
    .line 1722
    const/4 v1, 0x1

    .line 1723
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1724
    .line 1725
    .line 1726
    move-result v1

    .line 1727
    invoke-static {v2, v0, v3, v1}, Lmk/a;->f(Lhg/m;Lay0/k;Ll2/o;I)V

    .line 1728
    .line 1729
    .line 1730
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1731
    .line 1732
    return-object v0

    .line 1733
    :pswitch_15
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1734
    .line 1735
    check-cast v2, Lyj/b;

    .line 1736
    .line 1737
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1738
    .line 1739
    check-cast v0, Ly1/i;

    .line 1740
    .line 1741
    move-object/from16 v3, p1

    .line 1742
    .line 1743
    check-cast v3, Ll2/o;

    .line 1744
    .line 1745
    check-cast v1, Ljava/lang/Integer;

    .line 1746
    .line 1747
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1748
    .line 1749
    .line 1750
    const/4 v1, 0x1

    .line 1751
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1752
    .line 1753
    .line 1754
    move-result v1

    .line 1755
    invoke-static {v2, v0, v3, v1}, Landroidx/datastore/preferences/protobuf/o1;->c(Lyj/b;Ly1/i;Ll2/o;I)V

    .line 1756
    .line 1757
    .line 1758
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1759
    .line 1760
    return-object v0

    .line 1761
    :pswitch_16
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1762
    .line 1763
    check-cast v2, Ljava/lang/String;

    .line 1764
    .line 1765
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1766
    .line 1767
    check-cast v0, Lay0/k;

    .line 1768
    .line 1769
    move-object/from16 v3, p1

    .line 1770
    .line 1771
    check-cast v3, Ll2/o;

    .line 1772
    .line 1773
    check-cast v1, Ljava/lang/Integer;

    .line 1774
    .line 1775
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1776
    .line 1777
    .line 1778
    const/4 v1, 0x1

    .line 1779
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1780
    .line 1781
    .line 1782
    move-result v1

    .line 1783
    invoke-static {v2, v0, v3, v1}, Lmg/a;->a(Ljava/lang/String;Lay0/k;Ll2/o;I)V

    .line 1784
    .line 1785
    .line 1786
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1787
    .line 1788
    return-object v0

    .line 1789
    :pswitch_17
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1790
    .line 1791
    check-cast v2, Lyj/b;

    .line 1792
    .line 1793
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1794
    .line 1795
    check-cast v0, Lyy0/l1;

    .line 1796
    .line 1797
    move-object/from16 v3, p1

    .line 1798
    .line 1799
    check-cast v3, Ll2/o;

    .line 1800
    .line 1801
    check-cast v1, Ljava/lang/Integer;

    .line 1802
    .line 1803
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1804
    .line 1805
    .line 1806
    const/4 v1, 0x1

    .line 1807
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1808
    .line 1809
    .line 1810
    move-result v1

    .line 1811
    invoke-static {v2, v0, v3, v1}, Ljp/e1;->a(Lyj/b;Lyy0/l1;Ll2/o;I)V

    .line 1812
    .line 1813
    .line 1814
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1815
    .line 1816
    return-object v0

    .line 1817
    :pswitch_18
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1818
    .line 1819
    check-cast v2, Ldd/f;

    .line 1820
    .line 1821
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1822
    .line 1823
    check-cast v0, Lzb/s0;

    .line 1824
    .line 1825
    move-object/from16 v3, p1

    .line 1826
    .line 1827
    check-cast v3, Ll2/o;

    .line 1828
    .line 1829
    check-cast v1, Ljava/lang/Integer;

    .line 1830
    .line 1831
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1832
    .line 1833
    .line 1834
    const/4 v1, 0x1

    .line 1835
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 1836
    .line 1837
    .line 1838
    move-result v1

    .line 1839
    invoke-static {v2, v0, v3, v1}, Ljp/c1;->a(Ldd/f;Lzb/s0;Ll2/o;I)V

    .line 1840
    .line 1841
    .line 1842
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1843
    .line 1844
    return-object v0

    .line 1845
    :pswitch_19
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 1846
    .line 1847
    check-cast v2, Ljava/lang/String;

    .line 1848
    .line 1849
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 1850
    .line 1851
    check-cast v0, Luf/a;

    .line 1852
    .line 1853
    move-object/from16 v3, p1

    .line 1854
    .line 1855
    check-cast v3, Ll2/o;

    .line 1856
    .line 1857
    check-cast v1, Ljava/lang/Integer;

    .line 1858
    .line 1859
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1860
    .line 1861
    .line 1862
    move-result v1

    .line 1863
    and-int/lit8 v4, v1, 0x3

    .line 1864
    .line 1865
    const/4 v5, 0x1

    .line 1866
    const/4 v6, 0x0

    .line 1867
    const/4 v7, 0x2

    .line 1868
    if-eq v4, v7, :cond_24

    .line 1869
    .line 1870
    move v4, v5

    .line 1871
    goto :goto_14

    .line 1872
    :cond_24
    move v4, v6

    .line 1873
    :goto_14
    and-int/2addr v1, v5

    .line 1874
    check-cast v3, Ll2/t;

    .line 1875
    .line 1876
    invoke-virtual {v3, v1, v4}, Ll2/t;->O(IZ)Z

    .line 1877
    .line 1878
    .line 1879
    move-result v1

    .line 1880
    if-eqz v1, :cond_2b

    .line 1881
    .line 1882
    const/16 v1, 0x10

    .line 1883
    .line 1884
    int-to-float v1, v1

    .line 1885
    const/4 v4, 0x0

    .line 1886
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 1887
    .line 1888
    invoke-static {v8, v1, v4, v7}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 1889
    .line 1890
    .line 1891
    move-result-object v1

    .line 1892
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 1893
    .line 1894
    sget-object v9, Lx2/c;->p:Lx2/h;

    .line 1895
    .line 1896
    invoke-static {v4, v9, v3, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1897
    .line 1898
    .line 1899
    move-result-object v4

    .line 1900
    iget-wide v9, v3, Ll2/t;->T:J

    .line 1901
    .line 1902
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 1903
    .line 1904
    .line 1905
    move-result v9

    .line 1906
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 1907
    .line 1908
    .line 1909
    move-result-object v10

    .line 1910
    invoke-static {v3, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1911
    .line 1912
    .line 1913
    move-result-object v1

    .line 1914
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 1915
    .line 1916
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1917
    .line 1918
    .line 1919
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 1920
    .line 1921
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 1922
    .line 1923
    .line 1924
    iget-boolean v12, v3, Ll2/t;->S:Z

    .line 1925
    .line 1926
    if-eqz v12, :cond_25

    .line 1927
    .line 1928
    invoke-virtual {v3, v11}, Ll2/t;->l(Lay0/a;)V

    .line 1929
    .line 1930
    .line 1931
    goto :goto_15

    .line 1932
    :cond_25
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 1933
    .line 1934
    .line 1935
    :goto_15
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 1936
    .line 1937
    invoke-static {v11, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1938
    .line 1939
    .line 1940
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 1941
    .line 1942
    invoke-static {v4, v10, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1943
    .line 1944
    .line 1945
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 1946
    .line 1947
    iget-boolean v10, v3, Ll2/t;->S:Z

    .line 1948
    .line 1949
    if-nez v10, :cond_26

    .line 1950
    .line 1951
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 1952
    .line 1953
    .line 1954
    move-result-object v10

    .line 1955
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1956
    .line 1957
    .line 1958
    move-result-object v11

    .line 1959
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1960
    .line 1961
    .line 1962
    move-result v10

    .line 1963
    if-nez v10, :cond_27

    .line 1964
    .line 1965
    :cond_26
    invoke-static {v9, v3, v9, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1966
    .line 1967
    .line 1968
    :cond_27
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 1969
    .line 1970
    invoke-static {v4, v1, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1971
    .line 1972
    .line 1973
    const/16 v1, 0x8

    .line 1974
    .line 1975
    int-to-float v10, v1

    .line 1976
    const/4 v12, 0x0

    .line 1977
    const/16 v13, 0xd

    .line 1978
    .line 1979
    const/4 v9, 0x0

    .line 1980
    const/4 v11, 0x0

    .line 1981
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 1982
    .line 1983
    .line 1984
    move-result-object v1

    .line 1985
    move v4, v10

    .line 1986
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 1987
    .line 1988
    .line 1989
    move-result-object v9

    .line 1990
    move-object v1, v8

    .line 1991
    iget-object v8, v0, Luf/a;->b:Ljava/lang/String;

    .line 1992
    .line 1993
    iget-object v2, v0, Luf/a;->d:Luf/q;

    .line 1994
    .line 1995
    iget-object v10, v0, Luf/a;->c:Ljava/lang/String;

    .line 1996
    .line 1997
    new-instance v0, Li91/a2;

    .line 1998
    .line 1999
    const v11, 0x7f120ad6

    .line 2000
    .line 2001
    .line 2002
    invoke-static {v3, v11}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 2003
    .line 2004
    .line 2005
    move-result-object v11

    .line 2006
    new-instance v12, Lg4/g;

    .line 2007
    .line 2008
    invoke-direct {v12, v11}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 2009
    .line 2010
    .line 2011
    invoke-direct {v0, v12}, Li91/a2;-><init>(Lg4/g;)V

    .line 2012
    .line 2013
    .line 2014
    sget-object v11, Luf/q;->d:Luf/q;

    .line 2015
    .line 2016
    if-ne v2, v11, :cond_28

    .line 2017
    .line 2018
    :goto_16
    move-object v12, v0

    .line 2019
    goto :goto_17

    .line 2020
    :cond_28
    const/4 v0, 0x0

    .line 2021
    goto :goto_16

    .line 2022
    :goto_17
    const/16 v20, 0x0

    .line 2023
    .line 2024
    const/16 v21, 0xfe8

    .line 2025
    .line 2026
    const/4 v11, 0x0

    .line 2027
    const/4 v13, 0x0

    .line 2028
    const/4 v14, 0x0

    .line 2029
    const/4 v15, 0x0

    .line 2030
    const/16 v16, 0x0

    .line 2031
    .line 2032
    const/16 v17, 0x0

    .line 2033
    .line 2034
    const/16 v19, 0x0

    .line 2035
    .line 2036
    move-object/from16 v18, v3

    .line 2037
    .line 2038
    invoke-static/range {v8 .. v21}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 2039
    .line 2040
    .line 2041
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 2042
    .line 2043
    .line 2044
    move-result v0

    .line 2045
    const/16 v2, 0x30

    .line 2046
    .line 2047
    if-eq v0, v7, :cond_2a

    .line 2048
    .line 2049
    const/4 v7, 0x3

    .line 2050
    if-eq v0, v7, :cond_29

    .line 2051
    .line 2052
    const v0, 0x4fa4d3f9

    .line 2053
    .line 2054
    .line 2055
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 2056
    .line 2057
    .line 2058
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 2059
    .line 2060
    .line 2061
    goto :goto_18

    .line 2062
    :cond_29
    const v0, -0x2efac797

    .line 2063
    .line 2064
    .line 2065
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 2066
    .line 2067
    .line 2068
    const v0, 0x7f120ac9

    .line 2069
    .line 2070
    .line 2071
    const-string v7, "plug_and_charge_update_required"

    .line 2072
    .line 2073
    invoke-static {v0, v2, v7, v3}, Llk/a;->i(IILjava/lang/String;Ll2/o;)V

    .line 2074
    .line 2075
    .line 2076
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 2077
    .line 2078
    .line 2079
    goto :goto_18

    .line 2080
    :cond_2a
    const v0, -0x2efae354

    .line 2081
    .line 2082
    .line 2083
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 2084
    .line 2085
    .line 2086
    const v0, 0x7f120ac5

    .line 2087
    .line 2088
    .line 2089
    const-string v7, "plug_and_charge_installation_error"

    .line 2090
    .line 2091
    invoke-static {v0, v2, v7, v3}, Llk/a;->i(IILjava/lang/String;Ll2/o;)V

    .line 2092
    .line 2093
    .line 2094
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 2095
    .line 2096
    .line 2097
    :goto_18
    invoke-static {v1, v4, v3, v5}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 2098
    .line 2099
    .line 2100
    goto :goto_19

    .line 2101
    :cond_2b
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 2102
    .line 2103
    .line 2104
    :goto_19
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2105
    .line 2106
    return-object v0

    .line 2107
    :pswitch_1a
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 2108
    .line 2109
    check-cast v2, Lk30/e;

    .line 2110
    .line 2111
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 2112
    .line 2113
    check-cast v0, Lx2/s;

    .line 2114
    .line 2115
    move-object/from16 v3, p1

    .line 2116
    .line 2117
    check-cast v3, Ll2/o;

    .line 2118
    .line 2119
    check-cast v1, Ljava/lang/Integer;

    .line 2120
    .line 2121
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2122
    .line 2123
    .line 2124
    const/4 v1, 0x1

    .line 2125
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 2126
    .line 2127
    .line 2128
    move-result v1

    .line 2129
    invoke-static {v2, v0, v3, v1}, Llp/ne;->c(Lk30/e;Lx2/s;Ll2/o;I)V

    .line 2130
    .line 2131
    .line 2132
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2133
    .line 2134
    return-object v0

    .line 2135
    :pswitch_1b
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 2136
    .line 2137
    check-cast v2, Lae0/a;

    .line 2138
    .line 2139
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 2140
    .line 2141
    check-cast v0, Lx2/s;

    .line 2142
    .line 2143
    move-object/from16 v3, p1

    .line 2144
    .line 2145
    check-cast v3, Ll2/o;

    .line 2146
    .line 2147
    check-cast v1, Ljava/lang/Integer;

    .line 2148
    .line 2149
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2150
    .line 2151
    .line 2152
    const/16 v1, 0x31

    .line 2153
    .line 2154
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 2155
    .line 2156
    .line 2157
    move-result v1

    .line 2158
    invoke-static {v2, v0, v3, v1}, Ll20/a;->v(Lae0/a;Lx2/s;Ll2/o;I)V

    .line 2159
    .line 2160
    .line 2161
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2162
    .line 2163
    return-object v0

    .line 2164
    :pswitch_1c
    iget-object v2, v0, Ll2/u;->e:Ljava/lang/Object;

    .line 2165
    .line 2166
    check-cast v2, Ljp/uf;

    .line 2167
    .line 2168
    iget-object v0, v0, Ll2/u;->f:Ljava/lang/Object;

    .line 2169
    .line 2170
    check-cast v0, Ll2/i2;

    .line 2171
    .line 2172
    move-object/from16 v3, p1

    .line 2173
    .line 2174
    check-cast v3, Ljava/lang/Integer;

    .line 2175
    .line 2176
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 2177
    .line 2178
    .line 2179
    move-result v3

    .line 2180
    instance-of v4, v1, Ll2/j;

    .line 2181
    .line 2182
    if-eqz v4, :cond_2c

    .line 2183
    .line 2184
    move-object v0, v1

    .line 2185
    check-cast v0, Ll2/j;

    .line 2186
    .line 2187
    iget-object v1, v2, Ljp/uf;->k:Ljava/util/RandomAccess;

    .line 2188
    .line 2189
    check-cast v1, Ln2/b;

    .line 2190
    .line 2191
    invoke-virtual {v1, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 2192
    .line 2193
    .line 2194
    goto :goto_1a

    .line 2195
    :cond_2c
    instance-of v4, v1, Ll2/a2;

    .line 2196
    .line 2197
    if-eqz v4, :cond_2d

    .line 2198
    .line 2199
    move-object v4, v1

    .line 2200
    check-cast v4, Ll2/a2;

    .line 2201
    .line 2202
    iget-object v5, v4, Ll2/a2;->a:Ll2/z1;

    .line 2203
    .line 2204
    instance-of v5, v5, Ll2/q;

    .line 2205
    .line 2206
    if-nez v5, :cond_2e

    .line 2207
    .line 2208
    invoke-static {v0, v3, v1}, Ll2/v;->f(Ll2/i2;ILjava/lang/Object;)V

    .line 2209
    .line 2210
    .line 2211
    invoke-virtual {v2, v4}, Ljp/uf;->e(Ll2/a2;)V

    .line 2212
    .line 2213
    .line 2214
    goto :goto_1a

    .line 2215
    :cond_2d
    instance-of v2, v1, Ll2/u1;

    .line 2216
    .line 2217
    if-eqz v2, :cond_2e

    .line 2218
    .line 2219
    invoke-static {v0, v3, v1}, Ll2/v;->f(Ll2/i2;ILjava/lang/Object;)V

    .line 2220
    .line 2221
    .line 2222
    move-object v0, v1

    .line 2223
    check-cast v0, Ll2/u1;

    .line 2224
    .line 2225
    invoke-virtual {v0}, Ll2/u1;->e()V

    .line 2226
    .line 2227
    .line 2228
    :cond_2e
    :goto_1a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2229
    .line 2230
    return-object v0

    .line 2231
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
