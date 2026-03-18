.class public final synthetic Li50/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Lm70/b;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li50/u;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Li50/u;->e:I

    iput-object p3, p0, Li50/u;->f:Ljava/lang/Object;

    iput-object p2, p0, Li50/u;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lh50/i0;ILay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li50/u;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li50/u;->f:Ljava/lang/Object;

    iput p2, p0, Li50/u;->e:I

    iput-object p3, p0, Li50/u;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ls10/j;Ls10/i;I)V
    .locals 1

    .line 3
    const/4 v0, 0x2

    iput v0, p0, Li50/u;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li50/u;->f:Ljava/lang/Object;

    iput-object p2, p0, Li50/u;->g:Ljava/lang/Object;

    iput p3, p0, Li50/u;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li50/u;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li50/u;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ls10/j;

    .line 11
    .line 12
    iget-object v2, v0, Li50/u;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ls10/i;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Lk1/h1;

    .line 19
    .line 20
    move-object/from16 v4, p2

    .line 21
    .line 22
    check-cast v4, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v5, p3

    .line 25
    .line 26
    check-cast v5, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const-string v6, "$this$PlanCard"

    .line 33
    .line 34
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    and-int/lit8 v3, v5, 0x11

    .line 38
    .line 39
    const/16 v6, 0x10

    .line 40
    .line 41
    const/4 v7, 0x1

    .line 42
    const/4 v8, 0x0

    .line 43
    if-eq v3, v6, :cond_0

    .line 44
    .line 45
    move v3, v7

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move v3, v8

    .line 48
    :goto_0
    and-int/2addr v5, v7

    .line 49
    move-object v14, v4

    .line 50
    check-cast v14, Ll2/t;

    .line 51
    .line 52
    invoke-virtual {v14, v5, v3}, Ll2/t;->O(IZ)Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_4

    .line 57
    .line 58
    iget-boolean v1, v1, Ls10/j;->c:Z

    .line 59
    .line 60
    if-nez v1, :cond_1

    .line 61
    .line 62
    const v1, -0x662a464b

    .line 63
    .line 64
    .line 65
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 66
    .line 67
    .line 68
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 69
    .line 70
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    check-cast v1, Lj91/e;

    .line 75
    .line 76
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 77
    .line 78
    .line 79
    move-result-wide v3

    .line 80
    :goto_1
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 81
    .line 82
    .line 83
    move-wide v12, v3

    .line 84
    goto :goto_2

    .line 85
    :cond_1
    const v1, -0x662a41ca

    .line 86
    .line 87
    .line 88
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 89
    .line 90
    .line 91
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 92
    .line 93
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    check-cast v1, Lj91/e;

    .line 98
    .line 99
    invoke-virtual {v1}, Lj91/e;->r()J

    .line 100
    .line 101
    .line 102
    move-result-wide v3

    .line 103
    goto :goto_1

    .line 104
    :goto_2
    iget-object v1, v2, Ls10/i;->f:Ljava/lang/String;

    .line 105
    .line 106
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 107
    .line 108
    iget v0, v0, Li50/u;->e:I

    .line 109
    .line 110
    const/16 v4, 0x14

    .line 111
    .line 112
    const-string v5, "departure_planner_timers_card_"

    .line 113
    .line 114
    if-nez v1, :cond_2

    .line 115
    .line 116
    const v1, -0x5f1cadb8

    .line 117
    .line 118
    .line 119
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 123
    .line 124
    .line 125
    move-object v7, v3

    .line 126
    goto/16 :goto_3

    .line 127
    .line 128
    :cond_2
    const v6, -0x5f1cadb7

    .line 129
    .line 130
    .line 131
    invoke-virtual {v14, v6}, Ll2/t;->Y(I)V

    .line 132
    .line 133
    .line 134
    const v6, 0x7f0803ad

    .line 135
    .line 136
    .line 137
    invoke-static {v6, v8, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 138
    .line 139
    .line 140
    move-result-object v9

    .line 141
    int-to-float v6, v4

    .line 142
    invoke-static {v3, v6}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    new-instance v7, Ljava/lang/StringBuilder;

    .line 147
    .line 148
    invoke-direct {v7, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    const-string v10, "_icon_fan"

    .line 155
    .line 156
    invoke-virtual {v7, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v7

    .line 163
    invoke-static {v6, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 164
    .line 165
    .line 166
    move-result-object v11

    .line 167
    const/16 v15, 0x30

    .line 168
    .line 169
    const/16 v16, 0x0

    .line 170
    .line 171
    const/4 v10, 0x0

    .line 172
    invoke-static/range {v9 .. v16}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 173
    .line 174
    .line 175
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 176
    .line 177
    invoke-virtual {v14, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v6

    .line 181
    check-cast v6, Lj91/f;

    .line 182
    .line 183
    invoke-virtual {v6}, Lj91/f;->e()Lg4/p0;

    .line 184
    .line 185
    .line 186
    move-result-object v10

    .line 187
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 188
    .line 189
    invoke-virtual {v14, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v7

    .line 193
    check-cast v7, Lj91/c;

    .line 194
    .line 195
    iget v7, v7, Lj91/c;->b:F

    .line 196
    .line 197
    const/16 v19, 0x0

    .line 198
    .line 199
    const/16 v20, 0xe

    .line 200
    .line 201
    const/16 v17, 0x0

    .line 202
    .line 203
    const/16 v18, 0x0

    .line 204
    .line 205
    move-object v15, v3

    .line 206
    move/from16 v16, v7

    .line 207
    .line 208
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 209
    .line 210
    .line 211
    move-result-object v3

    .line 212
    move-object v7, v15

    .line 213
    new-instance v9, Ljava/lang/StringBuilder;

    .line 214
    .line 215
    invoke-direct {v9, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 219
    .line 220
    .line 221
    const-string v11, "_ac"

    .line 222
    .line 223
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 224
    .line 225
    .line 226
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v9

    .line 230
    invoke-static {v3, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 231
    .line 232
    .line 233
    move-result-object v11

    .line 234
    const/16 v29, 0x0

    .line 235
    .line 236
    const v30, 0xfff0

    .line 237
    .line 238
    .line 239
    move-object/from16 v27, v14

    .line 240
    .line 241
    const-wide/16 v14, 0x0

    .line 242
    .line 243
    const/16 v16, 0x0

    .line 244
    .line 245
    const-wide/16 v17, 0x0

    .line 246
    .line 247
    const/16 v19, 0x0

    .line 248
    .line 249
    const/16 v20, 0x0

    .line 250
    .line 251
    const-wide/16 v21, 0x0

    .line 252
    .line 253
    const/16 v23, 0x0

    .line 254
    .line 255
    const/16 v24, 0x0

    .line 256
    .line 257
    const/16 v25, 0x0

    .line 258
    .line 259
    const/16 v26, 0x0

    .line 260
    .line 261
    const/16 v28, 0x0

    .line 262
    .line 263
    move-object v9, v1

    .line 264
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 265
    .line 266
    .line 267
    move-object/from16 v14, v27

    .line 268
    .line 269
    invoke-virtual {v14, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v1

    .line 273
    check-cast v1, Lj91/c;

    .line 274
    .line 275
    iget v1, v1, Lj91/c;->c:F

    .line 276
    .line 277
    invoke-static {v7, v1, v14, v8}, Lvj/b;->C(Lx2/p;FLl2/t;Z)V

    .line 278
    .line 279
    .line 280
    :goto_3
    iget-object v1, v2, Ls10/i;->g:Ljava/lang/String;

    .line 281
    .line 282
    if-nez v1, :cond_3

    .line 283
    .line 284
    const v0, -0x5f0e59e9

    .line 285
    .line 286
    .line 287
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 288
    .line 289
    .line 290
    :goto_4
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 291
    .line 292
    .line 293
    goto/16 :goto_5

    .line 294
    .line 295
    :cond_3
    const v2, -0x5f0e59e8

    .line 296
    .line 297
    .line 298
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 299
    .line 300
    .line 301
    const v2, 0x7f0802d5

    .line 302
    .line 303
    .line 304
    invoke-static {v2, v8, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 305
    .line 306
    .line 307
    move-result-object v9

    .line 308
    int-to-float v2, v4

    .line 309
    invoke-static {v7, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    new-instance v3, Ljava/lang/StringBuilder;

    .line 314
    .line 315
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 319
    .line 320
    .line 321
    const-string v4, "_icon_bolt"

    .line 322
    .line 323
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 324
    .line 325
    .line 326
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v3

    .line 330
    invoke-static {v2, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 331
    .line 332
    .line 333
    move-result-object v11

    .line 334
    const/16 v15, 0x30

    .line 335
    .line 336
    const/16 v16, 0x0

    .line 337
    .line 338
    const/4 v10, 0x0

    .line 339
    invoke-static/range {v9 .. v16}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 340
    .line 341
    .line 342
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 343
    .line 344
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v2

    .line 348
    check-cast v2, Lj91/f;

    .line 349
    .line 350
    invoke-virtual {v2}, Lj91/f;->e()Lg4/p0;

    .line 351
    .line 352
    .line 353
    move-result-object v10

    .line 354
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 355
    .line 356
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v2

    .line 360
    check-cast v2, Lj91/c;

    .line 361
    .line 362
    iget v2, v2, Lj91/c;->b:F

    .line 363
    .line 364
    const/16 v19, 0x0

    .line 365
    .line 366
    const/16 v20, 0xe

    .line 367
    .line 368
    const/16 v17, 0x0

    .line 369
    .line 370
    const/16 v18, 0x0

    .line 371
    .line 372
    move/from16 v16, v2

    .line 373
    .line 374
    move-object v15, v7

    .line 375
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 376
    .line 377
    .line 378
    move-result-object v2

    .line 379
    new-instance v3, Ljava/lang/StringBuilder;

    .line 380
    .line 381
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    const-string v0, "_charging"

    .line 388
    .line 389
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 390
    .line 391
    .line 392
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    invoke-static {v2, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 397
    .line 398
    .line 399
    move-result-object v11

    .line 400
    const/16 v29, 0x0

    .line 401
    .line 402
    const v30, 0xfff0

    .line 403
    .line 404
    .line 405
    move-object/from16 v27, v14

    .line 406
    .line 407
    const-wide/16 v14, 0x0

    .line 408
    .line 409
    const/16 v16, 0x0

    .line 410
    .line 411
    const-wide/16 v17, 0x0

    .line 412
    .line 413
    const/16 v19, 0x0

    .line 414
    .line 415
    const/16 v20, 0x0

    .line 416
    .line 417
    const-wide/16 v21, 0x0

    .line 418
    .line 419
    const/16 v23, 0x0

    .line 420
    .line 421
    const/16 v24, 0x0

    .line 422
    .line 423
    const/16 v25, 0x0

    .line 424
    .line 425
    const/16 v26, 0x0

    .line 426
    .line 427
    const/16 v28, 0x0

    .line 428
    .line 429
    move-object v9, v1

    .line 430
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 431
    .line 432
    .line 433
    move-object/from16 v14, v27

    .line 434
    .line 435
    goto/16 :goto_4

    .line 436
    .line 437
    :cond_4
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 438
    .line 439
    .line 440
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 441
    .line 442
    return-object v0

    .line 443
    :pswitch_0
    iget-object v1, v0, Li50/u;->f:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v1, Lm70/b;

    .line 446
    .line 447
    iget-object v2, v0, Li50/u;->g:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast v2, Lay0/k;

    .line 450
    .line 451
    move-object/from16 v3, p1

    .line 452
    .line 453
    check-cast v3, Lk1/q;

    .line 454
    .line 455
    move-object/from16 v4, p2

    .line 456
    .line 457
    check-cast v4, Ll2/o;

    .line 458
    .line 459
    move-object/from16 v5, p3

    .line 460
    .line 461
    check-cast v5, Ljava/lang/Integer;

    .line 462
    .line 463
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 464
    .line 465
    .line 466
    move-result v5

    .line 467
    const-string v6, "$this$GradientBox"

    .line 468
    .line 469
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    and-int/lit8 v3, v5, 0x11

    .line 473
    .line 474
    const/16 v6, 0x10

    .line 475
    .line 476
    const/4 v7, 0x1

    .line 477
    if-eq v3, v6, :cond_5

    .line 478
    .line 479
    move v3, v7

    .line 480
    goto :goto_6

    .line 481
    :cond_5
    const/4 v3, 0x0

    .line 482
    :goto_6
    and-int/2addr v5, v7

    .line 483
    move-object v11, v4

    .line 484
    check-cast v11, Ll2/t;

    .line 485
    .line 486
    invoke-virtual {v11, v5, v3}, Ll2/t;->O(IZ)Z

    .line 487
    .line 488
    .line 489
    move-result v3

    .line 490
    if-eqz v3, :cond_8

    .line 491
    .line 492
    sget-object v3, Lj91/a;->a:Ll2/u2;

    .line 493
    .line 494
    invoke-virtual {v11, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v4

    .line 498
    check-cast v4, Lj91/c;

    .line 499
    .line 500
    iget v4, v4, Lj91/c;->e:F

    .line 501
    .line 502
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 503
    .line 504
    iget v0, v0, Li50/u;->e:I

    .line 505
    .line 506
    invoke-static {v5, v4, v11, v0, v11}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v10

    .line 510
    iget-boolean v13, v1, Lm70/b;->q:Z

    .line 511
    .line 512
    invoke-static {v5, v0}, Lxf0/i0;->H(Lx2/s;I)Lx2/s;

    .line 513
    .line 514
    .line 515
    move-result-object v12

    .line 516
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 517
    .line 518
    .line 519
    move-result v0

    .line 520
    invoke-virtual {v11, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 521
    .line 522
    .line 523
    move-result v4

    .line 524
    or-int/2addr v0, v4

    .line 525
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    move-result-object v4

    .line 529
    if-nez v0, :cond_6

    .line 530
    .line 531
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 532
    .line 533
    if-ne v4, v0, :cond_7

    .line 534
    .line 535
    :cond_6
    new-instance v4, Llk/j;

    .line 536
    .line 537
    const/16 v0, 0x8

    .line 538
    .line 539
    invoke-direct {v4, v0, v2, v1}, Llk/j;-><init>(ILay0/k;Ljava/lang/Object;)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 543
    .line 544
    .line 545
    :cond_7
    move-object v8, v4

    .line 546
    check-cast v8, Lay0/a;

    .line 547
    .line 548
    const/4 v6, 0x0

    .line 549
    const/16 v7, 0x28

    .line 550
    .line 551
    const/4 v9, 0x0

    .line 552
    const/4 v14, 0x0

    .line 553
    invoke-static/range {v6 .. v14}, Li91/j0;->X(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v11, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 557
    .line 558
    .line 559
    move-result-object v0

    .line 560
    check-cast v0, Lj91/c;

    .line 561
    .line 562
    iget v0, v0, Lj91/c;->f:F

    .line 563
    .line 564
    invoke-static {v5, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    invoke-static {v11, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 569
    .line 570
    .line 571
    goto :goto_7

    .line 572
    :cond_8
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 573
    .line 574
    .line 575
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 576
    .line 577
    return-object v0

    .line 578
    :pswitch_1
    iget-object v1, v0, Li50/u;->f:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast v1, Lh50/i0;

    .line 581
    .line 582
    iget-object v2, v0, Li50/u;->g:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast v2, Lay0/a;

    .line 585
    .line 586
    move-object/from16 v3, p1

    .line 587
    .line 588
    check-cast v3, Lb1/a0;

    .line 589
    .line 590
    move-object/from16 v4, p2

    .line 591
    .line 592
    check-cast v4, Ll2/o;

    .line 593
    .line 594
    move-object/from16 v5, p3

    .line 595
    .line 596
    check-cast v5, Ljava/lang/Integer;

    .line 597
    .line 598
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 599
    .line 600
    .line 601
    const-string v5, "$this$AnimatedVisibility"

    .line 602
    .line 603
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    const/4 v3, 0x0

    .line 607
    iget v0, v0, Li50/u;->e:I

    .line 608
    .line 609
    invoke-static {v1, v0, v2, v4, v3}, Li50/z;->a(Lh50/i0;ILay0/a;Ll2/o;I)V

    .line 610
    .line 611
    .line 612
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 613
    .line 614
    return-object v0

    .line 615
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
