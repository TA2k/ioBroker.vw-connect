.class public final synthetic Ldl0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ldl0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldl0/f;->e:I

    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 2
    const/4 p2, 0x7

    iput p2, p0, Ldl0/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldl0/f;->e:I

    return-void
.end method

.method public synthetic constructor <init>(IIB)V
    .locals 0

    .line 3
    iput p2, p0, Ldl0/f;->d:I

    iput p1, p0, Ldl0/f;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ldl0/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/16 v2, 0x31

    .line 20
    .line 21
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    iget v0, v0, Ldl0/f;->e:I

    .line 26
    .line 27
    invoke-static {v0, v2, v1}, Lzj0/d;->e(IILl2/o;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_0
    move-object/from16 v1, p1

    .line 34
    .line 35
    check-cast v1, Ll2/o;

    .line 36
    .line 37
    move-object/from16 v2, p2

    .line 38
    .line 39
    check-cast v2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    and-int/lit8 v3, v2, 0x3

    .line 46
    .line 47
    const/4 v4, 0x2

    .line 48
    const/4 v5, 0x1

    .line 49
    if-eq v3, v4, :cond_0

    .line 50
    .line 51
    move v3, v5

    .line 52
    goto :goto_1

    .line 53
    :cond_0
    const/4 v3, 0x0

    .line 54
    :goto_1
    and-int/2addr v2, v5

    .line 55
    check-cast v1, Ll2/t;

    .line 56
    .line 57
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_1

    .line 62
    .line 63
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 64
    .line 65
    iget v0, v0, Ldl0/f;->e:I

    .line 66
    .line 67
    int-to-float v0, v0

    .line 68
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-static {v1, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_1
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 77
    .line 78
    .line 79
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object v0

    .line 82
    :pswitch_1
    move-object/from16 v1, p1

    .line 83
    .line 84
    check-cast v1, Ll2/o;

    .line 85
    .line 86
    move-object/from16 v2, p2

    .line 87
    .line 88
    check-cast v2, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    and-int/lit8 v3, v2, 0x3

    .line 95
    .line 96
    const/4 v4, 0x2

    .line 97
    const/4 v5, 0x1

    .line 98
    if-eq v3, v4, :cond_2

    .line 99
    .line 100
    move v3, v5

    .line 101
    goto :goto_3

    .line 102
    :cond_2
    const/4 v3, 0x0

    .line 103
    :goto_3
    and-int/2addr v2, v5

    .line 104
    check-cast v1, Ll2/t;

    .line 105
    .line 106
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    if-eqz v2, :cond_3

    .line 111
    .line 112
    iget v0, v0, Ldl0/f;->e:I

    .line 113
    .line 114
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Lj91/f;

    .line 125
    .line 126
    invoke-virtual {v0}, Lj91/f;->j()Lg4/p0;

    .line 127
    .line 128
    .line 129
    move-result-object v5

    .line 130
    const/16 v24, 0x0

    .line 131
    .line 132
    const v25, 0xfffc

    .line 133
    .line 134
    .line 135
    const/4 v6, 0x0

    .line 136
    const-wide/16 v7, 0x0

    .line 137
    .line 138
    const-wide/16 v9, 0x0

    .line 139
    .line 140
    const/4 v11, 0x0

    .line 141
    const-wide/16 v12, 0x0

    .line 142
    .line 143
    const/4 v14, 0x0

    .line 144
    const/4 v15, 0x0

    .line 145
    const-wide/16 v16, 0x0

    .line 146
    .line 147
    const/16 v18, 0x0

    .line 148
    .line 149
    const/16 v19, 0x0

    .line 150
    .line 151
    const/16 v20, 0x0

    .line 152
    .line 153
    const/16 v21, 0x0

    .line 154
    .line 155
    const/16 v23, 0x0

    .line 156
    .line 157
    move-object/from16 v22, v1

    .line 158
    .line 159
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 160
    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_3
    move-object/from16 v22, v1

    .line 164
    .line 165
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 166
    .line 167
    .line 168
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object v0

    .line 171
    :pswitch_2
    move-object/from16 v1, p1

    .line 172
    .line 173
    check-cast v1, Ll2/o;

    .line 174
    .line 175
    move-object/from16 v2, p2

    .line 176
    .line 177
    check-cast v2, Ljava/lang/Integer;

    .line 178
    .line 179
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 180
    .line 181
    .line 182
    move-result v2

    .line 183
    and-int/lit8 v3, v2, 0x3

    .line 184
    .line 185
    const/4 v4, 0x2

    .line 186
    const/4 v5, 0x1

    .line 187
    if-eq v3, v4, :cond_4

    .line 188
    .line 189
    move v3, v5

    .line 190
    goto :goto_5

    .line 191
    :cond_4
    const/4 v3, 0x0

    .line 192
    :goto_5
    and-int/2addr v2, v5

    .line 193
    check-cast v1, Ll2/t;

    .line 194
    .line 195
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 196
    .line 197
    .line 198
    move-result v2

    .line 199
    if-eqz v2, :cond_5

    .line 200
    .line 201
    iget v0, v0, Ldl0/f;->e:I

    .line 202
    .line 203
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 208
    .line 209
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    check-cast v0, Lj91/f;

    .line 214
    .line 215
    invoke-virtual {v0}, Lj91/f;->j()Lg4/p0;

    .line 216
    .line 217
    .line 218
    move-result-object v5

    .line 219
    const/16 v24, 0x0

    .line 220
    .line 221
    const v25, 0xfffc

    .line 222
    .line 223
    .line 224
    const/4 v6, 0x0

    .line 225
    const-wide/16 v7, 0x0

    .line 226
    .line 227
    const-wide/16 v9, 0x0

    .line 228
    .line 229
    const/4 v11, 0x0

    .line 230
    const-wide/16 v12, 0x0

    .line 231
    .line 232
    const/4 v14, 0x0

    .line 233
    const/4 v15, 0x0

    .line 234
    const-wide/16 v16, 0x0

    .line 235
    .line 236
    const/16 v18, 0x0

    .line 237
    .line 238
    const/16 v19, 0x0

    .line 239
    .line 240
    const/16 v20, 0x0

    .line 241
    .line 242
    const/16 v21, 0x0

    .line 243
    .line 244
    const/16 v23, 0x0

    .line 245
    .line 246
    move-object/from16 v22, v1

    .line 247
    .line 248
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 249
    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_5
    move-object/from16 v22, v1

    .line 253
    .line 254
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 255
    .line 256
    .line 257
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 258
    .line 259
    return-object v0

    .line 260
    :pswitch_3
    move-object/from16 v1, p1

    .line 261
    .line 262
    check-cast v1, Ll2/o;

    .line 263
    .line 264
    move-object/from16 v2, p2

    .line 265
    .line 266
    check-cast v2, Ljava/lang/Integer;

    .line 267
    .line 268
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 269
    .line 270
    .line 271
    move-result v2

    .line 272
    and-int/lit8 v3, v2, 0x3

    .line 273
    .line 274
    const/4 v4, 0x2

    .line 275
    const/4 v5, 0x1

    .line 276
    if-eq v3, v4, :cond_6

    .line 277
    .line 278
    move v3, v5

    .line 279
    goto :goto_7

    .line 280
    :cond_6
    const/4 v3, 0x0

    .line 281
    :goto_7
    and-int/2addr v2, v5

    .line 282
    check-cast v1, Ll2/t;

    .line 283
    .line 284
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 285
    .line 286
    .line 287
    move-result v2

    .line 288
    if-eqz v2, :cond_7

    .line 289
    .line 290
    iget v0, v0, Ldl0/f;->e:I

    .line 291
    .line 292
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v4

    .line 296
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 297
    .line 298
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    check-cast v0, Lj91/f;

    .line 303
    .line 304
    invoke-virtual {v0}, Lj91/f;->j()Lg4/p0;

    .line 305
    .line 306
    .line 307
    move-result-object v5

    .line 308
    const/16 v24, 0x0

    .line 309
    .line 310
    const v25, 0xfffc

    .line 311
    .line 312
    .line 313
    const/4 v6, 0x0

    .line 314
    const-wide/16 v7, 0x0

    .line 315
    .line 316
    const-wide/16 v9, 0x0

    .line 317
    .line 318
    const/4 v11, 0x0

    .line 319
    const-wide/16 v12, 0x0

    .line 320
    .line 321
    const/4 v14, 0x0

    .line 322
    const/4 v15, 0x0

    .line 323
    const-wide/16 v16, 0x0

    .line 324
    .line 325
    const/16 v18, 0x0

    .line 326
    .line 327
    const/16 v19, 0x0

    .line 328
    .line 329
    const/16 v20, 0x0

    .line 330
    .line 331
    const/16 v21, 0x0

    .line 332
    .line 333
    const/16 v23, 0x0

    .line 334
    .line 335
    move-object/from16 v22, v1

    .line 336
    .line 337
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 338
    .line 339
    .line 340
    goto :goto_8

    .line 341
    :cond_7
    move-object/from16 v22, v1

    .line 342
    .line 343
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 344
    .line 345
    .line 346
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 347
    .line 348
    return-object v0

    .line 349
    :pswitch_4
    move-object/from16 v1, p1

    .line 350
    .line 351
    check-cast v1, Ll2/o;

    .line 352
    .line 353
    move-object/from16 v2, p2

    .line 354
    .line 355
    check-cast v2, Ljava/lang/Integer;

    .line 356
    .line 357
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 358
    .line 359
    .line 360
    move-result v2

    .line 361
    and-int/lit8 v3, v2, 0x3

    .line 362
    .line 363
    const/4 v4, 0x2

    .line 364
    const/4 v5, 0x1

    .line 365
    if-eq v3, v4, :cond_8

    .line 366
    .line 367
    move v3, v5

    .line 368
    goto :goto_9

    .line 369
    :cond_8
    const/4 v3, 0x0

    .line 370
    :goto_9
    and-int/2addr v2, v5

    .line 371
    check-cast v1, Ll2/t;

    .line 372
    .line 373
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 374
    .line 375
    .line 376
    move-result v2

    .line 377
    if-eqz v2, :cond_9

    .line 378
    .line 379
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 380
    .line 381
    const/high16 v3, 0x3f800000    # 1.0f

    .line 382
    .line 383
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 384
    .line 385
    .line 386
    move-result-object v2

    .line 387
    const/16 v3, 0x30

    .line 388
    .line 389
    iget v0, v0, Ldl0/f;->e:I

    .line 390
    .line 391
    invoke-static {v0, v3, v1, v2}, Li40/l1;->Z(IILl2/o;Lx2/s;)V

    .line 392
    .line 393
    .line 394
    goto :goto_a

    .line 395
    :cond_9
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 396
    .line 397
    .line 398
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 399
    .line 400
    return-object v0

    .line 401
    :pswitch_5
    move-object/from16 v1, p1

    .line 402
    .line 403
    check-cast v1, Ll2/o;

    .line 404
    .line 405
    move-object/from16 v2, p2

    .line 406
    .line 407
    check-cast v2, Ljava/lang/Integer;

    .line 408
    .line 409
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 410
    .line 411
    .line 412
    move-result v2

    .line 413
    and-int/lit8 v3, v2, 0x3

    .line 414
    .line 415
    const/4 v4, 0x2

    .line 416
    const/4 v5, 0x1

    .line 417
    if-eq v3, v4, :cond_a

    .line 418
    .line 419
    move v3, v5

    .line 420
    goto :goto_b

    .line 421
    :cond_a
    const/4 v3, 0x0

    .line 422
    :goto_b
    and-int/2addr v2, v5

    .line 423
    check-cast v1, Ll2/t;

    .line 424
    .line 425
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 426
    .line 427
    .line 428
    move-result v2

    .line 429
    if-eqz v2, :cond_b

    .line 430
    .line 431
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 432
    .line 433
    const/high16 v3, 0x3f800000    # 1.0f

    .line 434
    .line 435
    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 436
    .line 437
    .line 438
    move-result-object v2

    .line 439
    const/16 v3, 0x30

    .line 440
    .line 441
    iget v0, v0, Ldl0/f;->e:I

    .line 442
    .line 443
    invoke-static {v0, v3, v1, v2}, Li40/l1;->Z(IILl2/o;Lx2/s;)V

    .line 444
    .line 445
    .line 446
    goto :goto_c

    .line 447
    :cond_b
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 448
    .line 449
    .line 450
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 451
    .line 452
    return-object v0

    .line 453
    :pswitch_6
    move-object/from16 v1, p1

    .line 454
    .line 455
    check-cast v1, Ll2/o;

    .line 456
    .line 457
    move-object/from16 v2, p2

    .line 458
    .line 459
    check-cast v2, Ljava/lang/Integer;

    .line 460
    .line 461
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 462
    .line 463
    .line 464
    iget v0, v0, Ldl0/f;->e:I

    .line 465
    .line 466
    or-int/lit8 v0, v0, 0x1

    .line 467
    .line 468
    invoke-static {v0}, Ll2/b;->x(I)I

    .line 469
    .line 470
    .line 471
    move-result v0

    .line 472
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 473
    .line 474
    invoke-static {v2, v1, v0}, Ldl0/e;->f(Lx2/s;Ll2/o;I)V

    .line 475
    .line 476
    .line 477
    goto/16 :goto_0

    .line 478
    .line 479
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
