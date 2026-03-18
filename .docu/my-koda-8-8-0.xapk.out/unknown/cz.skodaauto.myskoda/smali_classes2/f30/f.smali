.class public final Lf30/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/List;Ld01/h0;Lay0/k;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lf30/f;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf30/f;->e:Ljava/util/List;

    iput-object p2, p0, Lf30/f;->g:Ljava/lang/Object;

    iput-object p3, p0, Lf30/f;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lf30/f;->f:Z

    return-void
.end method

.method public constructor <init>(Ljava/util/List;Li91/c1;ZLjava/util/List;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lf30/f;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lf30/f;->e:Ljava/util/List;

    iput-object p2, p0, Lf30/f;->g:Ljava/lang/Object;

    iput-boolean p3, p0, Lf30/f;->f:Z

    iput-object p4, p0, Lf30/f;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf30/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move-object/from16 v3, p3

    .line 21
    .line 22
    check-cast v3, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v4, p4

    .line 25
    .line 26
    check-cast v4, Ljava/lang/Number;

    .line 27
    .line 28
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    and-int/lit8 v5, v4, 0x6

    .line 33
    .line 34
    const/4 v6, 0x2

    .line 35
    if-nez v5, :cond_1

    .line 36
    .line 37
    move-object v5, v3

    .line 38
    check-cast v5, Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_0

    .line 45
    .line 46
    const/4 v1, 0x4

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move v1, v6

    .line 49
    :goto_0
    or-int/2addr v1, v4

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    move v1, v4

    .line 52
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 53
    .line 54
    if-nez v4, :cond_3

    .line 55
    .line 56
    move-object v4, v3

    .line 57
    check-cast v4, Ll2/t;

    .line 58
    .line 59
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_2

    .line 64
    .line 65
    const/16 v4, 0x20

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    const/16 v4, 0x10

    .line 69
    .line 70
    :goto_2
    or-int/2addr v1, v4

    .line 71
    :cond_3
    and-int/lit16 v4, v1, 0x93

    .line 72
    .line 73
    const/16 v5, 0x92

    .line 74
    .line 75
    const/4 v7, 0x1

    .line 76
    const/4 v8, 0x0

    .line 77
    if-eq v4, v5, :cond_4

    .line 78
    .line 79
    move v4, v7

    .line 80
    goto :goto_3

    .line 81
    :cond_4
    move v4, v8

    .line 82
    :goto_3
    and-int/2addr v1, v7

    .line 83
    move-object v12, v3

    .line 84
    check-cast v12, Ll2/t;

    .line 85
    .line 86
    invoke-virtual {v12, v1, v4}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-eqz v1, :cond_9

    .line 91
    .line 92
    iget-object v1, v0, Lf30/f;->e:Ljava/util/List;

    .line 93
    .line 94
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Li91/d2;

    .line 99
    .line 100
    const v3, -0x3a6aef7d

    .line 101
    .line 102
    .line 103
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    iget-object v3, v0, Lf30/f;->g:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v3, Li91/c1;

    .line 109
    .line 110
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    invoke-virtual {v3, v12, v4}, Li91/c1;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    check-cast v3, Lt4/f;

    .line 119
    .line 120
    iget v11, v3, Lt4/f;->d:F

    .line 121
    .line 122
    instance-of v3, v1, Li91/m1;

    .line 123
    .line 124
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 125
    .line 126
    const/4 v5, 0x0

    .line 127
    const v9, -0x3aab1561

    .line 128
    .line 129
    .line 130
    if-eqz v3, :cond_6

    .line 131
    .line 132
    const v0, -0x3a69591a

    .line 133
    .line 134
    .line 135
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    if-lez v2, :cond_5

    .line 139
    .line 140
    const v0, -0x3a690b1e

    .line 141
    .line 142
    .line 143
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 144
    .line 145
    .line 146
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 147
    .line 148
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Lj91/c;

    .line 153
    .line 154
    iget v0, v0, Lj91/c;->c:F

    .line 155
    .line 156
    invoke-static {v4, v0, v12, v8}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 157
    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_5
    invoke-virtual {v12, v9}, Ll2/t;->Y(I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    .line 164
    .line 165
    .line 166
    :goto_4
    check-cast v1, Li91/m1;

    .line 167
    .line 168
    iget-object v9, v1, Li91/m1;->a:Ljava/lang/String;

    .line 169
    .line 170
    const v0, -0x5cb8f496

    .line 171
    .line 172
    .line 173
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 174
    .line 175
    .line 176
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 177
    .line 178
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    check-cast v0, Lj91/f;

    .line 183
    .line 184
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 185
    .line 186
    .line 187
    move-result-object v10

    .line 188
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    invoke-static {v4, v11, v5, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object v11

    .line 195
    const/4 v15, 0x0

    .line 196
    const/16 v16, 0x0

    .line 197
    .line 198
    move-object v14, v12

    .line 199
    const/4 v12, 0x0

    .line 200
    const/4 v13, 0x0

    .line 201
    invoke-static/range {v9 .. v16}, Li91/j0;->H(Ljava/lang/String;Lg4/p0;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ll2/o;II)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 205
    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_6
    move-object v14, v12

    .line 209
    instance-of v3, v1, Li91/c2;

    .line 210
    .line 211
    if-eqz v3, :cond_8

    .line 212
    .line 213
    const v3, -0x3a61341c

    .line 214
    .line 215
    .line 216
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 217
    .line 218
    .line 219
    iget-boolean v3, v0, Lf30/f;->f:Z

    .line 220
    .line 221
    if-eqz v3, :cond_7

    .line 222
    .line 223
    if-lez v2, :cond_7

    .line 224
    .line 225
    iget-object v0, v0, Lf30/f;->h:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v0, Ljava/util/List;

    .line 228
    .line 229
    sub-int/2addr v2, v7

    .line 230
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    instance-of v0, v0, Li91/m1;

    .line 235
    .line 236
    if-nez v0, :cond_7

    .line 237
    .line 238
    const v0, -0x3a600449

    .line 239
    .line 240
    .line 241
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 242
    .line 243
    .line 244
    invoke-static {v4, v11, v5, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    invoke-static {v8, v8, v14, v0}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 249
    .line 250
    .line 251
    :goto_5
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 252
    .line 253
    .line 254
    goto :goto_6

    .line 255
    :cond_7
    invoke-virtual {v14, v9}, Ll2/t;->Y(I)V

    .line 256
    .line 257
    .line 258
    goto :goto_5

    .line 259
    :goto_6
    move-object v9, v1

    .line 260
    check-cast v9, Li91/c2;

    .line 261
    .line 262
    const/4 v13, 0x0

    .line 263
    move-object v12, v14

    .line 264
    const/4 v14, 0x2

    .line 265
    const/4 v10, 0x0

    .line 266
    invoke-static/range {v9 .. v14}, Li91/j0;->J(Li91/c2;Lx2/s;FLl2/o;II)V

    .line 267
    .line 268
    .line 269
    move-object v14, v12

    .line 270
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 271
    .line 272
    .line 273
    :goto_7
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 274
    .line 275
    .line 276
    goto :goto_8

    .line 277
    :cond_8
    const v0, -0x5cb917a9

    .line 278
    .line 279
    .line 280
    invoke-static {v0, v14, v8}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    throw v0

    .line 285
    :cond_9
    move-object v14, v12

    .line 286
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 287
    .line 288
    .line 289
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    return-object v0

    .line 292
    :pswitch_0
    move-object/from16 v1, p1

    .line 293
    .line 294
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 295
    .line 296
    move-object/from16 v2, p2

    .line 297
    .line 298
    check-cast v2, Ljava/lang/Number;

    .line 299
    .line 300
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 301
    .line 302
    .line 303
    move-result v2

    .line 304
    move-object/from16 v3, p3

    .line 305
    .line 306
    check-cast v3, Ll2/o;

    .line 307
    .line 308
    move-object/from16 v4, p4

    .line 309
    .line 310
    check-cast v4, Ljava/lang/Number;

    .line 311
    .line 312
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 313
    .line 314
    .line 315
    move-result v4

    .line 316
    and-int/lit8 v5, v4, 0x6

    .line 317
    .line 318
    const/4 v6, 0x2

    .line 319
    if-nez v5, :cond_b

    .line 320
    .line 321
    move-object v5, v3

    .line 322
    check-cast v5, Ll2/t;

    .line 323
    .line 324
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 325
    .line 326
    .line 327
    move-result v1

    .line 328
    if-eqz v1, :cond_a

    .line 329
    .line 330
    const/4 v1, 0x4

    .line 331
    goto :goto_9

    .line 332
    :cond_a
    move v1, v6

    .line 333
    :goto_9
    or-int/2addr v1, v4

    .line 334
    goto :goto_a

    .line 335
    :cond_b
    move v1, v4

    .line 336
    :goto_a
    and-int/lit8 v4, v4, 0x30

    .line 337
    .line 338
    if-nez v4, :cond_d

    .line 339
    .line 340
    move-object v4, v3

    .line 341
    check-cast v4, Ll2/t;

    .line 342
    .line 343
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 344
    .line 345
    .line 346
    move-result v4

    .line 347
    if-eqz v4, :cond_c

    .line 348
    .line 349
    const/16 v4, 0x20

    .line 350
    .line 351
    goto :goto_b

    .line 352
    :cond_c
    const/16 v4, 0x10

    .line 353
    .line 354
    :goto_b
    or-int/2addr v1, v4

    .line 355
    :cond_d
    and-int/lit16 v4, v1, 0x93

    .line 356
    .line 357
    const/16 v5, 0x92

    .line 358
    .line 359
    const/4 v7, 0x1

    .line 360
    const/4 v8, 0x0

    .line 361
    if-eq v4, v5, :cond_e

    .line 362
    .line 363
    move v4, v7

    .line 364
    goto :goto_c

    .line 365
    :cond_e
    move v4, v8

    .line 366
    :goto_c
    and-int/2addr v1, v7

    .line 367
    move-object v13, v3

    .line 368
    check-cast v13, Ll2/t;

    .line 369
    .line 370
    invoke-virtual {v13, v1, v4}, Ll2/t;->O(IZ)Z

    .line 371
    .line 372
    .line 373
    move-result v1

    .line 374
    if-eqz v1, :cond_10

    .line 375
    .line 376
    iget-object v1, v0, Lf30/f;->e:Ljava/util/List;

    .line 377
    .line 378
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    move-object v9, v1

    .line 383
    check-cast v9, Le30/m;

    .line 384
    .line 385
    const v1, -0x7994c2ec

    .line 386
    .line 387
    .line 388
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 389
    .line 390
    .line 391
    if-lez v2, :cond_f

    .line 392
    .line 393
    const v1, -0x79949318

    .line 394
    .line 395
    .line 396
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 397
    .line 398
    .line 399
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 400
    .line 401
    invoke-virtual {v13, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v1

    .line 405
    check-cast v1, Lj91/c;

    .line 406
    .line 407
    iget v1, v1, Lj91/c;->j:F

    .line 408
    .line 409
    const/4 v2, 0x0

    .line 410
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 411
    .line 412
    invoke-static {v3, v1, v2, v6}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    invoke-static {v8, v8, v13, v1}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 417
    .line 418
    .line 419
    :goto_d
    invoke-virtual {v13, v8}, Ll2/t;->q(Z)V

    .line 420
    .line 421
    .line 422
    goto :goto_e

    .line 423
    :cond_f
    const v1, -0x7a0fdcba

    .line 424
    .line 425
    .line 426
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 427
    .line 428
    .line 429
    goto :goto_d

    .line 430
    :goto_e
    iget-object v1, v0, Lf30/f;->g:Ljava/lang/Object;

    .line 431
    .line 432
    move-object v10, v1

    .line 433
    check-cast v10, Ld01/h0;

    .line 434
    .line 435
    iget-object v1, v0, Lf30/f;->h:Ljava/lang/Object;

    .line 436
    .line 437
    move-object v11, v1

    .line 438
    check-cast v11, Lay0/k;

    .line 439
    .line 440
    iget-boolean v12, v0, Lf30/f;->f:Z

    .line 441
    .line 442
    const/4 v14, 0x0

    .line 443
    invoke-static/range {v9 .. v14}, Lf30/a;->f(Le30/m;Ld01/h0;Lay0/k;ZLl2/o;I)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v13, v8}, Ll2/t;->q(Z)V

    .line 447
    .line 448
    .line 449
    goto :goto_f

    .line 450
    :cond_10
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 451
    .line 452
    .line 453
    :goto_f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object v0

    .line 456
    nop

    .line 457
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
