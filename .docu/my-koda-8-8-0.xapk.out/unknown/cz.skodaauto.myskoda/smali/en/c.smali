.class public abstract Len/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lb81/c;

.field public static final b:Lb81/c;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const-string v8, "sk"

    .line 2
    .line 3
    const-string v9, "sa"

    .line 4
    .line 5
    const-string v0, "a"

    .line 6
    .line 7
    const-string v1, "p"

    .line 8
    .line 9
    const-string v2, "s"

    .line 10
    .line 11
    const-string v3, "rz"

    .line 12
    .line 13
    const-string v4, "r"

    .line 14
    .line 15
    const-string v5, "o"

    .line 16
    .line 17
    const-string v6, "so"

    .line 18
    .line 19
    const-string v7, "eo"

    .line 20
    .line 21
    filled-new-array/range {v0 .. v9}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Len/c;->a:Lb81/c;

    .line 30
    .line 31
    const-string v0, "k"

    .line 32
    .line 33
    filled-new-array {v0}, [Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    sput-object v0, Len/c;->b:Lb81/c;

    .line 42
    .line 43
    return-void
.end method

.method public static a(Lfn/b;Lum/a;)Lbn/e;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    const/4 v8, 0x0

    .line 6
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 7
    .line 8
    .line 9
    move-result-object v3

    .line 10
    invoke-virtual {v0}, Lfn/b;->B()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v4, 0x3

    .line 15
    const/4 v9, 0x0

    .line 16
    if-ne v1, v4, :cond_0

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    move v10, v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v10, v9

    .line 22
    :goto_0
    if-eqz v10, :cond_1

    .line 23
    .line 24
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 25
    .line 26
    .line 27
    :cond_1
    const/4 v1, 0x0

    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v12, 0x0

    .line 30
    const/4 v13, 0x0

    .line 31
    const/4 v14, 0x0

    .line 32
    const/4 v15, 0x0

    .line 33
    const/16 v21, 0x0

    .line 34
    .line 35
    const/16 v22, 0x0

    .line 36
    .line 37
    const/16 v23, 0x0

    .line 38
    .line 39
    :goto_1
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    const/high16 v6, 0x3f800000    # 1.0f

    .line 44
    .line 45
    if-eqz v5, :cond_6

    .line 46
    .line 47
    sget-object v5, Len/c;->a:Lb81/c;

    .line 48
    .line 49
    invoke-virtual {v0, v5}, Lfn/b;->H(Lb81/c;)I

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    packed-switch v5, :pswitch_data_0

    .line 54
    .line 55
    .line 56
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :pswitch_0
    invoke-static {v0, v2, v9}, Lkp/m6;->d(Lfn/a;Lum/a;Z)Lbn/b;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    goto :goto_1

    .line 68
    :pswitch_1
    invoke-static {v0, v2, v9}, Lkp/m6;->d(Lfn/a;Lum/a;Z)Lbn/b;

    .line 69
    .line 70
    .line 71
    move-result-object v15

    .line 72
    goto :goto_1

    .line 73
    :pswitch_2
    invoke-static {v0, v2, v9}, Lkp/m6;->d(Lfn/a;Lum/a;Z)Lbn/b;

    .line 74
    .line 75
    .line 76
    move-result-object v23

    .line 77
    goto :goto_1

    .line 78
    :pswitch_3
    invoke-static {v0, v2, v9}, Lkp/m6;->d(Lfn/a;Lum/a;Z)Lbn/b;

    .line 79
    .line 80
    .line 81
    move-result-object v22

    .line 82
    goto :goto_1

    .line 83
    :pswitch_4
    invoke-static/range {p0 .. p1}, Lkp/m6;->f(Lfn/a;Lum/a;)Lbn/a;

    .line 84
    .line 85
    .line 86
    move-result-object v21

    .line 87
    goto :goto_1

    .line 88
    :pswitch_5
    const-string v1, "Lottie doesn\'t support 3D layers."

    .line 89
    .line 90
    invoke-virtual {v2, v1}, Lum/a;->a(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    :pswitch_6
    invoke-static {v0, v2, v9}, Lkp/m6;->d(Lfn/a;Lum/a;Z)Lbn/b;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    iget-object v5, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v5, Ljava/util/List;

    .line 100
    .line 101
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 102
    .line 103
    .line 104
    move-result v6

    .line 105
    if-eqz v6, :cond_2

    .line 106
    .line 107
    move-object v6, v1

    .line 108
    new-instance v1, Lhn/a;

    .line 109
    .line 110
    iget v7, v2, Lum/a;->m:F

    .line 111
    .line 112
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    move-object/from16 v16, v5

    .line 117
    .line 118
    const/4 v5, 0x0

    .line 119
    move-object/from16 v17, v6

    .line 120
    .line 121
    const/4 v6, 0x0

    .line 122
    move-object/from16 v18, v4

    .line 123
    .line 124
    move-object v4, v3

    .line 125
    move-object/from16 v8, v16

    .line 126
    .line 127
    move-object/from16 v11, v18

    .line 128
    .line 129
    invoke-direct/range {v1 .. v7}, Lhn/a;-><init>(Lum/a;Ljava/lang/Object;Ljava/lang/Object;Landroid/view/animation/Interpolator;FLjava/lang/Float;)V

    .line 130
    .line 131
    .line 132
    invoke-interface {v8, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_2
    move-object/from16 v17, v1

    .line 137
    .line 138
    move-object v11, v4

    .line 139
    move-object v8, v5

    .line 140
    invoke-interface {v8, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    check-cast v1, Lhn/a;

    .line 145
    .line 146
    iget-object v1, v1, Lhn/a;->b:Ljava/lang/Object;

    .line 147
    .line 148
    if-nez v1, :cond_3

    .line 149
    .line 150
    new-instance v1, Lhn/a;

    .line 151
    .line 152
    iget v4, v2, Lum/a;->m:F

    .line 153
    .line 154
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    const/4 v5, 0x0

    .line 159
    const/4 v6, 0x0

    .line 160
    move-object v4, v3

    .line 161
    invoke-direct/range {v1 .. v7}, Lhn/a;-><init>(Lum/a;Ljava/lang/Object;Ljava/lang/Object;Landroid/view/animation/Interpolator;FLjava/lang/Float;)V

    .line 162
    .line 163
    .line 164
    invoke-interface {v8, v9, v1}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    :cond_3
    :goto_2
    move-object v4, v11

    .line 168
    move-object/from16 v1, v17

    .line 169
    .line 170
    :goto_3
    const/4 v8, 0x0

    .line 171
    goto/16 :goto_1

    .line 172
    .line 173
    :pswitch_7
    move-object v11, v4

    .line 174
    new-instance v14, Lbn/a;

    .line 175
    .line 176
    sget-object v4, Len/f;->j:Len/f;

    .line 177
    .line 178
    invoke-static {v0, v2, v6, v4, v9}, Len/p;->a(Lfn/a;Lum/a;FLen/d0;Z)Ljava/util/ArrayList;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    const/4 v5, 0x4

    .line 183
    invoke-direct {v14, v4, v5}, Lbn/a;-><init>(Ljava/util/List;I)V

    .line 184
    .line 185
    .line 186
    :goto_4
    move-object v4, v11

    .line 187
    goto :goto_3

    .line 188
    :pswitch_8
    move-object v11, v4

    .line 189
    invoke-static/range {p0 .. p1}, Len/a;->b(Lfn/b;Lum/a;)Lbn/f;

    .line 190
    .line 191
    .line 192
    move-result-object v13

    .line 193
    goto :goto_3

    .line 194
    :pswitch_9
    move-object v11, v4

    .line 195
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 196
    .line 197
    .line 198
    :goto_5
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 199
    .line 200
    .line 201
    move-result v4

    .line 202
    if-eqz v4, :cond_5

    .line 203
    .line 204
    sget-object v4, Len/c;->b:Lb81/c;

    .line 205
    .line 206
    invoke-virtual {v0, v4}, Lfn/b;->H(Lb81/c;)I

    .line 207
    .line 208
    .line 209
    move-result v4

    .line 210
    if-eqz v4, :cond_4

    .line 211
    .line 212
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 216
    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_4
    invoke-static/range {p0 .. p1}, Len/a;->a(Lfn/b;Lum/a;)Lbn/c;

    .line 220
    .line 221
    .line 222
    move-result-object v12

    .line 223
    goto :goto_5

    .line 224
    :cond_5
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 225
    .line 226
    .line 227
    goto :goto_4

    .line 228
    :cond_6
    move-object v11, v4

    .line 229
    if-eqz v10, :cond_7

    .line 230
    .line 231
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 232
    .line 233
    .line 234
    :cond_7
    if-eqz v12, :cond_9

    .line 235
    .line 236
    invoke-virtual {v12}, Lbn/c;->isStatic()Z

    .line 237
    .line 238
    .line 239
    move-result v0

    .line 240
    if-eqz v0, :cond_8

    .line 241
    .line 242
    iget-object v0, v12, Lbn/c;->d:Ljava/util/ArrayList;

    .line 243
    .line 244
    invoke-virtual {v0, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    check-cast v0, Lhn/a;

    .line 249
    .line 250
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Landroid/graphics/PointF;

    .line 253
    .line 254
    const/4 v2, 0x0

    .line 255
    invoke-virtual {v0, v2, v2}, Landroid/graphics/PointF;->equals(FF)Z

    .line 256
    .line 257
    .line 258
    move-result v0

    .line 259
    if-eqz v0, :cond_8

    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_8
    move-object/from16 v17, v12

    .line 263
    .line 264
    goto :goto_7

    .line 265
    :cond_9
    :goto_6
    const/16 v17, 0x0

    .line 266
    .line 267
    :goto_7
    if-eqz v13, :cond_a

    .line 268
    .line 269
    instance-of v0, v13, Lbn/d;

    .line 270
    .line 271
    if-nez v0, :cond_b

    .line 272
    .line 273
    invoke-interface {v13}, Lbn/f;->isStatic()Z

    .line 274
    .line 275
    .line 276
    move-result v0

    .line 277
    if-eqz v0, :cond_b

    .line 278
    .line 279
    invoke-interface {v13}, Lbn/f;->q()Ljava/util/List;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v0

    .line 287
    check-cast v0, Lhn/a;

    .line 288
    .line 289
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v0, Landroid/graphics/PointF;

    .line 292
    .line 293
    const/4 v2, 0x0

    .line 294
    invoke-virtual {v0, v2, v2}, Landroid/graphics/PointF;->equals(FF)Z

    .line 295
    .line 296
    .line 297
    move-result v0

    .line 298
    if-eqz v0, :cond_b

    .line 299
    .line 300
    :cond_a
    const/4 v13, 0x0

    .line 301
    :cond_b
    if-eqz v1, :cond_d

    .line 302
    .line 303
    invoke-virtual {v1}, Lap0/o;->isStatic()Z

    .line 304
    .line 305
    .line 306
    move-result v0

    .line 307
    if-eqz v0, :cond_c

    .line 308
    .line 309
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v0, Ljava/util/List;

    .line 312
    .line 313
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    check-cast v0, Lhn/a;

    .line 318
    .line 319
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 320
    .line 321
    check-cast v0, Ljava/lang/Float;

    .line 322
    .line 323
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 324
    .line 325
    .line 326
    move-result v0

    .line 327
    const/16 v18, 0x0

    .line 328
    .line 329
    cmpl-float v0, v0, v18

    .line 330
    .line 331
    if-nez v0, :cond_c

    .line 332
    .line 333
    goto :goto_8

    .line 334
    :cond_c
    move-object/from16 v20, v1

    .line 335
    .line 336
    goto :goto_9

    .line 337
    :cond_d
    :goto_8
    const/16 v20, 0x0

    .line 338
    .line 339
    :goto_9
    if-eqz v14, :cond_f

    .line 340
    .line 341
    invoke-virtual {v14}, Lap0/o;->isStatic()Z

    .line 342
    .line 343
    .line 344
    move-result v0

    .line 345
    if-eqz v0, :cond_e

    .line 346
    .line 347
    iget-object v0, v14, Lap0/o;->e:Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v0, Ljava/util/List;

    .line 350
    .line 351
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    check-cast v0, Lhn/a;

    .line 356
    .line 357
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 358
    .line 359
    check-cast v0, Lhn/b;

    .line 360
    .line 361
    iget v1, v0, Lhn/b;->a:F

    .line 362
    .line 363
    cmpl-float v1, v1, v6

    .line 364
    .line 365
    if-nez v1, :cond_e

    .line 366
    .line 367
    iget v0, v0, Lhn/b;->b:F

    .line 368
    .line 369
    cmpl-float v0, v0, v6

    .line 370
    .line 371
    if-nez v0, :cond_e

    .line 372
    .line 373
    goto :goto_a

    .line 374
    :cond_e
    move-object/from16 v19, v14

    .line 375
    .line 376
    goto :goto_b

    .line 377
    :cond_f
    :goto_a
    const/16 v19, 0x0

    .line 378
    .line 379
    :goto_b
    if-eqz v15, :cond_11

    .line 380
    .line 381
    invoke-virtual {v15}, Lap0/o;->isStatic()Z

    .line 382
    .line 383
    .line 384
    move-result v0

    .line 385
    if-eqz v0, :cond_10

    .line 386
    .line 387
    iget-object v0, v15, Lap0/o;->e:Ljava/lang/Object;

    .line 388
    .line 389
    check-cast v0, Ljava/util/List;

    .line 390
    .line 391
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v0

    .line 395
    check-cast v0, Lhn/a;

    .line 396
    .line 397
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 398
    .line 399
    check-cast v0, Ljava/lang/Float;

    .line 400
    .line 401
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 402
    .line 403
    .line 404
    move-result v0

    .line 405
    const/16 v18, 0x0

    .line 406
    .line 407
    cmpl-float v0, v0, v18

    .line 408
    .line 409
    if-nez v0, :cond_10

    .line 410
    .line 411
    goto :goto_c

    .line 412
    :cond_10
    move-object/from16 v24, v15

    .line 413
    .line 414
    goto :goto_d

    .line 415
    :cond_11
    :goto_c
    const/16 v24, 0x0

    .line 416
    .line 417
    :goto_d
    if-eqz v11, :cond_13

    .line 418
    .line 419
    invoke-virtual {v11}, Lap0/o;->isStatic()Z

    .line 420
    .line 421
    .line 422
    move-result v0

    .line 423
    if-eqz v0, :cond_12

    .line 424
    .line 425
    iget-object v0, v11, Lap0/o;->e:Ljava/lang/Object;

    .line 426
    .line 427
    check-cast v0, Ljava/util/List;

    .line 428
    .line 429
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    check-cast v0, Lhn/a;

    .line 434
    .line 435
    iget-object v0, v0, Lhn/a;->b:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast v0, Ljava/lang/Float;

    .line 438
    .line 439
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 440
    .line 441
    .line 442
    move-result v0

    .line 443
    const/16 v18, 0x0

    .line 444
    .line 445
    cmpl-float v0, v0, v18

    .line 446
    .line 447
    if-nez v0, :cond_12

    .line 448
    .line 449
    goto :goto_e

    .line 450
    :cond_12
    move-object/from16 v25, v11

    .line 451
    .line 452
    goto :goto_f

    .line 453
    :cond_13
    :goto_e
    const/16 v25, 0x0

    .line 454
    .line 455
    :goto_f
    new-instance v16, Lbn/e;

    .line 456
    .line 457
    move-object/from16 v18, v13

    .line 458
    .line 459
    invoke-direct/range {v16 .. v25}, Lbn/e;-><init>(Lbn/c;Lbn/f;Lbn/a;Lbn/b;Lbn/a;Lbn/b;Lbn/b;Lbn/b;Lbn/b;)V

    .line 460
    .line 461
    .line 462
    return-object v16

    .line 463
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_5
        :pswitch_6
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
