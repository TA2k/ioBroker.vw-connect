.class public final Li5/l;
.super Li5/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:[I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Li5/l;->k:[I

    .line 5
    .line 6
    return-void
.end method

.method public static m([IIIIIFI)V
    .locals 2

    .line 1
    sub-int/2addr p2, p1

    .line 2
    sub-int/2addr p4, p3

    .line 3
    const/4 p1, -0x1

    .line 4
    const/4 p3, 0x0

    .line 5
    const/high16 v0, 0x3f000000    # 0.5f

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-eq p6, p1, :cond_2

    .line 9
    .line 10
    if-eqz p6, :cond_1

    .line 11
    .line 12
    if-eq p6, v1, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    int-to-float p1, p2

    .line 16
    mul-float/2addr p1, p5

    .line 17
    add-float/2addr p1, v0

    .line 18
    float-to-int p1, p1

    .line 19
    aput p2, p0, p3

    .line 20
    .line 21
    aput p1, p0, v1

    .line 22
    .line 23
    return-void

    .line 24
    :cond_1
    int-to-float p1, p4

    .line 25
    mul-float/2addr p1, p5

    .line 26
    add-float/2addr p1, v0

    .line 27
    float-to-int p1, p1

    .line 28
    aput p1, p0, p3

    .line 29
    .line 30
    aput p4, p0, v1

    .line 31
    .line 32
    return-void

    .line 33
    :cond_2
    int-to-float p1, p4

    .line 34
    mul-float/2addr p1, p5

    .line 35
    add-float/2addr p1, v0

    .line 36
    float-to-int p1, p1

    .line 37
    int-to-float p6, p2

    .line 38
    div-float/2addr p6, p5

    .line 39
    add-float/2addr p6, v0

    .line 40
    float-to-int p5, p6

    .line 41
    if-gt p1, p2, :cond_3

    .line 42
    .line 43
    aput p1, p0, p3

    .line 44
    .line 45
    aput p4, p0, v1

    .line 46
    .line 47
    return-void

    .line 48
    :cond_3
    if-gt p5, p4, :cond_4

    .line 49
    .line 50
    aput p2, p0, p3

    .line 51
    .line 52
    aput p5, p0, v1

    .line 53
    .line 54
    :cond_4
    :goto_0
    return-void
.end method


# virtual methods
.method public final a(Li5/e;)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li5/p;->j:I

    .line 4
    .line 5
    invoke-static {v1}, Lu/w;->o(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x3

    .line 10
    const/4 v3, 0x0

    .line 11
    if-eq v1, v2, :cond_26

    .line 12
    .line 13
    iget-object v1, v0, Li5/p;->e:Li5/h;

    .line 14
    .line 15
    iget-boolean v4, v1, Li5/g;->j:Z

    .line 16
    .line 17
    const/high16 v5, 0x3f000000    # 0.5f

    .line 18
    .line 19
    const/4 v6, 0x1

    .line 20
    iget-object v7, v0, Li5/p;->h:Li5/g;

    .line 21
    .line 22
    iget-object v8, v0, Li5/p;->i:Li5/g;

    .line 23
    .line 24
    if-nez v4, :cond_0

    .line 25
    .line 26
    iget v4, v0, Li5/p;->d:I

    .line 27
    .line 28
    if-ne v4, v2, :cond_0

    .line 29
    .line 30
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 31
    .line 32
    iget v9, v4, Lh5/d;->s:I

    .line 33
    .line 34
    const/4 v10, 0x2

    .line 35
    if-eq v9, v10, :cond_1c

    .line 36
    .line 37
    if-eq v9, v2, :cond_1

    .line 38
    .line 39
    :cond_0
    :goto_0
    move/from16 p1, v5

    .line 40
    .line 41
    goto/16 :goto_a

    .line 42
    .line 43
    :cond_1
    iget v9, v4, Lh5/d;->t:I

    .line 44
    .line 45
    const/4 v10, -0x1

    .line 46
    if-eqz v9, :cond_6

    .line 47
    .line 48
    if-ne v9, v2, :cond_2

    .line 49
    .line 50
    goto :goto_4

    .line 51
    :cond_2
    iget v9, v4, Lh5/d;->Y:I

    .line 52
    .line 53
    if-eq v9, v10, :cond_5

    .line 54
    .line 55
    if-eqz v9, :cond_4

    .line 56
    .line 57
    if-eq v9, v6, :cond_3

    .line 58
    .line 59
    move v4, v3

    .line 60
    goto :goto_3

    .line 61
    :cond_3
    iget-object v9, v4, Lh5/d;->e:Li5/n;

    .line 62
    .line 63
    iget-object v9, v9, Li5/p;->e:Li5/h;

    .line 64
    .line 65
    iget v9, v9, Li5/g;->g:I

    .line 66
    .line 67
    int-to-float v9, v9

    .line 68
    iget v4, v4, Lh5/d;->X:F

    .line 69
    .line 70
    :goto_1
    mul-float/2addr v9, v4

    .line 71
    :goto_2
    add-float/2addr v9, v5

    .line 72
    float-to-int v4, v9

    .line 73
    goto :goto_3

    .line 74
    :cond_4
    iget-object v9, v4, Lh5/d;->e:Li5/n;

    .line 75
    .line 76
    iget-object v9, v9, Li5/p;->e:Li5/h;

    .line 77
    .line 78
    iget v9, v9, Li5/g;->g:I

    .line 79
    .line 80
    int-to-float v9, v9

    .line 81
    iget v4, v4, Lh5/d;->X:F

    .line 82
    .line 83
    div-float/2addr v9, v4

    .line 84
    goto :goto_2

    .line 85
    :cond_5
    iget-object v9, v4, Lh5/d;->e:Li5/n;

    .line 86
    .line 87
    iget-object v9, v9, Li5/p;->e:Li5/h;

    .line 88
    .line 89
    iget v9, v9, Li5/g;->g:I

    .line 90
    .line 91
    int-to-float v9, v9

    .line 92
    iget v4, v4, Lh5/d;->X:F

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :goto_3
    invoke-virtual {v1, v4}, Li5/h;->d(I)V

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_6
    :goto_4
    iget-object v9, v4, Lh5/d;->e:Li5/n;

    .line 100
    .line 101
    iget-object v11, v9, Li5/p;->h:Li5/g;

    .line 102
    .line 103
    iget-object v9, v9, Li5/p;->i:Li5/g;

    .line 104
    .line 105
    iget-object v12, v4, Lh5/d;->J:Lh5/c;

    .line 106
    .line 107
    iget-object v12, v12, Lh5/c;->f:Lh5/c;

    .line 108
    .line 109
    if-eqz v12, :cond_7

    .line 110
    .line 111
    move v12, v6

    .line 112
    goto :goto_5

    .line 113
    :cond_7
    move v12, v3

    .line 114
    :goto_5
    iget-object v13, v4, Lh5/d;->K:Lh5/c;

    .line 115
    .line 116
    iget-object v13, v13, Lh5/c;->f:Lh5/c;

    .line 117
    .line 118
    if-eqz v13, :cond_8

    .line 119
    .line 120
    move v13, v6

    .line 121
    goto :goto_6

    .line 122
    :cond_8
    move v13, v3

    .line 123
    :goto_6
    iget-object v14, v4, Lh5/d;->L:Lh5/c;

    .line 124
    .line 125
    iget-object v14, v14, Lh5/c;->f:Lh5/c;

    .line 126
    .line 127
    if-eqz v14, :cond_9

    .line 128
    .line 129
    move v14, v6

    .line 130
    goto :goto_7

    .line 131
    :cond_9
    move v14, v3

    .line 132
    :goto_7
    iget-object v15, v4, Lh5/d;->M:Lh5/c;

    .line 133
    .line 134
    iget-object v15, v15, Lh5/c;->f:Lh5/c;

    .line 135
    .line 136
    if-eqz v15, :cond_a

    .line 137
    .line 138
    move v15, v6

    .line 139
    :goto_8
    move/from16 p1, v5

    .line 140
    .line 141
    goto :goto_9

    .line 142
    :cond_a
    move v15, v3

    .line 143
    goto :goto_8

    .line 144
    :goto_9
    iget v5, v4, Lh5/d;->Y:I

    .line 145
    .line 146
    if-eqz v12, :cond_10

    .line 147
    .line 148
    if-eqz v13, :cond_10

    .line 149
    .line 150
    if-eqz v14, :cond_10

    .line 151
    .line 152
    if-eqz v15, :cond_10

    .line 153
    .line 154
    iget v4, v4, Lh5/d;->X:F

    .line 155
    .line 156
    iget-boolean v10, v11, Li5/g;->j:Z

    .line 157
    .line 158
    iget-object v12, v11, Li5/g;->l:Ljava/util/ArrayList;

    .line 159
    .line 160
    sget-object v16, Li5/l;->k:[I

    .line 161
    .line 162
    if-eqz v10, :cond_c

    .line 163
    .line 164
    iget-boolean v10, v9, Li5/g;->j:Z

    .line 165
    .line 166
    if-eqz v10, :cond_c

    .line 167
    .line 168
    iget-boolean v2, v7, Li5/g;->c:Z

    .line 169
    .line 170
    if-eqz v2, :cond_25

    .line 171
    .line 172
    iget-boolean v2, v8, Li5/g;->c:Z

    .line 173
    .line 174
    if-nez v2, :cond_b

    .line 175
    .line 176
    goto/16 :goto_c

    .line 177
    .line 178
    :cond_b
    iget-object v2, v7, Li5/g;->l:Ljava/util/ArrayList;

    .line 179
    .line 180
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    check-cast v2, Li5/g;

    .line 185
    .line 186
    iget v2, v2, Li5/g;->g:I

    .line 187
    .line 188
    iget v7, v7, Li5/g;->f:I

    .line 189
    .line 190
    add-int v17, v2, v7

    .line 191
    .line 192
    iget-object v2, v8, Li5/g;->l:Ljava/util/ArrayList;

    .line 193
    .line 194
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    check-cast v2, Li5/g;

    .line 199
    .line 200
    iget v2, v2, Li5/g;->g:I

    .line 201
    .line 202
    iget v7, v8, Li5/g;->f:I

    .line 203
    .line 204
    sub-int v18, v2, v7

    .line 205
    .line 206
    iget v2, v11, Li5/g;->g:I

    .line 207
    .line 208
    iget v7, v11, Li5/g;->f:I

    .line 209
    .line 210
    add-int v19, v2, v7

    .line 211
    .line 212
    iget v2, v9, Li5/g;->g:I

    .line 213
    .line 214
    iget v7, v9, Li5/g;->f:I

    .line 215
    .line 216
    sub-int v20, v2, v7

    .line 217
    .line 218
    move/from16 v21, v4

    .line 219
    .line 220
    move/from16 v22, v5

    .line 221
    .line 222
    invoke-static/range {v16 .. v22}, Li5/l;->m([IIIIIFI)V

    .line 223
    .line 224
    .line 225
    aget v2, v16, v3

    .line 226
    .line 227
    invoke-virtual {v1, v2}, Li5/h;->d(I)V

    .line 228
    .line 229
    .line 230
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 231
    .line 232
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 233
    .line 234
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 235
    .line 236
    aget v1, v16, v6

    .line 237
    .line 238
    invoke-virtual {v0, v1}, Li5/h;->d(I)V

    .line 239
    .line 240
    .line 241
    return-void

    .line 242
    :cond_c
    move/from16 v21, v4

    .line 243
    .line 244
    move/from16 v22, v5

    .line 245
    .line 246
    iget-boolean v4, v7, Li5/g;->j:Z

    .line 247
    .line 248
    if-eqz v4, :cond_e

    .line 249
    .line 250
    iget-boolean v4, v8, Li5/g;->j:Z

    .line 251
    .line 252
    if-eqz v4, :cond_e

    .line 253
    .line 254
    iget-boolean v4, v11, Li5/g;->c:Z

    .line 255
    .line 256
    if-eqz v4, :cond_25

    .line 257
    .line 258
    iget-boolean v4, v9, Li5/g;->c:Z

    .line 259
    .line 260
    if-nez v4, :cond_d

    .line 261
    .line 262
    goto/16 :goto_c

    .line 263
    .line 264
    :cond_d
    iget v4, v7, Li5/g;->g:I

    .line 265
    .line 266
    iget v5, v7, Li5/g;->f:I

    .line 267
    .line 268
    add-int v17, v4, v5

    .line 269
    .line 270
    iget v4, v8, Li5/g;->g:I

    .line 271
    .line 272
    iget v5, v8, Li5/g;->f:I

    .line 273
    .line 274
    sub-int v18, v4, v5

    .line 275
    .line 276
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v4

    .line 280
    check-cast v4, Li5/g;

    .line 281
    .line 282
    iget v4, v4, Li5/g;->g:I

    .line 283
    .line 284
    iget v5, v11, Li5/g;->f:I

    .line 285
    .line 286
    add-int v19, v4, v5

    .line 287
    .line 288
    iget-object v4, v9, Li5/g;->l:Ljava/util/ArrayList;

    .line 289
    .line 290
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v4

    .line 294
    check-cast v4, Li5/g;

    .line 295
    .line 296
    iget v4, v4, Li5/g;->g:I

    .line 297
    .line 298
    iget v5, v9, Li5/g;->f:I

    .line 299
    .line 300
    sub-int v20, v4, v5

    .line 301
    .line 302
    invoke-static/range {v16 .. v22}, Li5/l;->m([IIIIIFI)V

    .line 303
    .line 304
    .line 305
    aget v4, v16, v3

    .line 306
    .line 307
    invoke-virtual {v1, v4}, Li5/h;->d(I)V

    .line 308
    .line 309
    .line 310
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 311
    .line 312
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 313
    .line 314
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 315
    .line 316
    aget v5, v16, v6

    .line 317
    .line 318
    invoke-virtual {v4, v5}, Li5/h;->d(I)V

    .line 319
    .line 320
    .line 321
    :cond_e
    iget-boolean v4, v7, Li5/g;->c:Z

    .line 322
    .line 323
    if-eqz v4, :cond_25

    .line 324
    .line 325
    iget-boolean v4, v8, Li5/g;->c:Z

    .line 326
    .line 327
    if-eqz v4, :cond_25

    .line 328
    .line 329
    iget-boolean v4, v11, Li5/g;->c:Z

    .line 330
    .line 331
    if-eqz v4, :cond_25

    .line 332
    .line 333
    iget-boolean v4, v9, Li5/g;->c:Z

    .line 334
    .line 335
    if-nez v4, :cond_f

    .line 336
    .line 337
    goto/16 :goto_c

    .line 338
    .line 339
    :cond_f
    iget-object v4, v7, Li5/g;->l:Ljava/util/ArrayList;

    .line 340
    .line 341
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v4

    .line 345
    check-cast v4, Li5/g;

    .line 346
    .line 347
    iget v4, v4, Li5/g;->g:I

    .line 348
    .line 349
    iget v5, v7, Li5/g;->f:I

    .line 350
    .line 351
    add-int v17, v4, v5

    .line 352
    .line 353
    iget-object v4, v8, Li5/g;->l:Ljava/util/ArrayList;

    .line 354
    .line 355
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v4

    .line 359
    check-cast v4, Li5/g;

    .line 360
    .line 361
    iget v4, v4, Li5/g;->g:I

    .line 362
    .line 363
    iget v5, v8, Li5/g;->f:I

    .line 364
    .line 365
    sub-int v18, v4, v5

    .line 366
    .line 367
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object v4

    .line 371
    check-cast v4, Li5/g;

    .line 372
    .line 373
    iget v4, v4, Li5/g;->g:I

    .line 374
    .line 375
    iget v5, v11, Li5/g;->f:I

    .line 376
    .line 377
    add-int v19, v4, v5

    .line 378
    .line 379
    iget-object v4, v9, Li5/g;->l:Ljava/util/ArrayList;

    .line 380
    .line 381
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v4

    .line 385
    check-cast v4, Li5/g;

    .line 386
    .line 387
    iget v4, v4, Li5/g;->g:I

    .line 388
    .line 389
    iget v5, v9, Li5/g;->f:I

    .line 390
    .line 391
    sub-int v20, v4, v5

    .line 392
    .line 393
    invoke-static/range {v16 .. v22}, Li5/l;->m([IIIIIFI)V

    .line 394
    .line 395
    .line 396
    aget v4, v16, v3

    .line 397
    .line 398
    invoke-virtual {v1, v4}, Li5/h;->d(I)V

    .line 399
    .line 400
    .line 401
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 402
    .line 403
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 404
    .line 405
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 406
    .line 407
    aget v5, v16, v6

    .line 408
    .line 409
    invoke-virtual {v4, v5}, Li5/h;->d(I)V

    .line 410
    .line 411
    .line 412
    goto/16 :goto_a

    .line 413
    .line 414
    :cond_10
    if-eqz v12, :cond_16

    .line 415
    .line 416
    if-eqz v14, :cond_16

    .line 417
    .line 418
    iget-boolean v9, v7, Li5/g;->c:Z

    .line 419
    .line 420
    if-eqz v9, :cond_25

    .line 421
    .line 422
    iget-boolean v9, v8, Li5/g;->c:Z

    .line 423
    .line 424
    if-nez v9, :cond_11

    .line 425
    .line 426
    goto/16 :goto_c

    .line 427
    .line 428
    :cond_11
    iget v4, v4, Lh5/d;->X:F

    .line 429
    .line 430
    iget-object v9, v7, Li5/g;->l:Ljava/util/ArrayList;

    .line 431
    .line 432
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v9

    .line 436
    check-cast v9, Li5/g;

    .line 437
    .line 438
    iget v9, v9, Li5/g;->g:I

    .line 439
    .line 440
    iget v11, v7, Li5/g;->f:I

    .line 441
    .line 442
    add-int/2addr v9, v11

    .line 443
    iget-object v11, v8, Li5/g;->l:Ljava/util/ArrayList;

    .line 444
    .line 445
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 446
    .line 447
    .line 448
    move-result-object v11

    .line 449
    check-cast v11, Li5/g;

    .line 450
    .line 451
    iget v11, v11, Li5/g;->g:I

    .line 452
    .line 453
    iget v12, v8, Li5/g;->f:I

    .line 454
    .line 455
    sub-int/2addr v11, v12

    .line 456
    if-eq v5, v10, :cond_14

    .line 457
    .line 458
    if-eqz v5, :cond_14

    .line 459
    .line 460
    if-eq v5, v6, :cond_12

    .line 461
    .line 462
    goto/16 :goto_a

    .line 463
    .line 464
    :cond_12
    sub-int/2addr v11, v9

    .line 465
    invoke-virtual {v0, v11, v3}, Li5/p;->g(II)I

    .line 466
    .line 467
    .line 468
    move-result v5

    .line 469
    int-to-float v9, v5

    .line 470
    div-float/2addr v9, v4

    .line 471
    add-float v9, v9, p1

    .line 472
    .line 473
    float-to-int v9, v9

    .line 474
    invoke-virtual {v0, v9, v6}, Li5/p;->g(II)I

    .line 475
    .line 476
    .line 477
    move-result v10

    .line 478
    if-eq v9, v10, :cond_13

    .line 479
    .line 480
    int-to-float v5, v10

    .line 481
    mul-float/2addr v5, v4

    .line 482
    add-float v5, v5, p1

    .line 483
    .line 484
    float-to-int v5, v5

    .line 485
    :cond_13
    invoke-virtual {v1, v5}, Li5/h;->d(I)V

    .line 486
    .line 487
    .line 488
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 489
    .line 490
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 491
    .line 492
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 493
    .line 494
    invoke-virtual {v4, v10}, Li5/h;->d(I)V

    .line 495
    .line 496
    .line 497
    goto/16 :goto_a

    .line 498
    .line 499
    :cond_14
    sub-int/2addr v11, v9

    .line 500
    invoke-virtual {v0, v11, v3}, Li5/p;->g(II)I

    .line 501
    .line 502
    .line 503
    move-result v5

    .line 504
    int-to-float v9, v5

    .line 505
    mul-float/2addr v9, v4

    .line 506
    add-float v9, v9, p1

    .line 507
    .line 508
    float-to-int v9, v9

    .line 509
    invoke-virtual {v0, v9, v6}, Li5/p;->g(II)I

    .line 510
    .line 511
    .line 512
    move-result v10

    .line 513
    if-eq v9, v10, :cond_15

    .line 514
    .line 515
    int-to-float v5, v10

    .line 516
    div-float/2addr v5, v4

    .line 517
    add-float v5, v5, p1

    .line 518
    .line 519
    float-to-int v5, v5

    .line 520
    :cond_15
    invoke-virtual {v1, v5}, Li5/h;->d(I)V

    .line 521
    .line 522
    .line 523
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 524
    .line 525
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 526
    .line 527
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 528
    .line 529
    invoke-virtual {v4, v10}, Li5/h;->d(I)V

    .line 530
    .line 531
    .line 532
    goto/16 :goto_a

    .line 533
    .line 534
    :cond_16
    if-eqz v13, :cond_1d

    .line 535
    .line 536
    if-eqz v15, :cond_1d

    .line 537
    .line 538
    iget-boolean v12, v11, Li5/g;->c:Z

    .line 539
    .line 540
    if-eqz v12, :cond_25

    .line 541
    .line 542
    iget-boolean v12, v9, Li5/g;->c:Z

    .line 543
    .line 544
    if-nez v12, :cond_17

    .line 545
    .line 546
    goto/16 :goto_c

    .line 547
    .line 548
    :cond_17
    iget v4, v4, Lh5/d;->X:F

    .line 549
    .line 550
    iget-object v12, v11, Li5/g;->l:Ljava/util/ArrayList;

    .line 551
    .line 552
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    move-result-object v12

    .line 556
    check-cast v12, Li5/g;

    .line 557
    .line 558
    iget v12, v12, Li5/g;->g:I

    .line 559
    .line 560
    iget v11, v11, Li5/g;->f:I

    .line 561
    .line 562
    add-int/2addr v12, v11

    .line 563
    iget-object v11, v9, Li5/g;->l:Ljava/util/ArrayList;

    .line 564
    .line 565
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    move-result-object v11

    .line 569
    check-cast v11, Li5/g;

    .line 570
    .line 571
    iget v11, v11, Li5/g;->g:I

    .line 572
    .line 573
    iget v9, v9, Li5/g;->f:I

    .line 574
    .line 575
    sub-int/2addr v11, v9

    .line 576
    if-eq v5, v10, :cond_1a

    .line 577
    .line 578
    if-eqz v5, :cond_18

    .line 579
    .line 580
    if-eq v5, v6, :cond_1a

    .line 581
    .line 582
    goto :goto_a

    .line 583
    :cond_18
    sub-int/2addr v11, v12

    .line 584
    invoke-virtual {v0, v11, v6}, Li5/p;->g(II)I

    .line 585
    .line 586
    .line 587
    move-result v5

    .line 588
    int-to-float v9, v5

    .line 589
    mul-float/2addr v9, v4

    .line 590
    add-float v9, v9, p1

    .line 591
    .line 592
    float-to-int v9, v9

    .line 593
    invoke-virtual {v0, v9, v3}, Li5/p;->g(II)I

    .line 594
    .line 595
    .line 596
    move-result v10

    .line 597
    if-eq v9, v10, :cond_19

    .line 598
    .line 599
    int-to-float v5, v10

    .line 600
    div-float/2addr v5, v4

    .line 601
    add-float v5, v5, p1

    .line 602
    .line 603
    float-to-int v5, v5

    .line 604
    :cond_19
    invoke-virtual {v1, v10}, Li5/h;->d(I)V

    .line 605
    .line 606
    .line 607
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 608
    .line 609
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 610
    .line 611
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 612
    .line 613
    invoke-virtual {v4, v5}, Li5/h;->d(I)V

    .line 614
    .line 615
    .line 616
    goto :goto_a

    .line 617
    :cond_1a
    sub-int/2addr v11, v12

    .line 618
    invoke-virtual {v0, v11, v6}, Li5/p;->g(II)I

    .line 619
    .line 620
    .line 621
    move-result v5

    .line 622
    int-to-float v9, v5

    .line 623
    div-float/2addr v9, v4

    .line 624
    add-float v9, v9, p1

    .line 625
    .line 626
    float-to-int v9, v9

    .line 627
    invoke-virtual {v0, v9, v3}, Li5/p;->g(II)I

    .line 628
    .line 629
    .line 630
    move-result v10

    .line 631
    if-eq v9, v10, :cond_1b

    .line 632
    .line 633
    int-to-float v5, v10

    .line 634
    mul-float/2addr v5, v4

    .line 635
    add-float v5, v5, p1

    .line 636
    .line 637
    float-to-int v5, v5

    .line 638
    :cond_1b
    invoke-virtual {v1, v10}, Li5/h;->d(I)V

    .line 639
    .line 640
    .line 641
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 642
    .line 643
    iget-object v4, v4, Lh5/d;->e:Li5/n;

    .line 644
    .line 645
    iget-object v4, v4, Li5/p;->e:Li5/h;

    .line 646
    .line 647
    invoke-virtual {v4, v5}, Li5/h;->d(I)V

    .line 648
    .line 649
    .line 650
    goto :goto_a

    .line 651
    :cond_1c
    move/from16 p1, v5

    .line 652
    .line 653
    iget-object v5, v4, Lh5/d;->U:Lh5/e;

    .line 654
    .line 655
    if-eqz v5, :cond_1d

    .line 656
    .line 657
    iget-object v5, v5, Lh5/d;->d:Li5/l;

    .line 658
    .line 659
    iget-object v5, v5, Li5/p;->e:Li5/h;

    .line 660
    .line 661
    iget-boolean v9, v5, Li5/g;->j:Z

    .line 662
    .line 663
    if-eqz v9, :cond_1d

    .line 664
    .line 665
    iget v4, v4, Lh5/d;->x:F

    .line 666
    .line 667
    iget v5, v5, Li5/g;->g:I

    .line 668
    .line 669
    int-to-float v5, v5

    .line 670
    mul-float/2addr v5, v4

    .line 671
    add-float v5, v5, p1

    .line 672
    .line 673
    float-to-int v4, v5

    .line 674
    invoke-virtual {v1, v4}, Li5/h;->d(I)V

    .line 675
    .line 676
    .line 677
    :cond_1d
    :goto_a
    iget-boolean v4, v7, Li5/g;->c:Z

    .line 678
    .line 679
    iget-object v5, v7, Li5/g;->l:Ljava/util/ArrayList;

    .line 680
    .line 681
    if-eqz v4, :cond_25

    .line 682
    .line 683
    iget-boolean v4, v8, Li5/g;->c:Z

    .line 684
    .line 685
    iget-object v9, v8, Li5/g;->l:Ljava/util/ArrayList;

    .line 686
    .line 687
    if-nez v4, :cond_1e

    .line 688
    .line 689
    goto/16 :goto_c

    .line 690
    .line 691
    :cond_1e
    iget-boolean v4, v7, Li5/g;->j:Z

    .line 692
    .line 693
    if-eqz v4, :cond_1f

    .line 694
    .line 695
    iget-boolean v4, v8, Li5/g;->j:Z

    .line 696
    .line 697
    if-eqz v4, :cond_1f

    .line 698
    .line 699
    iget-boolean v4, v1, Li5/g;->j:Z

    .line 700
    .line 701
    if-eqz v4, :cond_1f

    .line 702
    .line 703
    goto/16 :goto_c

    .line 704
    .line 705
    :cond_1f
    iget-boolean v4, v1, Li5/g;->j:Z

    .line 706
    .line 707
    if-nez v4, :cond_20

    .line 708
    .line 709
    iget v4, v0, Li5/p;->d:I

    .line 710
    .line 711
    if-ne v4, v2, :cond_20

    .line 712
    .line 713
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 714
    .line 715
    iget v10, v4, Lh5/d;->s:I

    .line 716
    .line 717
    if-nez v10, :cond_20

    .line 718
    .line 719
    invoke-virtual {v4}, Lh5/d;->y()Z

    .line 720
    .line 721
    .line 722
    move-result v4

    .line 723
    if-nez v4, :cond_20

    .line 724
    .line 725
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 726
    .line 727
    .line 728
    move-result-object v0

    .line 729
    check-cast v0, Li5/g;

    .line 730
    .line 731
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v2

    .line 735
    check-cast v2, Li5/g;

    .line 736
    .line 737
    iget v0, v0, Li5/g;->g:I

    .line 738
    .line 739
    iget v3, v7, Li5/g;->f:I

    .line 740
    .line 741
    add-int/2addr v0, v3

    .line 742
    iget v2, v2, Li5/g;->g:I

    .line 743
    .line 744
    iget v3, v8, Li5/g;->f:I

    .line 745
    .line 746
    add-int/2addr v2, v3

    .line 747
    sub-int v3, v2, v0

    .line 748
    .line 749
    invoke-virtual {v7, v0}, Li5/g;->d(I)V

    .line 750
    .line 751
    .line 752
    invoke-virtual {v8, v2}, Li5/g;->d(I)V

    .line 753
    .line 754
    .line 755
    invoke-virtual {v1, v3}, Li5/h;->d(I)V

    .line 756
    .line 757
    .line 758
    return-void

    .line 759
    :cond_20
    iget-boolean v4, v1, Li5/g;->j:Z

    .line 760
    .line 761
    if-nez v4, :cond_22

    .line 762
    .line 763
    iget v4, v0, Li5/p;->d:I

    .line 764
    .line 765
    if-ne v4, v2, :cond_22

    .line 766
    .line 767
    iget v2, v0, Li5/p;->a:I

    .line 768
    .line 769
    if-ne v2, v6, :cond_22

    .line 770
    .line 771
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 772
    .line 773
    .line 774
    move-result v2

    .line 775
    if-lez v2, :cond_22

    .line 776
    .line 777
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 778
    .line 779
    .line 780
    move-result v2

    .line 781
    if-lez v2, :cond_22

    .line 782
    .line 783
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 784
    .line 785
    .line 786
    move-result-object v2

    .line 787
    check-cast v2, Li5/g;

    .line 788
    .line 789
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 790
    .line 791
    .line 792
    move-result-object v4

    .line 793
    check-cast v4, Li5/g;

    .line 794
    .line 795
    iget v2, v2, Li5/g;->g:I

    .line 796
    .line 797
    iget v6, v7, Li5/g;->f:I

    .line 798
    .line 799
    add-int/2addr v2, v6

    .line 800
    iget v4, v4, Li5/g;->g:I

    .line 801
    .line 802
    iget v6, v8, Li5/g;->f:I

    .line 803
    .line 804
    add-int/2addr v4, v6

    .line 805
    sub-int/2addr v4, v2

    .line 806
    iget v2, v1, Li5/h;->m:I

    .line 807
    .line 808
    invoke-static {v4, v2}, Ljava/lang/Math;->min(II)I

    .line 809
    .line 810
    .line 811
    move-result v2

    .line 812
    iget-object v4, v0, Li5/p;->b:Lh5/d;

    .line 813
    .line 814
    iget v6, v4, Lh5/d;->w:I

    .line 815
    .line 816
    iget v4, v4, Lh5/d;->v:I

    .line 817
    .line 818
    invoke-static {v4, v2}, Ljava/lang/Math;->max(II)I

    .line 819
    .line 820
    .line 821
    move-result v2

    .line 822
    if-lez v6, :cond_21

    .line 823
    .line 824
    invoke-static {v6, v2}, Ljava/lang/Math;->min(II)I

    .line 825
    .line 826
    .line 827
    move-result v2

    .line 828
    :cond_21
    invoke-virtual {v1, v2}, Li5/h;->d(I)V

    .line 829
    .line 830
    .line 831
    :cond_22
    iget-boolean v2, v1, Li5/g;->j:Z

    .line 832
    .line 833
    if-nez v2, :cond_23

    .line 834
    .line 835
    goto :goto_c

    .line 836
    :cond_23
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v2

    .line 840
    check-cast v2, Li5/g;

    .line 841
    .line 842
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 843
    .line 844
    .line 845
    move-result-object v3

    .line 846
    check-cast v3, Li5/g;

    .line 847
    .line 848
    iget v4, v2, Li5/g;->g:I

    .line 849
    .line 850
    iget v5, v7, Li5/g;->f:I

    .line 851
    .line 852
    add-int/2addr v5, v4

    .line 853
    iget v6, v3, Li5/g;->g:I

    .line 854
    .line 855
    iget v9, v8, Li5/g;->f:I

    .line 856
    .line 857
    add-int/2addr v9, v6

    .line 858
    iget-object v0, v0, Li5/p;->b:Lh5/d;

    .line 859
    .line 860
    iget v0, v0, Lh5/d;->e0:F

    .line 861
    .line 862
    if-ne v2, v3, :cond_24

    .line 863
    .line 864
    move/from16 v0, p1

    .line 865
    .line 866
    goto :goto_b

    .line 867
    :cond_24
    move v4, v5

    .line 868
    move v6, v9

    .line 869
    :goto_b
    sub-int/2addr v6, v4

    .line 870
    iget v2, v1, Li5/g;->g:I

    .line 871
    .line 872
    sub-int/2addr v6, v2

    .line 873
    int-to-float v2, v4

    .line 874
    add-float v2, v2, p1

    .line 875
    .line 876
    int-to-float v3, v6

    .line 877
    mul-float/2addr v3, v0

    .line 878
    add-float/2addr v3, v2

    .line 879
    float-to-int v0, v3

    .line 880
    invoke-virtual {v7, v0}, Li5/g;->d(I)V

    .line 881
    .line 882
    .line 883
    iget v0, v7, Li5/g;->g:I

    .line 884
    .line 885
    iget v1, v1, Li5/g;->g:I

    .line 886
    .line 887
    add-int/2addr v0, v1

    .line 888
    invoke-virtual {v8, v0}, Li5/g;->d(I)V

    .line 889
    .line 890
    .line 891
    :cond_25
    :goto_c
    return-void

    .line 892
    :cond_26
    iget-object v1, v0, Li5/p;->b:Lh5/d;

    .line 893
    .line 894
    iget-object v2, v1, Lh5/d;->J:Lh5/c;

    .line 895
    .line 896
    iget-object v1, v1, Lh5/d;->L:Lh5/c;

    .line 897
    .line 898
    invoke-virtual {v0, v2, v1, v3}, Li5/p;->l(Lh5/c;Lh5/c;I)V

    .line 899
    .line 900
    .line 901
    return-void
.end method

.method public final d()V
    .locals 13

    .line 1
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 2
    .line 3
    iget-boolean v1, v0, Lh5/d;->a:Z

    .line 4
    .line 5
    iget-object v2, p0, Li5/p;->e:Li5/h;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Lh5/d;->r()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-virtual {v2, v0}, Li5/h;->d(I)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-boolean v0, v2, Li5/g;->j:Z

    .line 17
    .line 18
    iget-object v1, v2, Li5/g;->k:Ljava/util/ArrayList;

    .line 19
    .line 20
    iget-object v3, v2, Li5/g;->l:Ljava/util/ArrayList;

    .line 21
    .line 22
    const/4 v4, 0x3

    .line 23
    const/4 v5, 0x4

    .line 24
    const/4 v6, 0x1

    .line 25
    const/4 v7, 0x0

    .line 26
    iget-object v8, p0, Li5/p;->i:Li5/g;

    .line 27
    .line 28
    iget-object v9, p0, Li5/p;->h:Li5/g;

    .line 29
    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 33
    .line 34
    iget-object v10, v0, Lh5/d;->q0:[I

    .line 35
    .line 36
    aget v10, v10, v7

    .line 37
    .line 38
    iput v10, p0, Li5/p;->d:I

    .line 39
    .line 40
    if-eq v10, v4, :cond_5

    .line 41
    .line 42
    if-ne v10, v5, :cond_2

    .line 43
    .line 44
    iget-object v11, v0, Lh5/d;->U:Lh5/e;

    .line 45
    .line 46
    if-eqz v11, :cond_2

    .line 47
    .line 48
    iget-object v12, v11, Lh5/d;->q0:[I

    .line 49
    .line 50
    aget v12, v12, v7

    .line 51
    .line 52
    if-eq v12, v6, :cond_1

    .line 53
    .line 54
    if-ne v12, v5, :cond_2

    .line 55
    .line 56
    :cond_1
    invoke-virtual {v11}, Lh5/d;->r()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 61
    .line 62
    iget-object v1, v1, Lh5/d;->J:Lh5/c;

    .line 63
    .line 64
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    sub-int/2addr v0, v1

    .line 69
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 70
    .line 71
    iget-object v1, v1, Lh5/d;->L:Lh5/c;

    .line 72
    .line 73
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    sub-int/2addr v0, v1

    .line 78
    iget-object v1, v11, Lh5/d;->d:Li5/l;

    .line 79
    .line 80
    iget-object v1, v1, Li5/p;->h:Li5/g;

    .line 81
    .line 82
    iget-object v3, p0, Li5/p;->b:Lh5/d;

    .line 83
    .line 84
    iget-object v3, v3, Lh5/d;->J:Lh5/c;

    .line 85
    .line 86
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    invoke-static {v9, v1, v3}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 91
    .line 92
    .line 93
    iget-object v1, v11, Lh5/d;->d:Li5/l;

    .line 94
    .line 95
    iget-object v1, v1, Li5/p;->i:Li5/g;

    .line 96
    .line 97
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 98
    .line 99
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 100
    .line 101
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    neg-int p0, p0

    .line 106
    invoke-static {v8, v1, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v2, v0}, Li5/h;->d(I)V

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :cond_2
    if-ne v10, v6, :cond_5

    .line 114
    .line 115
    invoke-virtual {v0}, Lh5/d;->r()I

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    invoke-virtual {v2, v0}, Li5/h;->d(I)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_3
    iget v0, p0, Li5/p;->d:I

    .line 124
    .line 125
    if-ne v0, v5, :cond_5

    .line 126
    .line 127
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 128
    .line 129
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    .line 130
    .line 131
    if-eqz v10, :cond_5

    .line 132
    .line 133
    iget-object v11, v10, Lh5/d;->q0:[I

    .line 134
    .line 135
    aget v11, v11, v7

    .line 136
    .line 137
    if-eq v11, v6, :cond_4

    .line 138
    .line 139
    if-ne v11, v5, :cond_5

    .line 140
    .line 141
    :cond_4
    iget-object v1, v10, Lh5/d;->d:Li5/l;

    .line 142
    .line 143
    iget-object v1, v1, Li5/p;->h:Li5/g;

    .line 144
    .line 145
    iget-object v0, v0, Lh5/d;->J:Lh5/c;

    .line 146
    .line 147
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    invoke-static {v9, v1, v0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 152
    .line 153
    .line 154
    iget-object v0, v10, Lh5/d;->d:Li5/l;

    .line 155
    .line 156
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 157
    .line 158
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 159
    .line 160
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 161
    .line 162
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    neg-int p0, p0

    .line 167
    invoke-static {v8, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 168
    .line 169
    .line 170
    return-void

    .line 171
    :cond_5
    :goto_0
    iget-boolean v0, v2, Li5/g;->j:Z

    .line 172
    .line 173
    if-eqz v0, :cond_c

    .line 174
    .line 175
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 176
    .line 177
    iget-boolean v10, v0, Lh5/d;->a:Z

    .line 178
    .line 179
    if-eqz v10, :cond_c

    .line 180
    .line 181
    iget-object v1, v0, Lh5/d;->R:[Lh5/c;

    .line 182
    .line 183
    aget-object v3, v1, v7

    .line 184
    .line 185
    iget-object v4, v3, Lh5/c;->f:Lh5/c;

    .line 186
    .line 187
    if-eqz v4, :cond_9

    .line 188
    .line 189
    aget-object v5, v1, v6

    .line 190
    .line 191
    iget-object v5, v5, Lh5/c;->f:Lh5/c;

    .line 192
    .line 193
    if-eqz v5, :cond_9

    .line 194
    .line 195
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-eqz v0, :cond_6

    .line 200
    .line 201
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 202
    .line 203
    iget-object v0, v0, Lh5/d;->R:[Lh5/c;

    .line 204
    .line 205
    aget-object v0, v0, v7

    .line 206
    .line 207
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    iput v0, v9, Li5/g;->f:I

    .line 212
    .line 213
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 214
    .line 215
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 216
    .line 217
    aget-object p0, p0, v6

    .line 218
    .line 219
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    neg-int p0, p0

    .line 224
    iput p0, v8, Li5/g;->f:I

    .line 225
    .line 226
    return-void

    .line 227
    :cond_6
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 228
    .line 229
    iget-object v0, v0, Lh5/d;->R:[Lh5/c;

    .line 230
    .line 231
    aget-object v0, v0, v7

    .line 232
    .line 233
    invoke-static {v0}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    if-eqz v0, :cond_7

    .line 238
    .line 239
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 240
    .line 241
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 242
    .line 243
    aget-object v1, v1, v7

    .line 244
    .line 245
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 246
    .line 247
    .line 248
    move-result v1

    .line 249
    invoke-static {v9, v0, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 250
    .line 251
    .line 252
    :cond_7
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 253
    .line 254
    iget-object v0, v0, Lh5/d;->R:[Lh5/c;

    .line 255
    .line 256
    aget-object v0, v0, v6

    .line 257
    .line 258
    invoke-static {v0}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    if-eqz v0, :cond_8

    .line 263
    .line 264
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 265
    .line 266
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 267
    .line 268
    aget-object p0, p0, v6

    .line 269
    .line 270
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 271
    .line 272
    .line 273
    move-result p0

    .line 274
    neg-int p0, p0

    .line 275
    invoke-static {v8, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 276
    .line 277
    .line 278
    :cond_8
    iput-boolean v6, v9, Li5/g;->b:Z

    .line 279
    .line 280
    iput-boolean v6, v8, Li5/g;->b:Z

    .line 281
    .line 282
    return-void

    .line 283
    :cond_9
    if-eqz v4, :cond_a

    .line 284
    .line 285
    invoke-static {v3}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    if-eqz v0, :cond_1a

    .line 290
    .line 291
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 292
    .line 293
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 294
    .line 295
    aget-object p0, p0, v7

    .line 296
    .line 297
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 298
    .line 299
    .line 300
    move-result p0

    .line 301
    invoke-static {v9, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 302
    .line 303
    .line 304
    iget p0, v2, Li5/g;->g:I

    .line 305
    .line 306
    invoke-static {v8, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 307
    .line 308
    .line 309
    return-void

    .line 310
    :cond_a
    aget-object v1, v1, v6

    .line 311
    .line 312
    iget-object v3, v1, Lh5/c;->f:Lh5/c;

    .line 313
    .line 314
    if-eqz v3, :cond_b

    .line 315
    .line 316
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    if-eqz v0, :cond_1a

    .line 321
    .line 322
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 323
    .line 324
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 325
    .line 326
    aget-object p0, p0, v6

    .line 327
    .line 328
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 329
    .line 330
    .line 331
    move-result p0

    .line 332
    neg-int p0, p0

    .line 333
    invoke-static {v8, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 334
    .line 335
    .line 336
    iget p0, v2, Li5/g;->g:I

    .line 337
    .line 338
    neg-int p0, p0

    .line 339
    invoke-static {v9, v8, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 340
    .line 341
    .line 342
    return-void

    .line 343
    :cond_b
    instance-of v1, v0, Lh5/i;

    .line 344
    .line 345
    if-nez v1, :cond_1a

    .line 346
    .line 347
    iget-object v1, v0, Lh5/d;->U:Lh5/e;

    .line 348
    .line 349
    if-eqz v1, :cond_1a

    .line 350
    .line 351
    const/4 v1, 0x7

    .line 352
    invoke-virtual {v0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    iget-object v0, v0, Lh5/c;->f:Lh5/c;

    .line 357
    .line 358
    if-nez v0, :cond_1a

    .line 359
    .line 360
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 361
    .line 362
    iget-object v0, p0, Lh5/d;->U:Lh5/e;

    .line 363
    .line 364
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 365
    .line 366
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 367
    .line 368
    invoke-virtual {p0}, Lh5/d;->s()I

    .line 369
    .line 370
    .line 371
    move-result p0

    .line 372
    invoke-static {v9, v0, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 373
    .line 374
    .line 375
    iget p0, v2, Li5/g;->g:I

    .line 376
    .line 377
    invoke-static {v8, v9, p0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 378
    .line 379
    .line 380
    return-void

    .line 381
    :cond_c
    iget v0, p0, Li5/p;->d:I

    .line 382
    .line 383
    if-ne v0, v4, :cond_13

    .line 384
    .line 385
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 386
    .line 387
    iget v10, v0, Lh5/d;->s:I

    .line 388
    .line 389
    const/4 v11, 0x2

    .line 390
    if-eq v10, v11, :cond_11

    .line 391
    .line 392
    if-eq v10, v4, :cond_d

    .line 393
    .line 394
    goto/16 :goto_1

    .line 395
    .line 396
    :cond_d
    iget v10, v0, Lh5/d;->t:I

    .line 397
    .line 398
    if-ne v10, v4, :cond_10

    .line 399
    .line 400
    iput-object p0, v9, Li5/g;->a:Li5/p;

    .line 401
    .line 402
    iput-object p0, v8, Li5/g;->a:Li5/p;

    .line 403
    .line 404
    iget-object v4, v0, Lh5/d;->e:Li5/n;

    .line 405
    .line 406
    iget-object v10, v4, Li5/p;->h:Li5/g;

    .line 407
    .line 408
    iput-object p0, v10, Li5/g;->a:Li5/p;

    .line 409
    .line 410
    iget-object v4, v4, Li5/p;->i:Li5/g;

    .line 411
    .line 412
    iput-object p0, v4, Li5/g;->a:Li5/p;

    .line 413
    .line 414
    iput-object p0, v2, Li5/g;->a:Li5/p;

    .line 415
    .line 416
    invoke-virtual {v0}, Lh5/d;->z()Z

    .line 417
    .line 418
    .line 419
    move-result v0

    .line 420
    if-eqz v0, :cond_e

    .line 421
    .line 422
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 423
    .line 424
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 425
    .line 426
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 427
    .line 428
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 429
    .line 430
    .line 431
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 432
    .line 433
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 434
    .line 435
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 436
    .line 437
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 438
    .line 439
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 440
    .line 441
    .line 442
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 443
    .line 444
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 445
    .line 446
    iget-object v1, v0, Li5/p;->e:Li5/h;

    .line 447
    .line 448
    iput-object p0, v1, Li5/g;->a:Li5/p;

    .line 449
    .line 450
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 451
    .line 452
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 453
    .line 454
    .line 455
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 456
    .line 457
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 458
    .line 459
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 460
    .line 461
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 462
    .line 463
    .line 464
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 465
    .line 466
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 467
    .line 468
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 469
    .line 470
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 471
    .line 472
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 476
    .line 477
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 478
    .line 479
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 480
    .line 481
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 482
    .line 483
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 484
    .line 485
    .line 486
    goto/16 :goto_1

    .line 487
    .line 488
    :cond_e
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 489
    .line 490
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 491
    .line 492
    .line 493
    move-result v0

    .line 494
    if-eqz v0, :cond_f

    .line 495
    .line 496
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 497
    .line 498
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 499
    .line 500
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 501
    .line 502
    iget-object v0, v0, Li5/g;->l:Ljava/util/ArrayList;

    .line 503
    .line 504
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 505
    .line 506
    .line 507
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 508
    .line 509
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 510
    .line 511
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 512
    .line 513
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 514
    .line 515
    .line 516
    goto :goto_1

    .line 517
    :cond_f
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 518
    .line 519
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 520
    .line 521
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 522
    .line 523
    iget-object v0, v0, Li5/g;->l:Ljava/util/ArrayList;

    .line 524
    .line 525
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 526
    .line 527
    .line 528
    goto :goto_1

    .line 529
    :cond_10
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 530
    .line 531
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 532
    .line 533
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 537
    .line 538
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 542
    .line 543
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 544
    .line 545
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 546
    .line 547
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 548
    .line 549
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 550
    .line 551
    .line 552
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 553
    .line 554
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 555
    .line 556
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 557
    .line 558
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 559
    .line 560
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 561
    .line 562
    .line 563
    iput-boolean v6, v2, Li5/g;->b:Z

    .line 564
    .line 565
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 566
    .line 567
    .line 568
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 569
    .line 570
    .line 571
    iget-object v0, v9, Li5/g;->l:Ljava/util/ArrayList;

    .line 572
    .line 573
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    iget-object v0, v8, Li5/g;->l:Ljava/util/ArrayList;

    .line 577
    .line 578
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 579
    .line 580
    .line 581
    goto :goto_1

    .line 582
    :cond_11
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 583
    .line 584
    if-nez v0, :cond_12

    .line 585
    .line 586
    goto :goto_1

    .line 587
    :cond_12
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 588
    .line 589
    iget-object v0, v0, Li5/p;->e:Li5/h;

    .line 590
    .line 591
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 592
    .line 593
    .line 594
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 595
    .line 596
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 597
    .line 598
    .line 599
    iput-boolean v6, v2, Li5/g;->b:Z

    .line 600
    .line 601
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 602
    .line 603
    .line 604
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    :cond_13
    :goto_1
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 608
    .line 609
    iget-object v1, v0, Lh5/d;->R:[Lh5/c;

    .line 610
    .line 611
    aget-object v3, v1, v7

    .line 612
    .line 613
    iget-object v4, v3, Lh5/c;->f:Lh5/c;

    .line 614
    .line 615
    if-eqz v4, :cond_17

    .line 616
    .line 617
    aget-object v10, v1, v6

    .line 618
    .line 619
    iget-object v10, v10, Lh5/c;->f:Lh5/c;

    .line 620
    .line 621
    if-eqz v10, :cond_17

    .line 622
    .line 623
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 624
    .line 625
    .line 626
    move-result v0

    .line 627
    if-eqz v0, :cond_14

    .line 628
    .line 629
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 630
    .line 631
    iget-object v0, v0, Lh5/d;->R:[Lh5/c;

    .line 632
    .line 633
    aget-object v0, v0, v7

    .line 634
    .line 635
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 636
    .line 637
    .line 638
    move-result v0

    .line 639
    iput v0, v9, Li5/g;->f:I

    .line 640
    .line 641
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 642
    .line 643
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 644
    .line 645
    aget-object p0, p0, v6

    .line 646
    .line 647
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 648
    .line 649
    .line 650
    move-result p0

    .line 651
    neg-int p0, p0

    .line 652
    iput p0, v8, Li5/g;->f:I

    .line 653
    .line 654
    return-void

    .line 655
    :cond_14
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 656
    .line 657
    iget-object v0, v0, Lh5/d;->R:[Lh5/c;

    .line 658
    .line 659
    aget-object v0, v0, v7

    .line 660
    .line 661
    invoke-static {v0}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 662
    .line 663
    .line 664
    move-result-object v0

    .line 665
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 666
    .line 667
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 668
    .line 669
    aget-object v1, v1, v6

    .line 670
    .line 671
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 672
    .line 673
    .line 674
    move-result-object v1

    .line 675
    if-eqz v0, :cond_15

    .line 676
    .line 677
    invoke-virtual {v0, p0}, Li5/g;->b(Li5/p;)V

    .line 678
    .line 679
    .line 680
    :cond_15
    if-eqz v1, :cond_16

    .line 681
    .line 682
    invoke-virtual {v1, p0}, Li5/g;->b(Li5/p;)V

    .line 683
    .line 684
    .line 685
    :cond_16
    iput v5, p0, Li5/p;->j:I

    .line 686
    .line 687
    return-void

    .line 688
    :cond_17
    if-eqz v4, :cond_18

    .line 689
    .line 690
    invoke-static {v3}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 691
    .line 692
    .line 693
    move-result-object v0

    .line 694
    if-eqz v0, :cond_1a

    .line 695
    .line 696
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 697
    .line 698
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 699
    .line 700
    aget-object v1, v1, v7

    .line 701
    .line 702
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 703
    .line 704
    .line 705
    move-result v1

    .line 706
    invoke-static {v9, v0, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 707
    .line 708
    .line 709
    invoke-virtual {p0, v8, v9, v6, v2}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 710
    .line 711
    .line 712
    return-void

    .line 713
    :cond_18
    aget-object v1, v1, v6

    .line 714
    .line 715
    iget-object v3, v1, Lh5/c;->f:Lh5/c;

    .line 716
    .line 717
    if-eqz v3, :cond_19

    .line 718
    .line 719
    invoke-static {v1}, Li5/p;->h(Lh5/c;)Li5/g;

    .line 720
    .line 721
    .line 722
    move-result-object v0

    .line 723
    if-eqz v0, :cond_1a

    .line 724
    .line 725
    iget-object v1, p0, Li5/p;->b:Lh5/d;

    .line 726
    .line 727
    iget-object v1, v1, Lh5/d;->R:[Lh5/c;

    .line 728
    .line 729
    aget-object v1, v1, v6

    .line 730
    .line 731
    invoke-virtual {v1}, Lh5/c;->e()I

    .line 732
    .line 733
    .line 734
    move-result v1

    .line 735
    neg-int v1, v1

    .line 736
    invoke-static {v8, v0, v1}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 737
    .line 738
    .line 739
    const/4 v0, -0x1

    .line 740
    invoke-virtual {p0, v9, v8, v0, v2}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 741
    .line 742
    .line 743
    return-void

    .line 744
    :cond_19
    instance-of v1, v0, Lh5/i;

    .line 745
    .line 746
    if-nez v1, :cond_1a

    .line 747
    .line 748
    iget-object v1, v0, Lh5/d;->U:Lh5/e;

    .line 749
    .line 750
    if-eqz v1, :cond_1a

    .line 751
    .line 752
    iget-object v1, v1, Lh5/d;->d:Li5/l;

    .line 753
    .line 754
    iget-object v1, v1, Li5/p;->h:Li5/g;

    .line 755
    .line 756
    invoke-virtual {v0}, Lh5/d;->s()I

    .line 757
    .line 758
    .line 759
    move-result v0

    .line 760
    invoke-static {v9, v1, v0}, Li5/p;->b(Li5/g;Li5/g;I)V

    .line 761
    .line 762
    .line 763
    invoke-virtual {p0, v8, v9, v6, v2}, Li5/p;->c(Li5/g;Li5/g;ILi5/h;)V

    .line 764
    .line 765
    .line 766
    :cond_1a
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object v0, p0, Li5/p;->h:Li5/g;

    .line 2
    .line 3
    iget-boolean v1, v0, Li5/g;->j:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 8
    .line 9
    iget v0, v0, Li5/g;->g:I

    .line 10
    .line 11
    iput v0, p0, Lh5/d;->Z:I

    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final f()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Li5/p;->c:Li5/m;

    .line 3
    .line 4
    iget-object v0, p0, Li5/p;->h:Li5/g;

    .line 5
    .line 6
    invoke-virtual {v0}, Li5/g;->c()V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Li5/p;->i:Li5/g;

    .line 10
    .line 11
    invoke-virtual {v0}, Li5/g;->c()V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Li5/p;->e:Li5/h;

    .line 15
    .line 16
    invoke-virtual {v0}, Li5/g;->c()V

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    iput-boolean v0, p0, Li5/p;->g:Z

    .line 21
    .line 22
    return-void
.end method

.method public final k()Z
    .locals 2

    .line 1
    iget v0, p0, Li5/p;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 7
    .line 8
    iget p0, p0, Lh5/d;->s:I

    .line 9
    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public final n()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Li5/p;->g:Z

    .line 3
    .line 4
    iget-object v1, p0, Li5/p;->h:Li5/g;

    .line 5
    .line 6
    invoke-virtual {v1}, Li5/g;->c()V

    .line 7
    .line 8
    .line 9
    iput-boolean v0, v1, Li5/g;->j:Z

    .line 10
    .line 11
    iget-object v1, p0, Li5/p;->i:Li5/g;

    .line 12
    .line 13
    invoke-virtual {v1}, Li5/g;->c()V

    .line 14
    .line 15
    .line 16
    iput-boolean v0, v1, Li5/g;->j:Z

    .line 17
    .line 18
    iget-object p0, p0, Li5/p;->e:Li5/h;

    .line 19
    .line 20
    iput-boolean v0, p0, Li5/g;->j:Z

    .line 21
    .line 22
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "HorizontalRun "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 9
    .line 10
    iget-object p0, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
