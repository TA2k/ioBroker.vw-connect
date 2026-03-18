.class public final Lbb/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/ViewTreeObserver$OnPreDrawListener;
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public d:Lbb/x;

.field public e:Landroid/view/ViewGroup;


# virtual methods
.method public final onPreDraw()Z
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lbb/a0;->d:Lbb/x;

    .line 4
    .line 5
    iget-object v2, v0, Lbb/a0;->e:Landroid/view/ViewGroup;

    .line 6
    .line 7
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-virtual {v3, v0}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, v0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 15
    .line 16
    .line 17
    sget-object v3, Lbb/b0;->c:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v6, 0x1

    .line 24
    if-nez v3, :cond_0

    .line 25
    .line 26
    move v15, v6

    .line 27
    goto/16 :goto_f

    .line 28
    .line 29
    :cond_0
    invoke-static {}, Lbb/b0;->b()Landroidx/collection/f;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-virtual {v3, v2}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Ljava/util/ArrayList;

    .line 38
    .line 39
    if-nez v4, :cond_2

    .line 40
    .line 41
    new-instance v4, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v3, v2, v4}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    :cond_1
    const/4 v7, 0x0

    .line 50
    goto :goto_0

    .line 51
    :cond_2
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    if-lez v7, :cond_1

    .line 56
    .line 57
    new-instance v7, Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-direct {v7, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 60
    .line 61
    .line 62
    :goto_0
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    new-instance v4, Lbb/z;

    .line 66
    .line 67
    invoke-direct {v4, v0, v3}, Lbb/z;-><init>(Lbb/a0;Landroidx/collection/f;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v4}, Lbb/x;->a(Lbb/v;)V

    .line 71
    .line 72
    .line 73
    const/4 v0, 0x0

    .line 74
    invoke-virtual {v1, v2, v0}, Lbb/x;->i(Landroid/view/ViewGroup;Z)V

    .line 75
    .line 76
    .line 77
    if-eqz v7, :cond_3

    .line 78
    .line 79
    invoke-virtual {v7}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    if-eqz v4, :cond_3

    .line 88
    .line 89
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    check-cast v4, Lbb/x;

    .line 94
    .line 95
    invoke-virtual {v4, v2}, Lbb/x;->D(Landroid/view/View;)V

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    new-instance v3, Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 102
    .line 103
    .line 104
    iput-object v3, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 105
    .line 106
    new-instance v3, Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 109
    .line 110
    .line 111
    iput-object v3, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 112
    .line 113
    iget-object v3, v1, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 114
    .line 115
    iget-object v4, v1, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 116
    .line 117
    new-instance v7, Landroidx/collection/f;

    .line 118
    .line 119
    iget-object v8, v3, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v8, Landroidx/collection/f;

    .line 122
    .line 123
    invoke-direct {v7, v8}, Landroidx/collection/f;-><init>(Landroidx/collection/f;)V

    .line 124
    .line 125
    .line 126
    new-instance v8, Landroidx/collection/f;

    .line 127
    .line 128
    iget-object v9, v4, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v9, Landroidx/collection/f;

    .line 131
    .line 132
    invoke-direct {v8, v9}, Landroidx/collection/f;-><init>(Landroidx/collection/f;)V

    .line 133
    .line 134
    .line 135
    move v9, v0

    .line 136
    :goto_2
    iget-object v10, v1, Lbb/x;->m:[I

    .line 137
    .line 138
    array-length v11, v10

    .line 139
    if-ge v9, v11, :cond_10

    .line 140
    .line 141
    aget v10, v10, v9

    .line 142
    .line 143
    if-eq v10, v6, :cond_d

    .line 144
    .line 145
    const/4 v11, 0x2

    .line 146
    if-eq v10, v11, :cond_b

    .line 147
    .line 148
    const/4 v11, 0x3

    .line 149
    if-eq v10, v11, :cond_9

    .line 150
    .line 151
    const/4 v11, 0x4

    .line 152
    if-eq v10, v11, :cond_5

    .line 153
    .line 154
    :cond_4
    move/from16 p0, v6

    .line 155
    .line 156
    goto/16 :goto_8

    .line 157
    .line 158
    :cond_5
    iget-object v10, v3, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v10, Landroidx/collection/u;

    .line 161
    .line 162
    iget-object v11, v4, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v11, Landroidx/collection/u;

    .line 165
    .line 166
    invoke-virtual {v10}, Landroidx/collection/u;->h()I

    .line 167
    .line 168
    .line 169
    move-result v12

    .line 170
    move v13, v0

    .line 171
    :goto_3
    if-ge v13, v12, :cond_4

    .line 172
    .line 173
    invoke-virtual {v10, v13}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v14

    .line 177
    check-cast v14, Landroid/view/View;

    .line 178
    .line 179
    if-eqz v14, :cond_7

    .line 180
    .line 181
    invoke-virtual {v1, v14}, Lbb/x;->w(Landroid/view/View;)Z

    .line 182
    .line 183
    .line 184
    move-result v15

    .line 185
    if-eqz v15, :cond_7

    .line 186
    .line 187
    move v15, v6

    .line 188
    invoke-virtual {v10, v13}, Landroidx/collection/u;->d(I)J

    .line 189
    .line 190
    .line 191
    move-result-wide v5

    .line 192
    invoke-virtual {v11, v5, v6}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v5

    .line 196
    check-cast v5, Landroid/view/View;

    .line 197
    .line 198
    if-eqz v5, :cond_6

    .line 199
    .line 200
    invoke-virtual {v1, v5}, Lbb/x;->w(Landroid/view/View;)Z

    .line 201
    .line 202
    .line 203
    move-result v6

    .line 204
    if-eqz v6, :cond_6

    .line 205
    .line 206
    invoke-virtual {v7, v14}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v6

    .line 210
    check-cast v6, Lbb/f0;

    .line 211
    .line 212
    invoke-virtual {v8, v5}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v16

    .line 216
    move/from16 p0, v15

    .line 217
    .line 218
    move-object/from16 v15, v16

    .line 219
    .line 220
    check-cast v15, Lbb/f0;

    .line 221
    .line 222
    if-eqz v6, :cond_8

    .line 223
    .line 224
    if-eqz v15, :cond_8

    .line 225
    .line 226
    iget-object v0, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 227
    .line 228
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    iget-object v0, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 232
    .line 233
    invoke-virtual {v0, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    invoke-virtual {v7, v14}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    invoke-virtual {v8, v5}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    goto :goto_4

    .line 243
    :cond_6
    move/from16 p0, v15

    .line 244
    .line 245
    goto :goto_4

    .line 246
    :cond_7
    move/from16 p0, v6

    .line 247
    .line 248
    :cond_8
    :goto_4
    add-int/lit8 v13, v13, 0x1

    .line 249
    .line 250
    const/4 v0, 0x0

    .line 251
    move/from16 v6, p0

    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_9
    move/from16 p0, v6

    .line 255
    .line 256
    iget-object v0, v3, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast v0, Landroid/util/SparseArray;

    .line 259
    .line 260
    iget-object v5, v4, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast v5, Landroid/util/SparseArray;

    .line 263
    .line 264
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 265
    .line 266
    .line 267
    move-result v6

    .line 268
    const/4 v10, 0x0

    .line 269
    :goto_5
    if-ge v10, v6, :cond_f

    .line 270
    .line 271
    invoke-virtual {v0, v10}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v11

    .line 275
    check-cast v11, Landroid/view/View;

    .line 276
    .line 277
    if-eqz v11, :cond_a

    .line 278
    .line 279
    invoke-virtual {v1, v11}, Lbb/x;->w(Landroid/view/View;)Z

    .line 280
    .line 281
    .line 282
    move-result v12

    .line 283
    if-eqz v12, :cond_a

    .line 284
    .line 285
    invoke-virtual {v0, v10}, Landroid/util/SparseArray;->keyAt(I)I

    .line 286
    .line 287
    .line 288
    move-result v12

    .line 289
    invoke-virtual {v5, v12}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v12

    .line 293
    check-cast v12, Landroid/view/View;

    .line 294
    .line 295
    if-eqz v12, :cond_a

    .line 296
    .line 297
    invoke-virtual {v1, v12}, Lbb/x;->w(Landroid/view/View;)Z

    .line 298
    .line 299
    .line 300
    move-result v13

    .line 301
    if-eqz v13, :cond_a

    .line 302
    .line 303
    invoke-virtual {v7, v11}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v13

    .line 307
    check-cast v13, Lbb/f0;

    .line 308
    .line 309
    invoke-virtual {v8, v12}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v14

    .line 313
    check-cast v14, Lbb/f0;

    .line 314
    .line 315
    if-eqz v13, :cond_a

    .line 316
    .line 317
    if-eqz v14, :cond_a

    .line 318
    .line 319
    iget-object v15, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 320
    .line 321
    invoke-virtual {v15, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 322
    .line 323
    .line 324
    iget-object v13, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 325
    .line 326
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    invoke-virtual {v7, v11}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    invoke-virtual {v8, v12}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    :cond_a
    add-int/lit8 v10, v10, 0x1

    .line 336
    .line 337
    goto :goto_5

    .line 338
    :cond_b
    move/from16 p0, v6

    .line 339
    .line 340
    iget-object v0, v3, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v0, Landroidx/collection/f;

    .line 343
    .line 344
    iget-object v5, v4, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v5, Landroidx/collection/f;

    .line 347
    .line 348
    invoke-virtual {v0}, Landroidx/collection/a1;->size()I

    .line 349
    .line 350
    .line 351
    move-result v6

    .line 352
    const/4 v10, 0x0

    .line 353
    :goto_6
    if-ge v10, v6, :cond_f

    .line 354
    .line 355
    invoke-virtual {v0, v10}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v11

    .line 359
    check-cast v11, Landroid/view/View;

    .line 360
    .line 361
    if-eqz v11, :cond_c

    .line 362
    .line 363
    invoke-virtual {v1, v11}, Lbb/x;->w(Landroid/view/View;)Z

    .line 364
    .line 365
    .line 366
    move-result v12

    .line 367
    if-eqz v12, :cond_c

    .line 368
    .line 369
    invoke-virtual {v0, v10}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v12

    .line 373
    invoke-virtual {v5, v12}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v12

    .line 377
    check-cast v12, Landroid/view/View;

    .line 378
    .line 379
    if-eqz v12, :cond_c

    .line 380
    .line 381
    invoke-virtual {v1, v12}, Lbb/x;->w(Landroid/view/View;)Z

    .line 382
    .line 383
    .line 384
    move-result v13

    .line 385
    if-eqz v13, :cond_c

    .line 386
    .line 387
    invoke-virtual {v7, v11}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v13

    .line 391
    check-cast v13, Lbb/f0;

    .line 392
    .line 393
    invoke-virtual {v8, v12}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object v14

    .line 397
    check-cast v14, Lbb/f0;

    .line 398
    .line 399
    if-eqz v13, :cond_c

    .line 400
    .line 401
    if-eqz v14, :cond_c

    .line 402
    .line 403
    iget-object v15, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 404
    .line 405
    invoke-virtual {v15, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 406
    .line 407
    .line 408
    iget-object v13, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 409
    .line 410
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 411
    .line 412
    .line 413
    invoke-virtual {v7, v11}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    invoke-virtual {v8, v12}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    :cond_c
    add-int/lit8 v10, v10, 0x1

    .line 420
    .line 421
    goto :goto_6

    .line 422
    :cond_d
    move/from16 p0, v6

    .line 423
    .line 424
    invoke-virtual {v7}, Landroidx/collection/a1;->size()I

    .line 425
    .line 426
    .line 427
    move-result v0

    .line 428
    add-int/lit8 v0, v0, -0x1

    .line 429
    .line 430
    :goto_7
    if-ltz v0, :cond_f

    .line 431
    .line 432
    invoke-virtual {v7, v0}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v5

    .line 436
    check-cast v5, Landroid/view/View;

    .line 437
    .line 438
    if-eqz v5, :cond_e

    .line 439
    .line 440
    invoke-virtual {v1, v5}, Lbb/x;->w(Landroid/view/View;)Z

    .line 441
    .line 442
    .line 443
    move-result v6

    .line 444
    if-eqz v6, :cond_e

    .line 445
    .line 446
    invoke-virtual {v8, v5}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v5

    .line 450
    check-cast v5, Lbb/f0;

    .line 451
    .line 452
    if-eqz v5, :cond_e

    .line 453
    .line 454
    iget-object v6, v5, Lbb/f0;->b:Landroid/view/View;

    .line 455
    .line 456
    invoke-virtual {v1, v6}, Lbb/x;->w(Landroid/view/View;)Z

    .line 457
    .line 458
    .line 459
    move-result v6

    .line 460
    if-eqz v6, :cond_e

    .line 461
    .line 462
    invoke-virtual {v7, v0}, Landroidx/collection/a1;->removeAt(I)Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v6

    .line 466
    check-cast v6, Lbb/f0;

    .line 467
    .line 468
    iget-object v10, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 469
    .line 470
    invoke-virtual {v10, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    iget-object v6, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 474
    .line 475
    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    :cond_e
    add-int/lit8 v0, v0, -0x1

    .line 479
    .line 480
    goto :goto_7

    .line 481
    :cond_f
    :goto_8
    add-int/lit8 v9, v9, 0x1

    .line 482
    .line 483
    const/4 v0, 0x0

    .line 484
    move/from16 v6, p0

    .line 485
    .line 486
    goto/16 :goto_2

    .line 487
    .line 488
    :cond_10
    move/from16 p0, v6

    .line 489
    .line 490
    const/4 v0, 0x0

    .line 491
    :goto_9
    invoke-virtual {v7}, Landroidx/collection/a1;->size()I

    .line 492
    .line 493
    .line 494
    move-result v3

    .line 495
    if-ge v0, v3, :cond_12

    .line 496
    .line 497
    invoke-virtual {v7, v0}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 498
    .line 499
    .line 500
    move-result-object v3

    .line 501
    check-cast v3, Lbb/f0;

    .line 502
    .line 503
    iget-object v4, v3, Lbb/f0;->b:Landroid/view/View;

    .line 504
    .line 505
    invoke-virtual {v1, v4}, Lbb/x;->w(Landroid/view/View;)Z

    .line 506
    .line 507
    .line 508
    move-result v4

    .line 509
    if-eqz v4, :cond_11

    .line 510
    .line 511
    iget-object v4, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 512
    .line 513
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 514
    .line 515
    .line 516
    iget-object v3, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 517
    .line 518
    const/4 v4, 0x0

    .line 519
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 520
    .line 521
    .line 522
    :cond_11
    add-int/lit8 v0, v0, 0x1

    .line 523
    .line 524
    goto :goto_9

    .line 525
    :cond_12
    const/4 v0, 0x0

    .line 526
    :goto_a
    invoke-virtual {v8}, Landroidx/collection/a1;->size()I

    .line 527
    .line 528
    .line 529
    move-result v3

    .line 530
    if-ge v0, v3, :cond_14

    .line 531
    .line 532
    invoke-virtual {v8, v0}, Landroidx/collection/a1;->valueAt(I)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v3

    .line 536
    check-cast v3, Lbb/f0;

    .line 537
    .line 538
    iget-object v4, v3, Lbb/f0;->b:Landroid/view/View;

    .line 539
    .line 540
    invoke-virtual {v1, v4}, Lbb/x;->w(Landroid/view/View;)Z

    .line 541
    .line 542
    .line 543
    move-result v4

    .line 544
    if-eqz v4, :cond_13

    .line 545
    .line 546
    iget-object v4, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 547
    .line 548
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    iget-object v3, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 552
    .line 553
    const/4 v4, 0x0

    .line 554
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 555
    .line 556
    .line 557
    goto :goto_b

    .line 558
    :cond_13
    const/4 v4, 0x0

    .line 559
    :goto_b
    add-int/lit8 v0, v0, 0x1

    .line 560
    .line 561
    goto :goto_a

    .line 562
    :cond_14
    invoke-static {}, Lbb/x;->q()Landroidx/collection/f;

    .line 563
    .line 564
    .line 565
    move-result-object v0

    .line 566
    invoke-virtual {v0}, Landroidx/collection/a1;->size()I

    .line 567
    .line 568
    .line 569
    move-result v3

    .line 570
    invoke-virtual {v2}, Landroid/view/View;->getWindowId()Landroid/view/WindowId;

    .line 571
    .line 572
    .line 573
    move-result-object v4

    .line 574
    add-int/lit8 v3, v3, -0x1

    .line 575
    .line 576
    :goto_c
    if-ltz v3, :cond_1c

    .line 577
    .line 578
    invoke-virtual {v0, v3}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v5

    .line 582
    check-cast v5, Landroid/animation/Animator;

    .line 583
    .line 584
    if-eqz v5, :cond_17

    .line 585
    .line 586
    invoke-virtual {v0, v5}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    move-result-object v6

    .line 590
    check-cast v6, Lbb/r;

    .line 591
    .line 592
    if-eqz v6, :cond_17

    .line 593
    .line 594
    iget-object v7, v6, Lbb/r;->e:Lbb/x;

    .line 595
    .line 596
    iget-object v8, v6, Lbb/r;->a:Landroid/view/View;

    .line 597
    .line 598
    if-eqz v8, :cond_17

    .line 599
    .line 600
    iget-object v9, v6, Lbb/r;->d:Landroid/view/WindowId;

    .line 601
    .line 602
    invoke-virtual {v4, v9}, Landroid/view/WindowId;->equals(Ljava/lang/Object;)Z

    .line 603
    .line 604
    .line 605
    move-result v9

    .line 606
    if-eqz v9, :cond_17

    .line 607
    .line 608
    iget-object v6, v6, Lbb/r;->c:Lbb/f0;

    .line 609
    .line 610
    move/from16 v15, p0

    .line 611
    .line 612
    invoke-virtual {v1, v8, v15}, Lbb/x;->s(Landroid/view/View;Z)Lbb/f0;

    .line 613
    .line 614
    .line 615
    move-result-object v9

    .line 616
    invoke-virtual {v1, v8, v15}, Lbb/x;->o(Landroid/view/View;Z)Lbb/f0;

    .line 617
    .line 618
    .line 619
    move-result-object v10

    .line 620
    if-nez v9, :cond_15

    .line 621
    .line 622
    if-nez v10, :cond_15

    .line 623
    .line 624
    iget-object v10, v1, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 625
    .line 626
    iget-object v10, v10, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 627
    .line 628
    check-cast v10, Landroidx/collection/f;

    .line 629
    .line 630
    invoke-virtual {v10, v8}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 631
    .line 632
    .line 633
    move-result-object v8

    .line 634
    move-object v10, v8

    .line 635
    check-cast v10, Lbb/f0;

    .line 636
    .line 637
    :cond_15
    if-nez v9, :cond_16

    .line 638
    .line 639
    if-eqz v10, :cond_17

    .line 640
    .line 641
    :cond_16
    invoke-virtual {v7, v6, v10}, Lbb/x;->v(Lbb/f0;Lbb/f0;)Z

    .line 642
    .line 643
    .line 644
    move-result v6

    .line 645
    if-eqz v6, :cond_17

    .line 646
    .line 647
    invoke-virtual {v7}, Lbb/x;->p()Lbb/x;

    .line 648
    .line 649
    .line 650
    move-result-object v6

    .line 651
    iget-object v8, v7, Lbb/x;->q:Ljava/util/ArrayList;

    .line 652
    .line 653
    iget-object v6, v6, Lbb/x;->B:Lbb/u;

    .line 654
    .line 655
    if-eqz v6, :cond_18

    .line 656
    .line 657
    invoke-virtual {v5}, Landroid/animation/Animator;->cancel()V

    .line 658
    .line 659
    .line 660
    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 661
    .line 662
    .line 663
    invoke-virtual {v0, v5}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 664
    .line 665
    .line 666
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 667
    .line 668
    .line 669
    move-result v5

    .line 670
    if-nez v5, :cond_17

    .line 671
    .line 672
    sget-object v5, Lbb/w;->j0:Lb8/b;

    .line 673
    .line 674
    const/4 v6, 0x0

    .line 675
    invoke-virtual {v7, v7, v5, v6}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 676
    .line 677
    .line 678
    iget-boolean v5, v7, Lbb/x;->u:Z

    .line 679
    .line 680
    if-nez v5, :cond_1b

    .line 681
    .line 682
    const/4 v15, 0x1

    .line 683
    iput-boolean v15, v7, Lbb/x;->u:Z

    .line 684
    .line 685
    sget-object v5, Lbb/w;->i0:Lb8/b;

    .line 686
    .line 687
    invoke-virtual {v7, v7, v5, v6}, Lbb/x;->y(Lbb/x;Lbb/w;Z)V

    .line 688
    .line 689
    .line 690
    goto :goto_e

    .line 691
    :cond_17
    const/4 v6, 0x0

    .line 692
    goto :goto_e

    .line 693
    :cond_18
    const/4 v6, 0x0

    .line 694
    invoke-virtual {v5}, Landroid/animation/Animator;->isRunning()Z

    .line 695
    .line 696
    .line 697
    move-result v7

    .line 698
    if-nez v7, :cond_1a

    .line 699
    .line 700
    invoke-virtual {v5}, Landroid/animation/Animator;->isStarted()Z

    .line 701
    .line 702
    .line 703
    move-result v7

    .line 704
    if-eqz v7, :cond_19

    .line 705
    .line 706
    goto :goto_d

    .line 707
    :cond_19
    invoke-virtual {v0, v5}, Landroidx/collection/f;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 708
    .line 709
    .line 710
    goto :goto_e

    .line 711
    :cond_1a
    :goto_d
    invoke-virtual {v5}, Landroid/animation/Animator;->cancel()V

    .line 712
    .line 713
    .line 714
    :cond_1b
    :goto_e
    add-int/lit8 v3, v3, -0x1

    .line 715
    .line 716
    const/16 p0, 0x1

    .line 717
    .line 718
    goto/16 :goto_c

    .line 719
    .line 720
    :cond_1c
    iget-object v0, v1, Lbb/x;->j:Lcom/google/firebase/messaging/w;

    .line 721
    .line 722
    iget-object v3, v1, Lbb/x;->k:Lcom/google/firebase/messaging/w;

    .line 723
    .line 724
    iget-object v4, v1, Lbb/x;->n:Ljava/util/ArrayList;

    .line 725
    .line 726
    iget-object v5, v1, Lbb/x;->o:Ljava/util/ArrayList;

    .line 727
    .line 728
    move-object/from16 v17, v2

    .line 729
    .line 730
    move-object v2, v0

    .line 731
    move-object v0, v1

    .line 732
    move-object/from16 v1, v17

    .line 733
    .line 734
    invoke-virtual/range {v0 .. v5}, Lbb/x;->m(Landroid/view/ViewGroup;Lcom/google/firebase/messaging/w;Lcom/google/firebase/messaging/w;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 735
    .line 736
    .line 737
    iget-object v1, v0, Lbb/x;->B:Lbb/u;

    .line 738
    .line 739
    if-nez v1, :cond_1d

    .line 740
    .line 741
    invoke-virtual {v0}, Lbb/x;->E()V

    .line 742
    .line 743
    .line 744
    const/4 v15, 0x1

    .line 745
    return v15

    .line 746
    :cond_1d
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 747
    .line 748
    const/16 v2, 0x22

    .line 749
    .line 750
    if-lt v1, v2, :cond_1f

    .line 751
    .line 752
    invoke-virtual {v0}, Lbb/x;->A()V

    .line 753
    .line 754
    .line 755
    iget-object v1, v0, Lbb/x;->B:Lbb/u;

    .line 756
    .line 757
    iget-object v2, v1, Lbb/u;->g:Lbb/d0;

    .line 758
    .line 759
    iget-wide v3, v2, Lbb/x;->A:J

    .line 760
    .line 761
    const-wide/16 v5, 0x0

    .line 762
    .line 763
    cmp-long v3, v3, v5

    .line 764
    .line 765
    if-nez v3, :cond_1e

    .line 766
    .line 767
    const-wide/16 v5, 0x1

    .line 768
    .line 769
    :cond_1e
    iget-wide v3, v1, Lbb/u;->a:J

    .line 770
    .line 771
    invoke-virtual {v2, v5, v6, v3, v4}, Lbb/d0;->F(JJ)V

    .line 772
    .line 773
    .line 774
    iput-wide v5, v1, Lbb/u;->a:J

    .line 775
    .line 776
    iget-object v0, v0, Lbb/x;->B:Lbb/u;

    .line 777
    .line 778
    const/4 v15, 0x1

    .line 779
    iput-boolean v15, v0, Lbb/u;->b:Z

    .line 780
    .line 781
    return v15

    .line 782
    :cond_1f
    const/4 v15, 0x1

    .line 783
    :goto_f
    return v15
.end method

.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lbb/a0;->e:Landroid/view/ViewGroup;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p0}, Landroid/view/ViewTreeObserver;->removeOnPreDrawListener(Landroid/view/ViewTreeObserver$OnPreDrawListener;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 11
    .line 12
    .line 13
    sget-object v0, Lbb/b0;->c:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lbb/b0;->b()Landroidx/collection/f;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0, p1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Ljava/util/ArrayList;

    .line 27
    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-lez v1, :cond_0

    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_0

    .line 45
    .line 46
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    check-cast v1, Lbb/x;

    .line 51
    .line 52
    invoke-virtual {v1, p1}, Lbb/x;->D(Landroid/view/View;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    iget-object p0, p0, Lbb/a0;->d:Lbb/x;

    .line 57
    .line 58
    const/4 p1, 0x1

    .line 59
    invoke-virtual {p0, p1}, Lbb/x;->j(Z)V

    .line 60
    .line 61
    .line 62
    return-void
.end method
