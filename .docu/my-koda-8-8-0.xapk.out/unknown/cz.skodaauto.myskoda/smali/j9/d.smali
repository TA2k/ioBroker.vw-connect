.class public final synthetic Lj9/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/r;
.implements Lw7/f;
.implements Lb0/j1;
.implements Ll4/d0;
.implements Lgr/e;
.implements Lp/a;
.implements Laq/b;
.implements Laq/f;
.implements Lno/nordicsemi/android/ble/t;
.implements Lgs/e;
.implements Lon/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lj9/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lss/b;)V
    .locals 0

    .line 2
    const/16 p1, 0xa

    iput p1, p0, Lj9/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Ljava/util/concurrent/ExecutorService;

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/concurrent/ExecutorService;->shutdown()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v0, v0, Lj9/d;->d:I

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    const/4 v2, 0x3

    .line 7
    const/4 v3, 0x2

    .line 8
    const/4 v7, 0x0

    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v0, p1

    .line 13
    .line 14
    check-cast v0, Ljava/util/List;

    .line 15
    .line 16
    if-eqz v0, :cond_6

    .line 17
    .line 18
    check-cast v0, Ljava/lang/Iterable;

    .line 19
    .line 20
    new-instance v1, Ljava/util/ArrayList;

    .line 21
    .line 22
    const/16 v2, 0xa

    .line 23
    .line 24
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_5

    .line 40
    .line 41
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Lmb/n;

    .line 46
    .line 47
    iget-object v3, v2, Lmb/n;->q:Ljava/util/List;

    .line 48
    .line 49
    iget-object v11, v2, Lmb/n;->b:Leb/h0;

    .line 50
    .line 51
    move-object v9, v3

    .line 52
    check-cast v9, Ljava/util/Collection;

    .line 53
    .line 54
    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    .line 55
    .line 56
    .line 57
    move-result v9

    .line 58
    if-nez v9, :cond_0

    .line 59
    .line 60
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    check-cast v3, Leb/h;

    .line 65
    .line 66
    :goto_1
    move-object v14, v3

    .line 67
    goto :goto_2

    .line 68
    :cond_0
    sget-object v3, Leb/h;->b:Leb/h;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :goto_2
    new-instance v9, Leb/i0;

    .line 72
    .line 73
    iget-object v3, v2, Lmb/n;->a:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v3}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 76
    .line 77
    .line 78
    move-result-object v10

    .line 79
    const-string v3, "fromString(...)"

    .line 80
    .line 81
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    new-instance v12, Ljava/util/HashSet;

    .line 85
    .line 86
    iget-object v3, v2, Lmb/n;->p:Ljava/util/List;

    .line 87
    .line 88
    check-cast v3, Ljava/util/Collection;

    .line 89
    .line 90
    invoke-direct {v12, v3}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 91
    .line 92
    .line 93
    iget-object v13, v2, Lmb/n;->c:Leb/h;

    .line 94
    .line 95
    iget v15, v2, Lmb/n;->h:I

    .line 96
    .line 97
    iget v3, v2, Lmb/n;->m:I

    .line 98
    .line 99
    const-wide/16 v32, 0x0

    .line 100
    .line 101
    iget-object v4, v2, Lmb/n;->g:Leb/e;

    .line 102
    .line 103
    move-object/from16 p1, v9

    .line 104
    .line 105
    iget-wide v8, v2, Lmb/n;->d:J

    .line 106
    .line 107
    iget-wide v6, v2, Lmb/n;->e:J

    .line 108
    .line 109
    cmp-long v16, v6, v32

    .line 110
    .line 111
    if-eqz v16, :cond_1

    .line 112
    .line 113
    new-instance v5, Leb/g0;

    .line 114
    .line 115
    move/from16 v34, v3

    .line 116
    .line 117
    move-object/from16 v35, v4

    .line 118
    .line 119
    iget-wide v3, v2, Lmb/n;->f:J

    .line 120
    .line 121
    invoke-direct {v5, v6, v7, v3, v4}, Leb/g0;-><init>(JJ)V

    .line 122
    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_1
    move/from16 v34, v3

    .line 126
    .line 127
    move-object/from16 v35, v4

    .line 128
    .line 129
    const/4 v5, 0x0

    .line 130
    :goto_3
    sget-object v3, Leb/h0;->d:Leb/h0;

    .line 131
    .line 132
    if-ne v11, v3, :cond_4

    .line 133
    .line 134
    sget-object v4, Lmb/o;->z:Ljava/lang/String;

    .line 135
    .line 136
    if-ne v11, v3, :cond_2

    .line 137
    .line 138
    if-lez v15, :cond_2

    .line 139
    .line 140
    move/from16 v3, v16

    .line 141
    .line 142
    move/from16 v16, v15

    .line 143
    .line 144
    const/4 v15, 0x1

    .line 145
    goto :goto_4

    .line 146
    :cond_2
    move/from16 v3, v16

    .line 147
    .line 148
    move/from16 v16, v15

    .line 149
    .line 150
    const/4 v15, 0x0

    .line 151
    :goto_4
    iget-object v4, v2, Lmb/n;->i:Leb/a;

    .line 152
    .line 153
    move/from16 v17, v3

    .line 154
    .line 155
    move-object/from16 v18, v4

    .line 156
    .line 157
    iget-wide v3, v2, Lmb/n;->j:J

    .line 158
    .line 159
    move-wide/from16 v19, v3

    .line 160
    .line 161
    iget-wide v3, v2, Lmb/n;->k:J

    .line 162
    .line 163
    move-object/from16 v36, v0

    .line 164
    .line 165
    iget v0, v2, Lmb/n;->l:I

    .line 166
    .line 167
    if-eqz v17, :cond_3

    .line 168
    .line 169
    const/16 v23, 0x1

    .line 170
    .line 171
    :goto_5
    move-wide/from16 v21, v3

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_3
    const/16 v23, 0x0

    .line 175
    .line 176
    goto :goto_5

    .line 177
    :goto_6
    iget-wide v3, v2, Lmb/n;->f:J

    .line 178
    .line 179
    move-wide/from16 v26, v3

    .line 180
    .line 181
    iget-wide v3, v2, Lmb/n;->n:J

    .line 182
    .line 183
    move-wide/from16 v30, v3

    .line 184
    .line 185
    move-wide/from16 v28, v6

    .line 186
    .line 187
    move-wide/from16 v24, v8

    .line 188
    .line 189
    move-object/from16 v17, v18

    .line 190
    .line 191
    move-wide/from16 v18, v19

    .line 192
    .line 193
    move-wide/from16 v20, v21

    .line 194
    .line 195
    move/from16 v22, v0

    .line 196
    .line 197
    invoke-static/range {v15 .. v31}, Ljp/x0;->a(ZILeb/a;JJIZJJJJ)J

    .line 198
    .line 199
    .line 200
    move-result-wide v3

    .line 201
    move-wide/from16 v18, v24

    .line 202
    .line 203
    :goto_7
    move-wide/from16 v21, v3

    .line 204
    .line 205
    goto :goto_8

    .line 206
    :cond_4
    move-object/from16 v36, v0

    .line 207
    .line 208
    move-wide/from16 v18, v8

    .line 209
    .line 210
    move/from16 v16, v15

    .line 211
    .line 212
    const-wide v3, 0x7fffffffffffffffL

    .line 213
    .line 214
    .line 215
    .line 216
    .line 217
    goto :goto_7

    .line 218
    :goto_8
    iget v0, v2, Lmb/n;->o:I

    .line 219
    .line 220
    move-object/from16 v9, p1

    .line 221
    .line 222
    move/from16 v23, v0

    .line 223
    .line 224
    move-object/from16 v20, v5

    .line 225
    .line 226
    move/from16 v15, v16

    .line 227
    .line 228
    move/from16 v16, v34

    .line 229
    .line 230
    move-object/from16 v17, v35

    .line 231
    .line 232
    invoke-direct/range {v9 .. v23}, Leb/i0;-><init>(Ljava/util/UUID;Leb/h0;Ljava/util/HashSet;Leb/h;Leb/h;IILeb/e;JLeb/g0;JI)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    move-object/from16 v0, v36

    .line 239
    .line 240
    const/4 v7, 0x0

    .line 241
    goto/16 :goto_0

    .line 242
    .line 243
    :cond_5
    move-object v8, v1

    .line 244
    goto :goto_9

    .line 245
    :cond_6
    const/4 v8, 0x0

    .line 246
    :goto_9
    return-object v8

    .line 247
    :pswitch_0
    const-wide/16 v32, 0x0

    .line 248
    .line 249
    move-object/from16 v0, p1

    .line 250
    .line 251
    check-cast v0, Ll9/a;

    .line 252
    .line 253
    iget-wide v0, v0, Ll9/a;->b:J

    .line 254
    .line 255
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 256
    .line 257
    .line 258
    .line 259
    .line 260
    cmp-long v2, v0, v2

    .line 261
    .line 262
    if-nez v2, :cond_7

    .line 263
    .line 264
    move-wide/from16 v4, v32

    .line 265
    .line 266
    goto :goto_a

    .line 267
    :cond_7
    move-wide v4, v0

    .line 268
    :goto_a
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    return-object v0

    .line 273
    :pswitch_1
    move-object/from16 v0, p1

    .line 274
    .line 275
    check-cast v0, Lv7/b;

    .line 276
    .line 277
    iget-object v4, v0, Lv7/b;->d:Landroid/graphics/Bitmap;

    .line 278
    .line 279
    new-instance v6, Landroid/os/Bundle;

    .line 280
    .line 281
    invoke-direct {v6}, Landroid/os/Bundle;-><init>()V

    .line 282
    .line 283
    .line 284
    iget-object v5, v0, Lv7/b;->a:Ljava/lang/CharSequence;

    .line 285
    .line 286
    if-eqz v5, :cond_c

    .line 287
    .line 288
    sget-object v7, Lv7/b;->s:Ljava/lang/String;

    .line 289
    .line 290
    invoke-virtual {v6, v7, v5}, Landroid/os/Bundle;->putCharSequence(Ljava/lang/String;Ljava/lang/CharSequence;)V

    .line 291
    .line 292
    .line 293
    instance-of v7, v5, Landroid/text/Spanned;

    .line 294
    .line 295
    if-eqz v7, :cond_c

    .line 296
    .line 297
    move-object v7, v5

    .line 298
    check-cast v7, Landroid/text/Spanned;

    .line 299
    .line 300
    sget-object v5, Lv7/d;->a:Ljava/lang/String;

    .line 301
    .line 302
    new-instance v8, Ljava/util/ArrayList;

    .line 303
    .line 304
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 305
    .line 306
    .line 307
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 308
    .line 309
    .line 310
    move-result v5

    .line 311
    const-class v9, Lv7/g;

    .line 312
    .line 313
    const/4 v10, 0x0

    .line 314
    invoke-interface {v7, v10, v5, v9}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v5

    .line 318
    move-object v9, v5

    .line 319
    check-cast v9, [Lv7/g;

    .line 320
    .line 321
    array-length v10, v9

    .line 322
    const/4 v11, 0x0

    .line 323
    :goto_b
    if-ge v11, v10, :cond_8

    .line 324
    .line 325
    aget-object v5, v9, v11

    .line 326
    .line 327
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 328
    .line 329
    .line 330
    new-instance v12, Landroid/os/Bundle;

    .line 331
    .line 332
    invoke-direct {v12}, Landroid/os/Bundle;-><init>()V

    .line 333
    .line 334
    .line 335
    sget-object v13, Lv7/g;->c:Ljava/lang/String;

    .line 336
    .line 337
    iget-object v14, v5, Lv7/g;->a:Ljava/lang/String;

    .line 338
    .line 339
    invoke-virtual {v12, v13, v14}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    sget-object v13, Lv7/g;->d:Ljava/lang/String;

    .line 343
    .line 344
    iget v14, v5, Lv7/g;->b:I

    .line 345
    .line 346
    invoke-virtual {v12, v13, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 347
    .line 348
    .line 349
    const/4 v13, 0x1

    .line 350
    invoke-static {v7, v5, v13, v12}, Lv7/d;->a(Landroid/text/Spanned;Ljava/lang/Object;ILandroid/os/Bundle;)Landroid/os/Bundle;

    .line 351
    .line 352
    .line 353
    move-result-object v12

    .line 354
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    add-int/lit8 v11, v11, 0x1

    .line 358
    .line 359
    goto :goto_b

    .line 360
    :cond_8
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 361
    .line 362
    .line 363
    move-result v5

    .line 364
    const-class v9, Lv7/h;

    .line 365
    .line 366
    const/4 v10, 0x0

    .line 367
    invoke-interface {v7, v10, v5, v9}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object v5

    .line 371
    check-cast v5, [Lv7/h;

    .line 372
    .line 373
    array-length v9, v5

    .line 374
    const/4 v10, 0x0

    .line 375
    :goto_c
    if-ge v10, v9, :cond_9

    .line 376
    .line 377
    aget-object v11, v5, v10

    .line 378
    .line 379
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    new-instance v12, Landroid/os/Bundle;

    .line 383
    .line 384
    invoke-direct {v12}, Landroid/os/Bundle;-><init>()V

    .line 385
    .line 386
    .line 387
    sget-object v13, Lv7/h;->d:Ljava/lang/String;

    .line 388
    .line 389
    iget v14, v11, Lv7/h;->a:I

    .line 390
    .line 391
    invoke-virtual {v12, v13, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 392
    .line 393
    .line 394
    sget-object v13, Lv7/h;->e:Ljava/lang/String;

    .line 395
    .line 396
    iget v14, v11, Lv7/h;->b:I

    .line 397
    .line 398
    invoke-virtual {v12, v13, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 399
    .line 400
    .line 401
    sget-object v13, Lv7/h;->f:Ljava/lang/String;

    .line 402
    .line 403
    iget v14, v11, Lv7/h;->c:I

    .line 404
    .line 405
    invoke-virtual {v12, v13, v14}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 406
    .line 407
    .line 408
    invoke-static {v7, v11, v3, v12}, Lv7/d;->a(Landroid/text/Spanned;Ljava/lang/Object;ILandroid/os/Bundle;)Landroid/os/Bundle;

    .line 409
    .line 410
    .line 411
    move-result-object v11

    .line 412
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 413
    .line 414
    .line 415
    add-int/lit8 v10, v10, 0x1

    .line 416
    .line 417
    goto :goto_c

    .line 418
    :cond_9
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 419
    .line 420
    .line 421
    move-result v3

    .line 422
    const-class v5, Lv7/e;

    .line 423
    .line 424
    const/4 v10, 0x0

    .line 425
    invoke-interface {v7, v10, v3, v5}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v3

    .line 429
    check-cast v3, [Lv7/e;

    .line 430
    .line 431
    array-length v5, v3

    .line 432
    const/4 v9, 0x0

    .line 433
    :goto_d
    if-ge v9, v5, :cond_a

    .line 434
    .line 435
    aget-object v10, v3, v9

    .line 436
    .line 437
    const/4 v11, 0x0

    .line 438
    invoke-static {v7, v10, v2, v11}, Lv7/d;->a(Landroid/text/Spanned;Ljava/lang/Object;ILandroid/os/Bundle;)Landroid/os/Bundle;

    .line 439
    .line 440
    .line 441
    move-result-object v10

    .line 442
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 443
    .line 444
    .line 445
    add-int/lit8 v9, v9, 0x1

    .line 446
    .line 447
    goto :goto_d

    .line 448
    :cond_a
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 449
    .line 450
    .line 451
    move-result v2

    .line 452
    const-class v3, Lv7/i;

    .line 453
    .line 454
    const/4 v10, 0x0

    .line 455
    invoke-interface {v7, v10, v2, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    check-cast v2, [Lv7/i;

    .line 460
    .line 461
    array-length v3, v2

    .line 462
    const/4 v5, 0x0

    .line 463
    :goto_e
    if-ge v5, v3, :cond_b

    .line 464
    .line 465
    aget-object v9, v2, v5

    .line 466
    .line 467
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 468
    .line 469
    .line 470
    new-instance v10, Landroid/os/Bundle;

    .line 471
    .line 472
    invoke-direct {v10}, Landroid/os/Bundle;-><init>()V

    .line 473
    .line 474
    .line 475
    sget-object v11, Lv7/i;->b:Ljava/lang/String;

    .line 476
    .line 477
    iget-object v12, v9, Lv7/i;->a:Ljava/lang/String;

    .line 478
    .line 479
    invoke-virtual {v10, v11, v12}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 480
    .line 481
    .line 482
    invoke-static {v7, v9, v1, v10}, Lv7/d;->a(Landroid/text/Spanned;Ljava/lang/Object;ILandroid/os/Bundle;)Landroid/os/Bundle;

    .line 483
    .line 484
    .line 485
    move-result-object v9

    .line 486
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 487
    .line 488
    .line 489
    add-int/lit8 v5, v5, 0x1

    .line 490
    .line 491
    goto :goto_e

    .line 492
    :cond_b
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 493
    .line 494
    .line 495
    move-result v1

    .line 496
    if-nez v1, :cond_c

    .line 497
    .line 498
    sget-object v1, Lv7/b;->t:Ljava/lang/String;

    .line 499
    .line 500
    invoke-virtual {v6, v1, v8}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 501
    .line 502
    .line 503
    :cond_c
    sget-object v1, Lv7/b;->u:Ljava/lang/String;

    .line 504
    .line 505
    iget-object v2, v0, Lv7/b;->b:Landroid/text/Layout$Alignment;

    .line 506
    .line 507
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    .line 508
    .line 509
    .line 510
    sget-object v1, Lv7/b;->v:Ljava/lang/String;

    .line 511
    .line 512
    iget-object v2, v0, Lv7/b;->c:Landroid/text/Layout$Alignment;

    .line 513
    .line 514
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putSerializable(Ljava/lang/String;Ljava/io/Serializable;)V

    .line 515
    .line 516
    .line 517
    sget-object v1, Lv7/b;->y:Ljava/lang/String;

    .line 518
    .line 519
    iget v2, v0, Lv7/b;->e:F

    .line 520
    .line 521
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 522
    .line 523
    .line 524
    sget-object v1, Lv7/b;->z:Ljava/lang/String;

    .line 525
    .line 526
    iget v2, v0, Lv7/b;->f:I

    .line 527
    .line 528
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 529
    .line 530
    .line 531
    sget-object v1, Lv7/b;->A:Ljava/lang/String;

    .line 532
    .line 533
    iget v2, v0, Lv7/b;->g:I

    .line 534
    .line 535
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 536
    .line 537
    .line 538
    sget-object v1, Lv7/b;->B:Ljava/lang/String;

    .line 539
    .line 540
    iget v2, v0, Lv7/b;->h:F

    .line 541
    .line 542
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 543
    .line 544
    .line 545
    sget-object v1, Lv7/b;->C:Ljava/lang/String;

    .line 546
    .line 547
    iget v2, v0, Lv7/b;->i:I

    .line 548
    .line 549
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 550
    .line 551
    .line 552
    sget-object v1, Lv7/b;->D:Ljava/lang/String;

    .line 553
    .line 554
    iget v2, v0, Lv7/b;->n:I

    .line 555
    .line 556
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 557
    .line 558
    .line 559
    sget-object v1, Lv7/b;->E:Ljava/lang/String;

    .line 560
    .line 561
    iget v2, v0, Lv7/b;->o:F

    .line 562
    .line 563
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 564
    .line 565
    .line 566
    sget-object v1, Lv7/b;->F:Ljava/lang/String;

    .line 567
    .line 568
    iget v2, v0, Lv7/b;->j:F

    .line 569
    .line 570
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 571
    .line 572
    .line 573
    sget-object v1, Lv7/b;->G:Ljava/lang/String;

    .line 574
    .line 575
    iget v2, v0, Lv7/b;->k:F

    .line 576
    .line 577
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 578
    .line 579
    .line 580
    sget-object v1, Lv7/b;->I:Ljava/lang/String;

    .line 581
    .line 582
    iget-boolean v2, v0, Lv7/b;->l:Z

    .line 583
    .line 584
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 585
    .line 586
    .line 587
    sget-object v1, Lv7/b;->H:Ljava/lang/String;

    .line 588
    .line 589
    iget v2, v0, Lv7/b;->m:I

    .line 590
    .line 591
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 592
    .line 593
    .line 594
    sget-object v1, Lv7/b;->J:Ljava/lang/String;

    .line 595
    .line 596
    iget v2, v0, Lv7/b;->p:I

    .line 597
    .line 598
    invoke-virtual {v6, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 599
    .line 600
    .line 601
    sget-object v1, Lv7/b;->K:Ljava/lang/String;

    .line 602
    .line 603
    iget v2, v0, Lv7/b;->q:F

    .line 604
    .line 605
    invoke-virtual {v6, v1, v2}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 606
    .line 607
    .line 608
    sget-object v1, Lv7/b;->L:Ljava/lang/String;

    .line 609
    .line 610
    iget v0, v0, Lv7/b;->r:I

    .line 611
    .line 612
    invoke-virtual {v6, v1, v0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 613
    .line 614
    .line 615
    if-eqz v4, :cond_d

    .line 616
    .line 617
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 618
    .line 619
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 620
    .line 621
    .line 622
    sget-object v1, Landroid/graphics/Bitmap$CompressFormat;->PNG:Landroid/graphics/Bitmap$CompressFormat;

    .line 623
    .line 624
    const/4 v10, 0x0

    .line 625
    invoke-virtual {v4, v1, v10, v0}, Landroid/graphics/Bitmap;->compress(Landroid/graphics/Bitmap$CompressFormat;ILjava/io/OutputStream;)Z

    .line 626
    .line 627
    .line 628
    move-result v1

    .line 629
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 630
    .line 631
    .line 632
    sget-object v1, Lv7/b;->x:Ljava/lang/String;

    .line 633
    .line 634
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    invoke-virtual {v6, v1, v0}, Landroid/os/Bundle;->putByteArray(Ljava/lang/String;[B)V

    .line 639
    .line 640
    .line 641
    :cond_d
    return-object v6

    .line 642
    :pswitch_2
    const/4 v11, 0x0

    .line 643
    move-object/from16 v0, p1

    .line 644
    .line 645
    check-cast v0, Landroid/os/Bundle;

    .line 646
    .line 647
    sget-object v4, Lv7/b;->s:Ljava/lang/String;

    .line 648
    .line 649
    invoke-virtual {v0, v4}, Landroid/os/Bundle;->getCharSequence(Ljava/lang/String;)Ljava/lang/CharSequence;

    .line 650
    .line 651
    .line 652
    move-result-object v4

    .line 653
    if-eqz v4, :cond_13

    .line 654
    .line 655
    sget-object v6, Lv7/b;->t:Ljava/lang/String;

    .line 656
    .line 657
    invoke-virtual {v0, v6}, Landroid/os/Bundle;->getParcelableArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 658
    .line 659
    .line 660
    move-result-object v6

    .line 661
    if-eqz v6, :cond_12

    .line 662
    .line 663
    invoke-static {v4}, Landroid/text/SpannableString;->valueOf(Ljava/lang/CharSequence;)Landroid/text/SpannableString;

    .line 664
    .line 665
    .line 666
    move-result-object v4

    .line 667
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 668
    .line 669
    .line 670
    move-result-object v6

    .line 671
    :goto_f
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 672
    .line 673
    .line 674
    move-result v7

    .line 675
    if-eqz v7, :cond_12

    .line 676
    .line 677
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 678
    .line 679
    .line 680
    move-result-object v7

    .line 681
    check-cast v7, Landroid/os/Bundle;

    .line 682
    .line 683
    sget-object v8, Lv7/d;->a:Ljava/lang/String;

    .line 684
    .line 685
    invoke-virtual {v7, v8}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 686
    .line 687
    .line 688
    move-result v8

    .line 689
    sget-object v9, Lv7/d;->b:Ljava/lang/String;

    .line 690
    .line 691
    invoke-virtual {v7, v9}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 692
    .line 693
    .line 694
    move-result v9

    .line 695
    sget-object v10, Lv7/d;->c:Ljava/lang/String;

    .line 696
    .line 697
    invoke-virtual {v7, v10}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 698
    .line 699
    .line 700
    move-result v10

    .line 701
    sget-object v12, Lv7/d;->d:Ljava/lang/String;

    .line 702
    .line 703
    const/4 v13, -0x1

    .line 704
    invoke-virtual {v7, v12, v13}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 705
    .line 706
    .line 707
    move-result v12

    .line 708
    sget-object v13, Lv7/d;->e:Ljava/lang/String;

    .line 709
    .line 710
    invoke-virtual {v7, v13}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 711
    .line 712
    .line 713
    move-result-object v7

    .line 714
    const/4 v5, 0x1

    .line 715
    if-eq v12, v5, :cond_11

    .line 716
    .line 717
    if-eq v12, v3, :cond_10

    .line 718
    .line 719
    if-eq v12, v2, :cond_f

    .line 720
    .line 721
    if-eq v12, v1, :cond_e

    .line 722
    .line 723
    goto :goto_f

    .line 724
    :cond_e
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 725
    .line 726
    .line 727
    new-instance v12, Lv7/i;

    .line 728
    .line 729
    sget-object v13, Lv7/i;->b:Ljava/lang/String;

    .line 730
    .line 731
    invoke-virtual {v7, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 732
    .line 733
    .line 734
    move-result-object v7

    .line 735
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 736
    .line 737
    .line 738
    invoke-direct {v12, v7}, Lv7/i;-><init>(Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    invoke-interface {v4, v12, v8, v9, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 742
    .line 743
    .line 744
    goto :goto_f

    .line 745
    :cond_f
    new-instance v7, Lv7/e;

    .line 746
    .line 747
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 748
    .line 749
    .line 750
    invoke-interface {v4, v7, v8, v9, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 751
    .line 752
    .line 753
    goto :goto_f

    .line 754
    :cond_10
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 755
    .line 756
    .line 757
    new-instance v12, Lv7/h;

    .line 758
    .line 759
    sget-object v13, Lv7/h;->d:Ljava/lang/String;

    .line 760
    .line 761
    invoke-virtual {v7, v13}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 762
    .line 763
    .line 764
    move-result v13

    .line 765
    sget-object v14, Lv7/h;->e:Ljava/lang/String;

    .line 766
    .line 767
    invoke-virtual {v7, v14}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 768
    .line 769
    .line 770
    move-result v14

    .line 771
    sget-object v15, Lv7/h;->f:Ljava/lang/String;

    .line 772
    .line 773
    invoke-virtual {v7, v15}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 774
    .line 775
    .line 776
    move-result v7

    .line 777
    invoke-direct {v12, v13, v14, v7}, Lv7/h;-><init>(III)V

    .line 778
    .line 779
    .line 780
    invoke-interface {v4, v12, v8, v9, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 781
    .line 782
    .line 783
    goto :goto_f

    .line 784
    :cond_11
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 785
    .line 786
    .line 787
    new-instance v12, Lv7/g;

    .line 788
    .line 789
    sget-object v13, Lv7/g;->c:Ljava/lang/String;

    .line 790
    .line 791
    invoke-virtual {v7, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 792
    .line 793
    .line 794
    move-result-object v13

    .line 795
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 796
    .line 797
    .line 798
    sget-object v14, Lv7/g;->d:Ljava/lang/String;

    .line 799
    .line 800
    invoke-virtual {v7, v14}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 801
    .line 802
    .line 803
    move-result v7

    .line 804
    invoke-direct {v12, v13, v7}, Lv7/g;-><init>(Ljava/lang/String;I)V

    .line 805
    .line 806
    .line 807
    invoke-interface {v4, v12, v8, v9, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 808
    .line 809
    .line 810
    goto/16 :goto_f

    .line 811
    .line 812
    :cond_12
    const/4 v5, 0x1

    .line 813
    goto :goto_10

    .line 814
    :cond_13
    const/4 v5, 0x1

    .line 815
    move-object v4, v11

    .line 816
    :goto_10
    sget-object v1, Lv7/b;->u:Ljava/lang/String;

    .line 817
    .line 818
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 819
    .line 820
    .line 821
    move-result-object v1

    .line 822
    check-cast v1, Landroid/text/Layout$Alignment;

    .line 823
    .line 824
    if-eqz v1, :cond_14

    .line 825
    .line 826
    move-object v14, v1

    .line 827
    goto :goto_11

    .line 828
    :cond_14
    move-object v14, v11

    .line 829
    :goto_11
    sget-object v1, Lv7/b;->v:Ljava/lang/String;

    .line 830
    .line 831
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getSerializable(Ljava/lang/String;)Ljava/io/Serializable;

    .line 832
    .line 833
    .line 834
    move-result-object v1

    .line 835
    check-cast v1, Landroid/text/Layout$Alignment;

    .line 836
    .line 837
    if-eqz v1, :cond_15

    .line 838
    .line 839
    move-object v15, v1

    .line 840
    goto :goto_12

    .line 841
    :cond_15
    move-object v15, v11

    .line 842
    :goto_12
    sget-object v1, Lv7/b;->w:Ljava/lang/String;

    .line 843
    .line 844
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 845
    .line 846
    .line 847
    move-result-object v1

    .line 848
    check-cast v1, Landroid/graphics/Bitmap;

    .line 849
    .line 850
    if-eqz v1, :cond_16

    .line 851
    .line 852
    :goto_13
    move-object/from16 v16, v1

    .line 853
    .line 854
    move-object v13, v11

    .line 855
    goto :goto_14

    .line 856
    :cond_16
    sget-object v1, Lv7/b;->x:Ljava/lang/String;

    .line 857
    .line 858
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getByteArray(Ljava/lang/String;)[B

    .line 859
    .line 860
    .line 861
    move-result-object v1

    .line 862
    if-eqz v1, :cond_17

    .line 863
    .line 864
    array-length v2, v1

    .line 865
    const/4 v10, 0x0

    .line 866
    invoke-static {v1, v10, v2}, Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;

    .line 867
    .line 868
    .line 869
    move-result-object v1

    .line 870
    goto :goto_13

    .line 871
    :cond_17
    move-object v13, v4

    .line 872
    move-object/from16 v16, v11

    .line 873
    .line 874
    :goto_14
    sget-object v1, Lv7/b;->y:Ljava/lang/String;

    .line 875
    .line 876
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 877
    .line 878
    .line 879
    move-result v2

    .line 880
    const v3, -0x800001

    .line 881
    .line 882
    .line 883
    const/high16 v4, -0x80000000

    .line 884
    .line 885
    if-eqz v2, :cond_18

    .line 886
    .line 887
    sget-object v2, Lv7/b;->z:Ljava/lang/String;

    .line 888
    .line 889
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 890
    .line 891
    .line 892
    move-result v6

    .line 893
    if-eqz v6, :cond_18

    .line 894
    .line 895
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 896
    .line 897
    .line 898
    move-result v1

    .line 899
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 900
    .line 901
    .line 902
    move-result v2

    .line 903
    move/from16 v17, v1

    .line 904
    .line 905
    move/from16 v18, v2

    .line 906
    .line 907
    goto :goto_15

    .line 908
    :cond_18
    move/from16 v17, v3

    .line 909
    .line 910
    move/from16 v18, v4

    .line 911
    .line 912
    :goto_15
    sget-object v1, Lv7/b;->A:Ljava/lang/String;

    .line 913
    .line 914
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 915
    .line 916
    .line 917
    move-result v2

    .line 918
    if-eqz v2, :cond_19

    .line 919
    .line 920
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 921
    .line 922
    .line 923
    move-result v1

    .line 924
    move/from16 v19, v1

    .line 925
    .line 926
    goto :goto_16

    .line 927
    :cond_19
    move/from16 v19, v4

    .line 928
    .line 929
    :goto_16
    sget-object v1, Lv7/b;->B:Ljava/lang/String;

    .line 930
    .line 931
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 932
    .line 933
    .line 934
    move-result v2

    .line 935
    if-eqz v2, :cond_1a

    .line 936
    .line 937
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 938
    .line 939
    .line 940
    move-result v1

    .line 941
    move/from16 v20, v1

    .line 942
    .line 943
    goto :goto_17

    .line 944
    :cond_1a
    move/from16 v20, v3

    .line 945
    .line 946
    :goto_17
    sget-object v1, Lv7/b;->C:Ljava/lang/String;

    .line 947
    .line 948
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 949
    .line 950
    .line 951
    move-result v2

    .line 952
    if-eqz v2, :cond_1b

    .line 953
    .line 954
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 955
    .line 956
    .line 957
    move-result v1

    .line 958
    move/from16 v21, v1

    .line 959
    .line 960
    goto :goto_18

    .line 961
    :cond_1b
    move/from16 v21, v4

    .line 962
    .line 963
    :goto_18
    sget-object v1, Lv7/b;->E:Ljava/lang/String;

    .line 964
    .line 965
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 966
    .line 967
    .line 968
    move-result v2

    .line 969
    if-eqz v2, :cond_1c

    .line 970
    .line 971
    sget-object v2, Lv7/b;->D:Ljava/lang/String;

    .line 972
    .line 973
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 974
    .line 975
    .line 976
    move-result v6

    .line 977
    if-eqz v6, :cond_1c

    .line 978
    .line 979
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 980
    .line 981
    .line 982
    move-result v1

    .line 983
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 984
    .line 985
    .line 986
    move-result v2

    .line 987
    move/from16 v23, v1

    .line 988
    .line 989
    move/from16 v22, v2

    .line 990
    .line 991
    goto :goto_19

    .line 992
    :cond_1c
    move/from16 v23, v3

    .line 993
    .line 994
    move/from16 v22, v4

    .line 995
    .line 996
    :goto_19
    sget-object v1, Lv7/b;->F:Ljava/lang/String;

    .line 997
    .line 998
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 999
    .line 1000
    .line 1001
    move-result v2

    .line 1002
    if-eqz v2, :cond_1d

    .line 1003
    .line 1004
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 1005
    .line 1006
    .line 1007
    move-result v1

    .line 1008
    move/from16 v24, v1

    .line 1009
    .line 1010
    goto :goto_1a

    .line 1011
    :cond_1d
    move/from16 v24, v3

    .line 1012
    .line 1013
    :goto_1a
    sget-object v1, Lv7/b;->G:Ljava/lang/String;

    .line 1014
    .line 1015
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 1016
    .line 1017
    .line 1018
    move-result v2

    .line 1019
    if-eqz v2, :cond_1e

    .line 1020
    .line 1021
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 1022
    .line 1023
    .line 1024
    move-result v3

    .line 1025
    :cond_1e
    move/from16 v25, v3

    .line 1026
    .line 1027
    sget-object v1, Lv7/b;->H:Ljava/lang/String;

    .line 1028
    .line 1029
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 1030
    .line 1031
    .line 1032
    move-result v2

    .line 1033
    if-eqz v2, :cond_1f

    .line 1034
    .line 1035
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 1036
    .line 1037
    .line 1038
    move-result v1

    .line 1039
    move v6, v5

    .line 1040
    :goto_1b
    move/from16 v27, v1

    .line 1041
    .line 1042
    goto :goto_1c

    .line 1043
    :cond_1f
    const/high16 v1, -0x1000000

    .line 1044
    .line 1045
    const/4 v6, 0x0

    .line 1046
    goto :goto_1b

    .line 1047
    :goto_1c
    sget-object v1, Lv7/b;->I:Ljava/lang/String;

    .line 1048
    .line 1049
    const/4 v10, 0x0

    .line 1050
    invoke-virtual {v0, v1, v10}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 1051
    .line 1052
    .line 1053
    move-result v1

    .line 1054
    if-nez v1, :cond_20

    .line 1055
    .line 1056
    move/from16 v26, v10

    .line 1057
    .line 1058
    goto :goto_1d

    .line 1059
    :cond_20
    move/from16 v26, v6

    .line 1060
    .line 1061
    :goto_1d
    sget-object v1, Lv7/b;->J:Ljava/lang/String;

    .line 1062
    .line 1063
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 1064
    .line 1065
    .line 1066
    move-result v2

    .line 1067
    if-eqz v2, :cond_21

    .line 1068
    .line 1069
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 1070
    .line 1071
    .line 1072
    move-result v4

    .line 1073
    :cond_21
    move/from16 v28, v4

    .line 1074
    .line 1075
    sget-object v1, Lv7/b;->K:Ljava/lang/String;

    .line 1076
    .line 1077
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 1078
    .line 1079
    .line 1080
    move-result v2

    .line 1081
    if-eqz v2, :cond_22

    .line 1082
    .line 1083
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getFloat(Ljava/lang/String;)F

    .line 1084
    .line 1085
    .line 1086
    move-result v1

    .line 1087
    :goto_1e
    move/from16 v29, v1

    .line 1088
    .line 1089
    goto :goto_1f

    .line 1090
    :cond_22
    const/4 v1, 0x0

    .line 1091
    goto :goto_1e

    .line 1092
    :goto_1f
    sget-object v1, Lv7/b;->L:Ljava/lang/String;

    .line 1093
    .line 1094
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 1095
    .line 1096
    .line 1097
    move-result v2

    .line 1098
    if-eqz v2, :cond_23

    .line 1099
    .line 1100
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;)I

    .line 1101
    .line 1102
    .line 1103
    move-result v7

    .line 1104
    move/from16 v30, v7

    .line 1105
    .line 1106
    goto :goto_20

    .line 1107
    :cond_23
    move/from16 v30, v10

    .line 1108
    .line 1109
    :goto_20
    new-instance v12, Lv7/b;

    .line 1110
    .line 1111
    invoke-direct/range {v12 .. v30}, Lv7/b;-><init>(Ljava/lang/CharSequence;Landroid/text/Layout$Alignment;Landroid/text/Layout$Alignment;Landroid/graphics/Bitmap;FIIFIIFFFZIIFI)V

    .line 1112
    .line 1113
    .line 1114
    return-object v12

    .line 1115
    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b(Lg4/g;)Ll4/b0;
    .locals 1

    .line 1
    new-instance p0, Ll4/b0;

    .line 2
    .line 3
    sget-object v0, Ll4/o;->a:Ll4/c0;

    .line 4
    .line 5
    invoke-direct {p0, p1, v0}, Ll4/b0;-><init>(Lg4/g;Ll4/p;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public d()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lj9/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "gatt.refresh() method not found"

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    const-string p0, "gatt.refresh() (hidden)"

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_1
    const-string p0, "Refreshing device cache..."

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_data_0
    .packed-switch 0xc
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Lcom/google/firebase/perf/FirebasePerfRegistrar;->a(Lin/z1;)Lot/b;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public f()Ljava/lang/reflect/Constructor;
    .locals 4

    .line 1
    iget p0, p0, Lj9/d;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const-class v1, Lo8/o;

    .line 5
    .line 6
    packed-switch p0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    const-string p0, "androidx.media3.decoder.midi.MidiExtractor"

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0, v1}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 25
    .line 26
    const-string v2, "androidx.media3.decoder.flac.FlacLibrary"

    .line 27
    .line 28
    invoke-static {v2}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    const-string v3, "isAvailable"

    .line 33
    .line 34
    invoke-virtual {v2, v3, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-virtual {v2, v0, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    invoke-virtual {p0, v2}, Ljava/lang/Boolean;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_0

    .line 47
    .line 48
    const-string p0, "androidx.media3.decoder.flac.FlacExtractor"

    .line 49
    .line 50
    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p0, v1}, Ljava/lang/Class;->asSubclass(Ljava/lang/Class;)Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    sget-object v0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 59
    .line 60
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p0, v0}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    :cond_0
    return-object v0

    .line 69
    :pswitch_data_0
    .packed-switch 0xf
        :pswitch_0
    .end packed-switch
.end method

.method public g()[Lo8/o;
    .locals 2

    .line 1
    iget p0, p0, Lj9/d;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Lp8/a;

    .line 9
    .line 10
    invoke-direct {p0}, Lp8/a;-><init>()V

    .line 11
    .line 12
    .line 13
    new-array v1, v1, [Lo8/o;

    .line 14
    .line 15
    aput-object p0, v1, v0

    .line 16
    .line 17
    return-object v1

    .line 18
    :pswitch_0
    new-instance p0, Lj9/e;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    new-array v1, v1, [Lo8/o;

    .line 24
    .line 25
    aput-object p0, v1, v0

    .line 26
    .line 27
    return-object v1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public h(Lb0/x1;)V
    .locals 4

    .line 1
    new-instance p0, Landroid/graphics/SurfaceTexture;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, v0}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p1, Lb0/x1;->b:Landroid/util/Size;

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    iget-object v1, p1, Lb0/x1;->b:Landroid/util/Size;

    .line 14
    .line 15
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {p0, v0, v1}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Landroid/graphics/SurfaceTexture;->detachFromGLContext()V

    .line 23
    .line 24
    .line 25
    new-instance v0, Landroid/view/Surface;

    .line 26
    .line 27
    invoke-direct {v0, p0}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 28
    .line 29
    .line 30
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    new-instance v2, Ll0/d;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-direct {v2, v3, v0, p0}, Ll0/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, v0, v1, v2}, Lb0/x1;->a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p1}, Laq/j;->i()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Laq/j;->g()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lms/a;

    .line 12
    .line 13
    sget-object p1, Ljs/c;->a:Ljs/c;

    .line 14
    .line 15
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v1, "Crashlytics report successfully enqueued to DataTransport: "

    .line 18
    .line 19
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Lms/a;->b:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {p1, v0}, Ljs/c;->b(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lms/a;->c:Ljava/io/File;

    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v1, 0x1

    .line 41
    if-eqz v0, :cond_0

    .line 42
    .line 43
    new-instance v0, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v2, "Deleted report file: "

    .line 46
    .line 47
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {p1, p0}, Ljs/c;->b(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    const-string v2, "Crashlytics could not delete report file: "

    .line 68
    .line 69
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const/4 v0, 0x0

    .line 84
    invoke-virtual {p1, p0, v0}, Ljs/c;->f(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    :cond_1
    invoke-virtual {p1}, Laq/j;->f()Ljava/lang/Exception;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    const-string p1, "FirebaseCrashlytics"

    .line 93
    .line 94
    const-string v0, "Crashlytics report could not be enqueued to DataTransport"

    .line 95
    .line 96
    invoke-static {p1, v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 97
    .line 98
    .line 99
    const/4 v1, 0x0

    .line 100
    :goto_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method
