.class public final Lcl0/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lal0/d1;

.field public final j:Lal0/c1;

.field public final k:Lij0/a;

.field public l:Lbl0/h;


# direct methods
.method public constructor <init>(Lal0/h0;Ltr0/b;Lal0/d1;Lal0/c1;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lcl0/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1, v1, v1}, Lcl0/i;-><init>(Lcl0/f;Lcl0/h;Lcl0/h;Lcl0/h;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, Lcl0/j;->h:Ltr0/b;

    .line 11
    .line 12
    iput-object p3, p0, Lcl0/j;->i:Lal0/d1;

    .line 13
    .line 14
    iput-object p4, p0, Lcl0/j;->j:Lal0/c1;

    .line 15
    .line 16
    iput-object p5, p0, Lcl0/j;->k:Lij0/a;

    .line 17
    .line 18
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    new-instance p3, Lc80/l;

    .line 23
    .line 24
    const/16 p4, 0xc

    .line 25
    .line 26
    invoke-direct {p3, p4, p1, p0, v1}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    const/4 p0, 0x3

    .line 30
    invoke-static {p2, v1, v1, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public static j(Ljava/util/List;Lbl0/f;)Ljava/util/ArrayList;
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/util/Collection;

    .line 3
    .line 4
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-eqz p0, :cond_0

    .line 13
    .line 14
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    return-object v0

    .line 18
    :cond_0
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    return-object v0
.end method


# virtual methods
.method public final h(Lbl0/h;)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iput-object v1, v0, Lcl0/j;->l:Lbl0/h;

    .line 6
    .line 7
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    check-cast v2, Lcl0/i;

    .line 12
    .line 13
    new-instance v3, Lcl0/f;

    .line 14
    .line 15
    new-instance v4, Lcl0/b;

    .line 16
    .line 17
    iget-object v5, v1, Lbl0/h;->a:Lbl0/e;

    .line 18
    .line 19
    sget-object v6, Lbl0/e;->c:Lbl0/e;

    .line 20
    .line 21
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v5

    .line 25
    invoke-direct {v4, v5}, Lcl0/b;-><init>(Z)V

    .line 26
    .line 27
    .line 28
    new-instance v5, Lcl0/a;

    .line 29
    .line 30
    iget-object v6, v1, Lbl0/h;->a:Lbl0/e;

    .line 31
    .line 32
    sget-object v7, Lbl0/e;->d:Lbl0/e;

    .line 33
    .line 34
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    invoke-direct {v5, v7}, Lcl0/a;-><init>(Z)V

    .line 39
    .line 40
    .line 41
    new-instance v7, Lcl0/c;

    .line 42
    .line 43
    sget-object v8, Lbl0/e;->e:Lbl0/e;

    .line 44
    .line 45
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v8

    .line 49
    invoke-direct {v7, v8}, Lcl0/c;-><init>(Z)V

    .line 50
    .line 51
    .line 52
    const/4 v8, 0x3

    .line 53
    new-array v9, v8, [Lcl0/d;

    .line 54
    .line 55
    const/4 v10, 0x0

    .line 56
    aput-object v4, v9, v10

    .line 57
    .line 58
    const/4 v4, 0x1

    .line 59
    aput-object v5, v9, v4

    .line 60
    .line 61
    const/4 v5, 0x2

    .line 62
    aput-object v7, v9, v5

    .line 63
    .line 64
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v7

    .line 68
    new-instance v9, Lcl0/e;

    .line 69
    .line 70
    invoke-static {v6}, Ljp/od;->c(Lbl0/e;)Lgy0/e;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    invoke-direct {v9, v6}, Lcl0/e;-><init>(Lgy0/f;)V

    .line 75
    .line 76
    .line 77
    iget-boolean v6, v1, Lbl0/h;->b:Z

    .line 78
    .line 79
    invoke-direct {v3, v7, v9, v6}, Lcl0/f;-><init>(Ljava/util/List;Lcl0/e;Z)V

    .line 80
    .line 81
    .line 82
    new-array v6, v10, [Ljava/lang/Object;

    .line 83
    .line 84
    iget-object v7, v0, Lcl0/j;->k:Lij0/a;

    .line 85
    .line 86
    move-object v9, v7

    .line 87
    check-cast v9, Ljj0/f;

    .line 88
    .line 89
    const v11, 0x7f12061e

    .line 90
    .line 91
    .line 92
    invoke-virtual {v9, v11, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    sget-object v11, Lbl0/b;->e:Lsx0/b;

    .line 97
    .line 98
    new-instance v12, Ljava/util/ArrayList;

    .line 99
    .line 100
    const/16 v13, 0xa

    .line 101
    .line 102
    invoke-static {v11, v13}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 103
    .line 104
    .line 105
    move-result v14

    .line 106
    invoke-direct {v12, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v11}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v11

    .line 113
    :goto_0
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v14

    .line 117
    const-string v15, "stringResource"

    .line 118
    .line 119
    const-string v13, "<this>"

    .line 120
    .line 121
    if-eqz v14, :cond_8

    .line 122
    .line 123
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v14

    .line 127
    check-cast v14, Lbl0/b;

    .line 128
    .line 129
    iget-object v10, v1, Lbl0/h;->c:Ljava/util/List;

    .line 130
    .line 131
    invoke-interface {v10, v14}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v22

    .line 135
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 142
    .line 143
    .line 144
    move-result v10

    .line 145
    if-eqz v10, :cond_3

    .line 146
    .line 147
    if-eq v10, v4, :cond_2

    .line 148
    .line 149
    if-eq v10, v5, :cond_1

    .line 150
    .line 151
    if-ne v10, v8, :cond_0

    .line 152
    .line 153
    const v10, 0x7f120621

    .line 154
    .line 155
    .line 156
    :goto_1
    const/4 v13, 0x0

    .line 157
    goto :goto_2

    .line 158
    :cond_0
    new-instance v0, La8/r0;

    .line 159
    .line 160
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 161
    .line 162
    .line 163
    throw v0

    .line 164
    :cond_1
    const v10, 0x7f12061f

    .line 165
    .line 166
    .line 167
    goto :goto_1

    .line 168
    :cond_2
    const v10, 0x7f120620

    .line 169
    .line 170
    .line 171
    goto :goto_1

    .line 172
    :cond_3
    const v10, 0x7f120622

    .line 173
    .line 174
    .line 175
    goto :goto_1

    .line 176
    :goto_2
    new-array v15, v13, [Ljava/lang/Object;

    .line 177
    .line 178
    move-object v13, v7

    .line 179
    check-cast v13, Ljj0/f;

    .line 180
    .line 181
    invoke-virtual {v13, v10, v15}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v18

    .line 185
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 186
    .line 187
    .line 188
    move-result v10

    .line 189
    if-eqz v10, :cond_7

    .line 190
    .line 191
    if-eq v10, v4, :cond_6

    .line 192
    .line 193
    if-eq v10, v5, :cond_5

    .line 194
    .line 195
    if-ne v10, v8, :cond_4

    .line 196
    .line 197
    const v10, 0x7f080476

    .line 198
    .line 199
    .line 200
    goto :goto_3

    .line 201
    :cond_4
    new-instance v0, La8/r0;

    .line 202
    .line 203
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 204
    .line 205
    .line 206
    throw v0

    .line 207
    :cond_5
    const v10, 0x7f0803a1

    .line 208
    .line 209
    .line 210
    goto :goto_3

    .line 211
    :cond_6
    const v10, 0x7f0803c5

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_7
    const v10, 0x7f0804bc

    .line 216
    .line 217
    .line 218
    :goto_3
    new-instance v16, Lcl0/g;

    .line 219
    .line 220
    const/16 v20, 0x0

    .line 221
    .line 222
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 223
    .line 224
    .line 225
    move-result-object v21

    .line 226
    const/16 v19, 0x0

    .line 227
    .line 228
    move-object/from16 v17, v14

    .line 229
    .line 230
    invoke-direct/range {v16 .. v22}, Lcl0/g;-><init>(Lbl0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Z)V

    .line 231
    .line 232
    .line 233
    move-object/from16 v10, v16

    .line 234
    .line 235
    invoke-virtual {v12, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    const/4 v10, 0x0

    .line 239
    const/16 v13, 0xa

    .line 240
    .line 241
    goto/16 :goto_0

    .line 242
    .line 243
    :cond_8
    new-instance v10, Lcl0/h;

    .line 244
    .line 245
    invoke-direct {v10, v6, v12}, Lcl0/h;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 246
    .line 247
    .line 248
    const v6, 0x7f1205ec

    .line 249
    .line 250
    .line 251
    const/4 v11, 0x0

    .line 252
    new-array v12, v11, [Ljava/lang/Object;

    .line 253
    .line 254
    invoke-virtual {v9, v6, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    sget-object v11, Lbl0/c;->e:Lsx0/b;

    .line 259
    .line 260
    new-instance v12, Ljava/util/ArrayList;

    .line 261
    .line 262
    const/16 v14, 0xa

    .line 263
    .line 264
    invoke-static {v11, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 265
    .line 266
    .line 267
    move-result v8

    .line 268
    invoke-direct {v12, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v11}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 272
    .line 273
    .line 274
    move-result-object v8

    .line 275
    :goto_4
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 276
    .line 277
    .line 278
    move-result v11

    .line 279
    if-eqz v11, :cond_d

    .line 280
    .line 281
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v11

    .line 285
    check-cast v11, Lbl0/c;

    .line 286
    .line 287
    iget-object v14, v1, Lbl0/h;->d:Ljava/util/List;

    .line 288
    .line 289
    invoke-interface {v14, v11}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    move-result v29

    .line 293
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v11}, Ljava/lang/Enum;->ordinal()I

    .line 300
    .line 301
    .line 302
    move-result v14

    .line 303
    if-eqz v14, :cond_c

    .line 304
    .line 305
    if-eq v14, v4, :cond_b

    .line 306
    .line 307
    if-eq v14, v5, :cond_a

    .line 308
    .line 309
    const/4 v5, 0x3

    .line 310
    if-ne v14, v5, :cond_9

    .line 311
    .line 312
    const v5, 0x7f1205df

    .line 313
    .line 314
    .line 315
    :goto_5
    const/4 v14, 0x0

    .line 316
    goto :goto_6

    .line 317
    :cond_9
    new-instance v0, La8/r0;

    .line 318
    .line 319
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 320
    .line 321
    .line 322
    throw v0

    .line 323
    :cond_a
    const v5, 0x7f1205e1

    .line 324
    .line 325
    .line 326
    goto :goto_5

    .line 327
    :cond_b
    const v5, 0x7f1205dd

    .line 328
    .line 329
    .line 330
    goto :goto_5

    .line 331
    :cond_c
    const v5, 0x7f1205e3

    .line 332
    .line 333
    .line 334
    goto :goto_5

    .line 335
    :goto_6
    new-array v4, v14, [Ljava/lang/Object;

    .line 336
    .line 337
    move-object v14, v7

    .line 338
    check-cast v14, Ljj0/f;

    .line 339
    .line 340
    invoke-virtual {v14, v5, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v25

    .line 344
    new-instance v23, Lcl0/g;

    .line 345
    .line 346
    const/16 v27, 0x0

    .line 347
    .line 348
    const/16 v28, 0x0

    .line 349
    .line 350
    const/16 v26, 0x0

    .line 351
    .line 352
    move-object/from16 v24, v11

    .line 353
    .line 354
    invoke-direct/range {v23 .. v29}, Lcl0/g;-><init>(Lbl0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Z)V

    .line 355
    .line 356
    .line 357
    move-object/from16 v4, v23

    .line 358
    .line 359
    invoke-virtual {v12, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 360
    .line 361
    .line 362
    const/4 v4, 0x1

    .line 363
    const/4 v5, 0x2

    .line 364
    goto :goto_4

    .line 365
    :cond_d
    new-instance v4, Lcl0/h;

    .line 366
    .line 367
    invoke-direct {v4, v6, v12}, Lcl0/h;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 368
    .line 369
    .line 370
    const v5, 0x7f120628

    .line 371
    .line 372
    .line 373
    const/4 v14, 0x0

    .line 374
    new-array v6, v14, [Ljava/lang/Object;

    .line 375
    .line 376
    invoke-virtual {v9, v5, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v5

    .line 380
    sget-object v6, Lbl0/d;->i:Lsx0/b;

    .line 381
    .line 382
    new-instance v8, Ljava/util/ArrayList;

    .line 383
    .line 384
    const/16 v14, 0xa

    .line 385
    .line 386
    invoke-static {v6, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 387
    .line 388
    .line 389
    move-result v9

    .line 390
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 391
    .line 392
    .line 393
    invoke-virtual {v6}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 394
    .line 395
    .line 396
    move-result-object v6

    .line 397
    :goto_7
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 398
    .line 399
    .line 400
    move-result v9

    .line 401
    if-eqz v9, :cond_16

    .line 402
    .line 403
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    move-result-object v9

    .line 407
    check-cast v9, Lbl0/d;

    .line 408
    .line 409
    iget-object v11, v1, Lbl0/h;->e:Ljava/util/List;

    .line 410
    .line 411
    invoke-interface {v11, v9}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result v29

    .line 415
    invoke-static {v9, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 416
    .line 417
    .line 418
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 422
    .line 423
    .line 424
    move-result v11

    .line 425
    if-eqz v11, :cond_11

    .line 426
    .line 427
    const/4 v12, 0x1

    .line 428
    if-eq v11, v12, :cond_10

    .line 429
    .line 430
    const/4 v12, 0x2

    .line 431
    if-eq v11, v12, :cond_f

    .line 432
    .line 433
    const/4 v12, 0x3

    .line 434
    if-ne v11, v12, :cond_e

    .line 435
    .line 436
    const v11, 0x7f120624

    .line 437
    .line 438
    .line 439
    :goto_8
    const/4 v14, 0x0

    .line 440
    goto :goto_9

    .line 441
    :cond_e
    new-instance v0, La8/r0;

    .line 442
    .line 443
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 444
    .line 445
    .line 446
    throw v0

    .line 447
    :cond_f
    const v11, 0x7f120623

    .line 448
    .line 449
    .line 450
    goto :goto_8

    .line 451
    :cond_10
    const v11, 0x7f120626

    .line 452
    .line 453
    .line 454
    goto :goto_8

    .line 455
    :cond_11
    const v11, 0x7f120625

    .line 456
    .line 457
    .line 458
    goto :goto_8

    .line 459
    :goto_9
    new-array v12, v14, [Ljava/lang/Object;

    .line 460
    .line 461
    move-object v14, v7

    .line 462
    check-cast v14, Ljj0/f;

    .line 463
    .line 464
    invoke-virtual {v14, v11, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object v25

    .line 468
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 469
    .line 470
    .line 471
    move-result v11

    .line 472
    if-eqz v11, :cond_15

    .line 473
    .line 474
    const/4 v12, 0x1

    .line 475
    if-eq v11, v12, :cond_14

    .line 476
    .line 477
    const/4 v14, 0x2

    .line 478
    if-eq v11, v14, :cond_13

    .line 479
    .line 480
    const/4 v12, 0x3

    .line 481
    if-ne v11, v12, :cond_12

    .line 482
    .line 483
    const v11, 0x7f080192

    .line 484
    .line 485
    .line 486
    goto :goto_a

    .line 487
    :cond_12
    new-instance v0, La8/r0;

    .line 488
    .line 489
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 490
    .line 491
    .line 492
    throw v0

    .line 493
    :cond_13
    const/4 v12, 0x3

    .line 494
    const v11, 0x7f08016b

    .line 495
    .line 496
    .line 497
    goto :goto_a

    .line 498
    :cond_14
    const/4 v12, 0x3

    .line 499
    const/4 v14, 0x2

    .line 500
    const v11, 0x7f0801b0

    .line 501
    .line 502
    .line 503
    goto :goto_a

    .line 504
    :cond_15
    const/4 v12, 0x3

    .line 505
    const/4 v14, 0x2

    .line 506
    const v11, 0x7f0801ac

    .line 507
    .line 508
    .line 509
    :goto_a
    new-instance v23, Lcl0/g;

    .line 510
    .line 511
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 512
    .line 513
    .line 514
    move-result-object v27

    .line 515
    const/16 v28, 0x0

    .line 516
    .line 517
    const/16 v26, 0x0

    .line 518
    .line 519
    move-object/from16 v24, v9

    .line 520
    .line 521
    invoke-direct/range {v23 .. v29}, Lcl0/g;-><init>(Lbl0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Z)V

    .line 522
    .line 523
    .line 524
    move-object/from16 v9, v23

    .line 525
    .line 526
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 527
    .line 528
    .line 529
    goto/16 :goto_7

    .line 530
    .line 531
    :cond_16
    new-instance v1, Lcl0/h;

    .line 532
    .line 533
    invoke-direct {v1, v5, v8}, Lcl0/h;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 537
    .line 538
    .line 539
    new-instance v2, Lcl0/i;

    .line 540
    .line 541
    invoke-direct {v2, v3, v10, v4, v1}, Lcl0/i;-><init>(Lcl0/f;Lcl0/h;Lcl0/h;Lcl0/h;)V

    .line 542
    .line 543
    .line 544
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 545
    .line 546
    .line 547
    return-void
.end method
