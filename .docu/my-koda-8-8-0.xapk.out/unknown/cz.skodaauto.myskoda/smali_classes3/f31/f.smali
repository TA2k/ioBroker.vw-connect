.class public final Lf31/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc31/b;


# direct methods
.method public constructor <init>(Lc31/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf31/f;->a:Lc31/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Li31/b;JLrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    instance-of v3, v2, Lf31/e;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lf31/e;

    .line 13
    .line 14
    iget v4, v3, Lf31/e;->f:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lf31/e;->f:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lf31/e;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lf31/e;-><init>(Lf31/f;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lf31/e;->d:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lf31/e;->f:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v6, :cond_1

    .line 41
    .line 42
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_b

    .line 46
    .line 47
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    new-instance v7, Le31/u;

    .line 59
    .line 60
    new-instance v8, Le31/h;

    .line 61
    .line 62
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 63
    .line 64
    const/16 v5, 0xa

    .line 65
    .line 66
    if-eqz v1, :cond_5

    .line 67
    .line 68
    iget-object v9, v1, Li31/b;->b:Li31/b0;

    .line 69
    .line 70
    iget-object v9, v9, Li31/b0;->b:Ljava/util/List;

    .line 71
    .line 72
    if-eqz v9, :cond_5

    .line 73
    .line 74
    check-cast v9, Ljava/lang/Iterable;

    .line 75
    .line 76
    new-instance v10, Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 79
    .line 80
    .line 81
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 82
    .line 83
    .line 84
    move-result-object v9

    .line 85
    :cond_3
    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    if-eqz v11, :cond_4

    .line 90
    .line 91
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v11

    .line 95
    move-object v12, v11

    .line 96
    check-cast v12, Li31/a0;

    .line 97
    .line 98
    iget-boolean v12, v12, Li31/a0;->b:Z

    .line 99
    .line 100
    if-eqz v12, :cond_3

    .line 101
    .line 102
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_4
    new-instance v9, Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-static {v10, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 109
    .line 110
    .line 111
    move-result v11

    .line 112
    invoke-direct {v9, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 120
    .line 121
    .line 122
    move-result v11

    .line 123
    if-eqz v11, :cond_6

    .line 124
    .line 125
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v11

    .line 129
    check-cast v11, Li31/a0;

    .line 130
    .line 131
    new-instance v12, Le31/k;

    .line 132
    .line 133
    iget-object v11, v11, Li31/a0;->a:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v11, Li31/z;

    .line 136
    .line 137
    iget v13, v11, Li31/z;->a:I

    .line 138
    .line 139
    iget v11, v11, Li31/z;->b:I

    .line 140
    .line 141
    invoke-direct {v12, v13, v11}, Le31/k;-><init>(II)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v9, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_5
    move-object v9, v2

    .line 149
    :cond_6
    if-eqz v1, :cond_9

    .line 150
    .line 151
    iget-object v10, v1, Li31/b;->b:Li31/b0;

    .line 152
    .line 153
    iget-object v10, v10, Li31/b0;->a:Ljava/util/List;

    .line 154
    .line 155
    if-eqz v10, :cond_9

    .line 156
    .line 157
    check-cast v10, Ljava/lang/Iterable;

    .line 158
    .line 159
    new-instance v11, Ljava/util/ArrayList;

    .line 160
    .line 161
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 162
    .line 163
    .line 164
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 165
    .line 166
    .line 167
    move-result-object v10

    .line 168
    :cond_7
    :goto_3
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 169
    .line 170
    .line 171
    move-result v12

    .line 172
    if-eqz v12, :cond_8

    .line 173
    .line 174
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v12

    .line 178
    move-object v13, v12

    .line 179
    check-cast v13, Li31/a0;

    .line 180
    .line 181
    iget-boolean v13, v13, Li31/a0;->b:Z

    .line 182
    .line 183
    if-eqz v13, :cond_7

    .line 184
    .line 185
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_8
    new-instance v10, Ljava/util/ArrayList;

    .line 190
    .line 191
    invoke-static {v11, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 192
    .line 193
    .line 194
    move-result v12

    .line 195
    invoke-direct {v10, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v11}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 199
    .line 200
    .line 201
    move-result-object v11

    .line 202
    :goto_4
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 203
    .line 204
    .line 205
    move-result v12

    .line 206
    if-eqz v12, :cond_a

    .line 207
    .line 208
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v12

    .line 212
    check-cast v12, Li31/a0;

    .line 213
    .line 214
    new-instance v13, Le31/t;

    .line 215
    .line 216
    iget-object v12, v12, Li31/a0;->a:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v12, Li31/g0;

    .line 219
    .line 220
    iget v12, v12, Li31/g0;->a:I

    .line 221
    .line 222
    invoke-direct {v13, v12}, Le31/t;-><init>(I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_9
    move-object v10, v2

    .line 230
    :cond_a
    invoke-direct {v8, v9, v10}, Le31/h;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 231
    .line 232
    .line 233
    const-string v9, "yyyy-MM-dd"

    .line 234
    .line 235
    move-wide/from16 v10, p2

    .line 236
    .line 237
    invoke-static {v10, v11, v9}, Lcom/google/android/gms/internal/measurement/i5;->b(JLjava/lang/String;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v9

    .line 241
    if-eqz v1, :cond_b

    .line 242
    .line 243
    iget-object v11, v1, Li31/b;->a:Ljava/lang/String;

    .line 244
    .line 245
    goto :goto_5

    .line 246
    :cond_b
    const/4 v11, 0x0

    .line 247
    :goto_5
    if-nez v11, :cond_c

    .line 248
    .line 249
    const-string v11, ""

    .line 250
    .line 251
    :cond_c
    if-eqz v1, :cond_11

    .line 252
    .line 253
    iget-object v12, v1, Li31/b;->b:Li31/b0;

    .line 254
    .line 255
    iget-object v12, v12, Li31/b0;->c:Ljava/util/List;

    .line 256
    .line 257
    if-eqz v12, :cond_11

    .line 258
    .line 259
    check-cast v12, Ljava/lang/Iterable;

    .line 260
    .line 261
    new-instance v2, Ljava/util/ArrayList;

    .line 262
    .line 263
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 264
    .line 265
    .line 266
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 267
    .line 268
    .line 269
    move-result-object v12

    .line 270
    :cond_d
    :goto_6
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 271
    .line 272
    .line 273
    move-result v13

    .line 274
    if-eqz v13, :cond_e

    .line 275
    .line 276
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v13

    .line 280
    move-object v14, v13

    .line 281
    check-cast v14, Li31/a0;

    .line 282
    .line 283
    iget-boolean v14, v14, Li31/a0;->b:Z

    .line 284
    .line 285
    if-eqz v14, :cond_d

    .line 286
    .line 287
    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    goto :goto_6

    .line 291
    :cond_e
    new-instance v12, Ljava/util/ArrayList;

    .line 292
    .line 293
    invoke-static {v2, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 294
    .line 295
    .line 296
    move-result v13

    .line 297
    invoke-direct {v12, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    :goto_7
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 305
    .line 306
    .line 307
    move-result v13

    .line 308
    if-eqz v13, :cond_10

    .line 309
    .line 310
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 311
    .line 312
    .line 313
    move-result-object v13

    .line 314
    check-cast v13, Li31/a0;

    .line 315
    .line 316
    iget-object v13, v13, Li31/a0;->a:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v13, Li31/c0;

    .line 319
    .line 320
    iget-object v14, v13, Li31/c0;->c:Ljava/lang/String;

    .line 321
    .line 322
    iget-object v13, v13, Li31/c0;->f:Ljava/util/ArrayList;

    .line 323
    .line 324
    new-instance v15, Ljava/util/ArrayList;

    .line 325
    .line 326
    invoke-static {v13, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 327
    .line 328
    .line 329
    move-result v10

    .line 330
    invoke-direct {v15, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 331
    .line 332
    .line 333
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 334
    .line 335
    .line 336
    move-result-object v10

    .line 337
    :goto_8
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 338
    .line 339
    .line 340
    move-result v13

    .line 341
    if-eqz v13, :cond_f

    .line 342
    .line 343
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object v13

    .line 347
    check-cast v13, Li31/f0;

    .line 348
    .line 349
    new-instance v5, Le31/n;

    .line 350
    .line 351
    iget-object v13, v13, Li31/f0;->a:Ljava/lang/String;

    .line 352
    .line 353
    invoke-direct {v5, v13}, Le31/n;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v15, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 357
    .line 358
    .line 359
    const/16 v5, 0xa

    .line 360
    .line 361
    goto :goto_8

    .line 362
    :cond_f
    new-instance v5, Le31/q;

    .line 363
    .line 364
    invoke-direct {v5, v14, v15}, Le31/q;-><init>(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v12, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 368
    .line 369
    .line 370
    const/16 v5, 0xa

    .line 371
    .line 372
    goto :goto_7

    .line 373
    :cond_10
    move-object v2, v12

    .line 374
    :cond_11
    if-eqz v1, :cond_12

    .line 375
    .line 376
    iget-object v10, v1, Li31/b;->e:Ljava/lang/String;

    .line 377
    .line 378
    move-object v12, v10

    .line 379
    :goto_9
    move-object v10, v11

    .line 380
    move-object v11, v2

    .line 381
    goto :goto_a

    .line 382
    :cond_12
    const/4 v12, 0x0

    .line 383
    goto :goto_9

    .line 384
    :goto_a
    invoke-direct/range {v7 .. v12}, Le31/u;-><init>(Le31/h;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 385
    .line 386
    .line 387
    iput v6, v3, Lf31/e;->f:I

    .line 388
    .line 389
    iget-object v0, v0, Lf31/f;->a:Lc31/b;

    .line 390
    .line 391
    invoke-virtual {v0, v7, v3}, Lc31/b;->a(Le31/u;Lrx0/c;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    if-ne v2, v4, :cond_13

    .line 396
    .line 397
    return-object v4

    .line 398
    :cond_13
    :goto_b
    check-cast v2, Lo41/c;

    .line 399
    .line 400
    new-instance v0, Leh/b;

    .line 401
    .line 402
    const/16 v1, 0x1c

    .line 403
    .line 404
    invoke-direct {v0, v1}, Leh/b;-><init>(I)V

    .line 405
    .line 406
    .line 407
    invoke-static {v2, v0}, Ljp/nb;->c(Lo41/c;Lay0/k;)Lo41/c;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    invoke-static {v0}, Ljp/nb;->b(Lo41/c;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v1

    .line 415
    check-cast v1, Li31/h;

    .line 416
    .line 417
    if-eqz v1, :cond_14

    .line 418
    .line 419
    iget-boolean v1, v1, Li31/h;->d:Z

    .line 420
    .line 421
    if-ne v1, v6, :cond_14

    .line 422
    .line 423
    return-object v0

    .line 424
    :cond_14
    new-instance v1, Lo41/a;

    .line 425
    .line 426
    new-instance v2, Ljava/lang/Exception;

    .line 427
    .line 428
    new-instance v3, Ljava/lang/StringBuilder;

    .line 429
    .line 430
    const-string v4, "Invalid Capacity: "

    .line 431
    .line 432
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 436
    .line 437
    .line 438
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 439
    .line 440
    .line 441
    move-result-object v0

    .line 442
    invoke-direct {v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 443
    .line 444
    .line 445
    invoke-direct {v1, v2}, Lo41/a;-><init>(Ljava/lang/Throwable;)V

    .line 446
    .line 447
    .line 448
    return-object v1
.end method
