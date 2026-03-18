.class public final Ly31/e;
.super Lq41/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Lay0/k;

.field public final i:Lk31/i0;

.field public final j:Li31/b;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lay0/k;Lk31/i0;Lk31/o;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ly31/g;

    .line 4
    .line 5
    const/4 v6, 0x0

    .line 6
    const-string v7, ""

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    const/4 v5, 0x0

    .line 13
    const/4 v8, 0x0

    .line 14
    invoke-direct/range {v1 .. v8}, Ly31/g;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {v0, v1}, Lq41/b;-><init>(Lq41/a;)V

    .line 18
    .line 19
    .line 20
    move-object/from16 v1, p1

    .line 21
    .line 22
    iput-object v1, v0, Ly31/e;->f:Ljava/lang/String;

    .line 23
    .line 24
    move-object/from16 v1, p2

    .line 25
    .line 26
    iput-object v1, v0, Ly31/e;->g:Ljava/lang/String;

    .line 27
    .line 28
    move-object/from16 v1, p3

    .line 29
    .line 30
    iput-object v1, v0, Ly31/e;->h:Lay0/k;

    .line 31
    .line 32
    move-object/from16 v1, p4

    .line 33
    .line 34
    iput-object v1, v0, Ly31/e;->i:Lk31/i0;

    .line 35
    .line 36
    invoke-virtual/range {p5 .. p5}, Lk31/o;->invoke()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    check-cast v1, Li31/b;

    .line 41
    .line 42
    iput-object v1, v0, Ly31/e;->j:Li31/b;

    .line 43
    .line 44
    iget-object v1, v0, Lq41/b;->d:Lyy0/c2;

    .line 45
    .line 46
    :cond_0
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    move-object v4, v2

    .line 51
    check-cast v4, Ly31/g;

    .line 52
    .line 53
    iget-object v5, v0, Ly31/e;->j:Li31/b;

    .line 54
    .line 55
    const/4 v6, 0x0

    .line 56
    if-eqz v5, :cond_1

    .line 57
    .line 58
    iget-object v7, v5, Li31/b;->d:Ljava/lang/String;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    move-object v7, v6

    .line 62
    :goto_0
    if-eqz v5, :cond_2

    .line 63
    .line 64
    iget-object v5, v5, Li31/b;->c:Ljava/lang/Long;

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    move-object v5, v6

    .line 68
    :goto_1
    if-eqz v7, :cond_3

    .line 69
    .line 70
    if-eqz v5, :cond_3

    .line 71
    .line 72
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 73
    .line 74
    .line 75
    move-result-wide v8

    .line 76
    const-string v5, "dd MMMM yyyy"

    .line 77
    .line 78
    invoke-static {v8, v9, v5}, Lcom/google/android/gms/internal/measurement/i5;->b(JLjava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    const-string v8, ", "

    .line 83
    .line 84
    const-string v9, " hrs"

    .line 85
    .line 86
    invoke-static {v5, v8, v7, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    goto :goto_2

    .line 91
    :cond_3
    move-object v5, v6

    .line 92
    :goto_2
    const/4 v7, 0x3

    .line 93
    new-array v7, v7, [Ljava/util/List;

    .line 94
    .line 95
    iget-object v8, v0, Ly31/e;->j:Li31/b;

    .line 96
    .line 97
    const/16 v9, 0xa

    .line 98
    .line 99
    if-eqz v8, :cond_6

    .line 100
    .line 101
    iget-object v8, v8, Li31/b;->b:Li31/b0;

    .line 102
    .line 103
    iget-object v8, v8, Li31/b0;->a:Ljava/util/List;

    .line 104
    .line 105
    if-eqz v8, :cond_6

    .line 106
    .line 107
    check-cast v8, Ljava/lang/Iterable;

    .line 108
    .line 109
    new-instance v10, Ljava/util/ArrayList;

    .line 110
    .line 111
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 112
    .line 113
    .line 114
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    :cond_4
    :goto_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 119
    .line 120
    .line 121
    move-result v11

    .line 122
    if-eqz v11, :cond_5

    .line 123
    .line 124
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v11

    .line 128
    move-object v12, v11

    .line 129
    check-cast v12, Li31/a0;

    .line 130
    .line 131
    iget-boolean v12, v12, Li31/a0;->b:Z

    .line 132
    .line 133
    if-eqz v12, :cond_4

    .line 134
    .line 135
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    goto :goto_3

    .line 139
    :cond_5
    new-instance v8, Ljava/util/ArrayList;

    .line 140
    .line 141
    invoke-static {v10, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 142
    .line 143
    .line 144
    move-result v11

    .line 145
    invoke-direct {v8, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 149
    .line 150
    .line 151
    move-result-object v10

    .line 152
    :goto_4
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 153
    .line 154
    .line 155
    move-result v11

    .line 156
    if-eqz v11, :cond_7

    .line 157
    .line 158
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v11

    .line 162
    check-cast v11, Li31/a0;

    .line 163
    .line 164
    new-instance v12, Ly31/f;

    .line 165
    .line 166
    iget-object v11, v11, Li31/a0;->a:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast v11, Li31/g0;

    .line 169
    .line 170
    iget-object v11, v11, Li31/g0;->b:Ljava/lang/String;

    .line 171
    .line 172
    invoke-direct {v12, v11, v6}, Ly31/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_6
    move-object v8, v6

    .line 180
    :cond_7
    if-nez v8, :cond_8

    .line 181
    .line 182
    move-object v8, v3

    .line 183
    :cond_8
    const/4 v10, 0x0

    .line 184
    aput-object v8, v7, v10

    .line 185
    .line 186
    iget-object v8, v0, Ly31/e;->j:Li31/b;

    .line 187
    .line 188
    if-eqz v8, :cond_b

    .line 189
    .line 190
    iget-object v8, v8, Li31/b;->b:Li31/b0;

    .line 191
    .line 192
    iget-object v8, v8, Li31/b0;->b:Ljava/util/List;

    .line 193
    .line 194
    if-eqz v8, :cond_b

    .line 195
    .line 196
    check-cast v8, Ljava/lang/Iterable;

    .line 197
    .line 198
    new-instance v10, Ljava/util/ArrayList;

    .line 199
    .line 200
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 201
    .line 202
    .line 203
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 204
    .line 205
    .line 206
    move-result-object v8

    .line 207
    :cond_9
    :goto_5
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 208
    .line 209
    .line 210
    move-result v11

    .line 211
    if-eqz v11, :cond_a

    .line 212
    .line 213
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v11

    .line 217
    move-object v12, v11

    .line 218
    check-cast v12, Li31/a0;

    .line 219
    .line 220
    iget-boolean v12, v12, Li31/a0;->b:Z

    .line 221
    .line 222
    if-eqz v12, :cond_9

    .line 223
    .line 224
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    goto :goto_5

    .line 228
    :cond_a
    new-instance v8, Ljava/util/ArrayList;

    .line 229
    .line 230
    invoke-static {v10, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 231
    .line 232
    .line 233
    move-result v11

    .line 234
    invoke-direct {v8, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 238
    .line 239
    .line 240
    move-result-object v10

    .line 241
    :goto_6
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 242
    .line 243
    .line 244
    move-result v11

    .line 245
    if-eqz v11, :cond_c

    .line 246
    .line 247
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v11

    .line 251
    check-cast v11, Li31/a0;

    .line 252
    .line 253
    new-instance v12, Ly31/f;

    .line 254
    .line 255
    iget-object v11, v11, Li31/a0;->a:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast v11, Li31/z;

    .line 258
    .line 259
    iget-object v11, v11, Li31/z;->c:Ljava/lang/String;

    .line 260
    .line 261
    invoke-direct {v12, v11, v6}, Ly31/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    goto :goto_6

    .line 268
    :cond_b
    move-object v8, v6

    .line 269
    :cond_c
    if-nez v8, :cond_d

    .line 270
    .line 271
    move-object v8, v3

    .line 272
    :cond_d
    const/4 v10, 0x1

    .line 273
    aput-object v8, v7, v10

    .line 274
    .line 275
    iget-object v8, v0, Ly31/e;->j:Li31/b;

    .line 276
    .line 277
    if-eqz v8, :cond_12

    .line 278
    .line 279
    iget-object v8, v8, Li31/b;->b:Li31/b0;

    .line 280
    .line 281
    iget-object v8, v8, Li31/b0;->c:Ljava/util/List;

    .line 282
    .line 283
    if-eqz v8, :cond_12

    .line 284
    .line 285
    check-cast v8, Ljava/lang/Iterable;

    .line 286
    .line 287
    new-instance v10, Ljava/util/ArrayList;

    .line 288
    .line 289
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 290
    .line 291
    .line 292
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 293
    .line 294
    .line 295
    move-result-object v8

    .line 296
    :cond_e
    :goto_7
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 297
    .line 298
    .line 299
    move-result v11

    .line 300
    if-eqz v11, :cond_f

    .line 301
    .line 302
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v11

    .line 306
    move-object v12, v11

    .line 307
    check-cast v12, Li31/a0;

    .line 308
    .line 309
    iget-boolean v12, v12, Li31/a0;->b:Z

    .line 310
    .line 311
    if-eqz v12, :cond_e

    .line 312
    .line 313
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    goto :goto_7

    .line 317
    :cond_f
    new-instance v8, Ljava/util/ArrayList;

    .line 318
    .line 319
    invoke-static {v10, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 320
    .line 321
    .line 322
    move-result v9

    .line 323
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v10}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 327
    .line 328
    .line 329
    move-result-object v9

    .line 330
    :goto_8
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 331
    .line 332
    .line 333
    move-result v10

    .line 334
    if-eqz v10, :cond_13

    .line 335
    .line 336
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v10

    .line 340
    check-cast v10, Li31/a0;

    .line 341
    .line 342
    iget-object v10, v10, Li31/a0;->a:Ljava/lang/Object;

    .line 343
    .line 344
    check-cast v10, Li31/c0;

    .line 345
    .line 346
    iget-object v11, v10, Li31/c0;->d:Ljava/lang/String;

    .line 347
    .line 348
    iget-object v10, v10, Li31/c0;->e:Li31/f;

    .line 349
    .line 350
    if-eqz v10, :cond_10

    .line 351
    .line 352
    iget-wide v12, v10, Li31/f;->b:D

    .line 353
    .line 354
    iget-object v10, v10, Li31/f;->a:Ljava/lang/String;

    .line 355
    .line 356
    new-instance v14, Ljava/lang/StringBuilder;

    .line 357
    .line 358
    invoke-direct {v14}, Ljava/lang/StringBuilder;-><init>()V

    .line 359
    .line 360
    .line 361
    invoke-virtual {v14, v12, v13}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 362
    .line 363
    .line 364
    const-string v12, " "

    .line 365
    .line 366
    invoke-virtual {v14, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 367
    .line 368
    .line 369
    invoke-virtual {v14, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 370
    .line 371
    .line 372
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v10

    .line 376
    if-nez v10, :cond_11

    .line 377
    .line 378
    :cond_10
    iget-object v10, v0, Ly31/e;->g:Ljava/lang/String;

    .line 379
    .line 380
    :cond_11
    new-instance v12, Ly31/f;

    .line 381
    .line 382
    invoke-direct {v12, v11, v10}, Ly31/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 386
    .line 387
    .line 388
    goto :goto_8

    .line 389
    :cond_12
    move-object v8, v6

    .line 390
    :cond_13
    if-nez v8, :cond_14

    .line 391
    .line 392
    move-object v8, v3

    .line 393
    :cond_14
    const/4 v9, 0x2

    .line 394
    aput-object v8, v7, v9

    .line 395
    .line 396
    invoke-static {v7}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 397
    .line 398
    .line 399
    move-result-object v7

    .line 400
    check-cast v7, Ljava/lang/Iterable;

    .line 401
    .line 402
    invoke-static {v7}, Lmx0/o;->t(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 403
    .line 404
    .line 405
    move-result-object v7

    .line 406
    iget-object v8, v0, Ly31/e;->j:Li31/b;

    .line 407
    .line 408
    if-eqz v8, :cond_15

    .line 409
    .line 410
    iget-object v6, v8, Li31/b;->e:Ljava/lang/String;

    .line 411
    .line 412
    :cond_15
    iget-object v10, v0, Ly31/e;->f:Ljava/lang/String;

    .line 413
    .line 414
    const/4 v11, 0x0

    .line 415
    const/16 v12, 0x58

    .line 416
    .line 417
    const/4 v8, 0x0

    .line 418
    const/4 v9, 0x0

    .line 419
    move-object v15, v7

    .line 420
    move-object v7, v6

    .line 421
    move-object v6, v15

    .line 422
    invoke-static/range {v4 .. v12}, Ly31/g;->a(Ly31/g;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/Integer;I)Ly31/g;

    .line 423
    .line 424
    .line 425
    move-result-object v4

    .line 426
    invoke-virtual {v1, v2, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 427
    .line 428
    .line 429
    move-result v2

    .line 430
    if-eqz v2, :cond_0

    .line 431
    .line 432
    return-void
.end method
