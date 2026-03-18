.class public abstract Lm70/s0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/time/format/DateTimeFormatter;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "dd.MM.yy"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/time/format/DateTimeFormatter;->ofPattern(Ljava/lang/String;)Ljava/time/format/DateTimeFormatter;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lm70/s0;->a:Ljava/time/format/DateTimeFormatter;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lm70/c1;Ljava/util/List;Lqr0/s;ZLij0/a;)Lm70/c1;
    .locals 25

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    move-object/from16 v4, p0

    .line 10
    .line 11
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v3, "tripStatistics"

    .line 15
    .line 16
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v3, "unitsType"

    .line 20
    .line 21
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v3, "stringResource"

    .line 25
    .line 26
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    move-object v3, v0

    .line 30
    check-cast v3, Ljava/lang/Iterable;

    .line 31
    .line 32
    new-instance v5, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_0

    .line 46
    .line 47
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v6

    .line 51
    check-cast v6, Ll70/j;

    .line 52
    .line 53
    iget-object v6, v6, Ll70/j;->b:Ljava/util/List;

    .line 54
    .line 55
    check-cast v6, Ljava/lang/Iterable;

    .line 56
    .line 57
    invoke-static {v6, v5}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    new-instance v3, La5/f;

    .line 62
    .line 63
    const/16 v6, 0x18

    .line 64
    .line 65
    invoke-direct {v3, v6}, La5/f;-><init>(I)V

    .line 66
    .line 67
    .line 68
    invoke-static {v5, v3}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    check-cast v3, Ljava/lang/Iterable;

    .line 73
    .line 74
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 75
    .line 76
    invoke-direct {v5}, Ljava/util/LinkedHashMap;-><init>()V

    .line 77
    .line 78
    .line 79
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

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
    move-result v6

    .line 87
    const/4 v7, 0x1

    .line 88
    if-eqz v6, :cond_2

    .line 89
    .line 90
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    move-object v8, v6

    .line 95
    check-cast v8, Ll70/a;

    .line 96
    .line 97
    iget-object v8, v8, Ll70/a;->a:Ljava/time/LocalDate;

    .line 98
    .line 99
    invoke-static {v8, v7}, Ljp/e1;->c(Ljava/time/LocalDate;Z)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    invoke-virtual {v5, v7}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v8

    .line 107
    if-nez v8, :cond_1

    .line 108
    .line 109
    new-instance v8, Ljava/util/ArrayList;

    .line 110
    .line 111
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 112
    .line 113
    .line 114
    invoke-interface {v5, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    :cond_1
    check-cast v8, Ljava/util/List;

    .line 118
    .line 119
    invoke-interface {v8, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_2
    new-instance v10, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-interface {v5}, Ljava/util/Map;->size()I

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    invoke-direct {v10, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v5}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    if-eqz v5, :cond_b

    .line 145
    .line 146
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v5

    .line 150
    check-cast v5, Ljava/util/Map$Entry;

    .line 151
    .line 152
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    check-cast v9, Ljava/lang/String;

    .line 157
    .line 158
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v5

    .line 162
    check-cast v5, Ljava/util/List;

    .line 163
    .line 164
    check-cast v5, Ljava/lang/Iterable;

    .line 165
    .line 166
    new-instance v11, Ljava/util/ArrayList;

    .line 167
    .line 168
    const/16 v12, 0xa

    .line 169
    .line 170
    invoke-static {v5, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 171
    .line 172
    .line 173
    move-result v13

    .line 174
    invoke-direct {v11, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 175
    .line 176
    .line 177
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 182
    .line 183
    .line 184
    move-result v13

    .line 185
    if-eqz v13, :cond_a

    .line 186
    .line 187
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v13

    .line 191
    check-cast v13, Ll70/a;

    .line 192
    .line 193
    iget-object v14, v13, Ll70/a;->a:Ljava/time/LocalDate;

    .line 194
    .line 195
    invoke-virtual {v14}, Ljava/time/LocalDate;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 196
    .line 197
    .line 198
    move-result-object v15

    .line 199
    const-string v7, "getDayOfWeek(...)"

    .line 200
    .line 201
    invoke-static {v15, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 202
    .line 203
    .line 204
    invoke-static {v15}, Ljp/c1;->e(Ljava/time/DayOfWeek;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v7

    .line 208
    invoke-static {v14}, Lu7/b;->e(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v14

    .line 212
    const-string v15, ", "

    .line 213
    .line 214
    invoke-static {v7, v15, v14}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    iget-object v14, v13, Ll70/a;->c:Ll70/u;

    .line 219
    .line 220
    if-eqz v14, :cond_3

    .line 221
    .line 222
    invoke-static {v14}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v14

    .line 226
    :goto_4
    move-object/from16 v16, v9

    .line 227
    .line 228
    goto :goto_5

    .line 229
    :cond_3
    const/4 v14, 0x0

    .line 230
    goto :goto_4

    .line 231
    :goto_5
    iget-wide v8, v13, Ll70/a;->d:D

    .line 232
    .line 233
    sget-object v15, Lqr0/e;->e:Lqr0/e;

    .line 234
    .line 235
    invoke-static {v8, v9, v1, v15}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v8

    .line 239
    iget-object v9, v13, Ll70/a;->b:Ljava/util/ArrayList;

    .line 240
    .line 241
    new-instance v13, Ljava/util/ArrayList;

    .line 242
    .line 243
    invoke-static {v9, v12}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 244
    .line 245
    .line 246
    move-result v15

    .line 247
    invoke-direct {v13, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 248
    .line 249
    .line 250
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 251
    .line 252
    .line 253
    move-result-object v9

    .line 254
    :goto_6
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 255
    .line 256
    .line 257
    move-result v15

    .line 258
    if-eqz v15, :cond_9

    .line 259
    .line 260
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v15

    .line 264
    check-cast v15, Ll70/i;

    .line 265
    .line 266
    if-eqz p3, :cond_7

    .line 267
    .line 268
    new-instance v17, Lm70/y0;

    .line 269
    .line 270
    iget-object v12, v15, Ll70/i;->a:Ljava/lang/String;

    .line 271
    .line 272
    iget-object v6, v15, Ll70/i;->e:Ljava/time/LocalTime;

    .line 273
    .line 274
    if-eqz v6, :cond_4

    .line 275
    .line 276
    invoke-static {v6}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 277
    .line 278
    .line 279
    move-result-object v6

    .line 280
    :goto_7
    move-object/from16 v19, v6

    .line 281
    .line 282
    goto :goto_8

    .line 283
    :cond_4
    const-string v6, ""

    .line 284
    .line 285
    goto :goto_7

    .line 286
    :goto_8
    iget-object v6, v15, Ll70/i;->f:Ljava/time/LocalTime;

    .line 287
    .line 288
    invoke-static {v6}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v20

    .line 292
    iget-object v6, v15, Ll70/i;->c:Ljava/lang/String;

    .line 293
    .line 294
    if-nez v6, :cond_5

    .line 295
    .line 296
    const/4 v0, 0x0

    .line 297
    new-array v6, v0, [Ljava/lang/Object;

    .line 298
    .line 299
    move-object v0, v2

    .line 300
    check-cast v0, Ljj0/f;

    .line 301
    .line 302
    move-object/from16 v24, v3

    .line 303
    .line 304
    const v3, 0x7f121468

    .line 305
    .line 306
    .line 307
    invoke-virtual {v0, v3, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v6

    .line 311
    :goto_9
    move-object/from16 v21, v6

    .line 312
    .line 313
    goto :goto_a

    .line 314
    :cond_5
    move-object/from16 v24, v3

    .line 315
    .line 316
    const v3, 0x7f121468

    .line 317
    .line 318
    .line 319
    goto :goto_9

    .line 320
    :goto_a
    iget-object v0, v15, Ll70/i;->d:Ljava/lang/String;

    .line 321
    .line 322
    if-nez v0, :cond_6

    .line 323
    .line 324
    const/4 v6, 0x0

    .line 325
    new-array v0, v6, [Ljava/lang/Object;

    .line 326
    .line 327
    move-object v6, v2

    .line 328
    check-cast v6, Ljj0/f;

    .line 329
    .line 330
    invoke-virtual {v6, v3, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v0

    .line 334
    :cond_6
    move-object/from16 v22, v0

    .line 335
    .line 336
    iget-wide v3, v15, Ll70/i;->i:D

    .line 337
    .line 338
    sget-object v0, Lqr0/e;->e:Lqr0/e;

    .line 339
    .line 340
    invoke-static {v3, v4, v1, v0}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v23

    .line 344
    move-object/from16 v18, v12

    .line 345
    .line 346
    invoke-direct/range {v17 .. v23}, Lm70/y0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    move-object/from16 v0, v17

    .line 350
    .line 351
    const/4 v12, 0x0

    .line 352
    goto :goto_d

    .line 353
    :cond_7
    move-object/from16 v24, v3

    .line 354
    .line 355
    new-instance v18, Lm70/z0;

    .line 356
    .line 357
    iget-object v0, v15, Ll70/i;->a:Ljava/lang/String;

    .line 358
    .line 359
    iget-object v3, v15, Ll70/i;->f:Ljava/time/LocalTime;

    .line 360
    .line 361
    invoke-static {v3}, Lua0/g;->b(Ljava/time/LocalTime;)Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object v20

    .line 365
    iget-wide v3, v15, Ll70/i;->j:J

    .line 366
    .line 367
    const/4 v6, 0x6

    .line 368
    const/4 v12, 0x0

    .line 369
    invoke-static {v3, v4, v2, v12, v6}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v21

    .line 373
    iget-wide v3, v15, Ll70/i;->i:D

    .line 374
    .line 375
    sget-object v6, Lqr0/e;->e:Lqr0/e;

    .line 376
    .line 377
    invoke-static {v3, v4, v1, v6}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v22

    .line 381
    iget-object v3, v15, Ll70/i;->t:Ll70/u;

    .line 382
    .line 383
    if-eqz v3, :cond_8

    .line 384
    .line 385
    invoke-static {v3}, Ljp/p0;->d(Ll70/u;)Ljava/lang/String;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    move-object/from16 v23, v3

    .line 390
    .line 391
    :goto_b
    move-object/from16 v19, v0

    .line 392
    .line 393
    goto :goto_c

    .line 394
    :cond_8
    const/16 v23, 0x0

    .line 395
    .line 396
    goto :goto_b

    .line 397
    :goto_c
    invoke-direct/range {v18 .. v23}, Lm70/z0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 398
    .line 399
    .line 400
    move-object/from16 v0, v18

    .line 401
    .line 402
    :goto_d
    invoke-virtual {v13, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-object/from16 v4, p0

    .line 406
    .line 407
    move-object/from16 v0, p1

    .line 408
    .line 409
    move-object/from16 v3, v24

    .line 410
    .line 411
    const/16 v12, 0xa

    .line 412
    .line 413
    goto/16 :goto_6

    .line 414
    .line 415
    :cond_9
    move-object/from16 v24, v3

    .line 416
    .line 417
    const/4 v12, 0x0

    .line 418
    new-instance v0, Lm70/x0;

    .line 419
    .line 420
    invoke-direct {v0, v7, v13, v14, v8}, Lm70/x0;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v11, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    const/4 v7, 0x1

    .line 427
    const/16 v12, 0xa

    .line 428
    .line 429
    move-object/from16 v4, p0

    .line 430
    .line 431
    move-object/from16 v0, p1

    .line 432
    .line 433
    move-object/from16 v9, v16

    .line 434
    .line 435
    goto/16 :goto_3

    .line 436
    .line 437
    :cond_a
    move-object/from16 v24, v3

    .line 438
    .line 439
    move-object/from16 v16, v9

    .line 440
    .line 441
    new-instance v0, Lm70/b1;

    .line 442
    .line 443
    invoke-direct {v0, v9, v11}, Lm70/b1;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 447
    .line 448
    .line 449
    const/4 v7, 0x1

    .line 450
    move-object/from16 v4, p0

    .line 451
    .line 452
    move-object/from16 v0, p1

    .line 453
    .line 454
    goto/16 :goto_2

    .line 455
    .line 456
    :cond_b
    const/4 v12, 0x0

    .line 457
    invoke-static/range {p1 .. p1}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v0

    .line 461
    check-cast v0, Ll70/j;

    .line 462
    .line 463
    if-eqz v0, :cond_c

    .line 464
    .line 465
    iget-object v8, v0, Ll70/j;->c:Ljava/lang/String;

    .line 466
    .line 467
    goto :goto_e

    .line 468
    :cond_c
    const/4 v8, 0x0

    .line 469
    :goto_e
    if-eqz v8, :cond_d

    .line 470
    .line 471
    const/4 v11, 0x1

    .line 472
    goto :goto_f

    .line 473
    :cond_d
    move v11, v12

    .line 474
    :goto_f
    const/4 v13, 0x0

    .line 475
    const/16 v15, 0x193

    .line 476
    .line 477
    const/4 v5, 0x0

    .line 478
    const/4 v6, 0x0

    .line 479
    const/4 v7, 0x0

    .line 480
    const/4 v8, 0x0

    .line 481
    const/4 v9, 0x0

    .line 482
    const/4 v12, 0x0

    .line 483
    move-object/from16 v4, p0

    .line 484
    .line 485
    move/from16 v14, p3

    .line 486
    .line 487
    invoke-static/range {v4 .. v15}, Lm70/c1;->a(Lm70/c1;Llf0/i;Ler0/g;ZZZLjava/util/List;ZLl70/k;Ljava/lang/String;ZI)Lm70/c1;

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    return-object v0
.end method
