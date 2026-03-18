.class public final Lvp/d;
.super Lvp/u3;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public h:Ljava/lang/String;

.field public i:Ljava/util/HashSet;

.field public j:Landroidx/collection/f;

.field public k:Ljava/lang/Long;

.field public l:Ljava/lang/Long;


# virtual methods
.method public final d0()V
    .locals 0

    .line 1
    return-void
.end method

.method public final e0(Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/lang/Long;Ljava/lang/Long;Z)Ljava/util/ArrayList;
    .locals 40

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    const-string v8, "current_results"

    .line 4
    .line 5
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v9, v0

    .line 8
    check-cast v9, Lvp/g1;

    .line 9
    .line 10
    invoke-static/range {p1 .. p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-static/range {p2 .. p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-static/range {p3 .. p3}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v0, p1

    .line 20
    .line 21
    iput-object v0, v1, Lvp/d;->h:Ljava/lang/String;

    .line 22
    .line 23
    new-instance v0, Ljava/util/HashSet;

    .line 24
    .line 25
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object v0, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 29
    .line 30
    new-instance v0, Landroidx/collection/f;

    .line 31
    .line 32
    invoke-direct {v0}, Landroidx/collection/f;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 36
    .line 37
    move-object/from16 v0, p4

    .line 38
    .line 39
    iput-object v0, v1, Lvp/d;->k:Ljava/lang/Long;

    .line 40
    .line 41
    move-object/from16 v0, p5

    .line 42
    .line 43
    iput-object v0, v1, Lvp/d;->l:Ljava/lang/Long;

    .line 44
    .line 45
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    const/4 v10, 0x0

    .line 54
    if-eqz v2, :cond_1

    .line 55
    .line 56
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    check-cast v2, Lcom/google/android/gms/internal/measurement/b3;

    .line 61
    .line 62
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    const-string v3, "_s"

    .line 67
    .line 68
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_0

    .line 73
    .line 74
    const/4 v2, 0x1

    .line 75
    goto :goto_0

    .line 76
    :cond_1
    move v2, v10

    .line 77
    :goto_0
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 78
    .line 79
    .line 80
    iget-object v0, v9, Lvp/g1;->g:Lvp/h;

    .line 81
    .line 82
    iget-object v3, v1, Lvp/d;->h:Ljava/lang/String;

    .line 83
    .line 84
    sget-object v4, Lvp/z;->F0:Lvp/y;

    .line 85
    .line 86
    invoke-virtual {v0, v3, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 87
    .line 88
    .line 89
    move-result v12

    .line 90
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 91
    .line 92
    .line 93
    iget-object v0, v9, Lvp/g1;->g:Lvp/h;

    .line 94
    .line 95
    iget-object v3, v1, Lvp/d;->h:Ljava/lang/String;

    .line 96
    .line 97
    sget-object v4, Lvp/z;->E0:Lvp/y;

    .line 98
    .line 99
    invoke-virtual {v0, v3, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 100
    .line 101
    .line 102
    move-result v13

    .line 103
    const-string v14, "events"

    .line 104
    .line 105
    iget-object v15, v1, Lvp/q3;->f:Lvp/z3;

    .line 106
    .line 107
    if-eqz v2, :cond_2

    .line 108
    .line 109
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    iget-object v4, v1, Lvp/d;->h:Ljava/lang/String;

    .line 114
    .line 115
    invoke-virtual {v3}, Lvp/u3;->b0()V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v3}, Lap0/o;->a0()V

    .line 119
    .line 120
    .line 121
    invoke-static {v4}, Lno/c0;->e(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    new-instance v0, Landroid/content/ContentValues;

    .line 125
    .line 126
    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 127
    .line 128
    .line 129
    const-string v5, "current_session_count"

    .line 130
    .line 131
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    invoke-virtual {v0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 136
    .line 137
    .line 138
    :try_start_0
    invoke-virtual {v3}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 139
    .line 140
    .line 141
    move-result-object v5

    .line 142
    const-string v6, "app_id = ?"

    .line 143
    .line 144
    filled-new-array {v4}, [Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    invoke-virtual {v5, v14, v0, v6, v7}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 149
    .line 150
    .line 151
    goto :goto_1

    .line 152
    :catch_0
    move-exception v0

    .line 153
    iget-object v3, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast v3, Lvp/g1;

    .line 156
    .line 157
    invoke-virtual {v3}, Lvp/g1;->d()Lvp/p0;

    .line 158
    .line 159
    .line 160
    move-result-object v3

    .line 161
    invoke-virtual {v3}, Lvp/p0;->e0()Lvp/n0;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    const-string v5, "Error resetting session-scoped event counts. appId"

    .line 170
    .line 171
    invoke-virtual {v3, v4, v0, v5}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    :cond_2
    :goto_1
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 175
    .line 176
    const-string v3, "Failed to merge filter. appId"

    .line 177
    .line 178
    const-string v4, "Database error querying filters. appId"

    .line 179
    .line 180
    const-string v5, "data"

    .line 181
    .line 182
    const-string v6, "audience_id"

    .line 183
    .line 184
    if-eqz v13, :cond_9

    .line 185
    .line 186
    if-eqz v12, :cond_9

    .line 187
    .line 188
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    iget-object v10, v7, Lap0/o;->e:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v10, Lvp/g1;

    .line 195
    .line 196
    iget-object v11, v1, Lvp/d;->h:Ljava/lang/String;

    .line 197
    .line 198
    invoke-static {v11}, Lno/c0;->e(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    move/from16 p4, v2

    .line 202
    .line 203
    new-instance v2, Landroidx/collection/f;

    .line 204
    .line 205
    invoke-direct {v2}, Landroidx/collection/f;-><init>()V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v7}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 209
    .line 210
    .line 211
    move-result-object v17

    .line 212
    :try_start_1
    const-string v18, "event_filters"

    .line 213
    .line 214
    filled-new-array {v6, v5}, [Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v19

    .line 218
    const-string v20, "app_id=?"

    .line 219
    .line 220
    filled-new-array {v11}, [Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v21

    .line 224
    const/16 v23, 0x0

    .line 225
    .line 226
    const/16 v24, 0x0

    .line 227
    .line 228
    const/16 v22, 0x0

    .line 229
    .line 230
    invoke-virtual/range {v17 .. v24}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 231
    .line 232
    .line 233
    move-result-object v7
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_5
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 234
    :try_start_2
    invoke-interface {v7}, Landroid/database/Cursor;->moveToFirst()Z

    .line 235
    .line 236
    .line 237
    move-result v17
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_4
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 238
    if-eqz v17, :cond_6

    .line 239
    .line 240
    move-object/from16 p5, v5

    .line 241
    .line 242
    :goto_2
    const/4 v5, 0x1

    .line 243
    :try_start_3
    invoke-interface {v7, v5}, Landroid/database/Cursor;->getBlob(I)[B

    .line 244
    .line 245
    .line 246
    move-result-object v0
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 247
    :try_start_4
    invoke-static {}, Lcom/google/android/gms/internal/measurement/o1;->B()Lcom/google/android/gms/internal/measurement/n1;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    invoke-static {v5, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    check-cast v0, Lcom/google/android/gms/internal/measurement/n1;

    .line 256
    .line 257
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 258
    .line 259
    .line 260
    move-result-object v0

    .line 261
    check-cast v0, Lcom/google/android/gms/internal/measurement/o1;
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 262
    .line 263
    :try_start_5
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 264
    .line 265
    .line 266
    move-result v5

    .line 267
    if-nez v5, :cond_3

    .line 268
    .line 269
    move-object/from16 v18, v7

    .line 270
    .line 271
    goto :goto_5

    .line 272
    :cond_3
    const/4 v5, 0x0

    .line 273
    invoke-interface {v7, v5}, Landroid/database/Cursor;->getInt(I)I

    .line 274
    .line 275
    .line 276
    move-result v17

    .line 277
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 278
    .line 279
    .line 280
    move-result-object v5

    .line 281
    invoke-interface {v2, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v17

    .line 285
    check-cast v17, Ljava/util/List;
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_2
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 286
    .line 287
    if-nez v17, :cond_4

    .line 288
    .line 289
    move-object/from16 v18, v7

    .line 290
    .line 291
    :try_start_6
    new-instance v7, Ljava/util/ArrayList;

    .line 292
    .line 293
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 294
    .line 295
    .line 296
    invoke-interface {v2, v5, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    goto :goto_3

    .line 300
    :catchall_0
    move-exception v0

    .line 301
    goto :goto_7

    .line 302
    :catch_1
    move-exception v0

    .line 303
    goto :goto_8

    .line 304
    :cond_4
    move-object/from16 v18, v7

    .line 305
    .line 306
    move-object/from16 v7, v17

    .line 307
    .line 308
    :goto_3
    invoke-interface {v7, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    goto :goto_5

    .line 312
    :catchall_1
    move-exception v0

    .line 313
    move-object/from16 v18, v7

    .line 314
    .line 315
    goto :goto_7

    .line 316
    :catch_2
    move-exception v0

    .line 317
    :goto_4
    move-object/from16 v18, v7

    .line 318
    .line 319
    goto :goto_8

    .line 320
    :catch_3
    move-exception v0

    .line 321
    move-object/from16 v18, v7

    .line 322
    .line 323
    invoke-virtual {v10}, Lvp/g1;->d()Lvp/p0;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    invoke-virtual {v5}, Lvp/p0;->e0()Lvp/n0;

    .line 328
    .line 329
    .line 330
    move-result-object v5

    .line 331
    invoke-static {v11}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 332
    .line 333
    .line 334
    move-result-object v7

    .line 335
    invoke-virtual {v5, v7, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    :goto_5
    invoke-interface/range {v18 .. v18}, Landroid/database/Cursor;->moveToNext()Z

    .line 339
    .line 340
    .line 341
    move-result v0
    :try_end_6
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 342
    if-nez v0, :cond_5

    .line 343
    .line 344
    invoke-interface/range {v18 .. v18}, Landroid/database/Cursor;->close()V

    .line 345
    .line 346
    .line 347
    move-object v10, v2

    .line 348
    goto :goto_d

    .line 349
    :cond_5
    move-object/from16 v7, v18

    .line 350
    .line 351
    goto :goto_2

    .line 352
    :cond_6
    move-object/from16 p5, v5

    .line 353
    .line 354
    move-object/from16 v18, v7

    .line 355
    .line 356
    invoke-interface/range {v18 .. v18}, Landroid/database/Cursor;->close()V

    .line 357
    .line 358
    .line 359
    :cond_7
    :goto_6
    move-object v10, v0

    .line 360
    goto :goto_d

    .line 361
    :goto_7
    move-object/from16 v7, v18

    .line 362
    .line 363
    goto :goto_c

    .line 364
    :catch_4
    move-exception v0

    .line 365
    move-object/from16 p5, v5

    .line 366
    .line 367
    goto :goto_4

    .line 368
    :goto_8
    move-object/from16 v7, v18

    .line 369
    .line 370
    goto :goto_b

    .line 371
    :catchall_2
    move-exception v0

    .line 372
    goto :goto_9

    .line 373
    :catch_5
    move-exception v0

    .line 374
    move-object/from16 p5, v5

    .line 375
    .line 376
    goto :goto_a

    .line 377
    :goto_9
    const/4 v7, 0x0

    .line 378
    goto :goto_c

    .line 379
    :goto_a
    const/4 v7, 0x0

    .line 380
    :goto_b
    :try_start_7
    invoke-virtual {v10}, Lvp/g1;->d()Lvp/p0;

    .line 381
    .line 382
    .line 383
    move-result-object v2

    .line 384
    invoke-virtual {v2}, Lvp/p0;->e0()Lvp/n0;

    .line 385
    .line 386
    .line 387
    move-result-object v2

    .line 388
    invoke-static {v11}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 389
    .line 390
    .line 391
    move-result-object v5

    .line 392
    invoke-virtual {v2, v5, v0, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 393
    .line 394
    .line 395
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 396
    .line 397
    if-eqz v7, :cond_7

    .line 398
    .line 399
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 400
    .line 401
    .line 402
    goto :goto_6

    .line 403
    :catchall_3
    move-exception v0

    .line 404
    :goto_c
    if-eqz v7, :cond_8

    .line 405
    .line 406
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 407
    .line 408
    .line 409
    :cond_8
    throw v0

    .line 410
    :cond_9
    move/from16 p4, v2

    .line 411
    .line 412
    move-object/from16 p5, v5

    .line 413
    .line 414
    goto :goto_6

    .line 415
    :goto_d
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast v2, Lvp/g1;

    .line 422
    .line 423
    iget-object v5, v1, Lvp/d;->h:Ljava/lang/String;

    .line 424
    .line 425
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 426
    .line 427
    .line 428
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 429
    .line 430
    .line 431
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 435
    .line 436
    .line 437
    move-result-object v17

    .line 438
    :try_start_8
    const-string v18, "audience_filter_values"

    .line 439
    .line 440
    filled-new-array {v6, v8}, [Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v19

    .line 444
    const-string v20, "app_id=?"

    .line 445
    .line 446
    filled-new-array {v5}, [Ljava/lang/String;

    .line 447
    .line 448
    .line 449
    move-result-object v21

    .line 450
    const/16 v23, 0x0

    .line 451
    .line 452
    const/16 v24, 0x0

    .line 453
    .line 454
    const/16 v22, 0x0

    .line 455
    .line 456
    invoke-virtual/range {v17 .. v24}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 457
    .line 458
    .line 459
    move-result-object v7
    :try_end_8
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_c
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 460
    :try_start_9
    invoke-interface {v7}, Landroid/database/Cursor;->moveToFirst()Z

    .line 461
    .line 462
    .line 463
    move-result v0

    .line 464
    if-nez v0, :cond_a

    .line 465
    .line 466
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_9
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_9 .. :try_end_9} :catch_6
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 467
    .line 468
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 469
    .line 470
    .line 471
    move-object v11, v0

    .line 472
    move-object/from16 v19, v3

    .line 473
    .line 474
    move-object/from16 v20, v4

    .line 475
    .line 476
    goto/16 :goto_16

    .line 477
    .line 478
    :catchall_4
    move-exception v0

    .line 479
    goto/16 :goto_5f

    .line 480
    .line 481
    :catch_6
    move-exception v0

    .line 482
    move-object/from16 v17, v2

    .line 483
    .line 484
    :goto_e
    move-object/from16 v19, v3

    .line 485
    .line 486
    :goto_f
    move-object/from16 v20, v4

    .line 487
    .line 488
    :goto_10
    move-object/from16 v21, v5

    .line 489
    .line 490
    goto/16 :goto_15

    .line 491
    .line 492
    :cond_a
    :try_start_a
    new-instance v11, Landroidx/collection/f;

    .line 493
    .line 494
    invoke-direct {v11}, Landroidx/collection/f;-><init>()V
    :try_end_a
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_a .. :try_end_a} :catch_6
    .catchall {:try_start_a .. :try_end_a} :catchall_4

    .line 495
    .line 496
    .line 497
    move-object/from16 v17, v2

    .line 498
    .line 499
    :goto_11
    const/4 v2, 0x0

    .line 500
    :try_start_b
    invoke-interface {v7, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 501
    .line 502
    .line 503
    move-result v18

    .line 504
    const/4 v2, 0x1

    .line 505
    invoke-interface {v7, v2}, Landroid/database/Cursor;->getBlob(I)[B

    .line 506
    .line 507
    .line 508
    move-result-object v0
    :try_end_b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_b .. :try_end_b} :catch_7
    .catchall {:try_start_b .. :try_end_b} :catchall_4

    .line 509
    :try_start_c
    invoke-static {}, Lcom/google/android/gms/internal/measurement/m3;->x()Lcom/google/android/gms/internal/measurement/l3;

    .line 510
    .line 511
    .line 512
    move-result-object v2

    .line 513
    invoke-static {v2, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    check-cast v0, Lcom/google/android/gms/internal/measurement/l3;

    .line 518
    .line 519
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    check-cast v0, Lcom/google/android/gms/internal/measurement/m3;
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_8
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_c .. :try_end_c} :catch_7
    .catchall {:try_start_c .. :try_end_c} :catchall_4

    .line 524
    .line 525
    :try_start_d
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 526
    .line 527
    .line 528
    move-result-object v2

    .line 529
    invoke-interface {v11, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-object/from16 v19, v3

    .line 533
    .line 534
    move-object/from16 v20, v4

    .line 535
    .line 536
    move-object/from16 v21, v5

    .line 537
    .line 538
    goto :goto_12

    .line 539
    :catch_7
    move-exception v0

    .line 540
    goto :goto_e

    .line 541
    :catch_8
    move-exception v0

    .line 542
    invoke-virtual/range {v17 .. v17}, Lvp/g1;->d()Lvp/p0;

    .line 543
    .line 544
    .line 545
    move-result-object v2

    .line 546
    invoke-virtual {v2}, Lvp/p0;->e0()Lvp/n0;

    .line 547
    .line 548
    .line 549
    move-result-object v2
    :try_end_d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_d .. :try_end_d} :catch_7
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    .line 550
    move-object/from16 v19, v3

    .line 551
    .line 552
    :try_start_e
    const-string v3, "Failed to merge filter results. appId, audienceId, error"
    :try_end_e
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_e .. :try_end_e} :catch_b
    .catchall {:try_start_e .. :try_end_e} :catchall_4

    .line 553
    .line 554
    move-object/from16 v20, v4

    .line 555
    .line 556
    :try_start_f
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 557
    .line 558
    .line 559
    move-result-object v4
    :try_end_f
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_f .. :try_end_f} :catch_a
    .catchall {:try_start_f .. :try_end_f} :catchall_4

    .line 560
    move-object/from16 v21, v5

    .line 561
    .line 562
    :try_start_10
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 563
    .line 564
    .line 565
    move-result-object v5

    .line 566
    invoke-virtual {v2, v3, v4, v5, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 567
    .line 568
    .line 569
    :goto_12
    invoke-interface {v7}, Landroid/database/Cursor;->moveToNext()Z

    .line 570
    .line 571
    .line 572
    move-result v0
    :try_end_10
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_10 .. :try_end_10} :catch_9
    .catchall {:try_start_10 .. :try_end_10} :catchall_4

    .line 573
    if-nez v0, :cond_b

    .line 574
    .line 575
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 576
    .line 577
    .line 578
    goto :goto_16

    .line 579
    :cond_b
    move-object/from16 v3, v19

    .line 580
    .line 581
    move-object/from16 v4, v20

    .line 582
    .line 583
    move-object/from16 v5, v21

    .line 584
    .line 585
    goto :goto_11

    .line 586
    :catch_9
    move-exception v0

    .line 587
    goto :goto_15

    .line 588
    :catch_a
    move-exception v0

    .line 589
    goto :goto_10

    .line 590
    :catch_b
    move-exception v0

    .line 591
    goto :goto_f

    .line 592
    :catchall_5
    move-exception v0

    .line 593
    goto :goto_13

    .line 594
    :catch_c
    move-exception v0

    .line 595
    move-object/from16 v17, v2

    .line 596
    .line 597
    move-object/from16 v19, v3

    .line 598
    .line 599
    move-object/from16 v20, v4

    .line 600
    .line 601
    move-object/from16 v21, v5

    .line 602
    .line 603
    goto :goto_14

    .line 604
    :goto_13
    const/4 v7, 0x0

    .line 605
    goto/16 :goto_5f

    .line 606
    .line 607
    :goto_14
    const/4 v7, 0x0

    .line 608
    :goto_15
    :try_start_11
    invoke-virtual/range {v17 .. v17}, Lvp/g1;->d()Lvp/p0;

    .line 609
    .line 610
    .line 611
    move-result-object v2

    .line 612
    invoke-virtual {v2}, Lvp/p0;->e0()Lvp/n0;

    .line 613
    .line 614
    .line 615
    move-result-object v2

    .line 616
    const-string v3, "Database error querying filter results. appId"

    .line 617
    .line 618
    invoke-static/range {v21 .. v21}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 619
    .line 620
    .line 621
    move-result-object v4

    .line 622
    invoke-virtual {v2, v4, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 623
    .line 624
    .line 625
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_4

    .line 626
    .line 627
    if-eqz v7, :cond_c

    .line 628
    .line 629
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 630
    .line 631
    .line 632
    :cond_c
    move-object v11, v0

    .line 633
    :goto_16
    invoke-interface {v11}, Ljava/util/Map;->isEmpty()Z

    .line 634
    .line 635
    .line 636
    move-result v0

    .line 637
    if-eqz v0, :cond_d

    .line 638
    .line 639
    move-object v13, v6

    .line 640
    move-object/from16 v24, v9

    .line 641
    .line 642
    :goto_17
    move-object/from16 v11, p5

    .line 643
    .line 644
    move-object/from16 v9, v19

    .line 645
    .line 646
    move-object/from16 v10, v20

    .line 647
    .line 648
    goto/16 :goto_31

    .line 649
    .line 650
    :cond_d
    new-instance v2, Ljava/util/HashSet;

    .line 651
    .line 652
    invoke-interface {v11}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 653
    .line 654
    .line 655
    move-result-object v0

    .line 656
    invoke-direct {v2, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 657
    .line 658
    .line 659
    if-eqz p4, :cond_1c

    .line 660
    .line 661
    iget-object v3, v1, Lvp/d;->h:Ljava/lang/String;

    .line 662
    .line 663
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 664
    .line 665
    .line 666
    move-result-object v4

    .line 667
    iget-object v5, v1, Lvp/d;->h:Ljava/lang/String;

    .line 668
    .line 669
    invoke-virtual {v4}, Lvp/u3;->b0()V

    .line 670
    .line 671
    .line 672
    invoke-virtual {v4}, Lap0/o;->a0()V

    .line 673
    .line 674
    .line 675
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 676
    .line 677
    .line 678
    new-instance v0, Landroidx/collection/f;

    .line 679
    .line 680
    invoke-direct {v0}, Landroidx/collection/f;-><init>()V

    .line 681
    .line 682
    .line 683
    invoke-virtual {v4}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 684
    .line 685
    .line 686
    move-result-object v7

    .line 687
    move-object/from16 p4, v2

    .line 688
    .line 689
    :try_start_12
    const-string v2, "select audience_id, filter_id from event_filters where app_id = ? and session_scoped = 1 UNION select audience_id, filter_id from property_filters where app_id = ? and session_scoped = 1;"
    :try_end_12
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_12 .. :try_end_12} :catch_f
    .catchall {:try_start_12 .. :try_end_12} :catchall_7

    .line 690
    .line 691
    move-object/from16 v17, v3

    .line 692
    .line 693
    :try_start_13
    filled-new-array {v5, v5}, [Ljava/lang/String;

    .line 694
    .line 695
    .line 696
    move-result-object v3

    .line 697
    invoke-virtual {v7, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 698
    .line 699
    .line 700
    move-result-object v2
    :try_end_13
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_13 .. :try_end_13} :catch_e
    .catchall {:try_start_13 .. :try_end_13} :catchall_7

    .line 701
    :try_start_14
    invoke-interface {v2}, Landroid/database/Cursor;->moveToFirst()Z

    .line 702
    .line 703
    .line 704
    move-result v3

    .line 705
    if-eqz v3, :cond_10

    .line 706
    .line 707
    :cond_e
    const/4 v3, 0x0

    .line 708
    invoke-interface {v2, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 709
    .line 710
    .line 711
    move-result v7

    .line 712
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 713
    .line 714
    .line 715
    move-result-object v3

    .line 716
    invoke-interface {v0, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v7

    .line 720
    check-cast v7, Ljava/util/List;

    .line 721
    .line 722
    if-nez v7, :cond_f

    .line 723
    .line 724
    new-instance v7, Ljava/util/ArrayList;

    .line 725
    .line 726
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 727
    .line 728
    .line 729
    invoke-interface {v0, v3, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    :cond_f
    const/4 v3, 0x1

    .line 733
    goto :goto_18

    .line 734
    :catchall_6
    move-exception v0

    .line 735
    goto :goto_1a

    .line 736
    :catch_d
    move-exception v0

    .line 737
    goto :goto_1d

    .line 738
    :goto_18
    invoke-interface {v2, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 739
    .line 740
    .line 741
    move-result v18

    .line 742
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 743
    .line 744
    .line 745
    move-result-object v3

    .line 746
    invoke-interface {v7, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 747
    .line 748
    .line 749
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 750
    .line 751
    .line 752
    move-result v3
    :try_end_14
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_14 .. :try_end_14} :catch_d
    .catchall {:try_start_14 .. :try_end_14} :catchall_6

    .line 753
    if-nez v3, :cond_e

    .line 754
    .line 755
    :goto_19
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 756
    .line 757
    .line 758
    goto :goto_1e

    .line 759
    :cond_10
    :try_start_15
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_15
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_15 .. :try_end_15} :catch_d
    .catchall {:try_start_15 .. :try_end_15} :catchall_6

    .line 760
    .line 761
    goto :goto_19

    .line 762
    :goto_1a
    move-object v7, v2

    .line 763
    goto/16 :goto_25

    .line 764
    .line 765
    :catchall_7
    move-exception v0

    .line 766
    goto :goto_1b

    .line 767
    :catch_e
    move-exception v0

    .line 768
    goto :goto_1c

    .line 769
    :goto_1b
    const/4 v7, 0x0

    .line 770
    goto/16 :goto_25

    .line 771
    .line 772
    :catch_f
    move-exception v0

    .line 773
    move-object/from16 v17, v3

    .line 774
    .line 775
    :goto_1c
    const/4 v2, 0x0

    .line 776
    :goto_1d
    :try_start_16
    iget-object v3, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 777
    .line 778
    check-cast v3, Lvp/g1;

    .line 779
    .line 780
    invoke-virtual {v3}, Lvp/g1;->d()Lvp/p0;

    .line 781
    .line 782
    .line 783
    move-result-object v3

    .line 784
    invoke-virtual {v3}, Lvp/p0;->e0()Lvp/n0;

    .line 785
    .line 786
    .line 787
    move-result-object v3

    .line 788
    const-string v4, "Database error querying scoped filters. appId"

    .line 789
    .line 790
    invoke-static {v5}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 791
    .line 792
    .line 793
    move-result-object v5

    .line 794
    invoke-virtual {v3, v5, v0, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 795
    .line 796
    .line 797
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_16
    .catchall {:try_start_16 .. :try_end_16} :catchall_6

    .line 798
    .line 799
    if-eqz v2, :cond_11

    .line 800
    .line 801
    goto :goto_19

    .line 802
    :cond_11
    :goto_1e
    invoke-static/range {v17 .. v17}, Lno/c0;->e(Ljava/lang/String;)V

    .line 803
    .line 804
    .line 805
    new-instance v2, Landroidx/collection/f;

    .line 806
    .line 807
    invoke-direct {v2}, Landroidx/collection/f;-><init>()V

    .line 808
    .line 809
    .line 810
    invoke-interface {v11}, Ljava/util/Map;->isEmpty()Z

    .line 811
    .line 812
    .line 813
    move-result v3

    .line 814
    if-eqz v3, :cond_13

    .line 815
    .line 816
    :cond_12
    move-object/from16 v22, v6

    .line 817
    .line 818
    move-object/from16 v24, v9

    .line 819
    .line 820
    goto/16 :goto_24

    .line 821
    .line 822
    :cond_13
    invoke-interface {v11}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 823
    .line 824
    .line 825
    move-result-object v3

    .line 826
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 827
    .line 828
    .line 829
    move-result-object v3

    .line 830
    :goto_1f
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 831
    .line 832
    .line 833
    move-result v4

    .line 834
    if-eqz v4, :cond_12

    .line 835
    .line 836
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 837
    .line 838
    .line 839
    move-result-object v4

    .line 840
    check-cast v4, Ljava/lang/Integer;

    .line 841
    .line 842
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 843
    .line 844
    .line 845
    invoke-interface {v11, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 846
    .line 847
    .line 848
    move-result-object v5

    .line 849
    check-cast v5, Lcom/google/android/gms/internal/measurement/m3;

    .line 850
    .line 851
    invoke-interface {v0, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 852
    .line 853
    .line 854
    move-result-object v7

    .line 855
    check-cast v7, Ljava/util/List;

    .line 856
    .line 857
    if-eqz v7, :cond_14

    .line 858
    .line 859
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 860
    .line 861
    .line 862
    move-result v17

    .line 863
    if-eqz v17, :cond_15

    .line 864
    .line 865
    :cond_14
    move-object/from16 v17, v0

    .line 866
    .line 867
    move-object/from16 v21, v3

    .line 868
    .line 869
    move-object/from16 v22, v6

    .line 870
    .line 871
    move-object/from16 v24, v9

    .line 872
    .line 873
    goto/16 :goto_23

    .line 874
    .line 875
    :cond_15
    move-object/from16 v17, v0

    .line 876
    .line 877
    invoke-virtual {v15}, Lvp/z3;->i0()Lvp/s0;

    .line 878
    .line 879
    .line 880
    move-result-object v0

    .line 881
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/m3;->r()Ljava/util/List;

    .line 882
    .line 883
    .line 884
    move-result-object v18

    .line 885
    move-object/from16 v21, v3

    .line 886
    .line 887
    move-object/from16 v3, v18

    .line 888
    .line 889
    check-cast v3, Lcom/google/android/gms/internal/measurement/q5;

    .line 890
    .line 891
    invoke-virtual {v0, v3, v7}, Lvp/s0;->J0(Lcom/google/android/gms/internal/measurement/q5;Ljava/util/List;)Ljava/util/List;

    .line 892
    .line 893
    .line 894
    move-result-object v0

    .line 895
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 896
    .line 897
    .line 898
    move-result v3

    .line 899
    if-nez v3, :cond_1a

    .line 900
    .line 901
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/l5;->i()Lcom/google/android/gms/internal/measurement/k5;

    .line 902
    .line 903
    .line 904
    move-result-object v3

    .line 905
    check-cast v3, Lcom/google/android/gms/internal/measurement/l3;

    .line 906
    .line 907
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/l3;->j()V

    .line 908
    .line 909
    .line 910
    check-cast v0, Ljava/util/List;

    .line 911
    .line 912
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 913
    .line 914
    .line 915
    move-object/from16 v18, v0

    .line 916
    .line 917
    iget-object v0, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 918
    .line 919
    check-cast v0, Lcom/google/android/gms/internal/measurement/m3;

    .line 920
    .line 921
    move-object/from16 v22, v6

    .line 922
    .line 923
    move-object/from16 v6, v18

    .line 924
    .line 925
    check-cast v6, Ljava/util/List;

    .line 926
    .line 927
    invoke-virtual {v0, v6}, Lcom/google/android/gms/internal/measurement/m3;->B(Ljava/util/List;)V

    .line 928
    .line 929
    .line 930
    invoke-virtual {v15}, Lvp/z3;->i0()Lvp/s0;

    .line 931
    .line 932
    .line 933
    move-result-object v0

    .line 934
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/m3;->p()Ljava/util/List;

    .line 935
    .line 936
    .line 937
    move-result-object v6

    .line 938
    check-cast v6, Lcom/google/android/gms/internal/measurement/q5;

    .line 939
    .line 940
    invoke-virtual {v0, v6, v7}, Lvp/s0;->J0(Lcom/google/android/gms/internal/measurement/q5;Ljava/util/List;)Ljava/util/List;

    .line 941
    .line 942
    .line 943
    move-result-object v0

    .line 944
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/l3;->i()V

    .line 945
    .line 946
    .line 947
    check-cast v0, Ljava/util/List;

    .line 948
    .line 949
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 950
    .line 951
    .line 952
    iget-object v6, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 953
    .line 954
    check-cast v6, Lcom/google/android/gms/internal/measurement/m3;

    .line 955
    .line 956
    invoke-virtual {v6, v0}, Lcom/google/android/gms/internal/measurement/m3;->z(Ljava/lang/Iterable;)V

    .line 957
    .line 958
    .line 959
    new-instance v0, Ljava/util/ArrayList;

    .line 960
    .line 961
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 962
    .line 963
    .line 964
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/m3;->t()Lcom/google/android/gms/internal/measurement/r5;

    .line 965
    .line 966
    .line 967
    move-result-object v6

    .line 968
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 969
    .line 970
    .line 971
    move-result-object v6

    .line 972
    :goto_20
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 973
    .line 974
    .line 975
    move-result v18

    .line 976
    if-eqz v18, :cond_17

    .line 977
    .line 978
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 979
    .line 980
    .line 981
    move-result-object v18

    .line 982
    move-object/from16 v23, v6

    .line 983
    .line 984
    move-object/from16 v6, v18

    .line 985
    .line 986
    check-cast v6, Lcom/google/android/gms/internal/measurement/z2;

    .line 987
    .line 988
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/z2;->q()I

    .line 989
    .line 990
    .line 991
    move-result v18

    .line 992
    move-object/from16 v24, v9

    .line 993
    .line 994
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 995
    .line 996
    .line 997
    move-result-object v9

    .line 998
    invoke-interface {v7, v9}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 999
    .line 1000
    .line 1001
    move-result v9

    .line 1002
    if-nez v9, :cond_16

    .line 1003
    .line 1004
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1005
    .line 1006
    .line 1007
    :cond_16
    move-object/from16 v6, v23

    .line 1008
    .line 1009
    move-object/from16 v9, v24

    .line 1010
    .line 1011
    goto :goto_20

    .line 1012
    :cond_17
    move-object/from16 v24, v9

    .line 1013
    .line 1014
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/l3;->k()V

    .line 1015
    .line 1016
    .line 1017
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 1018
    .line 1019
    .line 1020
    iget-object v6, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1021
    .line 1022
    check-cast v6, Lcom/google/android/gms/internal/measurement/m3;

    .line 1023
    .line 1024
    invoke-virtual {v6, v0}, Lcom/google/android/gms/internal/measurement/m3;->D(Ljava/util/ArrayList;)V

    .line 1025
    .line 1026
    .line 1027
    new-instance v0, Ljava/util/ArrayList;

    .line 1028
    .line 1029
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1030
    .line 1031
    .line 1032
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/m3;->v()Ljava/util/List;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v5

    .line 1036
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v5

    .line 1040
    :cond_18
    :goto_21
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 1041
    .line 1042
    .line 1043
    move-result v6

    .line 1044
    if-eqz v6, :cond_19

    .line 1045
    .line 1046
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v6

    .line 1050
    check-cast v6, Lcom/google/android/gms/internal/measurement/o3;

    .line 1051
    .line 1052
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/o3;->q()I

    .line 1053
    .line 1054
    .line 1055
    move-result v9

    .line 1056
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v9

    .line 1060
    invoke-interface {v7, v9}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 1061
    .line 1062
    .line 1063
    move-result v9

    .line 1064
    if-nez v9, :cond_18

    .line 1065
    .line 1066
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1067
    .line 1068
    .line 1069
    goto :goto_21

    .line 1070
    :cond_19
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/l3;->l()V

    .line 1071
    .line 1072
    .line 1073
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 1074
    .line 1075
    .line 1076
    iget-object v5, v3, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 1077
    .line 1078
    check-cast v5, Lcom/google/android/gms/internal/measurement/m3;

    .line 1079
    .line 1080
    invoke-virtual {v5, v0}, Lcom/google/android/gms/internal/measurement/m3;->F(Ljava/lang/Iterable;)V

    .line 1081
    .line 1082
    .line 1083
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 1084
    .line 1085
    .line 1086
    move-result-object v0

    .line 1087
    check-cast v0, Lcom/google/android/gms/internal/measurement/m3;

    .line 1088
    .line 1089
    invoke-interface {v2, v4, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    :goto_22
    move-object/from16 v0, v17

    .line 1093
    .line 1094
    move-object/from16 v3, v21

    .line 1095
    .line 1096
    move-object/from16 v6, v22

    .line 1097
    .line 1098
    move-object/from16 v9, v24

    .line 1099
    .line 1100
    goto/16 :goto_1f

    .line 1101
    .line 1102
    :cond_1a
    move-object/from16 v0, v17

    .line 1103
    .line 1104
    move-object/from16 v3, v21

    .line 1105
    .line 1106
    goto/16 :goto_1f

    .line 1107
    .line 1108
    :goto_23
    invoke-interface {v2, v4, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1109
    .line 1110
    .line 1111
    goto :goto_22

    .line 1112
    :goto_24
    move-object v9, v2

    .line 1113
    goto :goto_26

    .line 1114
    :goto_25
    if-eqz v7, :cond_1b

    .line 1115
    .line 1116
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 1117
    .line 1118
    .line 1119
    :cond_1b
    throw v0

    .line 1120
    :cond_1c
    move-object/from16 p4, v2

    .line 1121
    .line 1122
    move-object/from16 v22, v6

    .line 1123
    .line 1124
    move-object/from16 v24, v9

    .line 1125
    .line 1126
    move-object v9, v11

    .line 1127
    :goto_26
    invoke-virtual/range {p4 .. p4}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v17

    .line 1131
    :goto_27
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    .line 1132
    .line 1133
    .line 1134
    move-result v0

    .line 1135
    if-eqz v0, :cond_2c

    .line 1136
    .line 1137
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v0

    .line 1141
    check-cast v0, Ljava/lang/Integer;

    .line 1142
    .line 1143
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1144
    .line 1145
    .line 1146
    invoke-interface {v9, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1147
    .line 1148
    .line 1149
    move-result-object v2

    .line 1150
    check-cast v2, Lcom/google/android/gms/internal/measurement/m3;

    .line 1151
    .line 1152
    new-instance v4, Ljava/util/BitSet;

    .line 1153
    .line 1154
    invoke-direct {v4}, Ljava/util/BitSet;-><init>()V

    .line 1155
    .line 1156
    .line 1157
    new-instance v5, Ljava/util/BitSet;

    .line 1158
    .line 1159
    invoke-direct {v5}, Ljava/util/BitSet;-><init>()V

    .line 1160
    .line 1161
    .line 1162
    new-instance v6, Landroidx/collection/f;

    .line 1163
    .line 1164
    invoke-direct {v6}, Landroidx/collection/f;-><init>()V

    .line 1165
    .line 1166
    .line 1167
    if-eqz v2, :cond_1d

    .line 1168
    .line 1169
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/m3;->u()I

    .line 1170
    .line 1171
    .line 1172
    move-result v3

    .line 1173
    if-nez v3, :cond_1e

    .line 1174
    .line 1175
    :cond_1d
    move-object/from16 p4, v2

    .line 1176
    .line 1177
    goto :goto_2a

    .line 1178
    :cond_1e
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/m3;->t()Lcom/google/android/gms/internal/measurement/r5;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v3

    .line 1182
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v3

    .line 1186
    :cond_1f
    :goto_28
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1187
    .line 1188
    .line 1189
    move-result v7

    .line 1190
    if-eqz v7, :cond_1d

    .line 1191
    .line 1192
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v7

    .line 1196
    check-cast v7, Lcom/google/android/gms/internal/measurement/z2;

    .line 1197
    .line 1198
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->p()Z

    .line 1199
    .line 1200
    .line 1201
    move-result v18

    .line 1202
    if-eqz v18, :cond_1f

    .line 1203
    .line 1204
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->q()I

    .line 1205
    .line 1206
    .line 1207
    move-result v18

    .line 1208
    move-object/from16 p4, v2

    .line 1209
    .line 1210
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1211
    .line 1212
    .line 1213
    move-result-object v2

    .line 1214
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->r()Z

    .line 1215
    .line 1216
    .line 1217
    move-result v18

    .line 1218
    if-eqz v18, :cond_20

    .line 1219
    .line 1220
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/z2;->s()J

    .line 1221
    .line 1222
    .line 1223
    move-result-wide v25

    .line 1224
    invoke-static/range {v25 .. v26}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1225
    .line 1226
    .line 1227
    move-result-object v7

    .line 1228
    goto :goto_29

    .line 1229
    :cond_20
    const/4 v7, 0x0

    .line 1230
    :goto_29
    invoke-interface {v6, v2, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1231
    .line 1232
    .line 1233
    move-object/from16 v2, p4

    .line 1234
    .line 1235
    goto :goto_28

    .line 1236
    :goto_2a
    new-instance v7, Landroidx/collection/f;

    .line 1237
    .line 1238
    invoke-direct {v7}, Landroidx/collection/f;-><init>()V

    .line 1239
    .line 1240
    .line 1241
    if-eqz p4, :cond_21

    .line 1242
    .line 1243
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/gms/internal/measurement/m3;->w()I

    .line 1244
    .line 1245
    .line 1246
    move-result v2

    .line 1247
    if-nez v2, :cond_22

    .line 1248
    .line 1249
    :cond_21
    move-object/from16 v23, v9

    .line 1250
    .line 1251
    goto :goto_2c

    .line 1252
    :cond_22
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/gms/internal/measurement/m3;->v()Ljava/util/List;

    .line 1253
    .line 1254
    .line 1255
    move-result-object v2

    .line 1256
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v2

    .line 1260
    :cond_23
    :goto_2b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1261
    .line 1262
    .line 1263
    move-result v3

    .line 1264
    if-eqz v3, :cond_21

    .line 1265
    .line 1266
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1267
    .line 1268
    .line 1269
    move-result-object v3

    .line 1270
    check-cast v3, Lcom/google/android/gms/internal/measurement/o3;

    .line 1271
    .line 1272
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o3;->p()Z

    .line 1273
    .line 1274
    .line 1275
    move-result v18

    .line 1276
    if-eqz v18, :cond_23

    .line 1277
    .line 1278
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o3;->s()I

    .line 1279
    .line 1280
    .line 1281
    move-result v18

    .line 1282
    if-lez v18, :cond_23

    .line 1283
    .line 1284
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o3;->q()I

    .line 1285
    .line 1286
    .line 1287
    move-result v18

    .line 1288
    move-object/from16 v21, v2

    .line 1289
    .line 1290
    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1291
    .line 1292
    .line 1293
    move-result-object v2

    .line 1294
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/o3;->s()I

    .line 1295
    .line 1296
    .line 1297
    move-result v18

    .line 1298
    move-object/from16 v23, v9

    .line 1299
    .line 1300
    add-int/lit8 v9, v18, -0x1

    .line 1301
    .line 1302
    invoke-virtual {v3, v9}, Lcom/google/android/gms/internal/measurement/o3;->t(I)J

    .line 1303
    .line 1304
    .line 1305
    move-result-wide v25

    .line 1306
    invoke-static/range {v25 .. v26}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v3

    .line 1310
    invoke-interface {v7, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1311
    .line 1312
    .line 1313
    move-object/from16 v2, v21

    .line 1314
    .line 1315
    move-object/from16 v9, v23

    .line 1316
    .line 1317
    goto :goto_2b

    .line 1318
    :goto_2c
    if-eqz p4, :cond_26

    .line 1319
    .line 1320
    const/4 v2, 0x0

    .line 1321
    :goto_2d
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/gms/internal/measurement/m3;->q()I

    .line 1322
    .line 1323
    .line 1324
    move-result v3

    .line 1325
    mul-int/lit8 v3, v3, 0x40

    .line 1326
    .line 1327
    if-ge v2, v3, :cond_26

    .line 1328
    .line 1329
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/gms/internal/measurement/m3;->p()Ljava/util/List;

    .line 1330
    .line 1331
    .line 1332
    move-result-object v3

    .line 1333
    check-cast v3, Lcom/google/android/gms/internal/measurement/q5;

    .line 1334
    .line 1335
    invoke-static {v3, v2}, Lvp/s0;->H0(Lcom/google/android/gms/internal/measurement/q5;I)Z

    .line 1336
    .line 1337
    .line 1338
    move-result v3

    .line 1339
    if-eqz v3, :cond_24

    .line 1340
    .line 1341
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 1342
    .line 1343
    .line 1344
    move-result-object v3

    .line 1345
    invoke-virtual {v3}, Lvp/p0;->h0()Lvp/n0;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v3

    .line 1349
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1350
    .line 1351
    .line 1352
    move-result-object v9

    .line 1353
    move/from16 v18, v12

    .line 1354
    .line 1355
    const-string v12, "Filter already evaluated. audience ID, filter ID"

    .line 1356
    .line 1357
    invoke-virtual {v3, v0, v9, v12}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1358
    .line 1359
    .line 1360
    invoke-virtual {v5, v2}, Ljava/util/BitSet;->set(I)V

    .line 1361
    .line 1362
    .line 1363
    invoke-virtual/range {p4 .. p4}, Lcom/google/android/gms/internal/measurement/m3;->r()Ljava/util/List;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v3

    .line 1367
    check-cast v3, Lcom/google/android/gms/internal/measurement/q5;

    .line 1368
    .line 1369
    invoke-static {v3, v2}, Lvp/s0;->H0(Lcom/google/android/gms/internal/measurement/q5;I)Z

    .line 1370
    .line 1371
    .line 1372
    move-result v3

    .line 1373
    if-eqz v3, :cond_25

    .line 1374
    .line 1375
    invoke-virtual {v4, v2}, Ljava/util/BitSet;->set(I)V

    .line 1376
    .line 1377
    .line 1378
    goto :goto_2e

    .line 1379
    :cond_24
    move/from16 v18, v12

    .line 1380
    .line 1381
    :cond_25
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1382
    .line 1383
    .line 1384
    move-result-object v3

    .line 1385
    invoke-interface {v6, v3}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1386
    .line 1387
    .line 1388
    :goto_2e
    add-int/lit8 v2, v2, 0x1

    .line 1389
    .line 1390
    move/from16 v12, v18

    .line 1391
    .line 1392
    goto :goto_2d

    .line 1393
    :cond_26
    move/from16 v18, v12

    .line 1394
    .line 1395
    invoke-interface {v11, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1396
    .line 1397
    .line 1398
    move-result-object v2

    .line 1399
    move-object v3, v2

    .line 1400
    check-cast v3, Lcom/google/android/gms/internal/measurement/m3;

    .line 1401
    .line 1402
    if-eqz v13, :cond_27

    .line 1403
    .line 1404
    if-eqz v18, :cond_27

    .line 1405
    .line 1406
    invoke-interface {v10, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1407
    .line 1408
    .line 1409
    move-result-object v2

    .line 1410
    check-cast v2, Ljava/util/List;

    .line 1411
    .line 1412
    if-eqz v2, :cond_27

    .line 1413
    .line 1414
    iget-object v9, v1, Lvp/d;->l:Ljava/lang/Long;

    .line 1415
    .line 1416
    if-eqz v9, :cond_27

    .line 1417
    .line 1418
    iget-object v9, v1, Lvp/d;->k:Ljava/lang/Long;

    .line 1419
    .line 1420
    if-nez v9, :cond_28

    .line 1421
    .line 1422
    :cond_27
    move-object/from16 p4, v0

    .line 1423
    .line 1424
    goto :goto_30

    .line 1425
    :cond_28
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1426
    .line 1427
    .line 1428
    move-result-object v2

    .line 1429
    :goto_2f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1430
    .line 1431
    .line 1432
    move-result v9

    .line 1433
    if-eqz v9, :cond_27

    .line 1434
    .line 1435
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v9

    .line 1439
    check-cast v9, Lcom/google/android/gms/internal/measurement/o1;

    .line 1440
    .line 1441
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 1442
    .line 1443
    .line 1444
    move-result v12

    .line 1445
    move-object/from16 p4, v0

    .line 1446
    .line 1447
    iget-object v0, v1, Lvp/d;->l:Ljava/lang/Long;

    .line 1448
    .line 1449
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 1450
    .line 1451
    .line 1452
    move-result-wide v25

    .line 1453
    const-wide/16 v27, 0x3e8

    .line 1454
    .line 1455
    div-long v25, v25, v27

    .line 1456
    .line 1457
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/o1;->y()Z

    .line 1458
    .line 1459
    .line 1460
    move-result v0

    .line 1461
    if-eqz v0, :cond_29

    .line 1462
    .line 1463
    iget-object v0, v1, Lvp/d;->k:Ljava/lang/Long;

    .line 1464
    .line 1465
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 1466
    .line 1467
    .line 1468
    move-result-wide v25

    .line 1469
    div-long v25, v25, v27

    .line 1470
    .line 1471
    :cond_29
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1472
    .line 1473
    .line 1474
    move-result-object v0

    .line 1475
    invoke-interface {v6, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 1476
    .line 1477
    .line 1478
    move-result v9

    .line 1479
    if-eqz v9, :cond_2a

    .line 1480
    .line 1481
    invoke-static/range {v25 .. v26}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1482
    .line 1483
    .line 1484
    move-result-object v9

    .line 1485
    invoke-interface {v6, v0, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1486
    .line 1487
    .line 1488
    :cond_2a
    invoke-interface {v7, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 1489
    .line 1490
    .line 1491
    move-result v9

    .line 1492
    if-eqz v9, :cond_2b

    .line 1493
    .line 1494
    invoke-static/range {v25 .. v26}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v9

    .line 1498
    invoke-interface {v7, v0, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1499
    .line 1500
    .line 1501
    :cond_2b
    move-object/from16 v0, p4

    .line 1502
    .line 1503
    goto :goto_2f

    .line 1504
    :goto_30
    new-instance v0, Lvp/h4;

    .line 1505
    .line 1506
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 1507
    .line 1508
    move-object/from16 p1, v20

    .line 1509
    .line 1510
    move-object/from16 v20, v10

    .line 1511
    .line 1512
    move-object/from16 v10, p1

    .line 1513
    .line 1514
    move-object/from16 v12, p4

    .line 1515
    .line 1516
    move-object/from16 p1, v11

    .line 1517
    .line 1518
    move/from16 p4, v13

    .line 1519
    .line 1520
    move-object/from16 v9, v19

    .line 1521
    .line 1522
    move-object/from16 v13, v22

    .line 1523
    .line 1524
    move-object/from16 v11, p5

    .line 1525
    .line 1526
    invoke-direct/range {v0 .. v7}, Lvp/h4;-><init>(Lvp/d;Ljava/lang/String;Lcom/google/android/gms/internal/measurement/m3;Ljava/util/BitSet;Ljava/util/BitSet;Landroidx/collection/f;Landroidx/collection/f;)V

    .line 1527
    .line 1528
    .line 1529
    iget-object v2, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 1530
    .line 1531
    invoke-interface {v2, v12, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1532
    .line 1533
    .line 1534
    move-object/from16 p5, v20

    .line 1535
    .line 1536
    move-object/from16 v20, v10

    .line 1537
    .line 1538
    move-object/from16 v10, p5

    .line 1539
    .line 1540
    move-object/from16 p5, v11

    .line 1541
    .line 1542
    move/from16 v12, v18

    .line 1543
    .line 1544
    move-object/from16 v9, v23

    .line 1545
    .line 1546
    move-object/from16 v11, p1

    .line 1547
    .line 1548
    move/from16 v13, p4

    .line 1549
    .line 1550
    goto/16 :goto_27

    .line 1551
    .line 1552
    :cond_2c
    move-object/from16 v13, v22

    .line 1553
    .line 1554
    goto/16 :goto_17

    .line 1555
    .line 1556
    :goto_31
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->isEmpty()Z

    .line 1557
    .line 1558
    .line 1559
    move-result v0

    .line 1560
    const-string v6, "Skipping failed audience ID"

    .line 1561
    .line 1562
    if-eqz v0, :cond_2d

    .line 1563
    .line 1564
    goto/16 :goto_43

    .line 1565
    .line 1566
    :cond_2d
    new-instance v7, Lh01/q;

    .line 1567
    .line 1568
    invoke-direct {v7, v1}, Lh01/q;-><init>(Lvp/d;)V

    .line 1569
    .line 1570
    .line 1571
    new-instance v12, Landroidx/collection/f;

    .line 1572
    .line 1573
    invoke-direct {v12}, Landroidx/collection/f;-><init>()V

    .line 1574
    .line 1575
    .line 1576
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1577
    .line 1578
    .line 1579
    move-result-object v17

    .line 1580
    :cond_2e
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->hasNext()Z

    .line 1581
    .line 1582
    .line 1583
    move-result v0

    .line 1584
    if-eqz v0, :cond_3a

    .line 1585
    .line 1586
    invoke-interface/range {v17 .. v17}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1587
    .line 1588
    .line 1589
    move-result-object v0

    .line 1590
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;

    .line 1591
    .line 1592
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 1593
    .line 1594
    invoke-virtual {v7, v0, v2}, Lh01/q;->b(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/b3;

    .line 1595
    .line 1596
    .line 1597
    move-result-object v28

    .line 1598
    if-eqz v28, :cond_2e

    .line 1599
    .line 1600
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 1601
    .line 1602
    .line 1603
    move-result-object v2

    .line 1604
    iget-object v3, v1, Lvp/d;->h:Ljava/lang/String;

    .line 1605
    .line 1606
    invoke-virtual/range {v28 .. v28}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 1607
    .line 1608
    .line 1609
    move-result-object v4

    .line 1610
    invoke-virtual {v2, v3, v0, v4}, Lvp/n;->G0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lvp/r;

    .line 1611
    .line 1612
    .line 1613
    move-result-object v2

    .line 1614
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v0

    .line 1618
    invoke-virtual {v0, v14, v2}, Lvp/n;->z0(Ljava/lang/String;Lvp/r;)V

    .line 1619
    .line 1620
    .line 1621
    if-nez p6, :cond_2e

    .line 1622
    .line 1623
    iget-wide v3, v2, Lvp/r;->c:J

    .line 1624
    .line 1625
    invoke-virtual/range {v28 .. v28}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 1626
    .line 1627
    .line 1628
    move-result-object v5

    .line 1629
    invoke-interface {v12, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1630
    .line 1631
    .line 1632
    move-result-object v0

    .line 1633
    check-cast v0, Ljava/util/Map;

    .line 1634
    .line 1635
    if-nez v0, :cond_34

    .line 1636
    .line 1637
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 1638
    .line 1639
    .line 1640
    move-result-object v0

    .line 1641
    move-object/from16 v31, v2

    .line 1642
    .line 1643
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 1644
    .line 1645
    check-cast v2, Lvp/g1;

    .line 1646
    .line 1647
    move-object/from16 p1, v2

    .line 1648
    .line 1649
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 1650
    .line 1651
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 1652
    .line 1653
    .line 1654
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 1655
    .line 1656
    .line 1657
    invoke-static {v2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 1658
    .line 1659
    .line 1660
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 1661
    .line 1662
    .line 1663
    move-wide/from16 v29, v3

    .line 1664
    .line 1665
    new-instance v3, Landroidx/collection/f;

    .line 1666
    .line 1667
    invoke-direct {v3}, Landroidx/collection/f;-><init>()V

    .line 1668
    .line 1669
    .line 1670
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 1671
    .line 1672
    .line 1673
    move-result-object v32

    .line 1674
    :try_start_17
    const-string v33, "event_filters"

    .line 1675
    .line 1676
    filled-new-array {v13, v11}, [Ljava/lang/String;

    .line 1677
    .line 1678
    .line 1679
    move-result-object v34

    .line 1680
    const-string v35, "app_id=? AND event_name=?"

    .line 1681
    .line 1682
    filled-new-array {v2, v5}, [Ljava/lang/String;

    .line 1683
    .line 1684
    .line 1685
    move-result-object v36

    .line 1686
    const/16 v38, 0x0

    .line 1687
    .line 1688
    const/16 v39, 0x0

    .line 1689
    .line 1690
    const/16 v37, 0x0

    .line 1691
    .line 1692
    invoke-virtual/range {v32 .. v39}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v4
    :try_end_17
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_17 .. :try_end_17} :catch_14
    .catchall {:try_start_17 .. :try_end_17} :catchall_a

    .line 1696
    :try_start_18
    invoke-interface {v4}, Landroid/database/Cursor;->moveToFirst()Z

    .line 1697
    .line 1698
    .line 1699
    move-result v0
    :try_end_18
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_18 .. :try_end_18} :catch_13
    .catchall {:try_start_18 .. :try_end_18} :catchall_9

    .line 1700
    if-eqz v0, :cond_31

    .line 1701
    .line 1702
    move-object/from16 v18, v2

    .line 1703
    .line 1704
    :goto_32
    const/4 v2, 0x1

    .line 1705
    :try_start_19
    invoke-interface {v4, v2}, Landroid/database/Cursor;->getBlob(I)[B

    .line 1706
    .line 1707
    .line 1708
    move-result-object v0
    :try_end_19
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_19 .. :try_end_19} :catch_11
    .catchall {:try_start_19 .. :try_end_19} :catchall_9

    .line 1709
    :try_start_1a
    invoke-static {}, Lcom/google/android/gms/internal/measurement/o1;->B()Lcom/google/android/gms/internal/measurement/n1;

    .line 1710
    .line 1711
    .line 1712
    move-result-object v2

    .line 1713
    invoke-static {v2, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 1714
    .line 1715
    .line 1716
    move-result-object v0

    .line 1717
    check-cast v0, Lcom/google/android/gms/internal/measurement/n1;

    .line 1718
    .line 1719
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 1720
    .line 1721
    .line 1722
    move-result-object v0

    .line 1723
    check-cast v0, Lcom/google/android/gms/internal/measurement/o1;
    :try_end_1a
    .catch Ljava/io/IOException; {:try_start_1a .. :try_end_1a} :catch_12
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1a .. :try_end_1a} :catch_11
    .catchall {:try_start_1a .. :try_end_1a} :catchall_9

    .line 1724
    .line 1725
    const/4 v2, 0x0

    .line 1726
    :try_start_1b
    invoke-interface {v4, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 1727
    .line 1728
    .line 1729
    move-result v20

    .line 1730
    invoke-static/range {v20 .. v20}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1731
    .line 1732
    .line 1733
    move-result-object v2

    .line 1734
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1735
    .line 1736
    .line 1737
    move-result-object v20

    .line 1738
    check-cast v20, Ljava/util/List;
    :try_end_1b
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1b .. :try_end_1b} :catch_11
    .catchall {:try_start_1b .. :try_end_1b} :catchall_9

    .line 1739
    .line 1740
    if-nez v20, :cond_2f

    .line 1741
    .line 1742
    move-object/from16 p2, v4

    .line 1743
    .line 1744
    :try_start_1c
    new-instance v4, Ljava/util/ArrayList;

    .line 1745
    .line 1746
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1747
    .line 1748
    .line 1749
    invoke-interface {v3, v2, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1750
    .line 1751
    .line 1752
    goto :goto_33

    .line 1753
    :catchall_8
    move-exception v0

    .line 1754
    goto :goto_36

    .line 1755
    :catch_10
    move-exception v0

    .line 1756
    goto :goto_37

    .line 1757
    :cond_2f
    move-object/from16 p2, v4

    .line 1758
    .line 1759
    move-object/from16 v4, v20

    .line 1760
    .line 1761
    :goto_33
    invoke-interface {v4, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1762
    .line 1763
    .line 1764
    goto :goto_35

    .line 1765
    :catchall_9
    move-exception v0

    .line 1766
    move-object/from16 p2, v4

    .line 1767
    .line 1768
    goto :goto_36

    .line 1769
    :catch_11
    move-exception v0

    .line 1770
    :goto_34
    move-object/from16 p2, v4

    .line 1771
    .line 1772
    goto :goto_37

    .line 1773
    :catch_12
    move-exception v0

    .line 1774
    move-object/from16 p2, v4

    .line 1775
    .line 1776
    invoke-virtual/range {p1 .. p1}, Lvp/g1;->d()Lvp/p0;

    .line 1777
    .line 1778
    .line 1779
    move-result-object v2

    .line 1780
    invoke-virtual {v2}, Lvp/p0;->e0()Lvp/n0;

    .line 1781
    .line 1782
    .line 1783
    move-result-object v2

    .line 1784
    invoke-static/range {v18 .. v18}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 1785
    .line 1786
    .line 1787
    move-result-object v4

    .line 1788
    invoke-virtual {v2, v4, v0, v9}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1789
    .line 1790
    .line 1791
    :goto_35
    invoke-interface/range {p2 .. p2}, Landroid/database/Cursor;->moveToNext()Z

    .line 1792
    .line 1793
    .line 1794
    move-result v0
    :try_end_1c
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1c .. :try_end_1c} :catch_10
    .catchall {:try_start_1c .. :try_end_1c} :catchall_8

    .line 1795
    if-nez v0, :cond_30

    .line 1796
    .line 1797
    invoke-interface/range {p2 .. p2}, Landroid/database/Cursor;->close()V

    .line 1798
    .line 1799
    .line 1800
    move-object v0, v3

    .line 1801
    goto :goto_3b

    .line 1802
    :cond_30
    move-object/from16 v4, p2

    .line 1803
    .line 1804
    goto :goto_32

    .line 1805
    :cond_31
    move-object/from16 v18, v2

    .line 1806
    .line 1807
    move-object/from16 p2, v4

    .line 1808
    .line 1809
    :try_start_1d
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_1d
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1d .. :try_end_1d} :catch_10
    .catchall {:try_start_1d .. :try_end_1d} :catchall_8

    .line 1810
    .line 1811
    invoke-interface/range {p2 .. p2}, Landroid/database/Cursor;->close()V

    .line 1812
    .line 1813
    .line 1814
    goto :goto_3b

    .line 1815
    :goto_36
    move-object/from16 v7, p2

    .line 1816
    .line 1817
    goto :goto_3c

    .line 1818
    :catch_13
    move-exception v0

    .line 1819
    move-object/from16 v18, v2

    .line 1820
    .line 1821
    goto :goto_34

    .line 1822
    :goto_37
    move-object/from16 v2, p2

    .line 1823
    .line 1824
    goto :goto_3a

    .line 1825
    :catchall_a
    move-exception v0

    .line 1826
    goto :goto_38

    .line 1827
    :catch_14
    move-exception v0

    .line 1828
    move-object/from16 v18, v2

    .line 1829
    .line 1830
    goto :goto_39

    .line 1831
    :goto_38
    const/4 v7, 0x0

    .line 1832
    goto :goto_3c

    .line 1833
    :goto_39
    const/4 v2, 0x0

    .line 1834
    :goto_3a
    :try_start_1e
    invoke-virtual/range {p1 .. p1}, Lvp/g1;->d()Lvp/p0;

    .line 1835
    .line 1836
    .line 1837
    move-result-object v3

    .line 1838
    invoke-virtual {v3}, Lvp/p0;->e0()Lvp/n0;

    .line 1839
    .line 1840
    .line 1841
    move-result-object v3

    .line 1842
    invoke-static/range {v18 .. v18}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 1843
    .line 1844
    .line 1845
    move-result-object v4

    .line 1846
    invoke-virtual {v3, v4, v0, v10}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1847
    .line 1848
    .line 1849
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_1e
    .catchall {:try_start_1e .. :try_end_1e} :catchall_b

    .line 1850
    .line 1851
    if-eqz v2, :cond_32

    .line 1852
    .line 1853
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 1854
    .line 1855
    .line 1856
    :cond_32
    :goto_3b
    invoke-interface {v12, v5, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1857
    .line 1858
    .line 1859
    goto :goto_3d

    .line 1860
    :catchall_b
    move-exception v0

    .line 1861
    move-object v7, v2

    .line 1862
    :goto_3c
    if-eqz v7, :cond_33

    .line 1863
    .line 1864
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 1865
    .line 1866
    .line 1867
    :cond_33
    throw v0

    .line 1868
    :cond_34
    move-object/from16 v31, v2

    .line 1869
    .line 1870
    move-wide/from16 v29, v3

    .line 1871
    .line 1872
    :goto_3d
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v2

    .line 1876
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1877
    .line 1878
    .line 1879
    move-result-object v18

    .line 1880
    :goto_3e
    invoke-interface/range {v18 .. v18}, Ljava/util/Iterator;->hasNext()Z

    .line 1881
    .line 1882
    .line 1883
    move-result v2

    .line 1884
    if-eqz v2, :cond_2e

    .line 1885
    .line 1886
    invoke-interface/range {v18 .. v18}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1887
    .line 1888
    .line 1889
    move-result-object v2

    .line 1890
    check-cast v2, Ljava/lang/Integer;

    .line 1891
    .line 1892
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1893
    .line 1894
    .line 1895
    move-result v3

    .line 1896
    iget-object v4, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 1897
    .line 1898
    invoke-virtual {v4, v2}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 1899
    .line 1900
    .line 1901
    move-result v4

    .line 1902
    if-eqz v4, :cond_35

    .line 1903
    .line 1904
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 1905
    .line 1906
    .line 1907
    move-result-object v3

    .line 1908
    invoke-virtual {v3}, Lvp/p0;->h0()Lvp/n0;

    .line 1909
    .line 1910
    .line 1911
    move-result-object v3

    .line 1912
    invoke-virtual {v3, v2, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1913
    .line 1914
    .line 1915
    goto :goto_3e

    .line 1916
    :cond_35
    invoke-interface {v0, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1917
    .line 1918
    .line 1919
    move-result-object v4

    .line 1920
    check-cast v4, Ljava/util/List;

    .line 1921
    .line 1922
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1923
    .line 1924
    .line 1925
    move-result-object v20

    .line 1926
    const/4 v5, 0x1

    .line 1927
    :goto_3f
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->hasNext()Z

    .line 1928
    .line 1929
    .line 1930
    move-result v4

    .line 1931
    if-eqz v4, :cond_38

    .line 1932
    .line 1933
    invoke-interface/range {v20 .. v20}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1934
    .line 1935
    .line 1936
    move-result-object v4

    .line 1937
    check-cast v4, Lcom/google/android/gms/internal/measurement/o1;

    .line 1938
    .line 1939
    new-instance v25, Lvp/b;

    .line 1940
    .line 1941
    move-object v5, v2

    .line 1942
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 1943
    .line 1944
    move-object/from16 v21, v5

    .line 1945
    .line 1946
    const/4 v5, 0x0

    .line 1947
    move-object/from16 p1, v7

    .line 1948
    .line 1949
    move-object/from16 v7, v21

    .line 1950
    .line 1951
    move-object/from16 v21, v0

    .line 1952
    .line 1953
    move-object/from16 v0, v25

    .line 1954
    .line 1955
    invoke-direct/range {v0 .. v5}, Lvp/b;-><init>(Lvp/d;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/l5;I)V

    .line 1956
    .line 1957
    .line 1958
    iget-object v0, v1, Lvp/d;->k:Ljava/lang/Long;

    .line 1959
    .line 1960
    iget-object v2, v1, Lvp/d;->l:Ljava/lang/Long;

    .line 1961
    .line 1962
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 1963
    .line 1964
    .line 1965
    move-result v4

    .line 1966
    iget-object v5, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 1967
    .line 1968
    invoke-interface {v5, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1969
    .line 1970
    .line 1971
    move-result-object v5

    .line 1972
    check-cast v5, Lvp/h4;

    .line 1973
    .line 1974
    if-nez v5, :cond_36

    .line 1975
    .line 1976
    const/16 v32, 0x0

    .line 1977
    .line 1978
    :goto_40
    move-object/from16 v26, v0

    .line 1979
    .line 1980
    move-object/from16 v27, v2

    .line 1981
    .line 1982
    goto :goto_41

    .line 1983
    :cond_36
    iget-object v5, v5, Lvp/h4;->d:Ljava/util/BitSet;

    .line 1984
    .line 1985
    invoke-virtual {v5, v4}, Ljava/util/BitSet;->get(I)Z

    .line 1986
    .line 1987
    .line 1988
    move-result v5

    .line 1989
    move/from16 v32, v5

    .line 1990
    .line 1991
    goto :goto_40

    .line 1992
    :goto_41
    invoke-virtual/range {v25 .. v32}, Lvp/b;->i(Ljava/lang/Long;Ljava/lang/Long;Lcom/google/android/gms/internal/measurement/b3;JLvp/r;Z)Z

    .line 1993
    .line 1994
    .line 1995
    move-result v5

    .line 1996
    move-object/from16 v0, v25

    .line 1997
    .line 1998
    if-eqz v5, :cond_37

    .line 1999
    .line 2000
    invoke-virtual {v1, v7}, Lvp/d;->f0(Ljava/lang/Integer;)Lvp/h4;

    .line 2001
    .line 2002
    .line 2003
    move-result-object v2

    .line 2004
    invoke-virtual {v2, v0}, Lvp/h4;->a(Lvp/c;)V

    .line 2005
    .line 2006
    .line 2007
    move-object v2, v7

    .line 2008
    move-object/from16 v0, v21

    .line 2009
    .line 2010
    move-object/from16 v7, p1

    .line 2011
    .line 2012
    goto :goto_3f

    .line 2013
    :cond_37
    iget-object v0, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2014
    .line 2015
    invoke-virtual {v0, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2016
    .line 2017
    .line 2018
    goto :goto_42

    .line 2019
    :cond_38
    move-object/from16 v21, v0

    .line 2020
    .line 2021
    move-object/from16 p1, v7

    .line 2022
    .line 2023
    move-object v7, v2

    .line 2024
    :goto_42
    if-nez v5, :cond_39

    .line 2025
    .line 2026
    iget-object v0, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2027
    .line 2028
    invoke-virtual {v0, v7}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2029
    .line 2030
    .line 2031
    :cond_39
    move-object/from16 v7, p1

    .line 2032
    .line 2033
    move-object/from16 v0, v21

    .line 2034
    .line 2035
    goto/16 :goto_3e

    .line 2036
    .line 2037
    :cond_3a
    :goto_43
    if-nez p6, :cond_50

    .line 2038
    .line 2039
    invoke-interface/range {p3 .. p3}, Ljava/util/List;->isEmpty()Z

    .line 2040
    .line 2041
    .line 2042
    move-result v0

    .line 2043
    if-eqz v0, :cond_3b

    .line 2044
    .line 2045
    goto/16 :goto_5c

    .line 2046
    .line 2047
    :cond_3b
    new-instance v2, Landroidx/collection/f;

    .line 2048
    .line 2049
    invoke-direct {v2}, Landroidx/collection/f;-><init>()V

    .line 2050
    .line 2051
    .line 2052
    invoke-interface/range {p3 .. p3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2053
    .line 2054
    .line 2055
    move-result-object v3

    .line 2056
    :goto_44
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 2057
    .line 2058
    .line 2059
    move-result v0

    .line 2060
    if-eqz v0, :cond_4d

    .line 2061
    .line 2062
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2063
    .line 2064
    .line 2065
    move-result-object v0

    .line 2066
    move-object v4, v0

    .line 2067
    check-cast v4, Lcom/google/android/gms/internal/measurement/s3;

    .line 2068
    .line 2069
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 2070
    .line 2071
    .line 2072
    move-result-object v5

    .line 2073
    invoke-interface {v2, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2074
    .line 2075
    .line 2076
    move-result-object v0

    .line 2077
    check-cast v0, Ljava/util/Map;

    .line 2078
    .line 2079
    if-nez v0, :cond_41

    .line 2080
    .line 2081
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 2082
    .line 2083
    .line 2084
    move-result-object v0

    .line 2085
    iget-object v7, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 2086
    .line 2087
    check-cast v7, Lvp/g1;

    .line 2088
    .line 2089
    iget-object v9, v1, Lvp/d;->h:Ljava/lang/String;

    .line 2090
    .line 2091
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 2092
    .line 2093
    .line 2094
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 2095
    .line 2096
    .line 2097
    invoke-static {v9}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2098
    .line 2099
    .line 2100
    invoke-static {v5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2101
    .line 2102
    .line 2103
    new-instance v12, Landroidx/collection/f;

    .line 2104
    .line 2105
    invoke-direct {v12}, Landroidx/collection/f;-><init>()V

    .line 2106
    .line 2107
    .line 2108
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2109
    .line 2110
    .line 2111
    move-result-object v25

    .line 2112
    :try_start_1f
    const-string v26, "property_filters"

    .line 2113
    .line 2114
    filled-new-array {v13, v11}, [Ljava/lang/String;

    .line 2115
    .line 2116
    .line 2117
    move-result-object v27

    .line 2118
    const-string v28, "app_id=? AND property_name=?"

    .line 2119
    .line 2120
    filled-new-array {v9, v5}, [Ljava/lang/String;

    .line 2121
    .line 2122
    .line 2123
    move-result-object v29

    .line 2124
    const/16 v31, 0x0

    .line 2125
    .line 2126
    const/16 v32, 0x0

    .line 2127
    .line 2128
    const/16 v30, 0x0

    .line 2129
    .line 2130
    invoke-virtual/range {v25 .. v32}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 2131
    .line 2132
    .line 2133
    move-result-object v14
    :try_end_1f
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1f .. :try_end_1f} :catch_1a
    .catchall {:try_start_1f .. :try_end_1f} :catchall_d

    .line 2134
    :try_start_20
    invoke-interface {v14}, Landroid/database/Cursor;->moveToFirst()Z

    .line 2135
    .line 2136
    .line 2137
    move-result v0
    :try_end_20
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_20 .. :try_end_20} :catch_19
    .catchall {:try_start_20 .. :try_end_20} :catchall_c

    .line 2138
    if-eqz v0, :cond_3e

    .line 2139
    .line 2140
    move-object/from16 v17, v3

    .line 2141
    .line 2142
    :goto_45
    const/4 v3, 0x1

    .line 2143
    :try_start_21
    invoke-interface {v14, v3}, Landroid/database/Cursor;->getBlob(I)[B

    .line 2144
    .line 2145
    .line 2146
    move-result-object v0
    :try_end_21
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_21 .. :try_end_21} :catch_16
    .catchall {:try_start_21 .. :try_end_21} :catchall_c

    .line 2147
    :try_start_22
    invoke-static {}, Lcom/google/android/gms/internal/measurement/v1;->x()Lcom/google/android/gms/internal/measurement/u1;

    .line 2148
    .line 2149
    .line 2150
    move-result-object v3

    .line 2151
    invoke-static {v3, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 2152
    .line 2153
    .line 2154
    move-result-object v0

    .line 2155
    check-cast v0, Lcom/google/android/gms/internal/measurement/u1;

    .line 2156
    .line 2157
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 2158
    .line 2159
    .line 2160
    move-result-object v0

    .line 2161
    check-cast v0, Lcom/google/android/gms/internal/measurement/v1;
    :try_end_22
    .catch Ljava/io/IOException; {:try_start_22 .. :try_end_22} :catch_17
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_22 .. :try_end_22} :catch_16
    .catchall {:try_start_22 .. :try_end_22} :catchall_c

    .line 2162
    .line 2163
    const/4 v3, 0x0

    .line 2164
    :try_start_23
    invoke-interface {v14, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 2165
    .line 2166
    .line 2167
    move-result v16

    .line 2168
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2169
    .line 2170
    .line 2171
    move-result-object v3

    .line 2172
    invoke-interface {v12, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2173
    .line 2174
    .line 2175
    move-result-object v16

    .line 2176
    check-cast v16, Ljava/util/List;
    :try_end_23
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_23 .. :try_end_23} :catch_16
    .catchall {:try_start_23 .. :try_end_23} :catchall_c

    .line 2177
    .line 2178
    if-nez v16, :cond_3c

    .line 2179
    .line 2180
    move-object/from16 p1, v7

    .line 2181
    .line 2182
    :try_start_24
    new-instance v7, Ljava/util/ArrayList;

    .line 2183
    .line 2184
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 2185
    .line 2186
    .line 2187
    invoke-interface {v12, v3, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2188
    .line 2189
    .line 2190
    goto :goto_47

    .line 2191
    :catchall_c
    move-exception v0

    .line 2192
    goto :goto_4a

    .line 2193
    :catch_15
    move-exception v0

    .line 2194
    :goto_46
    move-object/from16 v16, v9

    .line 2195
    .line 2196
    goto :goto_4b

    .line 2197
    :cond_3c
    move-object/from16 p1, v7

    .line 2198
    .line 2199
    move-object/from16 v7, v16

    .line 2200
    .line 2201
    :goto_47
    invoke-interface {v7, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 2202
    .line 2203
    .line 2204
    move-object/from16 v16, v9

    .line 2205
    .line 2206
    goto :goto_49

    .line 2207
    :catch_16
    move-exception v0

    .line 2208
    :goto_48
    move-object/from16 p1, v7

    .line 2209
    .line 2210
    goto :goto_46

    .line 2211
    :catch_17
    move-exception v0

    .line 2212
    move-object/from16 p1, v7

    .line 2213
    .line 2214
    invoke-virtual/range {p1 .. p1}, Lvp/g1;->d()Lvp/p0;

    .line 2215
    .line 2216
    .line 2217
    move-result-object v3

    .line 2218
    invoke-virtual {v3}, Lvp/p0;->e0()Lvp/n0;

    .line 2219
    .line 2220
    .line 2221
    move-result-object v3

    .line 2222
    const-string v7, "Failed to merge filter"
    :try_end_24
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_24 .. :try_end_24} :catch_15
    .catchall {:try_start_24 .. :try_end_24} :catchall_c

    .line 2223
    .line 2224
    move-object/from16 v16, v9

    .line 2225
    .line 2226
    :try_start_25
    invoke-static/range {v16 .. v16}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 2227
    .line 2228
    .line 2229
    move-result-object v9

    .line 2230
    invoke-virtual {v3, v9, v0, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 2231
    .line 2232
    .line 2233
    :goto_49
    invoke-interface {v14}, Landroid/database/Cursor;->moveToNext()Z

    .line 2234
    .line 2235
    .line 2236
    move-result v0
    :try_end_25
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_25 .. :try_end_25} :catch_18
    .catchall {:try_start_25 .. :try_end_25} :catchall_c

    .line 2237
    if-nez v0, :cond_3d

    .line 2238
    .line 2239
    invoke-interface {v14}, Landroid/database/Cursor;->close()V

    .line 2240
    .line 2241
    .line 2242
    move-object v0, v12

    .line 2243
    goto :goto_4f

    .line 2244
    :cond_3d
    move-object/from16 v7, p1

    .line 2245
    .line 2246
    move-object/from16 v9, v16

    .line 2247
    .line 2248
    goto :goto_45

    .line 2249
    :catch_18
    move-exception v0

    .line 2250
    goto :goto_4b

    .line 2251
    :cond_3e
    move-object/from16 v17, v3

    .line 2252
    .line 2253
    move-object/from16 p1, v7

    .line 2254
    .line 2255
    move-object/from16 v16, v9

    .line 2256
    .line 2257
    :try_start_26
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_26
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_26 .. :try_end_26} :catch_18
    .catchall {:try_start_26 .. :try_end_26} :catchall_c

    .line 2258
    .line 2259
    invoke-interface {v14}, Landroid/database/Cursor;->close()V

    .line 2260
    .line 2261
    .line 2262
    goto :goto_4f

    .line 2263
    :goto_4a
    move-object v7, v14

    .line 2264
    goto :goto_50

    .line 2265
    :catch_19
    move-exception v0

    .line 2266
    move-object/from16 v17, v3

    .line 2267
    .line 2268
    goto :goto_48

    .line 2269
    :goto_4b
    move-object v7, v14

    .line 2270
    goto :goto_4e

    .line 2271
    :catchall_d
    move-exception v0

    .line 2272
    goto :goto_4c

    .line 2273
    :catch_1a
    move-exception v0

    .line 2274
    move-object/from16 v17, v3

    .line 2275
    .line 2276
    move-object/from16 p1, v7

    .line 2277
    .line 2278
    move-object/from16 v16, v9

    .line 2279
    .line 2280
    goto :goto_4d

    .line 2281
    :goto_4c
    const/4 v7, 0x0

    .line 2282
    goto :goto_50

    .line 2283
    :goto_4d
    const/4 v7, 0x0

    .line 2284
    :goto_4e
    :try_start_27
    invoke-virtual/range {p1 .. p1}, Lvp/g1;->d()Lvp/p0;

    .line 2285
    .line 2286
    .line 2287
    move-result-object v3

    .line 2288
    invoke-virtual {v3}, Lvp/p0;->e0()Lvp/n0;

    .line 2289
    .line 2290
    .line 2291
    move-result-object v3

    .line 2292
    invoke-static/range {v16 .. v16}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 2293
    .line 2294
    .line 2295
    move-result-object v9

    .line 2296
    invoke-virtual {v3, v9, v0, v10}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 2297
    .line 2298
    .line 2299
    sget-object v0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;
    :try_end_27
    .catchall {:try_start_27 .. :try_end_27} :catchall_e

    .line 2300
    .line 2301
    if-eqz v7, :cond_3f

    .line 2302
    .line 2303
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 2304
    .line 2305
    .line 2306
    :cond_3f
    :goto_4f
    invoke-interface {v2, v5, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2307
    .line 2308
    .line 2309
    goto :goto_51

    .line 2310
    :catchall_e
    move-exception v0

    .line 2311
    :goto_50
    if-eqz v7, :cond_40

    .line 2312
    .line 2313
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 2314
    .line 2315
    .line 2316
    :cond_40
    throw v0

    .line 2317
    :cond_41
    move-object/from16 v17, v3

    .line 2318
    .line 2319
    :goto_51
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 2320
    .line 2321
    .line 2322
    move-result-object v3

    .line 2323
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 2324
    .line 2325
    .line 2326
    move-result-object v3

    .line 2327
    :goto_52
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 2328
    .line 2329
    .line 2330
    move-result v5

    .line 2331
    if-eqz v5, :cond_42

    .line 2332
    .line 2333
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2334
    .line 2335
    .line 2336
    move-result-object v5

    .line 2337
    check-cast v5, Ljava/lang/Integer;

    .line 2338
    .line 2339
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 2340
    .line 2341
    .line 2342
    move-result v7

    .line 2343
    iget-object v9, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2344
    .line 2345
    invoke-virtual {v9, v5}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 2346
    .line 2347
    .line 2348
    move-result v9

    .line 2349
    if-eqz v9, :cond_43

    .line 2350
    .line 2351
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 2352
    .line 2353
    .line 2354
    move-result-object v0

    .line 2355
    invoke-virtual {v0}, Lvp/p0;->h0()Lvp/n0;

    .line 2356
    .line 2357
    .line 2358
    move-result-object v0

    .line 2359
    invoke-virtual {v0, v5, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2360
    .line 2361
    .line 2362
    :cond_42
    move-object/from16 v3, v17

    .line 2363
    .line 2364
    goto/16 :goto_44

    .line 2365
    .line 2366
    :cond_43
    invoke-interface {v0, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2367
    .line 2368
    .line 2369
    move-result-object v9

    .line 2370
    check-cast v9, Ljava/util/List;

    .line 2371
    .line 2372
    invoke-interface {v9}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 2373
    .line 2374
    .line 2375
    move-result-object v9

    .line 2376
    const/4 v12, 0x1

    .line 2377
    :goto_53
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 2378
    .line 2379
    .line 2380
    move-result v14

    .line 2381
    if-eqz v14, :cond_4b

    .line 2382
    .line 2383
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2384
    .line 2385
    .line 2386
    move-result-object v12

    .line 2387
    check-cast v12, Lcom/google/android/gms/internal/measurement/v1;

    .line 2388
    .line 2389
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 2390
    .line 2391
    .line 2392
    move-result-object v14

    .line 2393
    invoke-virtual {v14}, Lvp/p0;->k0()Ljava/lang/String;

    .line 2394
    .line 2395
    .line 2396
    move-result-object v14

    .line 2397
    move-object/from16 v16, v0

    .line 2398
    .line 2399
    const/4 v0, 0x2

    .line 2400
    invoke-static {v14, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 2401
    .line 2402
    .line 2403
    move-result v0

    .line 2404
    if-eqz v0, :cond_45

    .line 2405
    .line 2406
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 2407
    .line 2408
    .line 2409
    move-result-object v0

    .line 2410
    invoke-virtual {v0}, Lvp/p0;->h0()Lvp/n0;

    .line 2411
    .line 2412
    .line 2413
    move-result-object v0

    .line 2414
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->p()Z

    .line 2415
    .line 2416
    .line 2417
    move-result v14

    .line 2418
    if-eqz v14, :cond_44

    .line 2419
    .line 2420
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 2421
    .line 2422
    .line 2423
    move-result v14

    .line 2424
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2425
    .line 2426
    .line 2427
    move-result-object v14

    .line 2428
    :goto_54
    move-object/from16 v20, v2

    .line 2429
    .line 2430
    goto :goto_55

    .line 2431
    :cond_44
    const/4 v14, 0x0

    .line 2432
    goto :goto_54

    .line 2433
    :goto_55
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->m()Lvp/k0;

    .line 2434
    .line 2435
    .line 2436
    move-result-object v2

    .line 2437
    move-object/from16 v21, v3

    .line 2438
    .line 2439
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->r()Ljava/lang/String;

    .line 2440
    .line 2441
    .line 2442
    move-result-object v3

    .line 2443
    invoke-virtual {v2, v3}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 2444
    .line 2445
    .line 2446
    move-result-object v2

    .line 2447
    const-string v3, "Evaluating filter. audience, filter, property"

    .line 2448
    .line 2449
    invoke-virtual {v0, v3, v5, v14, v2}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 2450
    .line 2451
    .line 2452
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 2453
    .line 2454
    .line 2455
    move-result-object v0

    .line 2456
    invoke-virtual {v0}, Lvp/p0;->h0()Lvp/n0;

    .line 2457
    .line 2458
    .line 2459
    move-result-object v0

    .line 2460
    invoke-virtual {v15}, Lvp/z3;->i0()Lvp/s0;

    .line 2461
    .line 2462
    .line 2463
    move-result-object v2

    .line 2464
    invoke-virtual {v2, v12}, Lvp/s0;->E0(Lcom/google/android/gms/internal/measurement/v1;)Ljava/lang/String;

    .line 2465
    .line 2466
    .line 2467
    move-result-object v2

    .line 2468
    const-string v3, "Filter definition"

    .line 2469
    .line 2470
    invoke-virtual {v0, v2, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2471
    .line 2472
    .line 2473
    goto :goto_56

    .line 2474
    :cond_45
    move-object/from16 v20, v2

    .line 2475
    .line 2476
    move-object/from16 v21, v3

    .line 2477
    .line 2478
    :goto_56
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->p()Z

    .line 2479
    .line 2480
    .line 2481
    move-result v0

    .line 2482
    if-eqz v0, :cond_49

    .line 2483
    .line 2484
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 2485
    .line 2486
    .line 2487
    move-result v0

    .line 2488
    const/16 v2, 0x100

    .line 2489
    .line 2490
    if-le v0, v2, :cond_46

    .line 2491
    .line 2492
    goto :goto_58

    .line 2493
    :cond_46
    new-instance v0, Lvp/b;

    .line 2494
    .line 2495
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 2496
    .line 2497
    const/4 v3, 0x1

    .line 2498
    move-object/from16 p1, v0

    .line 2499
    .line 2500
    move-object/from16 p2, v1

    .line 2501
    .line 2502
    move-object/from16 p3, v2

    .line 2503
    .line 2504
    move/from16 p6, v3

    .line 2505
    .line 2506
    move/from16 p4, v7

    .line 2507
    .line 2508
    move-object/from16 p5, v12

    .line 2509
    .line 2510
    invoke-direct/range {p1 .. p6}, Lvp/b;-><init>(Lvp/d;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/l5;I)V

    .line 2511
    .line 2512
    .line 2513
    move-object/from16 v2, p1

    .line 2514
    .line 2515
    move/from16 v0, p4

    .line 2516
    .line 2517
    iget-object v3, v1, Lvp/d;->k:Ljava/lang/Long;

    .line 2518
    .line 2519
    iget-object v7, v1, Lvp/d;->l:Ljava/lang/Long;

    .line 2520
    .line 2521
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 2522
    .line 2523
    .line 2524
    move-result v12

    .line 2525
    iget-object v14, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 2526
    .line 2527
    invoke-interface {v14, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2528
    .line 2529
    .line 2530
    move-result-object v14

    .line 2531
    check-cast v14, Lvp/h4;

    .line 2532
    .line 2533
    if-nez v14, :cond_47

    .line 2534
    .line 2535
    const/4 v12, 0x0

    .line 2536
    goto :goto_57

    .line 2537
    :cond_47
    iget-object v14, v14, Lvp/h4;->d:Ljava/util/BitSet;

    .line 2538
    .line 2539
    invoke-virtual {v14, v12}, Ljava/util/BitSet;->get(I)Z

    .line 2540
    .line 2541
    .line 2542
    move-result v12

    .line 2543
    :goto_57
    invoke-virtual {v2, v3, v7, v4, v12}, Lvp/b;->j(Ljava/lang/Long;Ljava/lang/Long;Lcom/google/android/gms/internal/measurement/s3;Z)Z

    .line 2544
    .line 2545
    .line 2546
    move-result v12

    .line 2547
    if-eqz v12, :cond_48

    .line 2548
    .line 2549
    invoke-virtual {v1, v5}, Lvp/d;->f0(Ljava/lang/Integer;)Lvp/h4;

    .line 2550
    .line 2551
    .line 2552
    move-result-object v3

    .line 2553
    invoke-virtual {v3, v2}, Lvp/h4;->a(Lvp/c;)V

    .line 2554
    .line 2555
    .line 2556
    move v7, v0

    .line 2557
    move-object/from16 v0, v16

    .line 2558
    .line 2559
    move-object/from16 v2, v20

    .line 2560
    .line 2561
    move-object/from16 v3, v21

    .line 2562
    .line 2563
    goto/16 :goto_53

    .line 2564
    .line 2565
    :cond_48
    iget-object v0, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2566
    .line 2567
    invoke-virtual {v0, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2568
    .line 2569
    .line 2570
    goto :goto_5a

    .line 2571
    :cond_49
    :goto_58
    invoke-virtual/range {v24 .. v24}, Lvp/g1;->d()Lvp/p0;

    .line 2572
    .line 2573
    .line 2574
    move-result-object v0

    .line 2575
    invoke-virtual {v0}, Lvp/p0;->f0()Lvp/n0;

    .line 2576
    .line 2577
    .line 2578
    move-result-object v0

    .line 2579
    iget-object v2, v1, Lvp/d;->h:Ljava/lang/String;

    .line 2580
    .line 2581
    invoke-static {v2}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 2582
    .line 2583
    .line 2584
    move-result-object v2

    .line 2585
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->p()Z

    .line 2586
    .line 2587
    .line 2588
    move-result v3

    .line 2589
    if-eqz v3, :cond_4a

    .line 2590
    .line 2591
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 2592
    .line 2593
    .line 2594
    move-result v3

    .line 2595
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2596
    .line 2597
    .line 2598
    move-result-object v7

    .line 2599
    goto :goto_59

    .line 2600
    :cond_4a
    const/4 v7, 0x0

    .line 2601
    :goto_59
    invoke-static {v7}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 2602
    .line 2603
    .line 2604
    move-result-object v3

    .line 2605
    const-string v7, "Invalid property filter ID. appId, id"

    .line 2606
    .line 2607
    invoke-virtual {v0, v2, v3, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 2608
    .line 2609
    .line 2610
    goto :goto_5b

    .line 2611
    :cond_4b
    move-object/from16 v16, v0

    .line 2612
    .line 2613
    move-object/from16 v20, v2

    .line 2614
    .line 2615
    move-object/from16 v21, v3

    .line 2616
    .line 2617
    :goto_5a
    if-nez v12, :cond_4c

    .line 2618
    .line 2619
    :goto_5b
    iget-object v0, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2620
    .line 2621
    invoke-virtual {v0, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2622
    .line 2623
    .line 2624
    :cond_4c
    move-object/from16 v0, v16

    .line 2625
    .line 2626
    move-object/from16 v2, v20

    .line 2627
    .line 2628
    move-object/from16 v3, v21

    .line 2629
    .line 2630
    goto/16 :goto_52

    .line 2631
    .line 2632
    :cond_4d
    :goto_5c
    new-instance v2, Ljava/util/ArrayList;

    .line 2633
    .line 2634
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 2635
    .line 2636
    .line 2637
    iget-object v0, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 2638
    .line 2639
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 2640
    .line 2641
    .line 2642
    move-result-object v0

    .line 2643
    iget-object v3, v1, Lvp/d;->i:Ljava/util/HashSet;

    .line 2644
    .line 2645
    invoke-interface {v0, v3}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 2646
    .line 2647
    .line 2648
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 2649
    .line 2650
    .line 2651
    move-result-object v3

    .line 2652
    :cond_4e
    :goto_5d
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 2653
    .line 2654
    .line 2655
    move-result v0

    .line 2656
    if-eqz v0, :cond_4f

    .line 2657
    .line 2658
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2659
    .line 2660
    .line 2661
    move-result-object v0

    .line 2662
    check-cast v0, Ljava/lang/Integer;

    .line 2663
    .line 2664
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 2665
    .line 2666
    .line 2667
    move-result v4

    .line 2668
    iget-object v5, v1, Lvp/d;->j:Landroidx/collection/f;

    .line 2669
    .line 2670
    invoke-interface {v5, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2671
    .line 2672
    .line 2673
    move-result-object v5

    .line 2674
    check-cast v5, Lvp/h4;

    .line 2675
    .line 2676
    invoke-static {v5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2677
    .line 2678
    .line 2679
    invoke-virtual {v5, v4}, Lvp/h4;->b(I)Lcom/google/android/gms/internal/measurement/t2;

    .line 2680
    .line 2681
    .line 2682
    move-result-object v4

    .line 2683
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2684
    .line 2685
    .line 2686
    invoke-virtual {v15}, Lvp/z3;->f0()Lvp/n;

    .line 2687
    .line 2688
    .line 2689
    move-result-object v5

    .line 2690
    iget-object v6, v5, Lap0/o;->e:Ljava/lang/Object;

    .line 2691
    .line 2692
    check-cast v6, Lvp/g1;

    .line 2693
    .line 2694
    iget-object v7, v1, Lvp/d;->h:Ljava/lang/String;

    .line 2695
    .line 2696
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/t2;->r()Lcom/google/android/gms/internal/measurement/m3;

    .line 2697
    .line 2698
    .line 2699
    move-result-object v4

    .line 2700
    invoke-virtual {v5}, Lvp/u3;->b0()V

    .line 2701
    .line 2702
    .line 2703
    invoke-virtual {v5}, Lap0/o;->a0()V

    .line 2704
    .line 2705
    .line 2706
    invoke-static {v7}, Lno/c0;->e(Ljava/lang/String;)V

    .line 2707
    .line 2708
    .line 2709
    invoke-static {v4}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 2710
    .line 2711
    .line 2712
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/t4;->a()[B

    .line 2713
    .line 2714
    .line 2715
    move-result-object v4

    .line 2716
    new-instance v9, Landroid/content/ContentValues;

    .line 2717
    .line 2718
    invoke-direct {v9}, Landroid/content/ContentValues;-><init>()V

    .line 2719
    .line 2720
    .line 2721
    const-string v10, "app_id"

    .line 2722
    .line 2723
    invoke-virtual {v9, v10, v7}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 2724
    .line 2725
    .line 2726
    invoke-virtual {v9, v13, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 2727
    .line 2728
    .line 2729
    invoke-virtual {v9, v8, v4}, Landroid/content/ContentValues;->put(Ljava/lang/String;[B)V

    .line 2730
    .line 2731
    .line 2732
    :try_start_28
    invoke-virtual {v5}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 2733
    .line 2734
    .line 2735
    move-result-object v0

    .line 2736
    const-string v4, "audience_filter_values"
    :try_end_28
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_28 .. :try_end_28} :catch_1c

    .line 2737
    .line 2738
    const/4 v5, 0x5

    .line 2739
    const/4 v10, 0x0

    .line 2740
    :try_start_29
    invoke-virtual {v0, v4, v10, v9, v5}, Landroid/database/sqlite/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 2741
    .line 2742
    .line 2743
    move-result-wide v4

    .line 2744
    const-wide/16 v11, -0x1

    .line 2745
    .line 2746
    cmp-long v0, v4, v11

    .line 2747
    .line 2748
    if-nez v0, :cond_4e

    .line 2749
    .line 2750
    invoke-virtual {v6}, Lvp/g1;->d()Lvp/p0;

    .line 2751
    .line 2752
    .line 2753
    move-result-object v0

    .line 2754
    invoke-virtual {v0}, Lvp/p0;->e0()Lvp/n0;

    .line 2755
    .line 2756
    .line 2757
    move-result-object v0

    .line 2758
    const-string v4, "Failed to insert filter results (got -1). appId"

    .line 2759
    .line 2760
    invoke-static {v7}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 2761
    .line 2762
    .line 2763
    move-result-object v5

    .line 2764
    invoke-virtual {v0, v5, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_29
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_29 .. :try_end_29} :catch_1b

    .line 2765
    .line 2766
    .line 2767
    goto :goto_5d

    .line 2768
    :catch_1b
    move-exception v0

    .line 2769
    goto :goto_5e

    .line 2770
    :catch_1c
    move-exception v0

    .line 2771
    const/4 v10, 0x0

    .line 2772
    :goto_5e
    invoke-virtual {v6}, Lvp/g1;->d()Lvp/p0;

    .line 2773
    .line 2774
    .line 2775
    move-result-object v4

    .line 2776
    invoke-virtual {v4}, Lvp/p0;->e0()Lvp/n0;

    .line 2777
    .line 2778
    .line 2779
    move-result-object v4

    .line 2780
    invoke-static {v7}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 2781
    .line 2782
    .line 2783
    move-result-object v5

    .line 2784
    const-string v6, "Error storing filter results. appId"

    .line 2785
    .line 2786
    invoke-virtual {v4, v5, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 2787
    .line 2788
    .line 2789
    goto/16 :goto_5d

    .line 2790
    .line 2791
    :cond_4f
    return-object v2

    .line 2792
    :cond_50
    new-instance v0, Ljava/util/ArrayList;

    .line 2793
    .line 2794
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2795
    .line 2796
    .line 2797
    return-object v0

    .line 2798
    :goto_5f
    if-eqz v7, :cond_51

    .line 2799
    .line 2800
    invoke-interface {v7}, Landroid/database/Cursor;->close()V

    .line 2801
    .line 2802
    .line 2803
    :cond_51
    throw v0
.end method

.method public final f0(Ljava/lang/Integer;)Lvp/h4;
    .locals 2

    .line 1
    iget-object v0, p0, Lvp/d;->j:Landroidx/collection/f;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lvp/d;->j:Landroidx/collection/f;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lvp/h4;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    new-instance v0, Lvp/h4;

    .line 19
    .line 20
    iget-object v1, p0, Lvp/d;->h:Ljava/lang/String;

    .line 21
    .line 22
    invoke-direct {v0, p0, v1}, Lvp/h4;-><init>(Lvp/d;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lvp/d;->j:Landroidx/collection/f;

    .line 26
    .line 27
    invoke-interface {p0, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    return-object v0
.end method
