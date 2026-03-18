.class public final Lcq/l;
.super Lcq/b2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic n:Lbq/e;


# direct methods
.method public constructor <init>(Lko/l;Lbq/e;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lcq/l;->n:Lbq/e;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lcq/b2;-><init>(Lko/l;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final synthetic c(Lcom/google/android/gms/common/api/Status;)Lko/p;
    .locals 1

    .line 1
    new-instance p0, Lcq/n;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, p1, v0}, Lcq/n;-><init>(Lcom/google/android/gms/common/api/Status;Lbq/b;)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final i(Lko/c;)V
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    check-cast v0, Lcq/t1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v2, v1, Lcq/l;->n:Lbq/e;

    .line 11
    .line 12
    invoke-virtual {v2}, Lbq/e;->x0()Ljava/util/Map;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    iget-object v5, v2, Lbq/e;->d:Landroid/net/Uri;

    .line 17
    .line 18
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    :cond_0
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_2

    .line 31
    .line 32
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Ljava/util/Map$Entry;

    .line 37
    .line 38
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v4

    .line 42
    check-cast v4, Lcom/google/android/gms/wearable/Asset;

    .line 43
    .line 44
    iget-object v6, v4, Lcom/google/android/gms/wearable/Asset;->d:[B

    .line 45
    .line 46
    if-nez v6, :cond_0

    .line 47
    .line 48
    iget-object v6, v4, Lcom/google/android/gms/wearable/Asset;->e:Ljava/lang/String;

    .line 49
    .line 50
    if-nez v6, :cond_0

    .line 51
    .line 52
    iget-object v6, v4, Lcom/google/android/gms/wearable/Asset;->f:Landroid/os/ParcelFileDescriptor;

    .line 53
    .line 54
    if-nez v6, :cond_0

    .line 55
    .line 56
    iget-object v6, v4, Lcom/google/android/gms/wearable/Asset;->g:Landroid/net/Uri;

    .line 57
    .line 58
    if-eqz v6, :cond_1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    invoke-static {v5}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-static {v4}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    const-string v3, "Put for "

    .line 72
    .line 73
    const-string v4, " contains invalid asset: "

    .line 74
    .line 75
    invoke-static {v3, v1, v4, v2}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0

    .line 83
    :cond_2
    const-string v3, "uri must not be null"

    .line 84
    .line 85
    invoke-static {v5, v3}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    new-instance v4, Lbq/e;

    .line 89
    .line 90
    new-instance v6, Landroid/os/Bundle;

    .line 91
    .line 92
    invoke-direct {v6}, Landroid/os/Bundle;-><init>()V

    .line 93
    .line 94
    .line 95
    const/4 v7, 0x0

    .line 96
    sget-wide v8, Lbq/e;->h:J

    .line 97
    .line 98
    invoke-direct/range {v4 .. v9}, Lbq/e;-><init>(Landroid/net/Uri;Landroid/os/Bundle;[BJ)V

    .line 99
    .line 100
    .line 101
    iget-object v3, v2, Lbq/e;->f:[B

    .line 102
    .line 103
    iput-object v3, v4, Lbq/e;->f:[B

    .line 104
    .line 105
    iget-wide v5, v2, Lbq/e;->g:J

    .line 106
    .line 107
    const-wide/16 v7, 0x0

    .line 108
    .line 109
    cmp-long v3, v5, v7

    .line 110
    .line 111
    if-nez v3, :cond_3

    .line 112
    .line 113
    iput-wide v7, v4, Lbq/e;->g:J

    .line 114
    .line 115
    :cond_3
    new-instance v3, Ljava/util/ArrayList;

    .line 116
    .line 117
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v2}, Lbq/e;->x0()Ljava/util/Map;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    invoke-interface {v5}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    invoke-interface {v5}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 133
    .line 134
    .line 135
    move-result v6

    .line 136
    const/4 v7, 0x1

    .line 137
    const/4 v8, 0x0

    .line 138
    if-eqz v6, :cond_b

    .line 139
    .line 140
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    check-cast v6, Ljava/util/Map$Entry;

    .line 145
    .line 146
    invoke-interface {v6}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    check-cast v9, Lcom/google/android/gms/wearable/Asset;

    .line 151
    .line 152
    iget-object v10, v9, Lcom/google/android/gms/wearable/Asset;->d:[B

    .line 153
    .line 154
    iget-object v11, v9, Lcom/google/android/gms/wearable/Asset;->f:Landroid/os/ParcelFileDescriptor;

    .line 155
    .line 156
    iget-object v12, v9, Lcom/google/android/gms/wearable/Asset;->g:Landroid/net/Uri;

    .line 157
    .line 158
    const-string v14, "WearableClient"

    .line 159
    .line 160
    iget-object v15, v4, Lbq/e;->e:Landroid/os/Bundle;

    .line 161
    .line 162
    if-eqz v10, :cond_6

    .line 163
    .line 164
    :try_start_0
    invoke-static {}, Landroid/os/ParcelFileDescriptor;->createPipe()[Landroid/os/ParcelFileDescriptor;

    .line 165
    .line 166
    .line 167
    move-result-object v10
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 168
    const/4 v11, 0x3

    .line 169
    invoke-static {v14, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 170
    .line 171
    .line 172
    move-result v11

    .line 173
    if-eqz v11, :cond_4

    .line 174
    .line 175
    invoke-static {v9}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v11

    .line 179
    aget-object v12, v10, v8

    .line 180
    .line 181
    invoke-static {v12}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v12

    .line 185
    aget-object v16, v10, v7

    .line 186
    .line 187
    move/from16 p1, v7

    .line 188
    .line 189
    invoke-static/range {v16 .. v16}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v7

    .line 193
    move/from16 v16, v8

    .line 194
    .line 195
    const-string v8, " read:"

    .line 196
    .line 197
    const-string v13, " write:"

    .line 198
    .line 199
    move-object/from16 v17, v2

    .line 200
    .line 201
    const-string v2, "processAssets: replacing data with FD in asset: "

    .line 202
    .line 203
    invoke-static {v2, v11, v8, v12, v13}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 208
    .line 209
    .line 210
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v2

    .line 214
    invoke-static {v14, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 215
    .line 216
    .line 217
    goto :goto_2

    .line 218
    :cond_4
    move-object/from16 v17, v2

    .line 219
    .line 220
    move/from16 p1, v7

    .line 221
    .line 222
    move/from16 v16, v8

    .line 223
    .line 224
    :goto_2
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v2

    .line 228
    check-cast v2, Ljava/lang/String;

    .line 229
    .line 230
    aget-object v6, v10, v16

    .line 231
    .line 232
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    new-instance v7, Lcom/google/android/gms/wearable/Asset;

    .line 236
    .line 237
    const/4 v8, 0x0

    .line 238
    invoke-direct {v7, v8, v8, v6, v8}, Lcom/google/android/gms/wearable/Asset;-><init>([BLjava/lang/String;Landroid/os/ParcelFileDescriptor;Landroid/net/Uri;)V

    .line 239
    .line 240
    .line 241
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v15, v2, v7}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 245
    .line 246
    .line 247
    aget-object v2, v10, p1

    .line 248
    .line 249
    iget-object v6, v9, Lcom/google/android/gms/wearable/Asset;->d:[B

    .line 250
    .line 251
    new-instance v7, Ljava/util/concurrent/FutureTask;

    .line 252
    .line 253
    new-instance v8, Lcq/s1;

    .line 254
    .line 255
    move/from16 v9, v16

    .line 256
    .line 257
    invoke-direct {v8, v9, v2, v6}, Lcq/s1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    invoke-direct {v7, v8}, Ljava/util/concurrent/FutureTask;-><init>(Ljava/util/concurrent/Callable;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    iget-object v2, v0, Lcq/t1;->z:Ljava/util/concurrent/ExecutorService;

    .line 267
    .line 268
    invoke-interface {v2, v7}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 269
    .line 270
    .line 271
    :cond_5
    :goto_3
    move-object/from16 v2, v17

    .line 272
    .line 273
    goto/16 :goto_1

    .line 274
    .line 275
    :catch_0
    move-exception v0

    .line 276
    move-object/from16 v17, v2

    .line 277
    .line 278
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 279
    .line 280
    invoke-static/range {v17 .. v17}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    const-string v3, "Unable to create ParcelFileDescriptor for asset in request: "

    .line 285
    .line 286
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object v2

    .line 290
    invoke-direct {v1, v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 291
    .line 292
    .line 293
    throw v1

    .line 294
    :cond_6
    move-object/from16 v17, v2

    .line 295
    .line 296
    const/16 v2, 0xfa5

    .line 297
    .line 298
    if-eqz v12, :cond_7

    .line 299
    .line 300
    :try_start_1
    iget-object v7, v0, Lno/e;->c:Landroid/content/Context;

    .line 301
    .line 302
    invoke-virtual {v7}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 303
    .line 304
    .line 305
    move-result-object v7

    .line 306
    const-string v8, "r"

    .line 307
    .line 308
    invoke-virtual {v7, v12, v8}, Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;

    .line 309
    .line 310
    .line 311
    move-result-object v7

    .line 312
    invoke-static {v7}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 313
    .line 314
    .line 315
    new-instance v8, Lcom/google/android/gms/wearable/Asset;

    .line 316
    .line 317
    const/4 v9, 0x0

    .line 318
    invoke-direct {v8, v9, v9, v7, v9}, Lcom/google/android/gms/wearable/Asset;-><init>([BLjava/lang/String;Landroid/os/ParcelFileDescriptor;Landroid/net/Uri;)V

    .line 319
    .line 320
    .line 321
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v6

    .line 325
    check-cast v6, Ljava/lang/String;

    .line 326
    .line 327
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v15, v6, v8}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V
    :try_end_1
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 331
    .line 332
    .line 333
    goto :goto_3

    .line 334
    :catch_1
    new-instance v0, Lcq/p1;

    .line 335
    .line 336
    invoke-direct {v0, v1, v3}, Lcq/p1;-><init>(Lcq/l;Ljava/util/ArrayList;)V

    .line 337
    .line 338
    .line 339
    new-instance v1, Lcq/g1;

    .line 340
    .line 341
    const/4 v8, 0x0

    .line 342
    invoke-direct {v1, v2, v8}, Lcq/g1;-><init>(ILcq/r;)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v0, v1}, Lcq/p1;->K(Lcq/g1;)V

    .line 346
    .line 347
    .line 348
    invoke-static {v12}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    const-string v1, "Couldn\'t resolve asset URI: "

    .line 353
    .line 354
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    invoke-static {v14, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 359
    .line 360
    .line 361
    goto :goto_7

    .line 362
    :cond_7
    if-eqz v11, :cond_a

    .line 363
    .line 364
    :try_start_2
    iget-object v7, v0, Lcq/t1;->L:Lop/c;

    .line 365
    .line 366
    invoke-virtual {v7}, Lop/c;->h()Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v7

    .line 370
    check-cast v7, Ljava/io/File;

    .line 371
    .line 372
    invoke-static {v11, v7}, Ljp/ec;->g(Landroid/os/ParcelFileDescriptor;Ljava/io/File;)Ljava/io/File;

    .line 373
    .line 374
    .line 375
    move-result-object v8
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_3
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 376
    const/high16 v7, 0x10000000

    .line 377
    .line 378
    :try_start_3
    invoke-static {v8, v7}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    .line 379
    .line 380
    .line 381
    move-result-object v7

    .line 382
    invoke-static {v7}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 383
    .line 384
    .line 385
    new-instance v9, Lcom/google/android/gms/wearable/Asset;

    .line 386
    .line 387
    const/4 v10, 0x0

    .line 388
    invoke-direct {v9, v10, v10, v7, v10}, Lcom/google/android/gms/wearable/Asset;-><init>([BLjava/lang/String;Landroid/os/ParcelFileDescriptor;Landroid/net/Uri;)V

    .line 389
    .line 390
    .line 391
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v6

    .line 395
    check-cast v6, Ljava/lang/String;

    .line 396
    .line 397
    invoke-static {v6}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 398
    .line 399
    .line 400
    invoke-virtual {v15, v6, v9}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 401
    .line 402
    .line 403
    if-eqz v8, :cond_5

    .line 404
    .line 405
    invoke-virtual {v8}, Ljava/io/File;->delete()Z

    .line 406
    .line 407
    .line 408
    goto/16 :goto_3

    .line 409
    .line 410
    :catch_2
    move-exception v0

    .line 411
    goto :goto_6

    .line 412
    :catchall_0
    move-exception v0

    .line 413
    move-object v13, v8

    .line 414
    goto :goto_8

    .line 415
    :catchall_1
    move-exception v0

    .line 416
    goto :goto_4

    .line 417
    :catch_3
    move-exception v0

    .line 418
    goto :goto_5

    .line 419
    :goto_4
    const/4 v13, 0x0

    .line 420
    goto :goto_8

    .line 421
    :goto_5
    const/4 v8, 0x0

    .line 422
    :goto_6
    :try_start_4
    const-string v4, "DataItem asset copy failed"

    .line 423
    .line 424
    invoke-static {v14, v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 425
    .line 426
    .line 427
    new-instance v0, Lcq/p1;

    .line 428
    .line 429
    invoke-direct {v0, v1, v3}, Lcq/p1;-><init>(Lcq/l;Ljava/util/ArrayList;)V

    .line 430
    .line 431
    .line 432
    new-instance v1, Lcq/g1;

    .line 433
    .line 434
    const/4 v9, 0x0

    .line 435
    invoke-direct {v1, v2, v9}, Lcq/g1;-><init>(ILcq/r;)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v0, v1}, Lcq/p1;->K(Lcq/g1;)V

    .line 439
    .line 440
    .line 441
    invoke-static {v11}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object v0

    .line 445
    new-instance v1, Ljava/lang/StringBuilder;

    .line 446
    .line 447
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 448
    .line 449
    .line 450
    const-string v2, "Couldn\'t asset from a file descriptor: "

    .line 451
    .line 452
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 453
    .line 454
    .line 455
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 456
    .line 457
    .line 458
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 459
    .line 460
    .line 461
    move-result-object v0

    .line 462
    invoke-static {v14, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 463
    .line 464
    .line 465
    if-eqz v8, :cond_8

    .line 466
    .line 467
    invoke-virtual {v8}, Ljava/io/File;->delete()Z

    .line 468
    .line 469
    .line 470
    :cond_8
    :goto_7
    return-void

    .line 471
    :goto_8
    if-eqz v13, :cond_9

    .line 472
    .line 473
    invoke-virtual {v13}, Ljava/io/File;->delete()Z

    .line 474
    .line 475
    .line 476
    :cond_9
    throw v0

    .line 477
    :cond_a
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v2

    .line 481
    check-cast v2, Ljava/lang/String;

    .line 482
    .line 483
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 484
    .line 485
    .line 486
    invoke-virtual {v15, v2, v9}, Landroid/os/Bundle;->putParcelable(Ljava/lang/String;Landroid/os/Parcelable;)V

    .line 487
    .line 488
    .line 489
    goto/16 :goto_3

    .line 490
    .line 491
    :cond_b
    move/from16 p1, v7

    .line 492
    .line 493
    invoke-virtual {v0}, Lno/e;->r()Landroid/os/IInterface;

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    check-cast v0, Lcq/w0;

    .line 498
    .line 499
    new-instance v2, Lcq/p1;

    .line 500
    .line 501
    invoke-direct {v2, v1, v3}, Lcq/p1;-><init>(Lcq/l;Ljava/util/ArrayList;)V

    .line 502
    .line 503
    .line 504
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    iget-object v3, v0, Lbp/a;->e:Ljava/lang/String;

    .line 509
    .line 510
    invoke-virtual {v1, v3}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    .line 511
    .line 512
    .line 513
    sget v3, Lop/e;->a:I

    .line 514
    .line 515
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 516
    .line 517
    .line 518
    move/from16 v2, p1

    .line 519
    .line 520
    invoke-virtual {v1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 521
    .line 522
    .line 523
    const/4 v9, 0x0

    .line 524
    invoke-interface {v4, v1, v9}, Landroid/os/Parcelable;->writeToParcel(Landroid/os/Parcel;I)V

    .line 525
    .line 526
    .line 527
    const/4 v2, 0x6

    .line 528
    invoke-virtual {v0, v1, v2}, Lbp/a;->R(Landroid/os/Parcel;I)V

    .line 529
    .line 530
    .line 531
    return-void
.end method
