.class public final synthetic Lcom/google/android/gms/internal/measurement/p4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgr/m;


# instance fields
.field public final synthetic d:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/p4;->d:Landroid/content/Context;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get()Ljava/lang/Object;
    .locals 16

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 2
    .line 3
    move-object/from16 v0, p0

    .line 4
    .line 5
    iget-object v0, v0, Lcom/google/android/gms/internal/measurement/p4;->d:Landroid/content/Context;

    .line 6
    .line 7
    sget-object v1, Lcom/google/android/gms/internal/measurement/j4;->a:Lgr/g;

    .line 8
    .line 9
    if-nez v1, :cond_c

    .line 10
    .line 11
    const-class v2, Lcom/google/android/gms/internal/measurement/j4;

    .line 12
    .line 13
    monitor-enter v2

    .line 14
    :try_start_0
    sget-object v1, Lcom/google/android/gms/internal/measurement/j4;->a:Lgr/g;

    .line 15
    .line 16
    if-nez v1, :cond_b

    .line 17
    .line 18
    sget-object v1, Landroid/os/Build;->TYPE:Ljava/lang/String;

    .line 19
    .line 20
    sget-object v3, Landroid/os/Build;->TAGS:Ljava/lang/String;

    .line 21
    .line 22
    sget-object v4, Lcom/google/android/gms/internal/measurement/m4;->a:Landroidx/collection/f;

    .line 23
    .line 24
    const-string v4, "eng"

    .line 25
    .line 26
    invoke-virtual {v1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-nez v4, :cond_0

    .line 31
    .line 32
    const-string v4, "userdebug"

    .line 33
    .line 34
    invoke-virtual {v1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception v0

    .line 42
    goto/16 :goto_c

    .line 43
    .line 44
    :cond_0
    :goto_0
    const-string v1, "dev-keys"

    .line 45
    .line 46
    invoke-virtual {v3, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_2

    .line 51
    .line 52
    const-string v1, "test-keys"

    .line 53
    .line 54
    invoke-virtual {v3, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    sget-object v0, Lgr/a;->d:Lgr/a;

    .line 62
    .line 63
    move-object v1, v0

    .line 64
    goto/16 :goto_9

    .line 65
    .line 66
    :cond_2
    :goto_1
    invoke-virtual {v0}, Landroid/content/Context;->isDeviceProtectedStorage()Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-nez v1, :cond_3

    .line 71
    .line 72
    invoke-virtual {v0}, Landroid/content/Context;->createDeviceProtectedStorageContext()Landroid/content/Context;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    :cond_3
    move-object v1, v0

    .line 77
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskReads()Landroid/os/StrictMode$ThreadPolicy;

    .line 78
    .line 79
    .line 80
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 81
    :try_start_1
    invoke-static {}, Landroid/os/StrictMode;->allowThreadDiskWrites()Landroid/os/StrictMode$ThreadPolicy;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 82
    .line 83
    .line 84
    const/4 v4, 0x0

    .line 85
    :try_start_2
    new-instance v0, Ljava/io/File;

    .line 86
    .line 87
    const-string v5, "phenotype_hermetic"

    .line 88
    .line 89
    invoke-virtual {v1, v5, v4}, Landroid/content/Context;->getDir(Ljava/lang/String;I)Ljava/io/File;

    .line 90
    .line 91
    .line 92
    move-result-object v5

    .line 93
    const-string v6, "overrides.txt"

    .line 94
    .line 95
    invoke-direct {v0, v5, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 96
    .line 97
    .line 98
    :try_start_3
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-eqz v5, :cond_4

    .line 103
    .line 104
    new-instance v5, Lgr/j;

    .line 105
    .line 106
    invoke-direct {v5, v0}, Lgr/j;-><init>(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    sget-object v5, Lgr/a;->d:Lgr/a;

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :catchall_1
    move-exception v0

    .line 114
    goto/16 :goto_a

    .line 115
    .line 116
    :catch_0
    move-exception v0

    .line 117
    const-string v5, "HermeticFileOverrides"

    .line 118
    .line 119
    const-string v6, "no data dir"

    .line 120
    .line 121
    invoke-static {v5, v6, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 122
    .line 123
    .line 124
    sget-object v5, Lgr/a;->d:Lgr/a;

    .line 125
    .line 126
    :goto_2
    invoke-virtual {v5}, Lgr/g;->b()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_a

    .line 131
    .line 132
    invoke-virtual {v5}, Lgr/g;->a()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    check-cast v0, Ljava/io/File;

    .line 137
    .line 138
    const-string v5, "Parsed "

    .line 139
    .line 140
    const-string v6, " for Android package "

    .line 141
    .line 142
    const-string v7, "Invalid: "
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 143
    .line 144
    :try_start_4
    new-instance v8, Ljava/io/BufferedReader;

    .line 145
    .line 146
    new-instance v9, Ljava/io/InputStreamReader;

    .line 147
    .line 148
    new-instance v10, Ljava/io/FileInputStream;

    .line 149
    .line 150
    invoke-direct {v10, v0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 151
    .line 152
    .line 153
    invoke-direct {v9, v10}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 154
    .line 155
    .line 156
    invoke-direct {v8, v9}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 157
    .line 158
    .line 159
    :try_start_5
    new-instance v9, Landroidx/collection/a1;

    .line 160
    .line 161
    invoke-direct {v9, v4}, Landroidx/collection/a1;-><init>(I)V

    .line 162
    .line 163
    .line 164
    new-instance v10, Ljava/util/HashMap;

    .line 165
    .line 166
    invoke-direct {v10}, Ljava/util/HashMap;-><init>()V

    .line 167
    .line 168
    .line 169
    :goto_3
    invoke-virtual {v8}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v11

    .line 173
    if-eqz v11, :cond_9

    .line 174
    .line 175
    const-string v12, " "

    .line 176
    .line 177
    const/4 v13, 0x3

    .line 178
    invoke-virtual {v11, v12, v13}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    array-length v14, v12

    .line 183
    if-eq v14, v13, :cond_5

    .line 184
    .line 185
    const-string v12, "HermeticFileOverrides"

    .line 186
    .line 187
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 188
    .line 189
    .line 190
    move-result v13

    .line 191
    add-int/lit8 v13, v13, 0x9

    .line 192
    .line 193
    new-instance v14, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    invoke-direct {v14, v13}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v14, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v14, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v11

    .line 208
    invoke-static {v12, v11}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 209
    .line 210
    .line 211
    goto :goto_3

    .line 212
    :catchall_2
    move-exception v0

    .line 213
    move-object v1, v0

    .line 214
    goto/16 :goto_5

    .line 215
    .line 216
    :cond_5
    aget-object v11, v12, v4

    .line 217
    .line 218
    new-instance v13, Ljava/lang/String;

    .line 219
    .line 220
    invoke-direct {v13, v11}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    const/4 v11, 0x1

    .line 224
    aget-object v11, v12, v11

    .line 225
    .line 226
    new-instance v14, Ljava/lang/String;

    .line 227
    .line 228
    invoke-direct {v14, v11}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    invoke-static {v14}, Landroid/net/Uri;->decode(Ljava/lang/String;)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v11

    .line 235
    const/4 v14, 0x2

    .line 236
    aget-object v15, v12, v14

    .line 237
    .line 238
    invoke-virtual {v10, v15}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v15

    .line 242
    check-cast v15, Ljava/lang/String;

    .line 243
    .line 244
    if-nez v15, :cond_7

    .line 245
    .line 246
    aget-object v12, v12, v14

    .line 247
    .line 248
    new-instance v14, Ljava/lang/String;

    .line 249
    .line 250
    invoke-direct {v14, v12}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    invoke-static {v14}, Landroid/net/Uri;->decode(Ljava/lang/String;)Ljava/lang/String;

    .line 254
    .line 255
    .line 256
    move-result-object v15

    .line 257
    invoke-virtual {v15}, Ljava/lang/String;->length()I

    .line 258
    .line 259
    .line 260
    move-result v12

    .line 261
    const/16 v4, 0x400

    .line 262
    .line 263
    if-lt v12, v4, :cond_6

    .line 264
    .line 265
    if-ne v15, v14, :cond_7

    .line 266
    .line 267
    :cond_6
    invoke-virtual {v10, v14, v15}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    :cond_7
    invoke-virtual {v9, v13}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v4

    .line 274
    check-cast v4, Landroidx/collection/a1;

    .line 275
    .line 276
    if-nez v4, :cond_8

    .line 277
    .line 278
    new-instance v4, Landroidx/collection/a1;

    .line 279
    .line 280
    const/4 v12, 0x0

    .line 281
    invoke-direct {v4, v12}, Landroidx/collection/a1;-><init>(I)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v9, v13, v4}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    goto :goto_4

    .line 288
    :cond_8
    const/4 v12, 0x0

    .line 289
    :goto_4
    invoke-virtual {v4, v11, v15}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move v4, v12

    .line 293
    goto :goto_3

    .line 294
    :cond_9
    const-string v4, "HermeticFileOverrides"

    .line 295
    .line 296
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 305
    .line 306
    .line 307
    move-result v7

    .line 308
    add-int/lit8 v7, v7, 0x1c

    .line 309
    .line 310
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v10

    .line 314
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 315
    .line 316
    .line 317
    move-result v10

    .line 318
    add-int/2addr v7, v10

    .line 319
    new-instance v10, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    invoke-direct {v10, v7}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v10, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 325
    .line 326
    .line 327
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    invoke-static {v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 341
    .line 342
    .line 343
    new-instance v0, Lcom/google/android/gms/internal/measurement/g4;

    .line 344
    .line 345
    invoke-direct {v0, v9}, Lcom/google/android/gms/internal/measurement/g4;-><init>(Landroidx/collection/a1;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 346
    .line 347
    .line 348
    :try_start_6
    invoke-virtual {v8}, Ljava/io/BufferedReader;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 349
    .line 350
    .line 351
    :try_start_7
    new-instance v1, Lgr/j;

    .line 352
    .line 353
    invoke-direct {v1, v0}, Lgr/j;-><init>(Ljava/lang/Object;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 354
    .line 355
    .line 356
    goto :goto_8

    .line 357
    :catch_1
    move-exception v0

    .line 358
    goto :goto_7

    .line 359
    :goto_5
    :try_start_8
    invoke-virtual {v8}, Ljava/io/BufferedReader;->close()V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 360
    .line 361
    .line 362
    goto :goto_6

    .line 363
    :catchall_3
    move-exception v0

    .line 364
    :try_start_9
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 365
    .line 366
    .line 367
    :goto_6
    throw v1
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_1
    .catchall {:try_start_9 .. :try_end_9} :catchall_1

    .line 368
    :goto_7
    :try_start_a
    new-instance v1, Ljava/lang/RuntimeException;

    .line 369
    .line 370
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 371
    .line 372
    .line 373
    throw v1

    .line 374
    :cond_a
    sget-object v1, Lgr/a;->d:Lgr/a;
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 375
    .line 376
    :goto_8
    :try_start_b
    invoke-static {v3}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 377
    .line 378
    .line 379
    :goto_9
    sput-object v1, Lcom/google/android/gms/internal/measurement/j4;->a:Lgr/g;

    .line 380
    .line 381
    goto :goto_b

    .line 382
    :goto_a
    invoke-static {v3}, Landroid/os/StrictMode;->setThreadPolicy(Landroid/os/StrictMode$ThreadPolicy;)V

    .line 383
    .line 384
    .line 385
    throw v0

    .line 386
    :cond_b
    :goto_b
    monitor-exit v2

    .line 387
    return-object v1

    .line 388
    :goto_c
    monitor-exit v2
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 389
    throw v0

    .line 390
    :cond_c
    return-object v1
.end method
