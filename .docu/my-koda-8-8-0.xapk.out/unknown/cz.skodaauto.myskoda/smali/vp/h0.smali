.class public final Lvp/h0;
.super Lvp/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Ljava/lang/String;

.field public h:Ljava/lang/String;

.field public i:I

.field public j:Ljava/lang/String;

.field public k:Ljava/lang/String;

.field public l:J

.field public final m:J

.field public final n:J

.field public o:Ljava/util/List;

.field public p:Ljava/lang/String;

.field public q:I

.field public r:Ljava/lang/String;

.field public s:Ljava/lang/String;

.field public t:J

.field public u:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lvp/g1;JJ)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lvp/b0;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    iput-wide v0, p0, Lvp/h0;->t:J

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput-object p1, p0, Lvp/h0;->u:Ljava/lang/String;

    .line 10
    .line 11
    iput-wide p2, p0, Lvp/h0;->m:J

    .line 12
    .line 13
    iput-wide p4, p0, Lvp/h0;->n:J

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final d0()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final e0(Ljava/lang/String;)Lvp/f4;
    .locals 45

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 4
    .line 5
    .line 6
    new-instance v2, Lvp/f4;

    .line 7
    .line 8
    move-object v3, v2

    .line 9
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    move-object v4, v3

    .line 14
    invoke-virtual {v1}, Lvp/h0;->h0()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 19
    .line 20
    .line 21
    move-object v5, v4

    .line 22
    iget-object v4, v1, Lvp/h0;->h:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 25
    .line 26
    .line 27
    iget v0, v1, Lvp/h0;->i:I

    .line 28
    .line 29
    int-to-long v6, v0

    .line 30
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 31
    .line 32
    .line 33
    iget-object v0, v1, Lvp/h0;->j:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    move-object v8, v5

    .line 39
    move-wide v5, v6

    .line 40
    iget-object v7, v1, Lvp/h0;->j:Ljava/lang/String;

    .line 41
    .line 42
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v9, v0

    .line 45
    check-cast v9, Lvp/g1;

    .line 46
    .line 47
    iget-object v0, v9, Lvp/g1;->g:Lvp/h;

    .line 48
    .line 49
    iget-object v10, v9, Lvp/g1;->i:Lvp/p0;

    .line 50
    .line 51
    iget-object v11, v9, Lvp/g1;->g:Lvp/h;

    .line 52
    .line 53
    iget-object v12, v9, Lvp/g1;->d:Landroid/content/Context;

    .line 54
    .line 55
    iget-object v13, v9, Lvp/g1;->l:Lvp/d4;

    .line 56
    .line 57
    iget-object v14, v9, Lvp/g1;->h:Lvp/w0;

    .line 58
    .line 59
    invoke-virtual {v0}, Lvp/h;->f0()V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 66
    .line 67
    .line 68
    move-object v15, v2

    .line 69
    move-object/from16 v16, v3

    .line 70
    .line 71
    iget-wide v2, v1, Lvp/h0;->l:J

    .line 72
    .line 73
    const-wide/16 v17, 0x0

    .line 74
    .line 75
    cmp-long v0, v2, v17

    .line 76
    .line 77
    move-wide/from16 v19, v2

    .line 78
    .line 79
    if-nez v0, :cond_4

    .line 80
    .line 81
    invoke-static {v13}, Lvp/g1;->g(Lap0/o;)V

    .line 82
    .line 83
    .line 84
    iget-object v0, v13, Lap0/o;->e:Ljava/lang/Object;

    .line 85
    .line 86
    move-object v3, v0

    .line 87
    check-cast v3, Lvp/g1;

    .line 88
    .line 89
    invoke-virtual {v12}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-virtual {v13}, Lap0/o;->a0()V

    .line 94
    .line 95
    .line 96
    invoke-static {v0}, Lno/c0;->e(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v12}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 100
    .line 101
    .line 102
    move-result-object v19

    .line 103
    const/16 v21, 0x0

    .line 104
    .line 105
    invoke-static {}, Lvp/d4;->r0()Ljava/security/MessageDigest;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const-wide/16 v22, -0x1

    .line 110
    .line 111
    if-nez v2, :cond_0

    .line 112
    .line 113
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 114
    .line 115
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 116
    .line 117
    .line 118
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 119
    .line 120
    const-string v2, "Could not get MD5 instance"

    .line 121
    .line 122
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    move-object/from16 v24, v4

    .line 126
    .line 127
    move-wide/from16 v25, v5

    .line 128
    .line 129
    :goto_0
    move-wide/from16 v2, v22

    .line 130
    .line 131
    goto/16 :goto_4

    .line 132
    .line 133
    :cond_0
    if-eqz v19, :cond_3

    .line 134
    .line 135
    :try_start_0
    invoke-virtual {v13, v12, v0}, Lvp/d4;->D0(Landroid/content/Context;Ljava/lang/String;)Z

    .line 136
    .line 137
    .line 138
    move-result v0

    .line 139
    if-nez v0, :cond_2

    .line 140
    .line 141
    invoke-static {v12}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 142
    .line 143
    .line 144
    move-result-object v0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_2

    .line 145
    move-object/from16 v24, v4

    .line 146
    .line 147
    :try_start_1
    iget-object v4, v3, Lvp/g1;->d:Landroid/content/Context;

    .line 148
    .line 149
    invoke-virtual {v4}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v4
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 153
    move-wide/from16 v25, v5

    .line 154
    .line 155
    const/16 v5, 0x40

    .line 156
    .line 157
    :try_start_2
    invoke-virtual {v0, v5, v4}, Lcq/r1;->c(ILjava/lang/String;)Landroid/content/pm/PackageInfo;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    iget-object v0, v0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    .line 162
    .line 163
    if-eqz v0, :cond_1

    .line 164
    .line 165
    array-length v4, v0

    .line 166
    if-lez v4, :cond_1

    .line 167
    .line 168
    aget-object v0, v0, v21

    .line 169
    .line 170
    invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    invoke-virtual {v2, v0}, Ljava/security/MessageDigest;->digest([B)[B

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    invoke-static {v0}, Lvp/d4;->s0([B)J

    .line 179
    .line 180
    .line 181
    move-result-wide v22

    .line 182
    goto :goto_0

    .line 183
    :catch_0
    move-exception v0

    .line 184
    goto :goto_2

    .line 185
    :cond_1
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 186
    .line 187
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 188
    .line 189
    .line 190
    iget-object v0, v0, Lvp/p0;->m:Lvp/n0;

    .line 191
    .line 192
    const-string v2, "Could not get signatures"

    .line 193
    .line 194
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_2
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_2 .. :try_end_2} :catch_0

    .line 195
    .line 196
    .line 197
    goto :goto_0

    .line 198
    :catch_1
    move-exception v0

    .line 199
    :goto_1
    move-wide/from16 v25, v5

    .line 200
    .line 201
    goto :goto_2

    .line 202
    :catch_2
    move-exception v0

    .line 203
    move-object/from16 v24, v4

    .line 204
    .line 205
    goto :goto_1

    .line 206
    :cond_2
    move-object/from16 v24, v4

    .line 207
    .line 208
    move-wide/from16 v25, v5

    .line 209
    .line 210
    move-wide/from16 v22, v17

    .line 211
    .line 212
    goto :goto_0

    .line 213
    :goto_2
    iget-object v2, v3, Lvp/g1;->i:Lvp/p0;

    .line 214
    .line 215
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 216
    .line 217
    .line 218
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 219
    .line 220
    const-string v3, "Package name not found"

    .line 221
    .line 222
    invoke-virtual {v2, v0, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    :goto_3
    move-wide/from16 v2, v17

    .line 226
    .line 227
    goto :goto_4

    .line 228
    :cond_3
    move-object/from16 v24, v4

    .line 229
    .line 230
    move-wide/from16 v25, v5

    .line 231
    .line 232
    goto :goto_3

    .line 233
    :goto_4
    iput-wide v2, v1, Lvp/h0;->l:J

    .line 234
    .line 235
    goto :goto_5

    .line 236
    :cond_4
    move-object/from16 v24, v4

    .line 237
    .line 238
    move-wide/from16 v25, v5

    .line 239
    .line 240
    const/16 v21, 0x0

    .line 241
    .line 242
    move-wide/from16 v2, v19

    .line 243
    .line 244
    :goto_5
    invoke-virtual {v9}, Lvp/g1;->a()Z

    .line 245
    .line 246
    .line 247
    move-result v0

    .line 248
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 249
    .line 250
    .line 251
    iget-boolean v4, v14, Lvp/w0;->v:Z

    .line 252
    .line 253
    const/4 v5, 0x1

    .line 254
    xor-int/2addr v4, v5

    .line 255
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v9}, Lvp/g1;->a()Z

    .line 259
    .line 260
    .line 261
    move-result v6

    .line 262
    const/4 v5, 0x0

    .line 263
    if-nez v6, :cond_5

    .line 264
    .line 265
    :goto_6
    move/from16 v23, v0

    .line 266
    .line 267
    move-object v12, v5

    .line 268
    goto/16 :goto_8

    .line 269
    .line 270
    :cond_5
    sget-object v6, Lcom/google/android/gms/internal/measurement/s9;->e:Lcom/google/android/gms/internal/measurement/s9;

    .line 271
    .line 272
    iget-object v6, v6, Lcom/google/android/gms/internal/measurement/s9;->d:Lgr/p;

    .line 273
    .line 274
    iget-object v6, v6, Lgr/p;->d:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v6, Lcom/google/android/gms/internal/measurement/t9;

    .line 277
    .line 278
    sget-object v6, Lvp/z;->H0:Lvp/y;

    .line 279
    .line 280
    invoke-virtual {v11, v5, v6}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 281
    .line 282
    .line 283
    move-result v6

    .line 284
    if-eqz v6, :cond_6

    .line 285
    .line 286
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 287
    .line 288
    .line 289
    iget-object v6, v10, Lvp/p0;->r:Lvp/n0;

    .line 290
    .line 291
    const-string v10, "Disabled IID for tests."

    .line 292
    .line 293
    invoke-virtual {v6, v10}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    goto :goto_6

    .line 297
    :cond_6
    :try_start_3
    invoke-virtual {v12}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 298
    .line 299
    .line 300
    move-result-object v6

    .line 301
    const-string v5, "com.google.firebase.analytics.FirebaseAnalytics"

    .line 302
    .line 303
    invoke-virtual {v6, v5}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    .line 304
    .line 305
    .line 306
    move-result-object v5
    :try_end_3
    .catch Ljava/lang/ClassNotFoundException; {:try_start_3 .. :try_end_3} :catch_3

    .line 307
    if-nez v5, :cond_7

    .line 308
    .line 309
    :catch_3
    move/from16 v23, v0

    .line 310
    .line 311
    :goto_7
    const/4 v12, 0x0

    .line 312
    goto :goto_8

    .line 313
    :cond_7
    :try_start_4
    const-string v6, "getInstance"

    .line 314
    .line 315
    const-class v22, Landroid/content/Context;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_5

    .line 316
    .line 317
    move/from16 v23, v0

    .line 318
    .line 319
    :try_start_5
    filled-new-array/range {v22 .. v22}, [Ljava/lang/Class;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    invoke-virtual {v5, v6, v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 324
    .line 325
    .line 326
    move-result-object v0

    .line 327
    filled-new-array {v12}, [Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v6

    .line 331
    const/4 v12, 0x0

    .line 332
    invoke-virtual {v0, v12, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v0
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_6

    .line 336
    if-nez v0, :cond_8

    .line 337
    .line 338
    goto :goto_8

    .line 339
    :cond_8
    :try_start_6
    const-string v6, "getFirebaseInstanceId"

    .line 340
    .line 341
    invoke-virtual {v5, v6, v12}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 342
    .line 343
    .line 344
    move-result-object v5

    .line 345
    invoke-virtual {v5, v0, v12}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    check-cast v0, Ljava/lang/String;
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_4

    .line 350
    .line 351
    move-object v12, v0

    .line 352
    goto :goto_8

    .line 353
    :catch_4
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 354
    .line 355
    .line 356
    iget-object v0, v10, Lvp/p0;->o:Lvp/n0;

    .line 357
    .line 358
    const-string v5, "Failed to retrieve Firebase Instance Id"

    .line 359
    .line 360
    invoke-virtual {v0, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    goto :goto_7

    .line 364
    :catch_5
    move/from16 v23, v0

    .line 365
    .line 366
    :catch_6
    invoke-static {v10}, Lvp/g1;->k(Lvp/n1;)V

    .line 367
    .line 368
    .line 369
    iget-object v0, v10, Lvp/p0;->n:Lvp/n0;

    .line 370
    .line 371
    const-string v5, "Failed to obtain Firebase Analytics instance"

    .line 372
    .line 373
    invoke-virtual {v0, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    goto :goto_7

    .line 377
    :goto_8
    iget-wide v5, v9, Lvp/g1;->G:J

    .line 378
    .line 379
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 380
    .line 381
    .line 382
    iget-object v0, v14, Lvp/w0;->j:La8/s1;

    .line 383
    .line 384
    move-wide/from16 v27, v2

    .line 385
    .line 386
    invoke-virtual {v0}, La8/s1;->g()J

    .line 387
    .line 388
    .line 389
    move-result-wide v2

    .line 390
    cmp-long v0, v2, v17

    .line 391
    .line 392
    if-nez v0, :cond_9

    .line 393
    .line 394
    goto :goto_9

    .line 395
    :cond_9
    invoke-static {v5, v6, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 396
    .line 397
    .line 398
    move-result-wide v5

    .line 399
    :goto_9
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 400
    .line 401
    .line 402
    iget v0, v1, Lvp/h0;->q:I

    .line 403
    .line 404
    const-string v2, "google_analytics_adid_collection_enabled"

    .line 405
    .line 406
    invoke-virtual {v11, v2}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 407
    .line 408
    .line 409
    move-result-object v2

    .line 410
    if-eqz v2, :cond_b

    .line 411
    .line 412
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 413
    .line 414
    .line 415
    move-result v2

    .line 416
    if-eqz v2, :cond_a

    .line 417
    .line 418
    goto :goto_a

    .line 419
    :cond_a
    move/from16 v2, v21

    .line 420
    .line 421
    goto :goto_b

    .line 422
    :cond_b
    :goto_a
    const/4 v2, 0x1

    .line 423
    :goto_b
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 424
    .line 425
    .line 426
    invoke-virtual {v14}, Lap0/o;->a0()V

    .line 427
    .line 428
    .line 429
    invoke-virtual {v14}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 430
    .line 431
    .line 432
    move-result-object v3

    .line 433
    const-string v10, "deferred_analytics_collection"

    .line 434
    .line 435
    move/from16 v22, v2

    .line 436
    .line 437
    move/from16 v2, v21

    .line 438
    .line 439
    invoke-interface {v3, v10, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 440
    .line 441
    .line 442
    move-result v3

    .line 443
    const-string v2, "google_analytics_default_allow_ad_personalization_signals"

    .line 444
    .line 445
    move/from16 v29, v0

    .line 446
    .line 447
    const/4 v10, 0x1

    .line 448
    invoke-virtual {v11, v2, v10}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 449
    .line 450
    .line 451
    move-result-object v0

    .line 452
    sget-object v10, Lvp/p1;->h:Lvp/p1;

    .line 453
    .line 454
    if-eq v0, v10, :cond_c

    .line 455
    .line 456
    const/4 v0, 0x1

    .line 457
    goto :goto_c

    .line 458
    :cond_c
    const/4 v0, 0x0

    .line 459
    :goto_c
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    iget-object v10, v1, Lvp/h0;->o:Ljava/util/List;

    .line 464
    .line 465
    invoke-virtual {v14}, Lvp/w0;->h0()Lvp/s1;

    .line 466
    .line 467
    .line 468
    move-result-object v30

    .line 469
    invoke-virtual/range {v30 .. v30}, Lvp/s1;->g()Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v30

    .line 473
    move-object/from16 v31, v0

    .line 474
    .line 475
    iget-object v0, v1, Lvp/h0;->p:Ljava/lang/String;

    .line 476
    .line 477
    if-nez v0, :cond_d

    .line 478
    .line 479
    invoke-static {v13}, Lvp/g1;->g(Lap0/o;)V

    .line 480
    .line 481
    .line 482
    invoke-virtual {v13}, Lvp/d4;->S0()Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v0

    .line 486
    iput-object v0, v1, Lvp/h0;->p:Ljava/lang/String;

    .line 487
    .line 488
    :cond_d
    iget-object v0, v1, Lvp/h0;->p:Ljava/lang/String;

    .line 489
    .line 490
    move-object/from16 v32, v0

    .line 491
    .line 492
    invoke-virtual {v14}, Lvp/w0;->h0()Lvp/s1;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    move/from16 v33, v3

    .line 497
    .line 498
    sget-object v3, Lvp/r1;->f:Lvp/r1;

    .line 499
    .line 500
    invoke-virtual {v0, v3}, Lvp/s1;->i(Lvp/r1;)Z

    .line 501
    .line 502
    .line 503
    move-result v0

    .line 504
    if-nez v0, :cond_e

    .line 505
    .line 506
    move/from16 v34, v4

    .line 507
    .line 508
    const/4 v0, 0x0

    .line 509
    goto :goto_e

    .line 510
    :cond_e
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 511
    .line 512
    .line 513
    move v0, v4

    .line 514
    iget-wide v3, v1, Lvp/h0;->t:J

    .line 515
    .line 516
    cmp-long v3, v3, v17

    .line 517
    .line 518
    if-nez v3, :cond_f

    .line 519
    .line 520
    move/from16 v34, v0

    .line 521
    .line 522
    goto :goto_d

    .line 523
    :cond_f
    iget-object v3, v9, Lvp/g1;->n:Lto/a;

    .line 524
    .line 525
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 526
    .line 527
    .line 528
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 529
    .line 530
    .line 531
    move-result-wide v3

    .line 532
    move-wide/from16 v34, v3

    .line 533
    .line 534
    iget-wide v3, v1, Lvp/h0;->t:J

    .line 535
    .line 536
    sub-long v3, v34, v3

    .line 537
    .line 538
    move/from16 v34, v0

    .line 539
    .line 540
    iget-object v0, v1, Lvp/h0;->s:Ljava/lang/String;

    .line 541
    .line 542
    if-eqz v0, :cond_10

    .line 543
    .line 544
    const-wide/32 v35, 0x5265c00

    .line 545
    .line 546
    .line 547
    cmp-long v0, v3, v35

    .line 548
    .line 549
    if-lez v0, :cond_10

    .line 550
    .line 551
    iget-object v0, v1, Lvp/h0;->u:Ljava/lang/String;

    .line 552
    .line 553
    if-nez v0, :cond_10

    .line 554
    .line 555
    invoke-virtual {v1}, Lvp/h0;->f0()V

    .line 556
    .line 557
    .line 558
    :cond_10
    :goto_d
    iget-object v0, v1, Lvp/h0;->s:Ljava/lang/String;

    .line 559
    .line 560
    if-nez v0, :cond_11

    .line 561
    .line 562
    invoke-virtual {v1}, Lvp/h0;->f0()V

    .line 563
    .line 564
    .line 565
    :cond_11
    iget-object v0, v1, Lvp/h0;->s:Ljava/lang/String;

    .line 566
    .line 567
    :goto_e
    const-string v3, "google_analytics_sgtm_upload_enabled"

    .line 568
    .line 569
    invoke-virtual {v11, v3}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 570
    .line 571
    .line 572
    move-result-object v3

    .line 573
    if-nez v3, :cond_12

    .line 574
    .line 575
    const/4 v3, 0x0

    .line 576
    goto :goto_f

    .line 577
    :cond_12
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 578
    .line 579
    .line 580
    move-result v3

    .line 581
    :goto_f
    invoke-static {v13}, Lvp/g1;->g(Lap0/o;)V

    .line 582
    .line 583
    .line 584
    iget-object v4, v13, Lap0/o;->e:Ljava/lang/Object;

    .line 585
    .line 586
    check-cast v4, Lvp/g1;

    .line 587
    .line 588
    move-object/from16 v35, v0

    .line 589
    .line 590
    invoke-virtual {v1}, Lvp/h0;->g0()Ljava/lang/String;

    .line 591
    .line 592
    .line 593
    move-result-object v0

    .line 594
    move/from16 v36, v3

    .line 595
    .line 596
    iget-object v3, v4, Lvp/g1;->d:Landroid/content/Context;

    .line 597
    .line 598
    invoke-virtual {v3}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 599
    .line 600
    .line 601
    move-result-object v3

    .line 602
    if-nez v3, :cond_13

    .line 603
    .line 604
    move-wide/from16 v37, v5

    .line 605
    .line 606
    move-wide/from16 v3, v17

    .line 607
    .line 608
    const/4 v5, 0x0

    .line 609
    goto :goto_12

    .line 610
    :cond_13
    :try_start_7
    iget-object v3, v4, Lvp/g1;->d:Landroid/content/Context;

    .line 611
    .line 612
    invoke-static {v3}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 613
    .line 614
    .line 615
    move-result-object v3
    :try_end_7
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_7 .. :try_end_7} :catch_7

    .line 616
    move-wide/from16 v37, v5

    .line 617
    .line 618
    const/4 v5, 0x0

    .line 619
    :try_start_8
    invoke-virtual {v3, v5, v0}, Lcq/r1;->b(ILjava/lang/String;)Landroid/content/pm/ApplicationInfo;

    .line 620
    .line 621
    .line 622
    move-result-object v3

    .line 623
    if-eqz v3, :cond_14

    .line 624
    .line 625
    iget v0, v3, Landroid/content/pm/ApplicationInfo;->targetSdkVersion:I
    :try_end_8
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_8 .. :try_end_8} :catch_8

    .line 626
    .line 627
    goto :goto_11

    .line 628
    :cond_14
    :goto_10
    move v0, v5

    .line 629
    goto :goto_11

    .line 630
    :catch_7
    move-wide/from16 v37, v5

    .line 631
    .line 632
    const/4 v5, 0x0

    .line 633
    :catch_8
    iget-object v3, v4, Lvp/g1;->i:Lvp/p0;

    .line 634
    .line 635
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 636
    .line 637
    .line 638
    iget-object v3, v3, Lvp/p0;->p:Lvp/n0;

    .line 639
    .line 640
    const-string v4, "PackageManager failed to find running app: app_id"

    .line 641
    .line 642
    invoke-virtual {v3, v0, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 643
    .line 644
    .line 645
    goto :goto_10

    .line 646
    :goto_11
    int-to-long v3, v0

    .line 647
    :goto_12
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 648
    .line 649
    .line 650
    invoke-virtual {v14}, Lvp/w0;->h0()Lvp/s1;

    .line 651
    .line 652
    .line 653
    move-result-object v0

    .line 654
    iget v0, v0, Lvp/s1;->b:I

    .line 655
    .line 656
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 657
    .line 658
    .line 659
    invoke-virtual {v14}, Lap0/o;->a0()V

    .line 660
    .line 661
    .line 662
    invoke-virtual {v14}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 663
    .line 664
    .line 665
    move-result-object v6

    .line 666
    const-string v14, "dma_consent_settings"

    .line 667
    .line 668
    const/4 v5, 0x0

    .line 669
    invoke-interface {v6, v14, v5}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 670
    .line 671
    .line 672
    move-result-object v6

    .line 673
    invoke-static {v6}, Lvp/p;->b(Ljava/lang/String;)Lvp/p;

    .line 674
    .line 675
    .line 676
    move-result-object v6

    .line 677
    iget-object v6, v6, Lvp/p;->b:Ljava/lang/String;

    .line 678
    .line 679
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 680
    .line 681
    .line 682
    sget-object v14, Lvp/z;->Q0:Lvp/y;

    .line 683
    .line 684
    invoke-virtual {v11, v5, v14}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 685
    .line 686
    .line 687
    move-result v39

    .line 688
    if-eqz v39, :cond_15

    .line 689
    .line 690
    invoke-static {v13}, Lvp/g1;->g(Lap0/o;)V

    .line 691
    .line 692
    .line 693
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 694
    .line 695
    move/from16 v39, v0

    .line 696
    .line 697
    const/16 v0, 0x1e

    .line 698
    .line 699
    if-lt v5, v0, :cond_16

    .line 700
    .line 701
    invoke-static {}, Ld6/t1;->D()I

    .line 702
    .line 703
    .line 704
    move-result v0

    .line 705
    const/4 v5, 0x3

    .line 706
    if-le v0, v5, :cond_16

    .line 707
    .line 708
    invoke-static {}, Ld6/t1;->C()I

    .line 709
    .line 710
    .line 711
    move-result v0

    .line 712
    goto :goto_13

    .line 713
    :cond_15
    move/from16 v39, v0

    .line 714
    .line 715
    :cond_16
    const/4 v0, 0x0

    .line 716
    :goto_13
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 717
    .line 718
    .line 719
    const/4 v5, 0x0

    .line 720
    invoke-virtual {v11, v5, v14}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 721
    .line 722
    .line 723
    move-result v5

    .line 724
    if-eqz v5, :cond_17

    .line 725
    .line 726
    invoke-static {v13}, Lvp/g1;->g(Lap0/o;)V

    .line 727
    .line 728
    .line 729
    invoke-virtual {v13}, Lvp/d4;->v0()J

    .line 730
    .line 731
    .line 732
    move-result-wide v17

    .line 733
    :cond_17
    iget-object v5, v11, Lvp/h;->g:Ljava/lang/String;

    .line 734
    .line 735
    const/4 v13, 0x1

    .line 736
    invoke-virtual {v11, v2, v13}, Lvp/h;->p0(Ljava/lang/String;Z)Lvp/p1;

    .line 737
    .line 738
    .line 739
    move-result-object v2

    .line 740
    invoke-static {v2}, Lvp/s1;->h(Lvp/p1;)C

    .line 741
    .line 742
    .line 743
    move-result v2

    .line 744
    invoke-static {v2}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 745
    .line 746
    .line 747
    move-result-object v2

    .line 748
    iget-wide v13, v9, Lvp/g1;->G:J

    .line 749
    .line 750
    iget-object v11, v9, Lvp/g1;->x:Lvp/o2;

    .line 751
    .line 752
    invoke-static {v11}, Lvp/g1;->e(Lvp/x;)V

    .line 753
    .line 754
    .line 755
    iget-object v9, v9, Lvp/g1;->x:Lvp/o2;

    .line 756
    .line 757
    invoke-virtual {v9}, Lvp/o2;->f0()I

    .line 758
    .line 759
    .line 760
    move-result v9

    .line 761
    invoke-static {v9}, Lc1/j0;->b(I)I

    .line 762
    .line 763
    .line 764
    move-result v40

    .line 765
    move-object v11, v8

    .line 766
    iget-wide v8, v1, Lvp/h0;->m:J

    .line 767
    .line 768
    move-object v1, v11

    .line 769
    move/from16 v19, v22

    .line 770
    .line 771
    move-object/from16 v21, v31

    .line 772
    .line 773
    move/from16 v20, v33

    .line 774
    .line 775
    move/from16 v31, v39

    .line 776
    .line 777
    move/from16 v33, v0

    .line 778
    .line 779
    move-object/from16 v41, v12

    .line 780
    .line 781
    move-object/from16 v12, p1

    .line 782
    .line 783
    move-wide/from16 v42, v37

    .line 784
    .line 785
    move-object/from16 v37, v2

    .line 786
    .line 787
    move-wide/from16 v38, v13

    .line 788
    .line 789
    move-object v2, v15

    .line 790
    move/from16 v13, v23

    .line 791
    .line 792
    move/from16 v14, v34

    .line 793
    .line 794
    move-wide/from16 v22, v8

    .line 795
    .line 796
    move-object/from16 v15, v41

    .line 797
    .line 798
    const-wide/32 v8, 0x2078d

    .line 799
    .line 800
    .line 801
    move/from16 v41, v36

    .line 802
    .line 803
    move-object/from16 v36, v5

    .line 804
    .line 805
    move-object/from16 v44, v32

    .line 806
    .line 807
    move-object/from16 v32, v6

    .line 808
    .line 809
    move-wide/from16 v5, v25

    .line 810
    .line 811
    move-object/from16 v25, v30

    .line 812
    .line 813
    move-object/from16 v26, v44

    .line 814
    .line 815
    move-object/from16 v44, v24

    .line 816
    .line 817
    move-object/from16 v24, v10

    .line 818
    .line 819
    move-wide/from16 v10, v27

    .line 820
    .line 821
    move-object/from16 v27, v35

    .line 822
    .line 823
    move/from16 v28, v41

    .line 824
    .line 825
    move-wide/from16 v34, v17

    .line 826
    .line 827
    move/from16 v18, v29

    .line 828
    .line 829
    move-wide/from16 v29, v3

    .line 830
    .line 831
    move-object/from16 v3, v16

    .line 832
    .line 833
    move-object/from16 v4, v44

    .line 834
    .line 835
    move-wide/from16 v16, v42

    .line 836
    .line 837
    invoke-direct/range {v1 .. v40}, Lvp/f4;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;JJLjava/lang/String;ZZLjava/lang/String;JIZZLjava/lang/Boolean;JLjava/util/List;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZJILjava/lang/String;IJLjava/lang/String;Ljava/lang/String;JI)V

    .line 838
    .line 839
    .line 840
    return-object v1
.end method

.method public final f0()V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 9
    .line 10
    iget-object v2, v0, Lvp/g1;->i:Lvp/p0;

    .line 11
    .line 12
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Lvp/w0;->h0()Lvp/s1;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    sget-object v3, Lvp/r1;->f:Lvp/r1;

    .line 20
    .line 21
    invoke-virtual {v1, v3}, Lvp/s1;->i(Lvp/r1;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-nez v1, :cond_0

    .line 26
    .line 27
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 28
    .line 29
    .line 30
    iget-object v1, v2, Lvp/p0;->q:Lvp/n0;

    .line 31
    .line 32
    const-string v3, "Analytics Storage consent is not granted"

    .line 33
    .line 34
    invoke-virtual {v1, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const/4 v1, 0x0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/16 v1, 0x10

    .line 40
    .line 41
    new-array v1, v1, [B

    .line 42
    .line 43
    iget-object v3, v0, Lvp/g1;->l:Lvp/d4;

    .line 44
    .line 45
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v3}, Lvp/d4;->X0()Ljava/security/SecureRandom;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-virtual {v3, v1}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 53
    .line 54
    .line 55
    sget-object v3, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 56
    .line 57
    new-instance v4, Ljava/math/BigInteger;

    .line 58
    .line 59
    const/4 v5, 0x1

    .line 60
    invoke-direct {v4, v5, v1}, Ljava/math/BigInteger;-><init>(I[B)V

    .line 61
    .line 62
    .line 63
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    const-string v4, "%032x"

    .line 68
    .line 69
    invoke-static {v3, v4, v1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    :goto_0
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 74
    .line 75
    .line 76
    iget-object v2, v2, Lvp/p0;->q:Lvp/n0;

    .line 77
    .line 78
    if-nez v1, :cond_1

    .line 79
    .line 80
    const-string v3, "null"

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_1
    const-string v3, "not null"

    .line 84
    .line 85
    :goto_1
    const-string v4, "Resetting session stitching token to "

    .line 86
    .line 87
    invoke-virtual {v4, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iput-object v1, p0, Lvp/h0;->s:Ljava/lang/String;

    .line 95
    .line 96
    iget-object v0, v0, Lvp/g1;->n:Lto/a;

    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 102
    .line 103
    .line 104
    move-result-wide v0

    .line 105
    iput-wide v0, p0, Lvp/h0;->t:J

    .line 106
    .line 107
    return-void
.end method

.method public final g0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lvp/h0;->g:Ljava/lang/String;

    .line 5
    .line 6
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lvp/h0;->g:Ljava/lang/String;

    .line 10
    .line 11
    return-object p0
.end method

.method public final h0()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lvp/h0;->r:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lvp/h0;->r:Ljava/lang/String;

    .line 13
    .line 14
    return-object p0
.end method
