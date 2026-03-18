.class public final Lvp/x1;
.super Lvp/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final synthetic f:Lvp/j2;


# direct methods
.method public constructor <init>(Lvp/j2;Lvp/o1;I)V
    .locals 0

    .line 1
    iput p3, p0, Lvp/x1;->e:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lvp/x1;->f:Lvp/j2;

    .line 10
    .line 11
    invoke-direct {p0, p2}, Lvp/o;-><init>(Lvp/o1;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    iput-object p1, p0, Lvp/x1;->f:Lvp/j2;

    .line 16
    .line 17
    invoke-direct {p0, p2}, Lvp/o;-><init>(Lvp/o1;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :pswitch_1
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lvp/x1;->f:Lvp/j2;

    .line 25
    .line 26
    invoke-direct {p0, p2}, Lvp/o;-><init>(Lvp/o1;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lvp/x1;->f:Lvp/j2;

    .line 34
    .line 35
    invoke-direct {p0, p2}, Lvp/o;-><init>(Lvp/o1;)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvp/x1;->e:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lvp/x1;->f:Lvp/j2;

    .line 9
    .line 10
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v2, v0

    .line 13
    check-cast v2, Lvp/g1;

    .line 14
    .line 15
    iget-object v3, v2, Lvp/g1;->h:Lvp/w0;

    .line 16
    .line 17
    iget-object v4, v2, Lvp/g1;->i:Lvp/p0;

    .line 18
    .line 19
    iget-object v0, v2, Lvp/g1;->j:Lvp/e1;

    .line 20
    .line 21
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 25
    .line 26
    .line 27
    iget-object v6, v2, Lvp/g1;->r:Lvp/n2;

    .line 28
    .line 29
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 30
    .line 31
    .line 32
    iget-object v0, v6, Lap0/o;->e:Ljava/lang/Object;

    .line 33
    .line 34
    move-object v5, v0

    .line 35
    check-cast v5, Lvp/g1;

    .line 36
    .line 37
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2}, Lvp/g1;->q()Lvp/h0;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {v0}, Lvp/h0;->g0()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v7

    .line 48
    iget-object v0, v2, Lvp/g1;->g:Lvp/h;

    .line 49
    .line 50
    const-string v8, "google_analytics_adid_collection_enabled"

    .line 51
    .line 52
    invoke-virtual {v0, v8}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    const/4 v12, 0x0

    .line 57
    if-eqz v0, :cond_1

    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_0

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 67
    .line 68
    .line 69
    iget-object v0, v4, Lvp/p0;->r:Lvp/n0;

    .line 70
    .line 71
    const-string v2, "ADID collection is disabled from Manifest. Skipping"

    .line 72
    .line 73
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    goto/16 :goto_11

    .line 77
    .line 78
    :cond_1
    :goto_0
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 79
    .line 80
    .line 81
    iget-object v0, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v8, v0

    .line 84
    check-cast v8, Lvp/g1;

    .line 85
    .line 86
    invoke-virtual {v3}, Lap0/o;->a0()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v3}, Lvp/w0;->h0()Lvp/s1;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    sget-object v9, Lvp/r1;->e:Lvp/r1;

    .line 94
    .line 95
    invoke-virtual {v0, v9}, Lvp/s1;->i(Lvp/r1;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    const-string v9, ""

    .line 100
    .line 101
    if-eqz v0, :cond_5

    .line 102
    .line 103
    iget-object v0, v8, Lvp/g1;->n:Lto/a;

    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 109
    .line 110
    .line 111
    move-result-wide v10

    .line 112
    iget-object v0, v3, Lvp/w0;->l:Ljava/lang/String;

    .line 113
    .line 114
    if-eqz v0, :cond_3

    .line 115
    .line 116
    iget-wide v13, v3, Lvp/w0;->n:J

    .line 117
    .line 118
    cmp-long v13, v10, v13

    .line 119
    .line 120
    if-ltz v13, :cond_2

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_2
    new-instance v8, Landroid/util/Pair;

    .line 124
    .line 125
    iget-boolean v9, v3, Lvp/w0;->m:Z

    .line 126
    .line 127
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 128
    .line 129
    .line 130
    move-result-object v9

    .line 131
    invoke-direct {v8, v0, v9}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_5

    .line 135
    :cond_3
    :goto_1
    iget-object v0, v8, Lvp/g1;->g:Lvp/h;

    .line 136
    .line 137
    sget-object v13, Lvp/z;->b:Lvp/y;

    .line 138
    .line 139
    invoke-virtual {v0, v7, v13}, Lvp/h;->h0(Ljava/lang/String;Lvp/y;)J

    .line 140
    .line 141
    .line 142
    move-result-wide v13

    .line 143
    add-long/2addr v13, v10

    .line 144
    iput-wide v13, v3, Lvp/w0;->n:J

    .line 145
    .line 146
    :try_start_0
    iget-object v0, v8, Lvp/g1;->d:Landroid/content/Context;

    .line 147
    .line 148
    invoke-static {v0}, Lco/b;->a(Landroid/content/Context;)Lco/a;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    iput-object v9, v3, Lvp/w0;->l:Ljava/lang/String;

    .line 153
    .line 154
    iget-object v10, v0, Lco/a;->c:Ljava/lang/String;

    .line 155
    .line 156
    if-eqz v10, :cond_4

    .line 157
    .line 158
    iput-object v10, v3, Lvp/w0;->l:Ljava/lang/String;

    .line 159
    .line 160
    goto :goto_2

    .line 161
    :catch_0
    move-exception v0

    .line 162
    goto :goto_3

    .line 163
    :cond_4
    :goto_2
    iget-boolean v0, v0, Lco/a;->b:Z

    .line 164
    .line 165
    iput-boolean v0, v3, Lvp/w0;->m:Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :goto_3
    iget-object v8, v8, Lvp/g1;->i:Lvp/p0;

    .line 169
    .line 170
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 171
    .line 172
    .line 173
    iget-object v8, v8, Lvp/p0;->q:Lvp/n0;

    .line 174
    .line 175
    const-string v10, "Unable to get advertising id"

    .line 176
    .line 177
    invoke-virtual {v8, v0, v10}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    iput-object v9, v3, Lvp/w0;->l:Ljava/lang/String;

    .line 181
    .line 182
    :goto_4
    new-instance v8, Landroid/util/Pair;

    .line 183
    .line 184
    iget-object v0, v3, Lvp/w0;->l:Ljava/lang/String;

    .line 185
    .line 186
    iget-boolean v9, v3, Lvp/w0;->m:Z

    .line 187
    .line 188
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 189
    .line 190
    .line 191
    move-result-object v9

    .line 192
    invoke-direct {v8, v0, v9}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    goto :goto_5

    .line 196
    :cond_5
    new-instance v8, Landroid/util/Pair;

    .line 197
    .line 198
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 199
    .line 200
    invoke-direct {v8, v9, v0}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    :goto_5
    iget-object v0, v8, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Ljava/lang/Boolean;

    .line 206
    .line 207
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    if-nez v0, :cond_16

    .line 212
    .line 213
    iget-object v0, v8, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v0, Ljava/lang/CharSequence;

    .line 216
    .line 217
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 218
    .line 219
    .line 220
    move-result v0

    .line 221
    if-eqz v0, :cond_6

    .line 222
    .line 223
    goto/16 :goto_10

    .line 224
    .line 225
    :cond_6
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v6}, Lvp/n1;->c0()V

    .line 229
    .line 230
    .line 231
    iget-object v0, v5, Lvp/g1;->d:Landroid/content/Context;

    .line 232
    .line 233
    const-string v9, "connectivity"

    .line 234
    .line 235
    invoke-virtual {v0, v9}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    check-cast v0, Landroid/net/ConnectivityManager;

    .line 240
    .line 241
    const/4 v9, 0x0

    .line 242
    if-eqz v0, :cond_7

    .line 243
    .line 244
    :try_start_1
    invoke-virtual {v0}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 245
    .line 246
    .line 247
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_1

    .line 248
    goto :goto_6

    .line 249
    :catch_1
    :cond_7
    move-object v0, v9

    .line 250
    :goto_6
    if-eqz v0, :cond_15

    .line 251
    .line 252
    invoke-virtual {v0}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-eqz v0, :cond_15

    .line 257
    .line 258
    new-instance v10, Ljava/lang/StringBuilder;

    .line 259
    .line 260
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v2}, Lvp/g1;->o()Lvp/d3;

    .line 264
    .line 265
    .line 266
    move-result-object v0

    .line 267
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 268
    .line 269
    .line 270
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 271
    .line 272
    .line 273
    invoke-virtual {v0}, Lvp/d3;->h0()Z

    .line 274
    .line 275
    .line 276
    move-result v11

    .line 277
    if-nez v11, :cond_8

    .line 278
    .line 279
    goto :goto_7

    .line 280
    :cond_8
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast v0, Lvp/g1;

    .line 283
    .line 284
    iget-object v0, v0, Lvp/g1;->l:Lvp/d4;

    .line 285
    .line 286
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v0}, Lvp/d4;->G0()I

    .line 290
    .line 291
    .line 292
    move-result v0

    .line 293
    const v11, 0x392d8

    .line 294
    .line 295
    .line 296
    if-lt v0, v11, :cond_11

    .line 297
    .line 298
    :goto_7
    iget-object v0, v2, Lvp/g1;->p:Lvp/j2;

    .line 299
    .line 300
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 301
    .line 302
    .line 303
    iget-object v11, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v11, Lvp/g1;

    .line 306
    .line 307
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v11}, Lvp/g1;->o()Lvp/d3;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    iget-object v11, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast v11, Lvp/g1;

    .line 317
    .line 318
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 322
    .line 323
    .line 324
    iget-object v13, v0, Lvp/d3;->h:Lvp/c0;

    .line 325
    .line 326
    if-nez v13, :cond_9

    .line 327
    .line 328
    invoke-virtual {v0}, Lvp/d3;->g0()V

    .line 329
    .line 330
    .line 331
    iget-object v0, v11, Lvp/g1;->i:Lvp/p0;

    .line 332
    .line 333
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 334
    .line 335
    .line 336
    iget-object v0, v0, Lvp/p0;->q:Lvp/n0;

    .line 337
    .line 338
    const-string v11, "Failed to get consents; not connected to service yet."

    .line 339
    .line 340
    invoke-virtual {v0, v11}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    :goto_8
    move-object v13, v9

    .line 344
    goto :goto_9

    .line 345
    :cond_9
    invoke-virtual {v0, v12}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 346
    .line 347
    .line 348
    move-result-object v14

    .line 349
    :try_start_2
    invoke-interface {v13, v14}, Lvp/c0;->M(Lvp/f4;)Lvp/j;

    .line 350
    .line 351
    .line 352
    move-result-object v13

    .line 353
    invoke-virtual {v0}, Lvp/d3;->n0()V
    :try_end_2
    .catch Landroid/os/RemoteException; {:try_start_2 .. :try_end_2} :catch_2

    .line 354
    .line 355
    .line 356
    goto :goto_9

    .line 357
    :catch_2
    move-exception v0

    .line 358
    iget-object v11, v11, Lvp/g1;->i:Lvp/p0;

    .line 359
    .line 360
    invoke-static {v11}, Lvp/g1;->k(Lvp/n1;)V

    .line 361
    .line 362
    .line 363
    iget-object v11, v11, Lvp/p0;->j:Lvp/n0;

    .line 364
    .line 365
    const-string v13, "Failed to get consents; remote exception"

    .line 366
    .line 367
    invoke-virtual {v11, v0, v13}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    goto :goto_8

    .line 371
    :goto_9
    if-eqz v13, :cond_a

    .line 372
    .line 373
    iget-object v0, v13, Lvp/j;->d:Landroid/os/Bundle;

    .line 374
    .line 375
    goto :goto_a

    .line 376
    :cond_a
    move-object v0, v9

    .line 377
    :goto_a
    const/4 v11, 0x1

    .line 378
    if-nez v0, :cond_d

    .line 379
    .line 380
    iget v0, v2, Lvp/g1;->E:I

    .line 381
    .line 382
    add-int/lit8 v3, v0, 0x1

    .line 383
    .line 384
    iput v3, v2, Lvp/g1;->E:I

    .line 385
    .line 386
    const/16 v3, 0xa

    .line 387
    .line 388
    if-ge v0, v3, :cond_b

    .line 389
    .line 390
    move v12, v11

    .line 391
    :cond_b
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 392
    .line 393
    .line 394
    if-ge v0, v3, :cond_c

    .line 395
    .line 396
    const-string v0, "Retrying."

    .line 397
    .line 398
    goto :goto_b

    .line 399
    :cond_c
    const-string v0, "Skipping."

    .line 400
    .line 401
    :goto_b
    iget-object v3, v4, Lvp/p0;->q:Lvp/n0;

    .line 402
    .line 403
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 404
    .line 405
    .line 406
    move-result v4

    .line 407
    new-instance v5, Ljava/lang/StringBuilder;

    .line 408
    .line 409
    add-int/lit8 v4, v4, 0x3c

    .line 410
    .line 411
    invoke-direct {v5, v4}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 412
    .line 413
    .line 414
    const-string v4, "Failed to retrieve DMA consent from the service, "

    .line 415
    .line 416
    const-string v6, " retryCount"

    .line 417
    .line 418
    invoke-static {v5, v4, v0, v6}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 419
    .line 420
    .line 421
    move-result-object v0

    .line 422
    iget v2, v2, Lvp/g1;->E:I

    .line 423
    .line 424
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    invoke-virtual {v3, v2, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 429
    .line 430
    .line 431
    goto/16 :goto_11

    .line 432
    .line 433
    :cond_d
    const/16 v13, 0x64

    .line 434
    .line 435
    invoke-static {v13, v0}, Lvp/s1;->b(ILandroid/os/Bundle;)Lvp/s1;

    .line 436
    .line 437
    .line 438
    move-result-object v14

    .line 439
    const-string v15, "&gcs="

    .line 440
    .line 441
    invoke-virtual {v10, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 442
    .line 443
    .line 444
    invoke-virtual {v14}, Lvp/s1;->f()Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object v14

    .line 448
    invoke-virtual {v10, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 449
    .line 450
    .line 451
    invoke-static {v13, v0}, Lvp/p;->c(ILandroid/os/Bundle;)Lvp/p;

    .line 452
    .line 453
    .line 454
    move-result-object v13

    .line 455
    iget-object v14, v13, Lvp/p;->d:Ljava/lang/String;

    .line 456
    .line 457
    const-string v15, "&dma="

    .line 458
    .line 459
    invoke-virtual {v10, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 460
    .line 461
    .line 462
    iget-object v13, v13, Lvp/p;->c:Ljava/lang/Boolean;

    .line 463
    .line 464
    sget-object v15, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 465
    .line 466
    invoke-static {v13, v15}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 467
    .line 468
    .line 469
    move-result v13

    .line 470
    xor-int/2addr v13, v11

    .line 471
    invoke-virtual {v10, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 472
    .line 473
    .line 474
    invoke-static {v14}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 475
    .line 476
    .line 477
    move-result v13

    .line 478
    if-nez v13, :cond_e

    .line 479
    .line 480
    const-string v13, "&dma_cps="

    .line 481
    .line 482
    invoke-virtual {v10, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 483
    .line 484
    .line 485
    invoke-virtual {v10, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 486
    .line 487
    .line 488
    :cond_e
    const-string v13, "ad_personalization"

    .line 489
    .line 490
    invoke-virtual {v0, v13}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    invoke-static {v0}, Lvp/s1;->d(Ljava/lang/String;)Lvp/p1;

    .line 495
    .line 496
    .line 497
    move-result-object v0

    .line 498
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 499
    .line 500
    .line 501
    move-result v0

    .line 502
    const/4 v13, 0x2

    .line 503
    if-eq v0, v13, :cond_10

    .line 504
    .line 505
    const/4 v13, 0x3

    .line 506
    if-eq v0, v13, :cond_f

    .line 507
    .line 508
    move-object v15, v9

    .line 509
    goto :goto_c

    .line 510
    :cond_f
    sget-object v15, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 511
    .line 512
    :cond_10
    :goto_c
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 513
    .line 514
    invoke-static {v15, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 515
    .line 516
    .line 517
    move-result v0

    .line 518
    xor-int/2addr v0, v11

    .line 519
    const-string v11, "&npa="

    .line 520
    .line 521
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 522
    .line 523
    .line 524
    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 525
    .line 526
    .line 527
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 528
    .line 529
    .line 530
    iget-object v0, v4, Lvp/p0;->r:Lvp/n0;

    .line 531
    .line 532
    const-string v4, "Consent query parameters to Bow"

    .line 533
    .line 534
    invoke-virtual {v0, v10, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    :cond_11
    iget-object v0, v2, Lvp/g1;->l:Lvp/d4;

    .line 538
    .line 539
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 540
    .line 541
    .line 542
    invoke-virtual {v2}, Lvp/g1;->q()Lvp/h0;

    .line 543
    .line 544
    .line 545
    move-result-object v4

    .line 546
    iget-object v4, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 547
    .line 548
    check-cast v4, Lvp/g1;

    .line 549
    .line 550
    iget-object v4, v4, Lvp/g1;->g:Lvp/h;

    .line 551
    .line 552
    invoke-virtual {v4}, Lvp/h;->f0()V

    .line 553
    .line 554
    .line 555
    iget-object v4, v8, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast v4, Ljava/lang/String;

    .line 558
    .line 559
    iget-object v3, v3, Lvp/w0;->y:La8/s1;

    .line 560
    .line 561
    invoke-virtual {v3}, La8/s1;->g()J

    .line 562
    .line 563
    .line 564
    move-result-wide v13

    .line 565
    const-wide/16 v15, -0x1

    .line 566
    .line 567
    add-long/2addr v13, v15

    .line 568
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object v3

    .line 572
    iget-object v8, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 573
    .line 574
    check-cast v8, Lvp/g1;

    .line 575
    .line 576
    const-string v10, "https://www.googleadservices.com/pagead/conversion/app/deeplink?id_type=adid&sdk_version="

    .line 577
    .line 578
    const-string v11, "v133005."

    .line 579
    .line 580
    :try_start_3
    invoke-static {v4}, Lno/c0;->e(Ljava/lang/String;)V

    .line 581
    .line 582
    .line 583
    invoke-static {v7}, Lno/c0;->e(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v0}, Lvp/d4;->G0()I

    .line 587
    .line 588
    .line 589
    move-result v0

    .line 590
    new-instance v15, Ljava/lang/StringBuilder;

    .line 591
    .line 592
    invoke-direct {v15, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    invoke-virtual {v15, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 596
    .line 597
    .line 598
    invoke-virtual {v15}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 599
    .line 600
    .line 601
    move-result-object v0

    .line 602
    new-instance v11, Ljava/lang/StringBuilder;

    .line 603
    .line 604
    invoke-direct {v11, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 605
    .line 606
    .line 607
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 608
    .line 609
    .line 610
    const-string v0, "&rdid="

    .line 611
    .line 612
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 613
    .line 614
    .line 615
    invoke-virtual {v11, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 616
    .line 617
    .line 618
    const-string v0, "&bundleid="

    .line 619
    .line 620
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 621
    .line 622
    .line 623
    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 624
    .line 625
    .line 626
    const-string v0, "&retry="

    .line 627
    .line 628
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 629
    .line 630
    .line 631
    invoke-virtual {v11, v13, v14}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 632
    .line 633
    .line 634
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 635
    .line 636
    .line 637
    move-result-object v0

    .line 638
    iget-object v4, v8, Lvp/g1;->g:Lvp/h;

    .line 639
    .line 640
    const-string v10, "debug.deferred.deeplink"

    .line 641
    .line 642
    invoke-virtual {v4, v10}, Lvp/h;->e0(Ljava/lang/String;)Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object v4

    .line 646
    invoke-virtual {v7, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 647
    .line 648
    .line 649
    move-result v4

    .line 650
    if-eqz v4, :cond_12

    .line 651
    .line 652
    const-string v4, "&ddl_test=1"

    .line 653
    .line 654
    invoke-virtual {v0, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 655
    .line 656
    .line 657
    move-result-object v0

    .line 658
    goto :goto_d

    .line 659
    :catch_3
    move-exception v0

    .line 660
    goto :goto_e

    .line 661
    :cond_12
    :goto_d
    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    .line 662
    .line 663
    .line 664
    move-result v4

    .line 665
    if-nez v4, :cond_14

    .line 666
    .line 667
    invoke-virtual {v3, v12}, Ljava/lang/String;->charAt(I)C

    .line 668
    .line 669
    .line 670
    move-result v4

    .line 671
    const/16 v10, 0x26

    .line 672
    .line 673
    if-eq v4, v10, :cond_13

    .line 674
    .line 675
    const-string v4, "&"

    .line 676
    .line 677
    invoke-virtual {v0, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 678
    .line 679
    .line 680
    move-result-object v0

    .line 681
    :cond_13
    invoke-virtual {v0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 682
    .line 683
    .line 684
    move-result-object v0

    .line 685
    :cond_14
    new-instance v3, Ljava/net/URL;

    .line 686
    .line 687
    invoke-direct {v3, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/net/MalformedURLException; {:try_start_3 .. :try_end_3} :catch_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_3

    .line 688
    .line 689
    .line 690
    move-object v8, v3

    .line 691
    goto :goto_f

    .line 692
    :goto_e
    iget-object v3, v8, Lvp/g1;->i:Lvp/p0;

    .line 693
    .line 694
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 695
    .line 696
    .line 697
    iget-object v3, v3, Lvp/p0;->j:Lvp/n0;

    .line 698
    .line 699
    const-string v4, "Failed to create BOW URL for Deferred Deep Link. exception"

    .line 700
    .line 701
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 702
    .line 703
    .line 704
    move-result-object v0

    .line 705
    invoke-virtual {v3, v0, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 706
    .line 707
    .line 708
    move-object v8, v9

    .line 709
    :goto_f
    if-eqz v8, :cond_17

    .line 710
    .line 711
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 712
    .line 713
    .line 714
    new-instance v11, Lvp/y0;

    .line 715
    .line 716
    invoke-direct {v11, v2}, Lvp/y0;-><init>(Lvp/g1;)V

    .line 717
    .line 718
    .line 719
    invoke-virtual {v6}, Lvp/n1;->c0()V

    .line 720
    .line 721
    .line 722
    iget-object v0, v5, Lvp/g1;->j:Lvp/e1;

    .line 723
    .line 724
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 725
    .line 726
    .line 727
    new-instance v5, Lvp/r0;

    .line 728
    .line 729
    const/4 v9, 0x0

    .line 730
    const/4 v10, 0x0

    .line 731
    invoke-direct/range {v5 .. v11}, Lvp/r0;-><init>(Lvp/n2;Ljava/lang/String;Ljava/net/URL;[BLjava/util/HashMap;Lvp/l2;)V

    .line 732
    .line 733
    .line 734
    invoke-virtual {v0, v5}, Lvp/e1;->m0(Ljava/lang/Runnable;)V

    .line 735
    .line 736
    .line 737
    goto :goto_11

    .line 738
    :cond_15
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 739
    .line 740
    .line 741
    iget-object v0, v4, Lvp/p0;->m:Lvp/n0;

    .line 742
    .line 743
    const-string v2, "Network is not available for Deferred Deep Link request. Skipping"

    .line 744
    .line 745
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 746
    .line 747
    .line 748
    goto :goto_11

    .line 749
    :cond_16
    :goto_10
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 750
    .line 751
    .line 752
    iget-object v0, v4, Lvp/p0;->r:Lvp/n0;

    .line 753
    .line 754
    const-string v2, "ADID unavailable to retrieve Deferred Deep Link. Skipping"

    .line 755
    .line 756
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    :cond_17
    :goto_11
    if-eqz v12, :cond_18

    .line 760
    .line 761
    iget-object v0, v1, Lvp/j2;->x:Lvp/x1;

    .line 762
    .line 763
    const-wide/16 v1, 0x7d0

    .line 764
    .line 765
    invoke-virtual {v0, v1, v2}, Lvp/o;->b(J)V

    .line 766
    .line 767
    .line 768
    :cond_18
    return-void

    .line 769
    :pswitch_0
    iget-object v0, v0, Lvp/x1;->f:Lvp/j2;

    .line 770
    .line 771
    invoke-virtual {v0}, Lvp/j2;->g0()V

    .line 772
    .line 773
    .line 774
    return-void

    .line 775
    :pswitch_1
    iget-object v0, v0, Lvp/x1;->f:Lvp/j2;

    .line 776
    .line 777
    invoke-virtual {v0}, Lvp/j2;->z0()V

    .line 778
    .line 779
    .line 780
    return-void

    .line 781
    :pswitch_2
    new-instance v1, Ljava/lang/Thread;

    .line 782
    .line 783
    iget-object v0, v0, Lvp/x1;->f:Lvp/j2;

    .line 784
    .line 785
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 786
    .line 787
    check-cast v0, Lvp/g1;

    .line 788
    .line 789
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 790
    .line 791
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 792
    .line 793
    .line 794
    new-instance v2, Lvp/w1;

    .line 795
    .line 796
    const/4 v3, 0x0

    .line 797
    invoke-direct {v2, v0, v3}, Lvp/w1;-><init>(Lvp/j2;I)V

    .line 798
    .line 799
    .line 800
    invoke-direct {v1, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 801
    .line 802
    .line 803
    invoke-virtual {v1}, Ljava/lang/Thread;->start()V

    .line 804
    .line 805
    .line 806
    return-void

    .line 807
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
