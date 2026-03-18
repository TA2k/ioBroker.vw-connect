.class public final Lx41/z0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lv51/f;

.field public final b:Lvy0/x;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Lpw0/a;


# direct methods
.method public constructor <init>(Lv51/f;Ljava/lang/String;Lvy0/x;)V
    .locals 1

    .line 1
    const-string v0, "dispatcher"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lx41/z0;->a:Lv51/f;

    .line 10
    .line 11
    iput-object p3, p0, Lx41/z0;->b:Lvy0/x;

    .line 12
    .line 13
    const-string p1, "_C2P_PAIRING_LOCAL_PAIRINGS"

    .line 14
    .line 15
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lx41/z0;->c:Ljava/lang/String;

    .line 20
    .line 21
    const-string p1, "_STORAGE_IDENTIFIER_LOCAL_PAIRINGS_V1"

    .line 22
    .line 23
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, Lx41/z0;->d:Ljava/lang/String;

    .line 28
    .line 29
    const-string p1, "_C2P_PAIRING_PROVIDER_PAIRINGS"

    .line 30
    .line 31
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lx41/z0;->e:Ljava/lang/String;

    .line 36
    .line 37
    const-string p1, "_C2P_PAIRING_PROVIDER_PAIRINGS_V1"

    .line 38
    .line 39
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    iput-object p1, p0, Lx41/z0;->f:Ljava/lang/String;

    .line 44
    .line 45
    const-string p1, "_C2P_PAIRING_LOCAL_KEYPAIR"

    .line 46
    .line 47
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    iput-object p1, p0, Lx41/z0;->g:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iput-object p1, p0, Lx41/z0;->h:Lpw0/a;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;)Ljava/util/Set;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "oldSecureStorageKey"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "newSecureStorageKey"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v7, Lh70/n;

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    invoke-direct {v7, v1, v2, v3}, Lh70/n;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    new-instance v4, Lt51/j;

    .line 24
    .line 25
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    const-string v3, "getName(...)"

    .line 30
    .line 31
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v10

    .line 35
    const-string v5, "Car2PhonePairing"

    .line 36
    .line 37
    sget-object v13, Lt51/g;->a:Lt51/g;

    .line 38
    .line 39
    const/4 v8, 0x0

    .line 40
    move-object v6, v13

    .line 41
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 45
    .line 46
    .line 47
    new-instance v4, Lx41/v0;

    .line 48
    .line 49
    const/4 v5, 0x2

    .line 50
    const/4 v6, 0x0

    .line 51
    invoke-direct {v4, v0, v1, v6, v5}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 52
    .line 53
    .line 54
    iget-object v5, v0, Lx41/z0;->b:Lvy0/x;

    .line 55
    .line 56
    invoke-static {v5, v4}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    check-cast v4, Llx0/o;

    .line 61
    .line 62
    iget-object v4, v4, Llx0/o;->d:Ljava/lang/Object;

    .line 63
    .line 64
    instance-of v7, v4, Llx0/n;

    .line 65
    .line 66
    sget-object v8, Lmx0/u;->d:Lmx0/u;

    .line 67
    .line 68
    if-eqz v7, :cond_0

    .line 69
    .line 70
    move-object v4, v8

    .line 71
    :cond_0
    check-cast v4, Ljava/util/Set;

    .line 72
    .line 73
    new-instance v7, Lx41/v0;

    .line 74
    .line 75
    const/4 v9, 0x1

    .line 76
    invoke-direct {v7, v0, v2, v6, v9}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 77
    .line 78
    .line 79
    invoke-static {v5, v7}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v7

    .line 83
    check-cast v7, Llx0/o;

    .line 84
    .line 85
    iget-object v7, v7, Llx0/o;->d:Ljava/lang/Object;

    .line 86
    .line 87
    instance-of v9, v7, Llx0/n;

    .line 88
    .line 89
    if-eqz v9, :cond_1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_1
    move-object v8, v7

    .line 93
    :goto_0
    check-cast v8, Ljava/util/Set;

    .line 94
    .line 95
    invoke-interface {v4}, Ljava/util/Set;->isEmpty()Z

    .line 96
    .line 97
    .line 98
    move-result v7

    .line 99
    if-eqz v7, :cond_2

    .line 100
    .line 101
    new-instance v2, Lq61/c;

    .line 102
    .line 103
    const/16 v3, 0xe

    .line 104
    .line 105
    invoke-direct {v2, v1, v3}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    const-string v1, "Car2PhonePairing"

    .line 109
    .line 110
    invoke-static {v0, v1, v6, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 111
    .line 112
    .line 113
    return-object v8

    .line 114
    :cond_2
    move-object v7, v4

    .line 115
    check-cast v7, Ljava/lang/Iterable;

    .line 116
    .line 117
    new-instance v9, Ljava/util/ArrayList;

    .line 118
    .line 119
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 120
    .line 121
    .line 122
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 123
    .line 124
    .line 125
    move-result-object v7

    .line 126
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 127
    .line 128
    .line 129
    move-result v10

    .line 130
    if-eqz v10, :cond_d

    .line 131
    .line 132
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    check-cast v10, Lx41/h1;

    .line 137
    .line 138
    invoke-interface {v10}, Lx41/h1;->b()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 139
    .line 140
    .line 141
    move-result-object v11

    .line 142
    invoke-interface {v10}, Lx41/h1;->a()Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 143
    .line 144
    .line 145
    move-result-object v12

    .line 146
    if-eqz v11, :cond_5

    .line 147
    .line 148
    if-eqz v12, :cond_5

    .line 149
    .line 150
    instance-of v14, v10, Lx41/g1;

    .line 151
    .line 152
    if-eqz v14, :cond_3

    .line 153
    .line 154
    new-instance v14, Lx41/m;

    .line 155
    .line 156
    check-cast v10, Lx41/g1;

    .line 157
    .line 158
    iget-object v15, v10, Lx41/g1;->a:Ljava/lang/String;

    .line 159
    .line 160
    new-instance v6, Lx41/f;

    .line 161
    .line 162
    move-object/from16 v18, v3

    .line 163
    .line 164
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    iget-short v3, v3, Lt41/b;->e:S

    .line 169
    .line 170
    move-object/from16 v16, v7

    .line 171
    .line 172
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 173
    .line 174
    .line 175
    move-result-object v7

    .line 176
    iget-short v7, v7, Lt41/b;->f:S

    .line 177
    .line 178
    invoke-direct {v6, v11, v3, v7}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 179
    .line 180
    .line 181
    new-instance v3, Lx41/f;

    .line 182
    .line 183
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 184
    .line 185
    .line 186
    move-result-object v7

    .line 187
    iget-short v7, v7, Lt41/b;->e:S

    .line 188
    .line 189
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 190
    .line 191
    .line 192
    move-result-object v10

    .line 193
    iget-short v10, v10, Lt41/b;->f:S

    .line 194
    .line 195
    invoke-direct {v3, v12, v7, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 196
    .line 197
    .line 198
    invoke-direct {v14, v15, v6, v3}, Lx41/m;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 199
    .line 200
    .line 201
    goto/16 :goto_2

    .line 202
    .line 203
    :cond_3
    move-object/from16 v18, v3

    .line 204
    .line 205
    move-object/from16 v16, v7

    .line 206
    .line 207
    instance-of v3, v10, Lx41/d1;

    .line 208
    .line 209
    if-eqz v3, :cond_4

    .line 210
    .line 211
    new-instance v14, Lx41/j;

    .line 212
    .line 213
    check-cast v10, Lx41/d1;

    .line 214
    .line 215
    iget-object v3, v10, Lx41/d1;->a:Ljava/lang/String;

    .line 216
    .line 217
    new-instance v6, Lx41/f;

    .line 218
    .line 219
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 220
    .line 221
    .line 222
    move-result-object v7

    .line 223
    iget-short v7, v7, Lt41/b;->e:S

    .line 224
    .line 225
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 226
    .line 227
    .line 228
    move-result-object v15

    .line 229
    iget-short v15, v15, Lt41/b;->f:S

    .line 230
    .line 231
    invoke-direct {v6, v11, v7, v15}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 232
    .line 233
    .line 234
    new-instance v7, Lx41/f;

    .line 235
    .line 236
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 237
    .line 238
    .line 239
    move-result-object v11

    .line 240
    iget-short v11, v11, Lt41/b;->e:S

    .line 241
    .line 242
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 243
    .line 244
    .line 245
    move-result-object v10

    .line 246
    iget-short v10, v10, Lt41/b;->f:S

    .line 247
    .line 248
    invoke-direct {v7, v12, v11, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 249
    .line 250
    .line 251
    invoke-direct {v14, v3, v6, v7}, Lx41/j;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 252
    .line 253
    .line 254
    goto/16 :goto_2

    .line 255
    .line 256
    :cond_4
    new-instance v0, La8/r0;

    .line 257
    .line 258
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 259
    .line 260
    .line 261
    throw v0

    .line 262
    :cond_5
    move-object/from16 v18, v3

    .line 263
    .line 264
    move-object/from16 v16, v7

    .line 265
    .line 266
    if-eqz v12, :cond_8

    .line 267
    .line 268
    instance-of v3, v10, Lx41/g1;

    .line 269
    .line 270
    if-eqz v3, :cond_6

    .line 271
    .line 272
    new-instance v14, Lx41/m;

    .line 273
    .line 274
    check-cast v10, Lx41/g1;

    .line 275
    .line 276
    iget-object v3, v10, Lx41/g1;->a:Ljava/lang/String;

    .line 277
    .line 278
    new-instance v6, Lx41/f;

    .line 279
    .line 280
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 281
    .line 282
    .line 283
    move-result-object v7

    .line 284
    iget-short v7, v7, Lt41/b;->e:S

    .line 285
    .line 286
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 287
    .line 288
    .line 289
    move-result-object v10

    .line 290
    iget-short v10, v10, Lt41/b;->f:S

    .line 291
    .line 292
    invoke-direct {v6, v12, v7, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 293
    .line 294
    .line 295
    const/4 v7, 0x0

    .line 296
    invoke-direct {v14, v3, v7, v6}, Lx41/m;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 297
    .line 298
    .line 299
    goto :goto_2

    .line 300
    :cond_6
    instance-of v3, v10, Lx41/d1;

    .line 301
    .line 302
    if-eqz v3, :cond_7

    .line 303
    .line 304
    new-instance v14, Lx41/j;

    .line 305
    .line 306
    check-cast v10, Lx41/d1;

    .line 307
    .line 308
    iget-object v3, v10, Lx41/d1;->a:Ljava/lang/String;

    .line 309
    .line 310
    new-instance v6, Lx41/f;

    .line 311
    .line 312
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 313
    .line 314
    .line 315
    move-result-object v7

    .line 316
    iget-short v7, v7, Lt41/b;->e:S

    .line 317
    .line 318
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 319
    .line 320
    .line 321
    move-result-object v10

    .line 322
    iget-short v10, v10, Lt41/b;->f:S

    .line 323
    .line 324
    invoke-direct {v6, v12, v7, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 325
    .line 326
    .line 327
    const/4 v7, 0x0

    .line 328
    invoke-direct {v14, v3, v7, v6}, Lx41/j;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 329
    .line 330
    .line 331
    goto :goto_2

    .line 332
    :cond_7
    new-instance v0, La8/r0;

    .line 333
    .line 334
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 335
    .line 336
    .line 337
    throw v0

    .line 338
    :cond_8
    if-eqz v11, :cond_b

    .line 339
    .line 340
    instance-of v3, v10, Lx41/g1;

    .line 341
    .line 342
    if-eqz v3, :cond_9

    .line 343
    .line 344
    new-instance v14, Lx41/m;

    .line 345
    .line 346
    check-cast v10, Lx41/g1;

    .line 347
    .line 348
    iget-object v3, v10, Lx41/g1;->a:Ljava/lang/String;

    .line 349
    .line 350
    new-instance v6, Lx41/f;

    .line 351
    .line 352
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 353
    .line 354
    .line 355
    move-result-object v7

    .line 356
    iget-short v7, v7, Lt41/b;->e:S

    .line 357
    .line 358
    invoke-virtual {v10}, Lx41/g1;->c()Lt41/b;

    .line 359
    .line 360
    .line 361
    move-result-object v10

    .line 362
    iget-short v10, v10, Lt41/b;->f:S

    .line 363
    .line 364
    invoke-direct {v6, v11, v7, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 365
    .line 366
    .line 367
    const/4 v7, 0x0

    .line 368
    invoke-direct {v14, v3, v6, v7}, Lx41/m;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 369
    .line 370
    .line 371
    goto :goto_2

    .line 372
    :cond_9
    instance-of v3, v10, Lx41/d1;

    .line 373
    .line 374
    if-eqz v3, :cond_a

    .line 375
    .line 376
    new-instance v14, Lx41/j;

    .line 377
    .line 378
    check-cast v10, Lx41/d1;

    .line 379
    .line 380
    iget-object v3, v10, Lx41/d1;->a:Ljava/lang/String;

    .line 381
    .line 382
    new-instance v6, Lx41/f;

    .line 383
    .line 384
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 385
    .line 386
    .line 387
    move-result-object v7

    .line 388
    iget-short v7, v7, Lt41/b;->e:S

    .line 389
    .line 390
    invoke-virtual {v10}, Lx41/d1;->c()Lt41/b;

    .line 391
    .line 392
    .line 393
    move-result-object v10

    .line 394
    iget-short v10, v10, Lt41/b;->f:S

    .line 395
    .line 396
    invoke-direct {v6, v11, v7, v10}, Lx41/f;-><init>(Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;SS)V

    .line 397
    .line 398
    .line 399
    const/4 v7, 0x0

    .line 400
    invoke-direct {v14, v3, v6, v7}, Lx41/j;-><init>(Ljava/lang/String;Lx41/f;Lx41/f;)V

    .line 401
    .line 402
    .line 403
    goto :goto_2

    .line 404
    :cond_a
    new-instance v0, La8/r0;

    .line 405
    .line 406
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 407
    .line 408
    .line 409
    throw v0

    .line 410
    :cond_b
    const/4 v14, 0x0

    .line 411
    :goto_2
    if-eqz v14, :cond_c

    .line 412
    .line 413
    invoke-virtual {v9, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 414
    .line 415
    .line 416
    :cond_c
    move-object/from16 v7, v16

    .line 417
    .line 418
    move-object/from16 v3, v18

    .line 419
    .line 420
    const/4 v6, 0x0

    .line 421
    goto/16 :goto_1

    .line 422
    .line 423
    :cond_d
    move-object/from16 v18, v3

    .line 424
    .line 425
    new-instance v14, Lvu/d;

    .line 426
    .line 427
    const/16 v3, 0xa

    .line 428
    .line 429
    invoke-direct {v14, v3, v4, v9}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 430
    .line 431
    .line 432
    new-instance v11, Lt51/j;

    .line 433
    .line 434
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 435
    .line 436
    .line 437
    move-result-object v16

    .line 438
    invoke-static/range {v18 .. v18}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 439
    .line 440
    .line 441
    move-result-object v17

    .line 442
    const-string v12, "Car2PhonePairing"

    .line 443
    .line 444
    const/4 v15, 0x0

    .line 445
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 449
    .line 450
    .line 451
    invoke-static {v8, v9}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 452
    .line 453
    .line 454
    move-result-object v3

    .line 455
    invoke-virtual {v0, v3}, Lx41/z0;->b(Ljava/util/Set;)V

    .line 456
    .line 457
    .line 458
    new-instance v3, Lx41/v0;

    .line 459
    .line 460
    const/4 v4, 0x0

    .line 461
    const/4 v7, 0x0

    .line 462
    invoke-direct {v3, v0, v1, v7, v4}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 463
    .line 464
    .line 465
    invoke-static {v5, v3}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    new-instance v14, Ltechnology/cariad/cat/genx/bluetooth/g;

    .line 469
    .line 470
    const/4 v1, 0x7

    .line 471
    invoke-direct {v14, v8, v9, v2, v1}, Ltechnology/cariad/cat/genx/bluetooth/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 472
    .line 473
    .line 474
    new-instance v11, Lt51/j;

    .line 475
    .line 476
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v16

    .line 480
    invoke-static/range {v18 .. v18}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 481
    .line 482
    .line 483
    move-result-object v17

    .line 484
    const-string v12, "Car2PhonePairing"

    .line 485
    .line 486
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 490
    .line 491
    .line 492
    invoke-static {v8, v9}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 493
    .line 494
    .line 495
    move-result-object v0

    .line 496
    return-object v0
.end method

.method public final b(Ljava/util/Set;)V
    .locals 7

    .line 1
    new-instance v3, Li61/b;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    invoke-direct {v3, v0, p1}, Li61/b;-><init>(ILjava/util/Set;)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lt51/j;

    .line 8
    .line 9
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    const-string v1, "getName(...)"

    .line 14
    .line 15
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v6

    .line 19
    const-string v1, "Car2PhonePairing"

    .line 20
    .line 21
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lx41/y0;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    const/4 v2, 0x0

    .line 34
    invoke-direct {v0, p0, p1, v2, v1}, Lx41/y0;-><init>(Lx41/z0;Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x3

    .line 38
    iget-object p0, p0, Lx41/z0;->h:Lpw0/a;

    .line 39
    .line 40
    invoke-static {p0, v2, v2, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 41
    .line 42
    .line 43
    return-void
.end method
