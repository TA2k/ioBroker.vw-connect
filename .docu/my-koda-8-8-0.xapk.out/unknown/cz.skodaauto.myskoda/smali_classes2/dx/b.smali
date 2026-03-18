.class public final synthetic Ldx/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ldx/i;Ljava/util/Date;Lc2/k;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ldx/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldx/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Ldx/b;->g:Ljava/lang/Object;

    iput-object p3, p0, Ldx/b;->h:Ljava/lang/Object;

    iput p4, p0, Ldx/b;->e:I

    return-void
.end method

.method public synthetic constructor <init>(Lqn/s;Lrn/j;ILjava/lang/Runnable;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ldx/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ldx/b;->f:Ljava/lang/Object;

    iput-object p2, p0, Ldx/b;->g:Ljava/lang/Object;

    iput p3, p0, Ldx/b;->e:I

    iput-object p4, p0, Ldx/b;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 11

    .line 1
    iget v0, p0, Ldx/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ldx/b;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lqn/s;

    .line 9
    .line 10
    iget-object v1, p0, Ldx/b;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lrn/j;

    .line 13
    .line 14
    iget v2, p0, Ldx/b;->e:I

    .line 15
    .line 16
    iget-object p0, p0, Ldx/b;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ljava/lang/Runnable;

    .line 19
    .line 20
    iget-object v3, v0, Lqn/s;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v3, Lzn/c;

    .line 23
    .line 24
    :try_start_0
    iget-object v4, v0, Lqn/s;->c:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v4, Lyn/d;

    .line 27
    .line 28
    invoke-static {v4}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    new-instance v5, Lrx/b;

    .line 32
    .line 33
    const/16 v6, 0x12

    .line 34
    .line 35
    invoke-direct {v5, v4, v6}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    move-object v4, v3

    .line 39
    check-cast v4, Lyn/h;

    .line 40
    .line 41
    invoke-virtual {v4, v5}, Lyn/h;->h(Lzn/b;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    iget-object v4, v0, Lqn/s;->a:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v4, Landroid/content/Context;

    .line 47
    .line 48
    const-string v5, "connectivity"

    .line 49
    .line 50
    invoke-virtual {v4, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    check-cast v4, Landroid/net/ConnectivityManager;

    .line 55
    .line 56
    invoke-virtual {v4}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    if-eqz v4, :cond_0

    .line 61
    .line 62
    invoke-virtual {v4}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-eqz v4, :cond_0

    .line 67
    .line 68
    invoke-virtual {v0, v1, v2}, Lqn/s;->c(Lrn/j;I)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :catchall_0
    move-exception v0

    .line 73
    goto :goto_2

    .line 74
    :cond_0
    new-instance v4, La8/b0;

    .line 75
    .line 76
    invoke-direct {v4, v0, v1, v2}, La8/b0;-><init>(Lqn/s;Lrn/j;I)V

    .line 77
    .line 78
    .line 79
    check-cast v3, Lyn/h;

    .line 80
    .line 81
    invoke-virtual {v3, v4}, Lyn/h;->h(Lzn/b;)Ljava/lang/Object;
    :try_end_0
    .catch Lzn/a; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    .line 83
    .line 84
    :goto_0
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :catch_0
    :try_start_1
    iget-object v0, v0, Lqn/s;->d:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v0, Lrn/i;

    .line 91
    .line 92
    add-int/lit8 v2, v2, 0x1

    .line 93
    .line 94
    const/4 v3, 0x0

    .line 95
    invoke-virtual {v0, v1, v2, v3}, Lrn/i;->z(Lrn/j;IZ)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :goto_1
    return-void

    .line 100
    :goto_2
    invoke-interface {p0}, Ljava/lang/Runnable;->run()V

    .line 101
    .line 102
    .line 103
    throw v0

    .line 104
    :pswitch_0
    iget-object v0, p0, Ldx/b;->f:Ljava/lang/Object;

    .line 105
    .line 106
    move-object v4, v0

    .line 107
    check-cast v4, Ldx/i;

    .line 108
    .line 109
    iget-object v0, p0, Ldx/b;->g:Ljava/lang/Object;

    .line 110
    .line 111
    move-object v3, v0

    .line 112
    check-cast v3, Ljava/util/Date;

    .line 113
    .line 114
    iget-object v0, p0, Ldx/b;->h:Ljava/lang/Object;

    .line 115
    .line 116
    move-object v7, v0

    .line 117
    check-cast v7, Lc2/k;

    .line 118
    .line 119
    iget p0, p0, Ldx/b;->e:I

    .line 120
    .line 121
    const-string v0, "$updateType"

    .line 122
    .line 123
    invoke-static {p0, v0}, Lia/b;->q(ILjava/lang/String;)V

    .line 124
    .line 125
    .line 126
    :try_start_2
    iget-object v0, v4, Ldx/i;->a:Ldx/k;

    .line 127
    .line 128
    iget-boolean v0, v0, Ldx/k;->c:Z

    .line 129
    .line 130
    const/4 v1, 0x0

    .line 131
    const/4 v2, 0x2

    .line 132
    if-eqz v0, :cond_1

    .line 133
    .line 134
    iget-object v0, v4, Ldx/i;->b:Lbu/c;

    .line 135
    .line 136
    const/16 v5, 0x10

    .line 137
    .line 138
    new-array v5, v5, [B

    .line 139
    .line 140
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v0, Ljava/security/SecureRandom;

    .line 143
    .line 144
    invoke-virtual {v0, v5}, Ljava/security/SecureRandom;->nextBytes([B)V

    .line 145
    .line 146
    .line 147
    invoke-static {v5, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    new-instance v5, Lhx/a;

    .line 152
    .line 153
    const-string v6, "X-Cert-Pinning-Challenge"

    .line 154
    .line 155
    new-instance v8, Llx0/l;

    .line 156
    .line 157
    invoke-direct {v8, v6, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    invoke-static {v8}, Lmx0/x;->l(Llx0/l;)Ljava/util/Map;

    .line 161
    .line 162
    .line 163
    move-result-object v6

    .line 164
    invoke-direct {v5, v6}, Lhx/a;-><init>(Ljava/util/Map;)V

    .line 165
    .line 166
    .line 167
    goto :goto_3

    .line 168
    :catch_1
    move-exception v0

    .line 169
    goto/16 :goto_7

    .line 170
    .line 171
    :cond_1
    new-instance v5, Lhx/a;

    .line 172
    .line 173
    sget-object v0, Lmx0/t;->d:Lmx0/t;

    .line 174
    .line 175
    invoke-direct {v5, v0}, Lhx/a;-><init>(Ljava/util/Map;)V

    .line 176
    .line 177
    .line 178
    move-object v0, v1

    .line 179
    :goto_3
    iget-object v6, v4, Ldx/i;->d:La0/j;

    .line 180
    .line 181
    invoke-virtual {v6, v5}, La0/j;->V(Lhx/a;)Lhx/b;

    .line 182
    .line 183
    .line 184
    move-result-object v5
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 185
    iget-object v6, v5, Lhx/b;->c:[B

    .line 186
    .line 187
    iget-object v5, v5, Lhx/b;->b:Ljava/util/LinkedHashMap;

    .line 188
    .line 189
    iget-object v8, v4, Ldx/i;->a:Ldx/k;

    .line 190
    .line 191
    iget-object v8, v8, Ldx/k;->b:[B

    .line 192
    .line 193
    move-object v9, v6

    .line 194
    new-instance v6, Lfx/a;

    .line 195
    .line 196
    new-instance v10, Lio/getlime/security/powerauth/core/EcPublicKey;

    .line 197
    .line 198
    invoke-direct {v10, v8}, Lio/getlime/security/powerauth/core/EcPublicKey;-><init>([B)V

    .line 199
    .line 200
    .line 201
    invoke-direct {v6, v10}, Lfx/a;-><init>(Lio/getlime/security/powerauth/core/EcPublicKey;)V

    .line 202
    .line 203
    .line 204
    iget-object v8, v4, Ldx/i;->a:Ldx/k;

    .line 205
    .line 206
    iget-boolean v8, v8, Ldx/k;->c:Z

    .line 207
    .line 208
    if-eqz v8, :cond_4

    .line 209
    .line 210
    if-eqz v0, :cond_3

    .line 211
    .line 212
    const-string v8, "x-cert-pinning-signature"

    .line 213
    .line 214
    invoke-virtual {v5, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v5

    .line 218
    check-cast v5, Ljava/lang/String;

    .line 219
    .line 220
    if-nez v5, :cond_2

    .line 221
    .line 222
    const-string v0, "Missing signature header."

    .line 223
    .line 224
    const-string v1, "Wultra-SSL-Pinning"

    .line 225
    .line 226
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 227
    .line 228
    .line 229
    sget-object v0, Ldx/l;->h:Ldx/l;

    .line 230
    .line 231
    goto/16 :goto_8

    .line 232
    .line 233
    :cond_2
    :try_start_3
    invoke-static {v5, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 234
    .line 235
    .line 236
    move-result-object v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 237
    sget-object v5, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 238
    .line 239
    invoke-virtual {v0, v5}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    const-string v5, "this as java.lang.String).getBytes(charset)"

    .line 244
    .line 245
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 246
    .line 247
    .line 248
    array-length v5, v0

    .line 249
    add-int/lit8 v8, v5, 0x1

    .line 250
    .line 251
    invoke-static {v0, v8}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    const/16 v8, 0x26

    .line 256
    .line 257
    aput-byte v8, v0, v5

    .line 258
    .line 259
    invoke-static {v0, v9}, Lmx0/n;->M([B[B)[B

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    const-string v5, "signature"

    .line 264
    .line 265
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    invoke-static {v0, v2, v10}, Lio/getlime/security/powerauth/core/CryptoUtils;->ecdsaValidateSignature([B[BLio/getlime/security/powerauth/core/EcPublicKey;)Z

    .line 269
    .line 270
    .line 271
    move-result v0

    .line 272
    if-nez v0, :cond_4

    .line 273
    .line 274
    const-string v0, "Invalid signature in x-cert-pinning-signature header"

    .line 275
    .line 276
    const-string v1, "Wultra-SSL-Pinning"

    .line 277
    .line 278
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 279
    .line 280
    .line 281
    sget-object v0, Ldx/l;->h:Ldx/l;

    .line 282
    .line 283
    goto/16 :goto_8

    .line 284
    .line 285
    :catchall_1
    move-exception v0

    .line 286
    new-instance v1, Ljava/lang/StringBuilder;

    .line 287
    .line 288
    const-string v2, "Failed to decode signature from header: "

    .line 289
    .line 290
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 294
    .line 295
    .line 296
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    const-string v1, "message"

    .line 301
    .line 302
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    const-string v1, "Wultra-SSL-Pinning"

    .line 306
    .line 307
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 308
    .line 309
    .line 310
    sget-object v0, Ldx/l;->h:Ldx/l;

    .line 311
    .line 312
    goto/16 :goto_8

    .line 313
    .line 314
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 315
    .line 316
    const-string v0, "Missing challenge"

    .line 317
    .line 318
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw p0

    .line 322
    :cond_4
    :try_start_4
    sget-object v0, Ldx/i;->j:Lcom/google/gson/j;

    .line 323
    .line 324
    new-instance v2, Ljava/lang/String;

    .line 325
    .line 326
    sget-object v5, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 327
    .line 328
    invoke-direct {v2, v9, v5}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 329
    .line 330
    .line 331
    const-class v5, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;

    .line 332
    .line 333
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 334
    .line 335
    .line 336
    invoke-static {v5}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/Class;)Lcom/google/gson/reflect/TypeToken;

    .line 337
    .line 338
    .line 339
    move-result-object v5

    .line 340
    invoke-virtual {v0, v2, v5}, Lcom/google/gson/j;->b(Ljava/lang/String;Lcom/google/gson/reflect/TypeToken;)Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v0

    .line 344
    check-cast v0, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 345
    .line 346
    move-object v2, v0

    .line 347
    goto :goto_4

    .line 348
    :catchall_2
    move-exception v0

    .line 349
    new-instance v2, Ljava/lang/StringBuilder;

    .line 350
    .line 351
    const-string v5, "Failed to parse received fingerprint data: "

    .line 352
    .line 353
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    const-string v2, "message"

    .line 364
    .line 365
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    const-string v2, "Wultra-SSL-Pinning"

    .line 369
    .line 370
    invoke-static {v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 371
    .line 372
    .line 373
    move-object v2, v1

    .line 374
    :goto_4
    if-nez v2, :cond_5

    .line 375
    .line 376
    sget-object v0, Ldx/l;->g:Ldx/l;

    .line 377
    .line 378
    goto :goto_8

    .line 379
    :cond_5
    invoke-virtual {v2}, Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;->getFingerprints()[Lcom/wultra/android/sslpinning/model/GetFingerprintResponse$Entry;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    if-nez v0, :cond_6

    .line 384
    .line 385
    sget-object v0, Ldx/l;->g:Ldx/l;

    .line 386
    .line 387
    goto :goto_8

    .line 388
    :cond_6
    new-instance v5, Lkotlin/jvm/internal/f0;

    .line 389
    .line 390
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 391
    .line 392
    .line 393
    sget-object v0, Ldx/l;->d:Ldx/l;

    .line 394
    .line 395
    iput-object v0, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 396
    .line 397
    new-instance v1, Ldx/d;

    .line 398
    .line 399
    invoke-direct/range {v1 .. v6}, Ldx/d;-><init>(Lcom/wultra/android/sslpinning/model/GetFingerprintResponse;Ljava/util/Date;Ldx/i;Lkotlin/jvm/internal/f0;Lfx/a;)V

    .line 400
    .line 401
    .line 402
    monitor-enter v4

    .line 403
    :try_start_5
    invoke-virtual {v4}, Ldx/i;->b()V

    .line 404
    .line 405
    .line 406
    iget-object v0, v4, Ldx/i;->f:Lcom/wultra/android/sslpinning/model/CachedData;

    .line 407
    .line 408
    invoke-virtual {v1, v0}, Ldx/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v0

    .line 412
    check-cast v0, Lcom/wultra/android/sslpinning/model/CachedData;

    .line 413
    .line 414
    if-eqz v0, :cond_7

    .line 415
    .line 416
    iput-object v0, v4, Ldx/i;->f:Lcom/wultra/android/sslpinning/model/CachedData;

    .line 417
    .line 418
    invoke-virtual {v4, v0}, Ldx/i;->c(Lcom/wultra/android/sslpinning/model/CachedData;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 419
    .line 420
    .line 421
    goto :goto_5

    .line 422
    :catchall_3
    move-exception v0

    .line 423
    move-object p0, v0

    .line 424
    goto :goto_6

    .line 425
    :cond_7
    :goto_5
    monitor-exit v4

    .line 426
    iget-object v0, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v0, Ldx/l;

    .line 429
    .line 430
    goto :goto_8

    .line 431
    :goto_6
    :try_start_6
    monitor-exit v4
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 432
    throw p0

    .line 433
    :goto_7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 434
    .line 435
    const-string v2, "Failed to update: "

    .line 436
    .line 437
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 441
    .line 442
    .line 443
    move-result-object v0

    .line 444
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 445
    .line 446
    .line 447
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v0

    .line 451
    const-string v1, "message"

    .line 452
    .line 453
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 454
    .line 455
    .line 456
    const-string v1, "Wultra-SSL-Pinning"

    .line 457
    .line 458
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 459
    .line 460
    .line 461
    sget-object v0, Ldx/l;->f:Ldx/l;

    .line 462
    .line 463
    :goto_8
    iget-object v1, v4, Ldx/i;->i:Landroid/os/Handler;

    .line 464
    .line 465
    new-instance v2, Lb/p;

    .line 466
    .line 467
    const/4 v3, 0x2

    .line 468
    invoke-direct {v2, p0, v3, v7, v0}, Lb/p;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 472
    .line 473
    .line 474
    return-void

    .line 475
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
