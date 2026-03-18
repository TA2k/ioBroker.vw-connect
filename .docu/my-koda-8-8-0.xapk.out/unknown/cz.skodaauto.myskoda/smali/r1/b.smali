.class public final synthetic Lr1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lr1/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr1/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lr1/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lr1/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ltz/n1;

    .line 9
    .line 10
    new-instance v0, Llj0/a;

    .line 11
    .line 12
    iget-object p0, p0, Ltz/n1;->j:Lij0/a;

    .line 13
    .line 14
    const v1, 0x7f120fb6

    .line 15
    .line 16
    .line 17
    check-cast p0, Ljj0/f;

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :pswitch_0
    check-cast p0, Ltz/k1;

    .line 28
    .line 29
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Ltz/j1;

    .line 34
    .line 35
    iget-object v0, v0, Ltz/j1;->d:Lrd0/h;

    .line 36
    .line 37
    if-nez v0, :cond_0

    .line 38
    .line 39
    iget-object v0, p0, Ltz/k1;->j:Lrz/b;

    .line 40
    .line 41
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    move-object v5, v0

    .line 46
    check-cast v5, Lrd0/h;

    .line 47
    .line 48
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    move-object v1, v0

    .line 53
    check-cast v1, Ltz/j1;

    .line 54
    .line 55
    const-string v0, "<this>"

    .line 56
    .line 57
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    const/16 v7, 0x17

    .line 62
    .line 63
    const/4 v2, 0x0

    .line 64
    const/4 v3, 0x0

    .line 65
    const/4 v4, 0x0

    .line 66
    invoke-static/range {v1 .. v7}, Ltz/j1;->a(Ltz/j1;ZLjava/util/List;Lrd0/h;Lrd0/h;ZI)Ltz/j1;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 71
    .line 72
    .line 73
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    return-object p0

    .line 76
    :pswitch_1
    check-cast p0, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;

    .line 77
    .line 78
    invoke-static {p0}, Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;->B(Lcariad/charging/multicharge/sdk/internal/MultiChargeSdkImpl;)Ljava/util/Locale;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_2
    check-cast p0, Lti/c;

    .line 84
    .line 85
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 86
    .line 87
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 88
    .line 89
    .line 90
    iget-object v1, p0, Lti/c;->e:Lyy0/c2;

    .line 91
    .line 92
    new-instance v2, Lo20/c;

    .line 93
    .line 94
    const/4 v3, 0x0

    .line 95
    const/16 v4, 0x11

    .line 96
    .line 97
    invoke-direct {v2, v4, v0, p0, v3}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 98
    .line 99
    .line 100
    invoke-static {v1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    iget-object p0, p0, Lti/c;->a:Lvy0/b0;

    .line 109
    .line 110
    sget-wide v1, Lti/d;->a:J

    .line 111
    .line 112
    const/4 v3, 0x2

    .line 113
    invoke-static {v3, v1, v2}, Lyy0/u1;->a(IJ)Lyy0/z1;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    new-instance v2, Lxi/c;

    .line 118
    .line 119
    const-string v3, "ChargingSessions"

    .line 120
    .line 121
    invoke-direct {v2, v1, v3}, Lxi/c;-><init>(Lyy0/v1;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    sget-object v1, Lri/b;->a:Lri/b;

    .line 125
    .line 126
    invoke-static {v0, p0, v2, v1}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    return-object p0

    .line 131
    :pswitch_3
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;

    .line 132
    .line 133
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;)Llx0/b0;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :pswitch_4
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 139
    .line 140
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->q(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;)Llx0/o;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0

    .line 145
    :pswitch_5
    check-cast p0, Ltechnology/cariad/cat/genx/KeyExchangeInformation;

    .line 146
    .line 147
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->u(Ltechnology/cariad/cat/genx/KeyExchangeInformation;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :pswitch_6
    check-cast p0, Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;

    .line 153
    .line 154
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->i(Ltechnology/cariad/cat/genx/services/kes/KeyExchangeServiceApp$Result;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    return-object p0

    .line 159
    :pswitch_7
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;

    .line 160
    .line 161
    invoke-static {p0}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->F(Ltechnology/cariad/cat/genx/keyexchange/InternalKeyExchangeInformation;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    return-object p0

    .line 166
    :pswitch_8
    check-cast p0, Ltechnology/cariad/cat/genx/Car2PhoneMode;

    .line 167
    .line 168
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->j(Ltechnology/cariad/cat/genx/Car2PhoneMode;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    return-object p0

    .line 173
    :pswitch_9
    check-cast p0, Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;

    .line 174
    .line 175
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->a(Ltechnology/cariad/cat/genx/SoftwareStackIncompatibility;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object p0

    .line 179
    return-object p0

    .line 180
    :pswitch_a
    check-cast p0, Lt41/z;

    .line 181
    .line 182
    iget-object p0, p0, Lt41/z;->k:Ljava/util/Set;

    .line 183
    .line 184
    check-cast p0, Ljava/lang/Iterable;

    .line 185
    .line 186
    new-instance v0, Ljava/util/ArrayList;

    .line 187
    .line 188
    const/16 v1, 0xa

    .line 189
    .line 190
    invoke-static {p0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 191
    .line 192
    .line 193
    move-result v1

    .line 194
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 195
    .line 196
    .line 197
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    if-eqz v1, :cond_1

    .line 206
    .line 207
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Lorg/altbeacon/beacon/Region;

    .line 212
    .line 213
    invoke-static {v1}, Lkp/i9;->i(Lorg/altbeacon/beacon/Region;)Lt41/b;

    .line 214
    .line 215
    .line 216
    move-result-object v1

    .line 217
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    goto :goto_0

    .line 221
    :cond_1
    const/4 v4, 0x0

    .line 222
    const/16 v5, 0x39

    .line 223
    .line 224
    const/4 v1, 0x0

    .line 225
    const-string v2, "["

    .line 226
    .line 227
    const-string v3, "]"

    .line 228
    .line 229
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    const-string v0, "stopScanning(): Drop found beacons = "

    .line 234
    .line 235
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    return-object p0

    .line 240
    :pswitch_b
    check-cast p0, Lt4/k;

    .line 241
    .line 242
    invoke-virtual {p0}, Lt4/k;->c()J

    .line 243
    .line 244
    .line 245
    move-result-wide v0

    .line 246
    new-instance p0, Lt4/j;

    .line 247
    .line 248
    invoke-direct {p0, v0, v1}, Lt4/j;-><init>(J)V

    .line 249
    .line 250
    .line 251
    return-object p0

    .line 252
    :pswitch_c
    check-cast p0, Lt1/p0;

    .line 253
    .line 254
    invoke-virtual {p0}, Lt1/p0;->d()Lt1/j1;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    return-object p0

    .line 259
    :pswitch_d
    check-cast p0, Lg1/w1;

    .line 260
    .line 261
    new-instance v0, Lt1/h1;

    .line 262
    .line 263
    const/4 v1, 0x0

    .line 264
    invoke-direct {v0, p0, v1}, Lt1/h1;-><init>(Lg1/w1;F)V

    .line 265
    .line 266
    .line 267
    return-object v0

    .line 268
    :pswitch_e
    check-cast p0, Lg4/g;

    .line 269
    .line 270
    return-object p0

    .line 271
    :pswitch_f
    check-cast p0, Lsz0/h;

    .line 272
    .line 273
    iget-object v0, p0, Lsz0/h;->k:[Lsz0/g;

    .line 274
    .line 275
    invoke-static {p0, v0}, Luz0/b1;->g(Lsz0/g;[Lsz0/g;)I

    .line 276
    .line 277
    .line 278
    move-result p0

    .line 279
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 280
    .line 281
    .line 282
    move-result-object p0

    .line 283
    return-object p0

    .line 284
    :pswitch_10
    check-cast p0, Lse/g;

    .line 285
    .line 286
    sget-object v0, Lse/d;->a:Lse/d;

    .line 287
    .line 288
    invoke-virtual {p0, v0}, Lse/g;->a(Lse/e;)V

    .line 289
    .line 290
    .line 291
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    return-object p0

    .line 294
    :pswitch_11
    check-cast p0, Ljava/util/concurrent/CancellationException;

    .line 295
    .line 296
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object p0

    .line 300
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object p0

    .line 304
    return-object p0

    .line 305
    :pswitch_12
    check-cast p0, Landroid/content/res/Configuration;

    .line 306
    .line 307
    iget p0, p0, Landroid/content/res/Configuration;->orientation:I

    .line 308
    .line 309
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object p0

    .line 313
    return-object p0

    .line 314
    :pswitch_13
    check-cast p0, Lre0/c;

    .line 315
    .line 316
    iget-object p0, p0, Lre0/c;->b:Llx0/q;

    .line 317
    .line 318
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object p0

    .line 322
    check-cast p0, Ljava/security/KeyStore;

    .line 323
    .line 324
    const-string v0, "MyskodaAlias"

    .line 325
    .line 326
    const/4 v1, 0x0

    .line 327
    invoke-virtual {p0, v0, v1}, Ljava/security/KeyStore;->getEntry(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;

    .line 328
    .line 329
    .line 330
    move-result-object p0

    .line 331
    instance-of v2, p0, Ljava/security/KeyStore$SecretKeyEntry;

    .line 332
    .line 333
    if-eqz v2, :cond_2

    .line 334
    .line 335
    move-object v1, p0

    .line 336
    check-cast v1, Ljava/security/KeyStore$SecretKeyEntry;

    .line 337
    .line 338
    :cond_2
    if-eqz v1, :cond_3

    .line 339
    .line 340
    invoke-virtual {v1}, Ljava/security/KeyStore$SecretKeyEntry;->getSecretKey()Ljavax/crypto/SecretKey;

    .line 341
    .line 342
    .line 343
    move-result-object p0

    .line 344
    if-nez p0, :cond_4

    .line 345
    .line 346
    :cond_3
    new-instance p0, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 347
    .line 348
    const/4 v1, 0x3

    .line 349
    invoke-direct {p0, v0, v1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 350
    .line 351
    .line 352
    const/16 v0, 0x100

    .line 353
    .line 354
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setKeySize(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 355
    .line 356
    .line 357
    move-result-object p0

    .line 358
    const-string v0, "GCM"

    .line 359
    .line 360
    filled-new-array {v0}, [Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setBlockModes([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 365
    .line 366
    .line 367
    move-result-object p0

    .line 368
    const-string v0, "NoPadding"

    .line 369
    .line 370
    filled-new-array {v0}, [Ljava/lang/String;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setEncryptionPaddings([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 375
    .line 376
    .line 377
    move-result-object p0

    .line 378
    const/4 v0, 0x0

    .line 379
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setUserAuthenticationRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 380
    .line 381
    .line 382
    move-result-object p0

    .line 383
    const/4 v0, 0x1

    .line 384
    invoke-virtual {p0, v0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setRandomizedEncryptionRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 385
    .line 386
    .line 387
    move-result-object p0

    .line 388
    invoke-virtual {p0}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 389
    .line 390
    .line 391
    move-result-object p0

    .line 392
    const-string v0, "build(...)"

    .line 393
    .line 394
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    const-string v0, "AES"

    .line 398
    .line 399
    invoke-static {v0}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 400
    .line 401
    .line 402
    move-result-object v0

    .line 403
    invoke-virtual {v0, p0}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 404
    .line 405
    .line 406
    invoke-virtual {v0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 407
    .line 408
    .line 409
    move-result-object p0

    .line 410
    const-string v0, "generateKey(...)"

    .line 411
    .line 412
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 413
    .line 414
    .line 415
    :cond_4
    return-object p0

    .line 416
    :pswitch_14
    check-cast p0, Lre/k;

    .line 417
    .line 418
    sget-object v0, Lre/e;->a:Lre/e;

    .line 419
    .line 420
    invoke-virtual {p0, v0}, Lre/k;->b(Lre/f;)V

    .line 421
    .line 422
    .line 423
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 424
    .line 425
    return-object p0

    .line 426
    :pswitch_15
    check-cast p0, Lb0/p1;

    .line 427
    .line 428
    invoke-virtual {p0}, Lb0/b0;->close()V

    .line 429
    .line 430
    .line 431
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 432
    .line 433
    return-object p0

    .line 434
    :pswitch_16
    check-cast p0, Lra/f;

    .line 435
    .line 436
    invoke-interface {p0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    new-instance v1, Lra/a;

    .line 441
    .line 442
    const/4 v2, 0x0

    .line 443
    invoke-direct {v1, p0, v2}, Lra/a;-><init>(Lra/f;I)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v0, v1}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 447
    .line 448
    .line 449
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 450
    .line 451
    return-object p0

    .line 452
    :pswitch_17
    check-cast p0, Lr80/f;

    .line 453
    .line 454
    new-instance v0, Llj0/b;

    .line 455
    .line 456
    iget-object p0, p0, Lr80/f;->i:Lij0/a;

    .line 457
    .line 458
    const v1, 0x7f121276

    .line 459
    .line 460
    .line 461
    check-cast p0, Ljj0/f;

    .line 462
    .line 463
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object p0

    .line 467
    const-string v1, "https://skoda.cubictelecom.com"

    .line 468
    .line 469
    invoke-direct {v0, p0, v1}, Llj0/b;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    return-object v0

    .line 473
    :pswitch_18
    check-cast p0, Lr60/a0;

    .line 474
    .line 475
    new-instance v0, Llj0/a;

    .line 476
    .line 477
    iget-object p0, p0, Lr60/a0;->q:Lij0/a;

    .line 478
    .line 479
    const v1, 0x7f12037f

    .line 480
    .line 481
    .line 482
    check-cast p0, Ljj0/f;

    .line 483
    .line 484
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 485
    .line 486
    .line 487
    move-result-object p0

    .line 488
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    return-object v0

    .line 492
    :pswitch_19
    check-cast p0, Lr60/s;

    .line 493
    .line 494
    new-instance v0, Llj0/a;

    .line 495
    .line 496
    iget-object p0, p0, Lr60/s;->o:Lij0/a;

    .line 497
    .line 498
    const v1, 0x7f12037f

    .line 499
    .line 500
    .line 501
    check-cast p0, Ljj0/f;

    .line 502
    .line 503
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 504
    .line 505
    .line 506
    move-result-object p0

    .line 507
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 508
    .line 509
    .line 510
    return-object v0

    .line 511
    :pswitch_1a
    check-cast p0, Lr60/p;

    .line 512
    .line 513
    new-instance v0, Llj0/a;

    .line 514
    .line 515
    iget-object p0, p0, Lr60/p;->p:Lij0/a;

    .line 516
    .line 517
    const v1, 0x7f12037f

    .line 518
    .line 519
    .line 520
    check-cast p0, Ljj0/f;

    .line 521
    .line 522
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 523
    .line 524
    .line 525
    move-result-object p0

    .line 526
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    return-object v0

    .line 530
    :pswitch_1b
    check-cast p0, Lr60/l;

    .line 531
    .line 532
    new-instance v0, Llj0/a;

    .line 533
    .line 534
    iget-object p0, p0, Lr60/l;->o:Lij0/a;

    .line 535
    .line 536
    const v1, 0x7f12037f

    .line 537
    .line 538
    .line 539
    check-cast p0, Ljj0/f;

    .line 540
    .line 541
    invoke-virtual {p0, v1}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 542
    .line 543
    .line 544
    move-result-object p0

    .line 545
    invoke-direct {v0, p0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 546
    .line 547
    .line 548
    return-object v0

    .line 549
    :pswitch_1c
    check-cast p0, Lr1/c;

    .line 550
    .line 551
    iget-object v0, p0, Lr1/c;->P:Lay0/k;

    .line 552
    .line 553
    iget-boolean p0, p0, Lr1/c;->O:Z

    .line 554
    .line 555
    xor-int/lit8 p0, p0, 0x1

    .line 556
    .line 557
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 558
    .line 559
    .line 560
    move-result-object p0

    .line 561
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 562
    .line 563
    .line 564
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 565
    .line 566
    return-object p0

    .line 567
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
