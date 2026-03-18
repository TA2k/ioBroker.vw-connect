.class public final Lx41/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx41/w;
.implements Lvy0/b0;


# static fields
.field public static final A:Lx41/d0;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Lh70/d;

.field public final f:Lx41/z0;

.field public final g:Ltechnology/cariad/cat/genx/VehicleManager;

.field public final h:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

.field public final i:Lvy0/x;

.field public final j:Lpx0/g;

.field public k:Lss/b;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/l1;

.field public final n:Lyy0/c2;

.field public final o:Lyy0/l1;

.field public final p:Lyy0/c2;

.field public final q:Lyy0/l1;

.field public final r:Lyy0/q1;

.field public final s:Ljava/util/concurrent/ConcurrentHashMap;

.field public final t:Ljava/util/concurrent/ConcurrentHashMap;

.field public final u:Lx41/m0;

.field public v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

.field public final w:Lez0/c;

.field public x:Ljava/util/Set;

.field public final y:Lez0/c;

.field public final z:Ljava/util/Set;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lx41/d0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lx41/u0;->A:Lx41/d0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lh70/d;Lx41/z0;Ltechnology/cariad/cat/genx/VehicleManager;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lvy0/i1;Lvy0/x;)V
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p4

    .line 8
    .line 9
    move-object/from16 v4, p7

    .line 10
    .line 11
    sget-object v5, Lvy0/p0;->a:Lcz0/e;

    .line 12
    .line 13
    sget-object v5, Laz0/m;->a:Lwy0/c;

    .line 14
    .line 15
    const-string v6, "vehicleManager"

    .line 16
    .line 17
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v6, "ioDispatcher"

    .line 21
    .line 22
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v6, "mainDispatcher"

    .line 26
    .line 27
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v1, v0, Lx41/u0;->d:Landroid/content/Context;

    .line 34
    .line 35
    move-object/from16 v6, p2

    .line 36
    .line 37
    iput-object v6, v0, Lx41/u0;->e:Lh70/d;

    .line 38
    .line 39
    iput-object v2, v0, Lx41/u0;->f:Lx41/z0;

    .line 40
    .line 41
    iput-object v3, v0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 42
    .line 43
    move-object/from16 v6, p5

    .line 44
    .line 45
    iput-object v6, v0, Lx41/u0;->h:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 46
    .line 47
    iput-object v5, v0, Lx41/u0;->i:Lvy0/x;

    .line 48
    .line 49
    new-instance v5, Lvy0/k1;

    .line 50
    .line 51
    move-object/from16 v6, p6

    .line 52
    .line 53
    invoke-direct {v5, v6}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 54
    .line 55
    .line 56
    new-instance v6, Lvy0/a0;

    .line 57
    .line 58
    const-string v7, "PairingManager"

    .line 59
    .line 60
    invoke-direct {v6, v7}, Lvy0/a0;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-static {v5, v6}, Ljp/ce;->a(Lpx0/g;Lpx0/g;)Lpx0/g;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    invoke-interface {v5, v4}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    new-instance v5, Lil/i;

    .line 72
    .line 73
    invoke-direct {v5, v0}, Lil/i;-><init>(Lx41/u0;)V

    .line 74
    .line 75
    .line 76
    invoke-interface {v4, v5}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 77
    .line 78
    .line 79
    move-result-object v4

    .line 80
    iput-object v4, v0, Lx41/u0;->j:Lpx0/g;

    .line 81
    .line 82
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-static {v4}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    iput-object v4, v0, Lx41/u0;->l:Lyy0/c2;

    .line 89
    .line 90
    new-instance v5, Lyy0/l1;

    .line 91
    .line 92
    invoke-direct {v5, v4}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 93
    .line 94
    .line 95
    iput-object v5, v0, Lx41/u0;->m:Lyy0/l1;

    .line 96
    .line 97
    const-string v4, "android.permission.ACCESS_FINE_LOCATION"

    .line 98
    .line 99
    invoke-static {v1, v4}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    const/4 v5, 0x1

    .line 104
    const/4 v6, 0x0

    .line 105
    if-nez v4, :cond_1

    .line 106
    .line 107
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 108
    .line 109
    const-string v7, "android.permission.ACCESS_BACKGROUND_LOCATION"

    .line 110
    .line 111
    invoke-static {v1, v7}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    if-nez v7, :cond_1

    .line 116
    .line 117
    const/16 v7, 0x1f

    .line 118
    .line 119
    if-lt v4, v7, :cond_0

    .line 120
    .line 121
    const-string v4, "android.permission.BLUETOOTH_SCAN"

    .line 122
    .line 123
    invoke-static {v1, v4}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 124
    .line 125
    .line 126
    move-result v4

    .line 127
    if-nez v4, :cond_1

    .line 128
    .line 129
    const-string v4, "android.permission.BLUETOOTH_CONNECT"

    .line 130
    .line 131
    invoke-static {v1, v4}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-nez v1, :cond_1

    .line 136
    .line 137
    :cond_0
    move v6, v5

    .line 138
    :cond_1
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    iput-object v1, v0, Lx41/u0;->n:Lyy0/c2;

    .line 147
    .line 148
    new-instance v4, Lyy0/l1;

    .line 149
    .line 150
    invoke-direct {v4, v1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 151
    .line 152
    .line 153
    iput-object v4, v0, Lx41/u0;->o:Lyy0/l1;

    .line 154
    .line 155
    sget-object v1, Lmx0/u;->d:Lmx0/u;

    .line 156
    .line 157
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    iput-object v4, v0, Lx41/u0;->p:Lyy0/c2;

    .line 162
    .line 163
    new-instance v6, Lyy0/l1;

    .line 164
    .line 165
    invoke-direct {v6, v4}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 166
    .line 167
    .line 168
    iput-object v6, v0, Lx41/u0;->q:Lyy0/l1;

    .line 169
    .line 170
    sget-object v4, Lxy0/a;->e:Lxy0/a;

    .line 171
    .line 172
    invoke-static {v5, v5, v4}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    iput-object v4, v0, Lx41/u0;->r:Lyy0/q1;

    .line 177
    .line 178
    new-instance v4, Ljava/util/concurrent/ConcurrentHashMap;

    .line 179
    .line 180
    invoke-direct {v4}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 181
    .line 182
    .line 183
    iput-object v4, v0, Lx41/u0;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 184
    .line 185
    new-instance v4, Ljava/util/concurrent/ConcurrentHashMap;

    .line 186
    .line 187
    invoke-direct {v4}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 188
    .line 189
    .line 190
    iput-object v4, v0, Lx41/u0;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 191
    .line 192
    invoke-interface {v3}, Ltechnology/cariad/cat/genx/VehicleManager;->getVehicleErrors()Lyy0/i;

    .line 193
    .line 194
    .line 195
    new-instance v4, Lx41/m0;

    .line 196
    .line 197
    invoke-direct {v4, v0}, Lx41/m0;-><init>(Lx41/u0;)V

    .line 198
    .line 199
    .line 200
    iput-object v4, v0, Lx41/u0;->u:Lx41/m0;

    .line 201
    .line 202
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 203
    .line 204
    .line 205
    move-result-object v4

    .line 206
    iput-object v4, v0, Lx41/u0;->w:Lez0/c;

    .line 207
    .line 208
    iget-object v4, v2, Lx41/z0;->b:Lvy0/x;

    .line 209
    .line 210
    new-instance v9, Lx41/y;

    .line 211
    .line 212
    const/16 v6, 0x13

    .line 213
    .line 214
    invoke-direct {v9, v6}, Lx41/y;-><init>(I)V

    .line 215
    .line 216
    .line 217
    new-instance v6, Lt51/j;

    .line 218
    .line 219
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v11

    .line 223
    const-string v13, "getName(...)"

    .line 224
    .line 225
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v12

    .line 229
    const-string v7, "Car2PhonePairing"

    .line 230
    .line 231
    sget-object v16, Lt51/g;->a:Lt51/g;

    .line 232
    .line 233
    const/4 v10, 0x0

    .line 234
    move-object/from16 v8, v16

    .line 235
    .line 236
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 240
    .line 241
    .line 242
    iget-object v6, v2, Lx41/z0;->c:Ljava/lang/String;

    .line 243
    .line 244
    iget-object v7, v2, Lx41/z0;->d:Ljava/lang/String;

    .line 245
    .line 246
    new-instance v8, Lx41/v0;

    .line 247
    .line 248
    const/4 v9, 0x0

    .line 249
    const/4 v10, 0x3

    .line 250
    invoke-direct {v8, v2, v6, v9, v10}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 251
    .line 252
    .line 253
    invoke-static {v4, v8}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v8

    .line 257
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 258
    .line 259
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v8

    .line 263
    const/4 v12, 0x4

    .line 264
    const/16 v14, 0x14

    .line 265
    .line 266
    const/4 v15, 0x5

    .line 267
    const-string v10, "Car2PhonePairing"

    .line 268
    .line 269
    if-eqz v8, :cond_2

    .line 270
    .line 271
    new-instance v8, Lx41/y;

    .line 272
    .line 273
    invoke-direct {v8, v14}, Lx41/y;-><init>(I)V

    .line 274
    .line 275
    .line 276
    invoke-static {v2, v10, v9, v8}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v2, v6, v7}, Lx41/z0;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/util/Set;

    .line 280
    .line 281
    .line 282
    move-result-object v6

    .line 283
    move-object v7, v6

    .line 284
    :goto_0
    move v8, v14

    .line 285
    move v6, v15

    .line 286
    goto :goto_1

    .line 287
    :cond_2
    new-instance v6, Lx41/v0;

    .line 288
    .line 289
    invoke-direct {v6, v2, v7, v9, v12}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 290
    .line 291
    .line 292
    invoke-static {v4, v6}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v6

    .line 296
    invoke-static {v6, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v6

    .line 300
    if-nez v6, :cond_3

    .line 301
    .line 302
    move-object v7, v1

    .line 303
    goto :goto_0

    .line 304
    :cond_3
    new-instance v6, Lx41/v0;

    .line 305
    .line 306
    invoke-direct {v6, v2, v7, v9, v15}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 307
    .line 308
    .line 309
    invoke-static {v4, v6}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v6

    .line 313
    check-cast v6, Llx0/o;

    .line 314
    .line 315
    iget-object v6, v6, Llx0/o;->d:Ljava/lang/Object;

    .line 316
    .line 317
    invoke-static {v6}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 318
    .line 319
    .line 320
    move-result-object v7

    .line 321
    if-nez v7, :cond_4

    .line 322
    .line 323
    check-cast v6, Ljava/util/Set;

    .line 324
    .line 325
    new-instance v7, Li61/b;

    .line 326
    .line 327
    invoke-direct {v7, v15, v6}, Li61/b;-><init>(ILjava/util/Set;)V

    .line 328
    .line 329
    .line 330
    move v8, v14

    .line 331
    new-instance v14, Lt51/j;

    .line 332
    .line 333
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v19

    .line 337
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v20

    .line 341
    move/from16 v17, v15

    .line 342
    .line 343
    const-string v15, "Car2PhonePairing"

    .line 344
    .line 345
    const/16 v18, 0x0

    .line 346
    .line 347
    move/from16 v21, v17

    .line 348
    .line 349
    move-object/from16 v17, v7

    .line 350
    .line 351
    move/from16 v7, v21

    .line 352
    .line 353
    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 357
    .line 358
    .line 359
    move-object v7, v6

    .line 360
    move/from16 v6, v21

    .line 361
    .line 362
    goto :goto_1

    .line 363
    :cond_4
    move v8, v14

    .line 364
    move v6, v15

    .line 365
    instance-of v14, v7, Lu51/d;

    .line 366
    .line 367
    if-nez v14, :cond_5

    .line 368
    .line 369
    new-instance v14, Lx41/y;

    .line 370
    .line 371
    const/16 v15, 0x15

    .line 372
    .line 373
    invoke-direct {v14, v15}, Lx41/y;-><init>(I)V

    .line 374
    .line 375
    .line 376
    invoke-static {v2, v10, v7, v14}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 377
    .line 378
    .line 379
    :cond_5
    move-object v7, v1

    .line 380
    :goto_1
    iput-object v7, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 381
    .line 382
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 383
    .line 384
    .line 385
    move-result-object v7

    .line 386
    iput-object v7, v0, Lx41/u0;->y:Lez0/c;

    .line 387
    .line 388
    new-instance v7, Lx41/y;

    .line 389
    .line 390
    const/16 v14, 0x16

    .line 391
    .line 392
    invoke-direct {v7, v14}, Lx41/y;-><init>(I)V

    .line 393
    .line 394
    .line 395
    new-instance v14, Lt51/j;

    .line 396
    .line 397
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v19

    .line 401
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v20

    .line 405
    const-string v15, "Car2PhonePairing"

    .line 406
    .line 407
    const/16 v18, 0x0

    .line 408
    .line 409
    move-object/from16 v17, v7

    .line 410
    .line 411
    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 415
    .line 416
    .line 417
    iget-object v7, v2, Lx41/z0;->e:Ljava/lang/String;

    .line 418
    .line 419
    iget-object v14, v2, Lx41/z0;->f:Ljava/lang/String;

    .line 420
    .line 421
    new-instance v15, Lx41/v0;

    .line 422
    .line 423
    const/4 v6, 0x6

    .line 424
    invoke-direct {v15, v2, v7, v9, v6}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 425
    .line 426
    .line 427
    invoke-static {v4, v15}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 428
    .line 429
    .line 430
    move-result-object v6

    .line 431
    invoke-static {v6, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v6

    .line 435
    if-eqz v6, :cond_6

    .line 436
    .line 437
    new-instance v4, Lx41/y;

    .line 438
    .line 439
    invoke-direct {v4, v8}, Lx41/y;-><init>(I)V

    .line 440
    .line 441
    .line 442
    move-object v6, v14

    .line 443
    new-instance v14, Lt51/j;

    .line 444
    .line 445
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 446
    .line 447
    .line 448
    move-result-object v19

    .line 449
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v20

    .line 453
    const-string v15, "Car2PhonePairing"

    .line 454
    .line 455
    const/16 v18, 0x0

    .line 456
    .line 457
    move-object/from16 v17, v4

    .line 458
    .line 459
    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 463
    .line 464
    .line 465
    invoke-virtual {v2, v7, v6}, Lx41/z0;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/util/Set;

    .line 466
    .line 467
    .line 468
    move-result-object v4

    .line 469
    goto :goto_3

    .line 470
    :cond_6
    move-object v6, v14

    .line 471
    new-instance v7, Lx41/v0;

    .line 472
    .line 473
    const/4 v8, 0x7

    .line 474
    invoke-direct {v7, v2, v6, v9, v8}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 475
    .line 476
    .line 477
    invoke-static {v4, v7}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v7

    .line 481
    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 482
    .line 483
    .line 484
    move-result v7

    .line 485
    if-nez v7, :cond_8

    .line 486
    .line 487
    :cond_7
    :goto_2
    move-object v4, v1

    .line 488
    goto :goto_3

    .line 489
    :cond_8
    new-instance v7, Lx41/v0;

    .line 490
    .line 491
    const/16 v8, 0x8

    .line 492
    .line 493
    invoke-direct {v7, v2, v6, v9, v8}, Lx41/v0;-><init>(Lx41/z0;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 494
    .line 495
    .line 496
    invoke-static {v4, v7}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object v4

    .line 500
    check-cast v4, Llx0/o;

    .line 501
    .line 502
    iget-object v4, v4, Llx0/o;->d:Ljava/lang/Object;

    .line 503
    .line 504
    invoke-static {v4}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 505
    .line 506
    .line 507
    move-result-object v6

    .line 508
    if-nez v6, :cond_9

    .line 509
    .line 510
    check-cast v4, Ljava/util/Set;

    .line 511
    .line 512
    new-instance v6, Li61/b;

    .line 513
    .line 514
    const/4 v7, 0x2

    .line 515
    invoke-direct {v6, v7, v4}, Li61/b;-><init>(ILjava/util/Set;)V

    .line 516
    .line 517
    .line 518
    new-instance v14, Lt51/j;

    .line 519
    .line 520
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 521
    .line 522
    .line 523
    move-result-object v19

    .line 524
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 525
    .line 526
    .line 527
    move-result-object v20

    .line 528
    const-string v15, "Car2PhonePairing"

    .line 529
    .line 530
    const/16 v18, 0x0

    .line 531
    .line 532
    move-object/from16 v17, v6

    .line 533
    .line 534
    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 538
    .line 539
    .line 540
    goto :goto_3

    .line 541
    :cond_9
    instance-of v4, v6, Lu51/d;

    .line 542
    .line 543
    if-nez v4, :cond_7

    .line 544
    .line 545
    new-instance v4, Lx41/y;

    .line 546
    .line 547
    const/16 v7, 0xf

    .line 548
    .line 549
    invoke-direct {v4, v7}, Lx41/y;-><init>(I)V

    .line 550
    .line 551
    .line 552
    invoke-static {v2, v10, v6, v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 553
    .line 554
    .line 555
    goto :goto_2

    .line 556
    :goto_3
    move-object v6, v4

    .line 557
    check-cast v6, Ljava/util/Collection;

    .line 558
    .line 559
    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    .line 560
    .line 561
    .line 562
    move-result v6

    .line 563
    if-nez v6, :cond_a

    .line 564
    .line 565
    new-instance v6, Lx41/y;

    .line 566
    .line 567
    invoke-direct {v6, v5}, Lx41/y;-><init>(I)V

    .line 568
    .line 569
    .line 570
    invoke-static {v0, v10, v9, v6}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 574
    .line 575
    .line 576
    const-string v6, "pairings"

    .line 577
    .line 578
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    new-instance v6, Li61/b;

    .line 582
    .line 583
    invoke-direct {v6, v12, v1}, Li61/b;-><init>(ILjava/util/Set;)V

    .line 584
    .line 585
    .line 586
    new-instance v14, Lt51/j;

    .line 587
    .line 588
    invoke-static {v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v19

    .line 592
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object v20

    .line 596
    const-string v15, "Car2PhonePairing"

    .line 597
    .line 598
    sget-object v16, Lt51/g;->a:Lt51/g;

    .line 599
    .line 600
    const/16 v18, 0x0

    .line 601
    .line 602
    move-object/from16 v17, v6

    .line 603
    .line 604
    invoke-direct/range {v14 .. v20}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 605
    .line 606
    .line 607
    invoke-static {v14}, Lt51/a;->a(Lt51/j;)V

    .line 608
    .line 609
    .line 610
    iget-object v6, v2, Lx41/z0;->h:Lpw0/a;

    .line 611
    .line 612
    new-instance v7, Lx41/y0;

    .line 613
    .line 614
    invoke-direct {v7, v2, v1, v9, v5}, Lx41/y0;-><init>(Lx41/z0;Ljava/util/Set;Lkotlin/coroutines/Continuation;I)V

    .line 615
    .line 616
    .line 617
    const/4 v1, 0x3

    .line 618
    invoke-static {v6, v9, v9, v7, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 619
    .line 620
    .line 621
    goto :goto_4

    .line 622
    :cond_a
    const/4 v1, 0x3

    .line 623
    :goto_4
    iput-object v4, v0, Lx41/u0;->z:Ljava/util/Set;

    .line 624
    .line 625
    new-instance v2, Lx41/a0;

    .line 626
    .line 627
    invoke-direct {v2, v0, v9}, Lx41/a0;-><init>(Lx41/u0;Lkotlin/coroutines/Continuation;)V

    .line 628
    .line 629
    .line 630
    invoke-static {v0, v9, v9, v2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 631
    .line 632
    .line 633
    invoke-interface {v3}, Ltechnology/cariad/cat/genx/VehicleManager;->getVehicleErrors()Lyy0/i;

    .line 634
    .line 635
    .line 636
    move-result-object v1

    .line 637
    new-instance v2, Lx41/b0;

    .line 638
    .line 639
    invoke-direct {v2, v0, v9}, Lx41/b0;-><init>(Lx41/u0;Lkotlin/coroutines/Continuation;)V

    .line 640
    .line 641
    .line 642
    new-instance v3, Lne0/n;

    .line 643
    .line 644
    const/4 v6, 0x5

    .line 645
    invoke-direct {v3, v1, v2, v6}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 646
    .line 647
    .line 648
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 649
    .line 650
    .line 651
    return-void
.end method


# virtual methods
.method public final G(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lx41/q0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lx41/q0;

    .line 7
    .line 8
    iget v1, v0, Lx41/q0;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lx41/q0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lx41/q0;

    .line 21
    .line 22
    check-cast p1, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p1}, Lx41/q0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lx41/q0;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lx41/q0;->f:I

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    check-cast p1, Llx0/o;

    .line 45
    .line 46
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    new-instance v8, Lx41/y;

    .line 65
    .line 66
    const/4 p1, 0x0

    .line 67
    invoke-direct {v8, p1}, Lx41/y;-><init>(I)V

    .line 68
    .line 69
    .line 70
    new-instance v5, Lt51/j;

    .line 71
    .line 72
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v10

    .line 76
    const-string p1, "getName(...)"

    .line 77
    .line 78
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v11

    .line 82
    const-string v6, "Car2PhonePairing"

    .line 83
    .line 84
    sget-object v7, Lt51/g;->a:Lt51/g;

    .line 85
    .line 86
    const/4 v9, 0x0

    .line 87
    invoke-direct/range {v5 .. v11}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-static {v5}, Lt51/a;->a(Lt51/j;)V

    .line 91
    .line 92
    .line 93
    iput v4, v0, Lx41/q0;->f:I

    .line 94
    .line 95
    iget-object p1, p0, Lx41/u0;->d:Landroid/content/Context;

    .line 96
    .line 97
    invoke-virtual {p0, p1, v0}, Lx41/u0;->f(Landroid/content/Context;Lrx0/c;)Ljava/io/Serializable;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v1, :cond_4

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_4
    :goto_1
    check-cast p1, Lx41/s;

    .line 105
    .line 106
    if-eqz p1, :cond_5

    .line 107
    .line 108
    return-object p1

    .line 109
    :cond_5
    iput v3, v0, Lx41/q0;->f:I

    .line 110
    .line 111
    iget-object p1, p0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 112
    .line 113
    invoke-interface {p1, v0}, Ltechnology/cariad/cat/genx/ScanningManager;->startScanningForClients-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    if-ne p1, v1, :cond_6

    .line 118
    .line 119
    :goto_2
    return-object v1

    .line 120
    :cond_6
    :goto_3
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    if-nez v0, :cond_8

    .line 125
    .line 126
    check-cast p1, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 127
    .line 128
    iget-object v0, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 129
    .line 130
    if-eqz v0, :cond_7

    .line 131
    .line 132
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 133
    .line 134
    .line 135
    :cond_7
    iput-object p1, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 136
    .line 137
    const/4 p0, 0x0

    .line 138
    return-object p0

    .line 139
    :cond_8
    new-instance p1, Lx41/y;

    .line 140
    .line 141
    const/4 v1, 0x6

    .line 142
    invoke-direct {p1, v1}, Lx41/y;-><init>(I)V

    .line 143
    .line 144
    .line 145
    const-string v1, "Car2PhonePairing"

    .line 146
    .line 147
    invoke-static {p0, v1, v0, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 148
    .line 149
    .line 150
    new-instance p0, Lx41/r;

    .line 151
    .line 152
    check-cast v0, Ltechnology/cariad/cat/genx/GenXError;

    .line 153
    .line 154
    invoke-direct {p0, v0}, Lx41/r;-><init>(Ltechnology/cariad/cat/genx/GenXError;)V

    .line 155
    .line 156
    .line 157
    return-object p0
.end method

.method public final J(Lss/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

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
    instance-of v3, v2, Lx41/p0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lx41/p0;

    .line 13
    .line 14
    iget v4, v3, Lx41/p0;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lx41/p0;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lx41/p0;

    .line 27
    .line 28
    check-cast v2, Lrx0/c;

    .line 29
    .line 30
    invoke-direct {v3, v0, v2}, Lx41/p0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v2, v3, Lx41/p0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v5, v3, Lx41/p0;->g:I

    .line 38
    .line 39
    iget-object v6, v0, Lx41/u0;->i:Lvy0/x;

    .line 40
    .line 41
    const-string v7, "getName(...)"

    .line 42
    .line 43
    sget-object v10, Lt51/g;->a:Lt51/g;

    .line 44
    .line 45
    const/4 v15, 0x3

    .line 46
    const/4 v8, 0x2

    .line 47
    sget-object v16, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    const/4 v9, 0x1

    .line 50
    const/4 v11, 0x0

    .line 51
    if-eqz v5, :cond_4

    .line 52
    .line 53
    if-eq v5, v9, :cond_3

    .line 54
    .line 55
    if-eq v5, v8, :cond_2

    .line 56
    .line 57
    if-ne v5, v15, :cond_1

    .line 58
    .line 59
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v16

    .line 63
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    iget-object v1, v3, Lx41/p0;->d:Lss/b;

    .line 72
    .line 73
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    move-object v15, v11

    .line 77
    goto :goto_1

    .line 78
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    return-object v16

    .line 82
    :cond_4
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move-object v2, v11

    .line 86
    new-instance v11, Lx41/y;

    .line 87
    .line 88
    const/16 v5, 0x9

    .line 89
    .line 90
    invoke-direct {v11, v5}, Lx41/y;-><init>(I)V

    .line 91
    .line 92
    .line 93
    move v5, v8

    .line 94
    new-instance v8, Lt51/j;

    .line 95
    .line 96
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v13

    .line 100
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v14

    .line 104
    move v12, v9

    .line 105
    const-string v9, "Car2PhonePairing"

    .line 106
    .line 107
    move/from16 v17, v12

    .line 108
    .line 109
    const/4 v12, 0x0

    .line 110
    move-object v15, v2

    .line 111
    move/from16 v2, v17

    .line 112
    .line 113
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 117
    .line 118
    .line 119
    iget-object v8, v0, Lx41/u0;->m:Lyy0/l1;

    .line 120
    .line 121
    iget-object v8, v8, Lyy0/l1;->d:Lyy0/a2;

    .line 122
    .line 123
    invoke-interface {v8}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    check-cast v8, Ljava/lang/Boolean;

    .line 128
    .line 129
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    if-eqz v8, :cond_5

    .line 134
    .line 135
    new-instance v5, Lx41/y;

    .line 136
    .line 137
    const/16 v7, 0xa

    .line 138
    .line 139
    invoke-direct {v5, v7}, Lx41/y;-><init>(I)V

    .line 140
    .line 141
    .line 142
    const-string v7, "Car2PhonePairing"

    .line 143
    .line 144
    invoke-static {v0, v7, v15, v5}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 145
    .line 146
    .line 147
    new-instance v0, Lx41/i0;

    .line 148
    .line 149
    const/4 v5, 0x2

    .line 150
    invoke-direct {v0, v1, v15, v5}, Lx41/i0;-><init>(Lss/b;Lkotlin/coroutines/Continuation;I)V

    .line 151
    .line 152
    .line 153
    iput-object v15, v3, Lx41/p0;->d:Lss/b;

    .line 154
    .line 155
    iput v2, v3, Lx41/p0;->g:I

    .line 156
    .line 157
    invoke-static {v6, v0, v3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    if-ne v0, v4, :cond_8

    .line 162
    .line 163
    goto :goto_2

    .line 164
    :cond_5
    iput-object v1, v3, Lx41/p0;->d:Lss/b;

    .line 165
    .line 166
    iput v5, v3, Lx41/p0;->g:I

    .line 167
    .line 168
    iget-object v2, v0, Lx41/u0;->d:Landroid/content/Context;

    .line 169
    .line 170
    invoke-virtual {v0, v2, v3}, Lx41/u0;->f(Landroid/content/Context;Lrx0/c;)Ljava/io/Serializable;

    .line 171
    .line 172
    .line 173
    move-result-object v2

    .line 174
    if-ne v2, v4, :cond_6

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_6
    :goto_1
    check-cast v2, Lx41/s;

    .line 178
    .line 179
    if-eqz v2, :cond_7

    .line 180
    .line 181
    new-instance v0, Lwa0/c;

    .line 182
    .line 183
    const/16 v5, 0x8

    .line 184
    .line 185
    invoke-direct {v0, v5, v1, v2, v15}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 186
    .line 187
    .line 188
    iput-object v15, v3, Lx41/p0;->d:Lss/b;

    .line 189
    .line 190
    const/4 v1, 0x3

    .line 191
    iput v1, v3, Lx41/p0;->g:I

    .line 192
    .line 193
    invoke-static {v6, v0, v3}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    if-ne v0, v4, :cond_8

    .line 198
    .line 199
    :goto_2
    return-object v4

    .line 200
    :cond_7
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 201
    .line 202
    iget-object v3, v0, Lx41/u0;->l:Lyy0/c2;

    .line 203
    .line 204
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    invoke-virtual {v3, v15, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    iput-object v1, v0, Lx41/u0;->k:Lss/b;

    .line 211
    .line 212
    new-instance v11, Lu2/a;

    .line 213
    .line 214
    const/16 v1, 0x16

    .line 215
    .line 216
    invoke-direct {v11, v0, v1}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 217
    .line 218
    .line 219
    new-instance v8, Lt51/j;

    .line 220
    .line 221
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v13

    .line 225
    invoke-static {v7}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v14

    .line 229
    const-string v9, "Car2PhonePairing"

    .line 230
    .line 231
    const/4 v12, 0x0

    .line 232
    invoke-direct/range {v8 .. v14}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-static {v8}, Lt51/a;->a(Lt51/j;)V

    .line 236
    .line 237
    .line 238
    iget-object v1, v0, Lx41/u0;->k:Lss/b;

    .line 239
    .line 240
    if-eqz v1, :cond_8

    .line 241
    .line 242
    new-instance v2, Lw81/c;

    .line 243
    .line 244
    const/16 v3, 0x16

    .line 245
    .line 246
    invoke-direct {v2, v0, v3}, Lw81/c;-><init>(Ljava/lang/Object;I)V

    .line 247
    .line 248
    .line 249
    new-instance v0, Lh50/p;

    .line 250
    .line 251
    const/16 v3, 0xd

    .line 252
    .line 253
    invoke-direct {v0, v3}, Lh50/p;-><init>(I)V

    .line 254
    .line 255
    .line 256
    invoke-static {v15, v1, v0}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 257
    .line 258
    .line 259
    sput-object v2, Lh70/m;->b:Lw81/c;

    .line 260
    .line 261
    iget-object v0, v1, Lss/b;->k:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast v0, Lay0/a;

    .line 264
    .line 265
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    :cond_8
    return-object v16
.end method

.method public final a(Lx41/n;Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Lx41/f0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lx41/f0;

    .line 7
    .line 8
    iget v1, v0, Lx41/f0;->h:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lx41/f0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lx41/f0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lx41/f0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lx41/f0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lx41/f0;->h:I

    .line 30
    .line 31
    const-string v3, "getName(...)"

    .line 32
    .line 33
    sget-object v6, Lt51/g;->a:Lt51/g;

    .line 34
    .line 35
    const/4 v11, 0x2

    .line 36
    const/4 v12, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v12, :cond_2

    .line 40
    .line 41
    if-ne v2, v11, :cond_1

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto/16 :goto_7

    .line 47
    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p1, v0, Lx41/f0;->e:Lez0/c;

    .line 57
    .line 58
    iget-object v2, v0, Lx41/f0;->d:Lx41/n;

    .line 59
    .line 60
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object p2, p1

    .line 64
    move-object p1, v2

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    new-instance v7, Lx41/z;

    .line 70
    .line 71
    const/4 p2, 0x0

    .line 72
    invoke-direct {v7, p1, p2}, Lx41/z;-><init>(Lx41/n;I)V

    .line 73
    .line 74
    .line 75
    new-instance v4, Lt51/j;

    .line 76
    .line 77
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v9

    .line 81
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v10

    .line 85
    const-string v5, "Car2PhonePairing"

    .line 86
    .line 87
    const/4 v8, 0x0

    .line 88
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 95
    .line 96
    .line 97
    iput-object p1, v0, Lx41/f0;->d:Lx41/n;

    .line 98
    .line 99
    iget-object p2, p0, Lx41/u0;->w:Lez0/c;

    .line 100
    .line 101
    iput-object p2, v0, Lx41/f0;->e:Lez0/c;

    .line 102
    .line 103
    iput v12, v0, Lx41/f0;->h:I

    .line 104
    .line 105
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    if-ne v2, v1, :cond_4

    .line 110
    .line 111
    goto/16 :goto_6

    .line 112
    .line 113
    :cond_4
    :goto_1
    const/4 v2, 0x0

    .line 114
    :try_start_0
    iget-object v4, p0, Lx41/u0;->x:Ljava/util/Set;

    .line 115
    .line 116
    check-cast v4, Ljava/lang/Iterable;

    .line 117
    .line 118
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    :cond_5
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    if-eqz v5, :cond_8

    .line 127
    .line 128
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    move-object v7, v5

    .line 133
    check-cast v7, Lx41/n;

    .line 134
    .line 135
    invoke-interface {v7}, Lx41/n;->getVin()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    invoke-interface {p1}, Lx41/n;->getVin()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v9

    .line 143
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v8

    .line 147
    if-eqz v8, :cond_5

    .line 148
    .line 149
    const-string v8, "first"

    .line 150
    .line 151
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    sget-object v8, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 155
    .line 156
    invoke-static {v7, v8}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 157
    .line 158
    .line 159
    move-result v9

    .line 160
    if-eqz v9, :cond_6

    .line 161
    .line 162
    invoke-static {p1, v8}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 163
    .line 164
    .line 165
    move-result v8

    .line 166
    if-eqz v8, :cond_6

    .line 167
    .line 168
    const/4 v8, 0x1

    .line 169
    goto :goto_2

    .line 170
    :cond_6
    const/4 v8, 0x0

    .line 171
    :goto_2
    if-nez v8, :cond_9

    .line 172
    .line 173
    const-string v8, "first"

    .line 174
    .line 175
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    sget-object v8, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 179
    .line 180
    invoke-static {v7, v8}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    if-eqz v7, :cond_7

    .line 185
    .line 186
    invoke-static {p1, v8}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 187
    .line 188
    .line 189
    move-result v7

    .line 190
    if-eqz v7, :cond_7

    .line 191
    .line 192
    const/4 v7, 0x1

    .line 193
    goto :goto_3

    .line 194
    :cond_7
    const/4 v7, 0x0

    .line 195
    :goto_3
    if-eqz v7, :cond_5

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :catchall_0
    move-exception v0

    .line 199
    move-object p0, v0

    .line 200
    goto :goto_8

    .line 201
    :cond_8
    move-object v5, v2

    .line 202
    :cond_9
    :goto_4
    check-cast v5, Lx41/n;

    .line 203
    .line 204
    if-nez v5, :cond_a

    .line 205
    .line 206
    new-instance v7, Lx41/z;

    .line 207
    .line 208
    const/4 v4, 0x1

    .line 209
    invoke-direct {v7, p1, v4}, Lx41/z;-><init>(Lx41/n;I)V

    .line 210
    .line 211
    .line 212
    const-string v5, "Car2PhonePairing"

    .line 213
    .line 214
    new-instance v4, Lt51/j;

    .line 215
    .line 216
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v9

    .line 220
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 221
    .line 222
    .line 223
    move-result-object v8

    .line 224
    invoke-virtual {v8}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v10

    .line 228
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    const/4 v8, 0x0

    .line 232
    invoke-direct/range {v4 .. v10}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-static {v4}, Lt51/a;->a(Lt51/j;)V

    .line 236
    .line 237
    .line 238
    iget-object v3, p0, Lx41/u0;->x:Ljava/util/Set;

    .line 239
    .line 240
    invoke-static {v3, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    invoke-static {p1}, Lx41/c;->a(Ljava/util/LinkedHashSet;)Ljava/util/ArrayList;

    .line 245
    .line 246
    .line 247
    move-result-object p1

    .line 248
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 249
    .line 250
    .line 251
    move-result-object p1

    .line 252
    invoke-virtual {p0, p1}, Lx41/u0;->l(Ljava/util/Set;)V

    .line 253
    .line 254
    .line 255
    goto :goto_5

    .line 256
    :cond_a
    invoke-virtual {p0, v5, p1}, Lx41/u0;->h(Lx41/n;Lx41/n;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 257
    .line 258
    .line 259
    :goto_5
    invoke-interface {p2, v2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    iput-object v2, v0, Lx41/f0;->d:Lx41/n;

    .line 263
    .line 264
    iput-object v2, v0, Lx41/f0;->e:Lez0/c;

    .line 265
    .line 266
    iput v11, v0, Lx41/f0;->h:I

    .line 267
    .line 268
    invoke-virtual {p0, v0}, Lx41/u0;->q(Lrx0/c;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    if-ne p0, v1, :cond_b

    .line 273
    .line 274
    :goto_6
    return-object v1

    .line 275
    :cond_b
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 276
    .line 277
    return-object p0

    .line 278
    :goto_8
    invoke-interface {p2, v2}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    throw p0
.end method

.method public final b(Ltechnology/cariad/cat/genx/VehicleAntenna;)V
    .locals 10

    .line 1
    invoke-static {p1}, Ltechnology/cariad/cat/genx/VehicleAntennaKt;->getIdentifier(Ltechnology/cariad/cat/genx/VehicleAntenna;)Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lx41/u0;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    new-instance v6, Ltechnology/cariad/cat/genx/keyexchange/f;

    .line 14
    .line 15
    const/4 v2, 0x2

    .line 16
    invoke-direct {v6, v0, v2}, Ltechnology/cariad/cat/genx/keyexchange/f;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;I)V

    .line 17
    .line 18
    .line 19
    new-instance v3, Lt51/j;

    .line 20
    .line 21
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    const-string v2, "getName(...)"

    .line 26
    .line 27
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v9

    .line 31
    const-string v4, "Car2PhonePairing"

    .line 32
    .line 33
    sget-object v5, Lt51/g;->a:Lt51/g;

    .line 34
    .line 35
    const/4 v7, 0x0

    .line 36
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 40
    .line 41
    .line 42
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/VehicleAntenna;->getEncounteredError()Lyy0/i;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance v2, Lx41/g0;

    .line 47
    .line 48
    const/4 v3, 0x0

    .line 49
    invoke-direct {v2, p0, v0, v3}, Lx41/g0;-><init>(Lx41/u0;Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;Lkotlin/coroutines/Continuation;)V

    .line 50
    .line 51
    .line 52
    new-instance v3, Lne0/n;

    .line 53
    .line 54
    const/4 v4, 0x5

    .line 55
    invoke-direct {v3, p1, v2, v4}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 56
    .line 57
    .line 58
    invoke-static {v3, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {v1, v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    :cond_0
    return-void
.end method

.method public final close()V
    .locals 7

    .line 1
    new-instance v3, Lqf0/d;

    .line 2
    .line 3
    const/16 v0, 0x18

    .line 4
    .line 5
    invoke-direct {v3, v0}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "Car2PhonePairing"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 32
    .line 33
    if-eqz v0, :cond_0

    .line 34
    .line 35
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 36
    .line 37
    .line 38
    :cond_0
    const/4 v0, 0x0

    .line 39
    iput-object v0, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 40
    .line 41
    new-instance v1, Lvo0/e;

    .line 42
    .line 43
    const/16 v2, 0x13

    .line 44
    .line 45
    invoke-direct {v1, p0, v0, v2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Lx41/u0;->j:Lpx0/g;

    .line 49
    .line 50
    invoke-static {v0, v1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    iget-object v0, p0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 54
    .line 55
    invoke-interface {v0}, Ltechnology/cariad/cat/genx/VehicleManager;->close()V

    .line 56
    .line 57
    .line 58
    const-string v0, "close"

    .line 59
    .line 60
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final d(Lrx0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p1, Lx41/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lx41/h0;

    .line 7
    .line 8
    iget v1, v0, Lx41/h0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lx41/h0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lx41/h0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lx41/h0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lx41/h0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lx41/h0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    iget-object v2, v0, Lx41/h0;->d:Lss/b;

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    check-cast p1, Llx0/o;

    .line 58
    .line 59
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    new-instance v9, Lx41/y;

    .line 66
    .line 67
    const/4 p1, 0x2

    .line 68
    invoke-direct {v9, p1}, Lx41/y;-><init>(I)V

    .line 69
    .line 70
    .line 71
    new-instance v6, Lt51/j;

    .line 72
    .line 73
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v11

    .line 77
    const-string p1, "getName(...)"

    .line 78
    .line 79
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v12

    .line 83
    const-string v7, "Car2PhonePairing"

    .line 84
    .line 85
    sget-object v8, Lt51/g;->a:Lt51/g;

    .line 86
    .line 87
    const/4 v10, 0x0

    .line 88
    invoke-direct/range {v6 .. v12}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v6}, Lt51/a;->a(Lt51/j;)V

    .line 92
    .line 93
    .line 94
    iget-object v2, p0, Lx41/u0;->k:Lss/b;

    .line 95
    .line 96
    iput-object v5, p0, Lx41/u0;->k:Lss/b;

    .line 97
    .line 98
    iput-object v2, v0, Lx41/h0;->d:Lss/b;

    .line 99
    .line 100
    iput v4, v0, Lx41/h0;->g:I

    .line 101
    .line 102
    iget-object p1, p0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 103
    .line 104
    invoke-interface {p1, v0}, Ltechnology/cariad/cat/genx/VehicleManager;->cancelKeyExchange-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v1, :cond_4

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_4
    :goto_1
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    if-eqz p1, :cond_5

    .line 116
    .line 117
    new-instance v4, Lx41/y;

    .line 118
    .line 119
    const/4 v6, 0x3

    .line 120
    invoke-direct {v4, v6}, Lx41/y;-><init>(I)V

    .line 121
    .line 122
    .line 123
    const-string v6, "Car2PhonePairing"

    .line 124
    .line 125
    invoke-static {p0, v6, p1, v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 126
    .line 127
    .line 128
    :cond_5
    new-instance p1, Lx41/i0;

    .line 129
    .line 130
    const/4 v4, 0x0

    .line 131
    invoke-direct {p1, v2, v5, v4}, Lx41/i0;-><init>(Lss/b;Lkotlin/coroutines/Continuation;I)V

    .line 132
    .line 133
    .line 134
    iput-object v5, v0, Lx41/h0;->d:Lss/b;

    .line 135
    .line 136
    iput v3, v0, Lx41/h0;->g:I

    .line 137
    .line 138
    iget-object v2, p0, Lx41/u0;->i:Lvy0/x;

    .line 139
    .line 140
    invoke-static {v2, p1, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    if-ne p1, v1, :cond_6

    .line 145
    .line 146
    :goto_2
    return-object v1

    .line 147
    :cond_6
    :goto_3
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 148
    .line 149
    iget-object p0, p0, Lx41/u0;->l:Lyy0/c2;

    .line 150
    .line 151
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    invoke-virtual {p0, v5, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    return-object p0
.end method

.method public final f(Landroid/content/Context;Lrx0/c;)Ljava/io/Serializable;
    .locals 18

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
    instance-of v3, v2, Lx41/j0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lx41/j0;

    .line 13
    .line 14
    iget v4, v3, Lx41/j0;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lx41/j0;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lx41/j0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lx41/j0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lx41/j0;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lx41/j0;->g:I

    .line 36
    .line 37
    const/4 v6, 0x4

    .line 38
    const/4 v7, 0x3

    .line 39
    const/4 v8, 0x1

    .line 40
    iget-object v9, v0, Lx41/u0;->n:Lyy0/c2;

    .line 41
    .line 42
    const/4 v10, 0x0

    .line 43
    if-eqz v5, :cond_5

    .line 44
    .line 45
    if-eq v5, v8, :cond_4

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    if-eq v5, v1, :cond_3

    .line 49
    .line 50
    if-eq v5, v7, :cond_2

    .line 51
    .line 52
    if-ne v5, v6, :cond_1

    .line 53
    .line 54
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_4

    .line 58
    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    iget-object v1, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 68
    .line 69
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    iget-object v1, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 74
    .line 75
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    check-cast v2, Lx41/s;

    .line 79
    .line 80
    if-eqz v2, :cond_8

    .line 81
    .line 82
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v9, v10, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    return-object v2

    .line 91
    :cond_4
    iget-object v1, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 92
    .line 93
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    new-instance v14, Lx41/y;

    .line 101
    .line 102
    const/16 v2, 0x8

    .line 103
    .line 104
    invoke-direct {v14, v2}, Lx41/y;-><init>(I)V

    .line 105
    .line 106
    .line 107
    new-instance v11, Lt51/j;

    .line 108
    .line 109
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v16

    .line 113
    const-string v2, "getName(...)"

    .line 114
    .line 115
    invoke-static {v2}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v17

    .line 119
    const-string v12, "Car2PhonePairing"

    .line 120
    .line 121
    sget-object v13, Lt51/g;->a:Lt51/g;

    .line 122
    .line 123
    const/4 v15, 0x0

    .line 124
    invoke-direct/range {v11 .. v17}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-static {v11}, Lt51/a;->a(Lt51/j;)V

    .line 128
    .line 129
    .line 130
    sget-object v2, Lx41/i1;->d:Lx41/i1;

    .line 131
    .line 132
    iput-object v1, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 133
    .line 134
    iput v8, v3, Lx41/j0;->g:I

    .line 135
    .line 136
    invoke-virtual {v0, v1, v2, v3}, Lx41/u0;->g(Landroid/content/Context;Lx41/j1;Lrx0/c;)Ljava/io/Serializable;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    if-ne v2, v4, :cond_6

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_6
    :goto_1
    check-cast v2, Lx41/s;

    .line 144
    .line 145
    if-eqz v2, :cond_7

    .line 146
    .line 147
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 148
    .line 149
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v9, v10, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    return-object v2

    .line 156
    :cond_7
    iget-object v2, v0, Lx41/u0;->e:Lh70/d;

    .line 157
    .line 158
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    :cond_8
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 162
    .line 163
    const/16 v5, 0x1f

    .line 164
    .line 165
    if-lt v2, v5, :cond_c

    .line 166
    .line 167
    sget-object v2, Lx41/i1;->c:Lx41/i1;

    .line 168
    .line 169
    iput-object v1, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 170
    .line 171
    iput v7, v3, Lx41/j0;->g:I

    .line 172
    .line 173
    invoke-virtual {v0, v1, v2, v3}, Lx41/u0;->g(Landroid/content/Context;Lx41/j1;Lrx0/c;)Ljava/io/Serializable;

    .line 174
    .line 175
    .line 176
    move-result-object v2

    .line 177
    if-ne v2, v4, :cond_9

    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_9
    :goto_2
    check-cast v2, Lx41/s;

    .line 181
    .line 182
    if-eqz v2, :cond_a

    .line 183
    .line 184
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 185
    .line 186
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v9, v10, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    return-object v2

    .line 193
    :cond_a
    sget-object v2, Lx41/i1;->b:Lx41/i1;

    .line 194
    .line 195
    iput-object v10, v3, Lx41/j0;->d:Landroid/content/Context;

    .line 196
    .line 197
    iput v6, v3, Lx41/j0;->g:I

    .line 198
    .line 199
    invoke-virtual {v0, v1, v2, v3}, Lx41/u0;->g(Landroid/content/Context;Lx41/j1;Lrx0/c;)Ljava/io/Serializable;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    if-ne v2, v4, :cond_b

    .line 204
    .line 205
    :goto_3
    return-object v4

    .line 206
    :cond_b
    :goto_4
    check-cast v2, Lx41/s;

    .line 207
    .line 208
    if-eqz v2, :cond_c

    .line 209
    .line 210
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 211
    .line 212
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v9, v10, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    return-object v2

    .line 219
    :cond_c
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 220
    .line 221
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v9, v10, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    return-object v10
.end method

.method public final g(Landroid/content/Context;Lx41/j1;Lrx0/c;)Ljava/io/Serializable;
    .locals 21

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
    move-object/from16 v3, p3

    .line 8
    .line 9
    instance-of v4, v3, Lx41/k0;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lx41/k0;

    .line 15
    .line 16
    iget v5, v4, Lx41/k0;->g:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lx41/k0;->g:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lx41/k0;

    .line 29
    .line 30
    invoke-direct {v4, v0, v3}, Lx41/k0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lx41/k0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lx41/k0;->g:I

    .line 38
    .line 39
    iget-object v7, v0, Lx41/u0;->i:Lvy0/x;

    .line 40
    .line 41
    const/4 v8, 0x3

    .line 42
    const/4 v9, 0x2

    .line 43
    const/4 v10, 0x1

    .line 44
    const-string v11, "Car2PhonePairing"

    .line 45
    .line 46
    const-string v12, "getName(...)"

    .line 47
    .line 48
    sget-object v15, Lt51/g;->a:Lt51/g;

    .line 49
    .line 50
    const/4 v13, 0x0

    .line 51
    if-eqz v6, :cond_4

    .line 52
    .line 53
    if-eq v6, v10, :cond_3

    .line 54
    .line 55
    if-eq v6, v9, :cond_2

    .line 56
    .line 57
    if-ne v6, v8, :cond_1

    .line 58
    .line 59
    iget-object v1, v4, Lx41/k0;->d:Lx41/j1;

    .line 60
    .line 61
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move-object v2, v3

    .line 65
    move-object v3, v13

    .line 66
    goto/16 :goto_4

    .line 67
    .line 68
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 71
    .line 72
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0

    .line 76
    :cond_2
    iget-object v1, v4, Lx41/k0;->d:Lx41/j1;

    .line 77
    .line 78
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    move-object v2, v3

    .line 82
    move-object v3, v13

    .line 83
    goto/16 :goto_2

    .line 84
    .line 85
    :cond_3
    iget-object v1, v4, Lx41/k0;->d:Lx41/j1;

    .line 86
    .line 87
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    move-object v2, v3

    .line 91
    move-object v3, v13

    .line 92
    goto :goto_1

    .line 93
    :cond_4
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    const-string v3, "context"

    .line 100
    .line 101
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-interface {v2}, Lx41/j1;->a()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-static {v1, v3}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_5

    .line 113
    .line 114
    move-object v1, v2

    .line 115
    move-object v3, v13

    .line 116
    goto/16 :goto_5

    .line 117
    .line 118
    :cond_5
    new-instance v1, Lx41/x;

    .line 119
    .line 120
    const/4 v3, 0x6

    .line 121
    invoke-direct {v1, v2, v3}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 122
    .line 123
    .line 124
    move-object v3, v13

    .line 125
    new-instance v13, Lt51/j;

    .line 126
    .line 127
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v18

    .line 131
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v19

    .line 135
    const-string v14, "Car2PhonePairing"

    .line 136
    .line 137
    const/16 v17, 0x0

    .line 138
    .line 139
    move-object/from16 v16, v1

    .line 140
    .line 141
    invoke-direct/range {v13 .. v19}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v13}, Lt51/a;->a(Lt51/j;)V

    .line 145
    .line 146
    .line 147
    iput-object v2, v4, Lx41/k0;->d:Lx41/j1;

    .line 148
    .line 149
    iput v10, v4, Lx41/k0;->g:I

    .line 150
    .line 151
    new-instance v1, Lx41/o0;

    .line 152
    .line 153
    const/4 v6, 0x0

    .line 154
    invoke-direct {v1, v0, v2, v3, v6}, Lx41/o0;-><init>(Lx41/u0;Lx41/j1;Lkotlin/coroutines/Continuation;I)V

    .line 155
    .line 156
    .line 157
    invoke-static {v7, v1, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    if-ne v1, v5, :cond_6

    .line 162
    .line 163
    goto/16 :goto_3

    .line 164
    .line 165
    :cond_6
    move-object/from16 v20, v2

    .line 166
    .line 167
    move-object v2, v1

    .line 168
    move-object/from16 v1, v20

    .line 169
    .line 170
    :goto_1
    sget-object v6, Lx41/v;->e:Lx41/v;

    .line 171
    .line 172
    if-ne v2, v6, :cond_c

    .line 173
    .line 174
    iget-object v2, v0, Lx41/u0;->e:Lh70/d;

    .line 175
    .line 176
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    const-string v6, "permission"

    .line 180
    .line 181
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    iget-object v2, v2, Lh70/d;->a:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 185
    .line 186
    if-eqz v2, :cond_b

    .line 187
    .line 188
    invoke-interface {v1}, Lx41/j1;->a()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v6

    .line 192
    invoke-static {v2, v6}, Landroidx/core/app/b;->f(Landroid/app/Activity;Ljava/lang/String;)Z

    .line 193
    .line 194
    .line 195
    move-result v2

    .line 196
    if-eqz v2, :cond_a

    .line 197
    .line 198
    new-instance v2, Lx41/x;

    .line 199
    .line 200
    const/4 v6, 0x0

    .line 201
    invoke-direct {v2, v1, v6}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 202
    .line 203
    .line 204
    new-instance v13, Lt51/j;

    .line 205
    .line 206
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v18

    .line 210
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v19

    .line 214
    const-string v14, "Car2PhonePairing"

    .line 215
    .line 216
    const/16 v17, 0x0

    .line 217
    .line 218
    move-object/from16 v16, v2

    .line 219
    .line 220
    invoke-direct/range {v13 .. v19}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    invoke-static {v13}, Lt51/a;->a(Lt51/j;)V

    .line 224
    .line 225
    .line 226
    iput-object v1, v4, Lx41/k0;->d:Lx41/j1;

    .line 227
    .line 228
    iput v9, v4, Lx41/k0;->g:I

    .line 229
    .line 230
    new-instance v2, Lx41/o0;

    .line 231
    .line 232
    const/4 v6, 0x1

    .line 233
    invoke-direct {v2, v0, v1, v3, v6}, Lx41/o0;-><init>(Lx41/u0;Lx41/j1;Lkotlin/coroutines/Continuation;I)V

    .line 234
    .line 235
    .line 236
    invoke-static {v7, v2, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v2

    .line 240
    if-ne v2, v5, :cond_7

    .line 241
    .line 242
    goto :goto_3

    .line 243
    :cond_7
    :goto_2
    sget-object v6, Lx41/u;->d:Lx41/u;

    .line 244
    .line 245
    if-ne v2, v6, :cond_9

    .line 246
    .line 247
    new-instance v2, Lx41/x;

    .line 248
    .line 249
    const/4 v6, 0x1

    .line 250
    invoke-direct {v2, v1, v6}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 251
    .line 252
    .line 253
    new-instance v13, Lt51/j;

    .line 254
    .line 255
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v18

    .line 259
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v19

    .line 263
    const-string v14, "Car2PhonePairing"

    .line 264
    .line 265
    const/16 v17, 0x0

    .line 266
    .line 267
    move-object/from16 v16, v2

    .line 268
    .line 269
    invoke-direct/range {v13 .. v19}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    invoke-static {v13}, Lt51/a;->a(Lt51/j;)V

    .line 273
    .line 274
    .line 275
    iput-object v1, v4, Lx41/k0;->d:Lx41/j1;

    .line 276
    .line 277
    iput v8, v4, Lx41/k0;->g:I

    .line 278
    .line 279
    new-instance v2, Lx41/o0;

    .line 280
    .line 281
    const/4 v6, 0x0

    .line 282
    invoke-direct {v2, v0, v1, v3, v6}, Lx41/o0;-><init>(Lx41/u0;Lx41/j1;Lkotlin/coroutines/Continuation;I)V

    .line 283
    .line 284
    .line 285
    invoke-static {v7, v2, v4}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v2

    .line 289
    if-ne v2, v5, :cond_8

    .line 290
    .line 291
    :goto_3
    return-object v5

    .line 292
    :cond_8
    :goto_4
    sget-object v4, Lx41/v;->e:Lx41/v;

    .line 293
    .line 294
    if-ne v2, v4, :cond_a

    .line 295
    .line 296
    new-instance v2, Lx41/x;

    .line 297
    .line 298
    const/4 v4, 0x2

    .line 299
    invoke-direct {v2, v1, v4}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 300
    .line 301
    .line 302
    invoke-static {v0, v11, v3, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 303
    .line 304
    .line 305
    new-instance v2, Lwa0/c;

    .line 306
    .line 307
    const/4 v4, 0x7

    .line 308
    invoke-direct {v2, v4, v0, v1, v3}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 309
    .line 310
    .line 311
    invoke-static {v0, v7, v3, v2, v9}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 312
    .line 313
    .line 314
    new-instance v0, Lx41/s;

    .line 315
    .line 316
    invoke-direct {v0, v1}, Lx41/s;-><init>(Lx41/j1;)V

    .line 317
    .line 318
    .line 319
    return-object v0

    .line 320
    :cond_9
    new-instance v2, Lx41/x;

    .line 321
    .line 322
    const/4 v4, 0x3

    .line 323
    invoke-direct {v2, v1, v4}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 324
    .line 325
    .line 326
    invoke-static {v0, v11, v3, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 327
    .line 328
    .line 329
    new-instance v2, Lwa0/c;

    .line 330
    .line 331
    const/4 v4, 0x7

    .line 332
    invoke-direct {v2, v4, v0, v1, v3}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 333
    .line 334
    .line 335
    invoke-static {v0, v7, v3, v2, v9}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 336
    .line 337
    .line 338
    new-instance v0, Lx41/s;

    .line 339
    .line 340
    invoke-direct {v0, v1}, Lx41/s;-><init>(Lx41/j1;)V

    .line 341
    .line 342
    .line 343
    return-object v0

    .line 344
    :cond_a
    new-instance v2, Lx41/x;

    .line 345
    .line 346
    const/4 v4, 0x4

    .line 347
    invoke-direct {v2, v1, v4}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 348
    .line 349
    .line 350
    invoke-static {v0, v11, v3, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 351
    .line 352
    .line 353
    new-instance v2, Lwa0/c;

    .line 354
    .line 355
    const/4 v4, 0x7

    .line 356
    invoke-direct {v2, v4, v0, v1, v3}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 357
    .line 358
    .line 359
    invoke-static {v0, v7, v3, v2, v9}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 360
    .line 361
    .line 362
    new-instance v0, Lx41/s;

    .line 363
    .line 364
    invoke-direct {v0, v1}, Lx41/s;-><init>(Lx41/j1;)V

    .line 365
    .line 366
    .line 367
    return-object v0

    .line 368
    :cond_b
    const-string v0, "activity"

    .line 369
    .line 370
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    throw v3

    .line 374
    :cond_c
    :goto_5
    new-instance v2, Lx41/x;

    .line 375
    .line 376
    const/4 v4, 0x5

    .line 377
    invoke-direct {v2, v1, v4}, Lx41/x;-><init>(Lx41/j1;I)V

    .line 378
    .line 379
    .line 380
    new-instance v13, Lt51/j;

    .line 381
    .line 382
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v18

    .line 386
    invoke-static {v12}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object v19

    .line 390
    const-string v14, "Car2PhonePairing"

    .line 391
    .line 392
    const/16 v17, 0x0

    .line 393
    .line 394
    move-object/from16 v16, v2

    .line 395
    .line 396
    invoke-direct/range {v13 .. v19}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 397
    .line 398
    .line 399
    invoke-static {v13}, Lt51/a;->a(Lt51/j;)V

    .line 400
    .line 401
    .line 402
    return-object v3
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lx41/u0;->j:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Lx41/n;Lx41/n;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lx41/u0;->w:Lez0/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lez0/c;->b()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_4

    .line 8
    .line 9
    const-string v0, "<this>"

    .line 10
    .line 11
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 15
    .line 16
    invoke-static {p2, v0}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 23
    .line 24
    invoke-static {p2, v0}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-eqz v0, :cond_0

    .line 29
    .line 30
    const/4 v0, 0x1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 v0, 0x0

    .line 33
    :goto_0
    if-eqz v0, :cond_1

    .line 34
    .line 35
    invoke-interface {p2}, Lx41/n;->a()Lx41/f;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-interface {p2}, Lx41/n;->b()Lx41/f;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    const/4 v1, 0x1

    .line 44
    invoke-static {p1, v0, p2, v1}, Lx41/p;->b(Lx41/n;Lx41/f;Lx41/f;I)Lx41/n;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    goto :goto_1

    .line 49
    :cond_1
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 50
    .line 51
    invoke-static {p2, v0}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    const/4 v1, 0x0

    .line 56
    if-eqz v0, :cond_2

    .line 57
    .line 58
    invoke-interface {p2}, Lx41/n;->a()Lx41/f;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    const/4 v0, 0x5

    .line 63
    invoke-static {p1, p2, v1, v0}, Lx41/p;->b(Lx41/n;Lx41/f;Lx41/f;I)Lx41/n;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    goto :goto_1

    .line 68
    :cond_2
    sget-object v0, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 69
    .line 70
    invoke-static {p2, v0}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_3

    .line 75
    .line 76
    invoke-interface {p2}, Lx41/n;->b()Lx41/f;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    const/4 v0, 0x3

    .line 81
    invoke-static {p1, v1, p2, v0}, Lx41/p;->b(Lx41/n;Lx41/f;Lx41/f;I)Lx41/n;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    :cond_3
    :goto_1
    new-instance v3, Lx41/a;

    .line 86
    .line 87
    const/4 v0, 0x2

    .line 88
    invoke-direct {v3, p1, p2, v0}, Lx41/a;-><init>(Lx41/n;Lx41/n;I)V

    .line 89
    .line 90
    .line 91
    new-instance v0, Lt51/j;

    .line 92
    .line 93
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    const-string v1, "getName(...)"

    .line 98
    .line 99
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    const-string v1, "Car2PhonePairing"

    .line 104
    .line 105
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 106
    .line 107
    const/4 v4, 0x0

    .line 108
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 112
    .line 113
    .line 114
    iget-object v0, p0, Lx41/u0;->x:Ljava/util/Set;

    .line 115
    .line 116
    invoke-static {v0, p1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-static {p1, p2}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-static {p1}, Lx41/c;->a(Ljava/util/LinkedHashSet;)Ljava/util/ArrayList;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    invoke-virtual {p0, p1}, Lx41/u0;->l(Ljava/util/Set;)V

    .line 133
    .line 134
    .line 135
    return-void

    .line 136
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 137
    .line 138
    const-string p1, "Failed requirement."

    .line 139
    .line 140
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw p0
.end method

.method public final j(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;)Z
    .locals 4

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "antenna"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lx41/u0;->q:Lyy0/l1;

    .line 12
    .line 13
    iget-object v0, p0, Lyy0/l1;->d:Lyy0/a2;

    .line 14
    .line 15
    invoke-interface {v0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Ljava/lang/Iterable;

    .line 20
    .line 21
    new-instance v1, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    instance-of v3, v2, Lx41/m;

    .line 41
    .line 42
    if-eqz v3, :cond_0

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    if-eqz v0, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    :cond_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_4

    .line 64
    .line 65
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    check-cast v1, Lx41/m;

    .line 70
    .line 71
    iget-object v2, v1, Lx41/m;->a:Ljava/lang/String;

    .line 72
    .line 73
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-eqz v2, :cond_3

    .line 78
    .line 79
    invoke-static {v1, p2}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-eqz v1, :cond_3

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_4
    :goto_1
    iget-object p0, p0, Lyy0/l1;->d:Lyy0/a2;

    .line 87
    .line 88
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ljava/lang/Iterable;

    .line 93
    .line 94
    new-instance v0, Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 97
    .line 98
    .line 99
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    :cond_5
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    if-eqz v1, :cond_6

    .line 108
    .line 109
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    instance-of v2, v1, Lx41/j;

    .line 114
    .line 115
    if-eqz v2, :cond_5

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_6
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    if-eqz p0, :cond_7

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_7
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    :cond_8
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-eqz v0, :cond_9

    .line 137
    .line 138
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    check-cast v0, Lx41/j;

    .line 143
    .line 144
    iget-object v1, v0, Lx41/j;->a:Ljava/lang/String;

    .line 145
    .line 146
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    if-eqz v1, :cond_8

    .line 151
    .line 152
    invoke-static {v0, p2}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 153
    .line 154
    .line 155
    move-result v0

    .line 156
    if-eqz v0, :cond_8

    .line 157
    .line 158
    :goto_3
    const/4 p0, 0x1

    .line 159
    return p0

    .line 160
    :cond_9
    :goto_4
    const/4 p0, 0x0

    .line 161
    return p0
.end method

.method public final k(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Lrx0/c;)Ljava/lang/Object;
    .locals 17

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
    move-object/from16 v3, p3

    .line 8
    .line 9
    instance-of v4, v3, Lx41/n0;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lx41/n0;

    .line 15
    .line 16
    iget v5, v4, Lx41/n0;->i:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lx41/n0;->i:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lx41/n0;

    .line 29
    .line 30
    invoke-direct {v4, v0, v3}, Lx41/n0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lx41/n0;->g:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lx41/n0;->i:I

    .line 38
    .line 39
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    if-eqz v6, :cond_3

    .line 44
    .line 45
    if-eq v6, v9, :cond_2

    .line 46
    .line 47
    if-ne v6, v8, :cond_1

    .line 48
    .line 49
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-object v7

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    iget-object v1, v4, Lx41/n0;->f:Lez0/c;

    .line 62
    .line 63
    iget-object v2, v4, Lx41/n0;->e:Ltechnology/cariad/cat/genx/Antenna;

    .line 64
    .line 65
    iget-object v6, v4, Lx41/n0;->d:Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    move-object v3, v1

    .line 71
    move-object v1, v6

    .line 72
    goto :goto_1

    .line 73
    :cond_3
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    new-instance v13, Lvu/d;

    .line 77
    .line 78
    const/16 v3, 0x9

    .line 79
    .line 80
    invoke-direct {v13, v3, v1, v2}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    new-instance v10, Lt51/j;

    .line 84
    .line 85
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v15

    .line 89
    const-string v3, "getName(...)"

    .line 90
    .line 91
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v16

    .line 95
    const-string v11, "Car2PhonePairing"

    .line 96
    .line 97
    sget-object v12, Lt51/g;->a:Lt51/g;

    .line 98
    .line 99
    const/4 v14, 0x0

    .line 100
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 104
    .line 105
    .line 106
    iput-object v1, v4, Lx41/n0;->d:Ljava/lang/String;

    .line 107
    .line 108
    iput-object v2, v4, Lx41/n0;->e:Ltechnology/cariad/cat/genx/Antenna;

    .line 109
    .line 110
    iget-object v3, v0, Lx41/u0;->w:Lez0/c;

    .line 111
    .line 112
    iput-object v3, v4, Lx41/n0;->f:Lez0/c;

    .line 113
    .line 114
    iput v9, v4, Lx41/n0;->i:I

    .line 115
    .line 116
    invoke-virtual {v3, v4}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    if-ne v6, v5, :cond_4

    .line 121
    .line 122
    goto/16 :goto_4

    .line 123
    .line 124
    :cond_4
    :goto_1
    const/4 v6, 0x0

    .line 125
    :try_start_0
    iget-object v10, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 126
    .line 127
    check-cast v10, Ljava/lang/Iterable;

    .line 128
    .line 129
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v10

    .line 133
    :cond_5
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v11

    .line 137
    if-eqz v11, :cond_6

    .line 138
    .line 139
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v11

    .line 143
    move-object v12, v11

    .line 144
    check-cast v12, Lx41/n;

    .line 145
    .line 146
    invoke-interface {v12}, Lx41/n;->getVin()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v12

    .line 150
    invoke-static {v12, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v12

    .line 154
    if-eqz v12, :cond_5

    .line 155
    .line 156
    invoke-virtual {v0, v1, v2}, Lx41/u0;->j(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 157
    .line 158
    .line 159
    move-result v12

    .line 160
    if-eqz v12, :cond_5

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :catchall_0
    move-exception v0

    .line 164
    goto/16 :goto_5

    .line 165
    .line 166
    :cond_6
    move-object v11, v6

    .line 167
    :goto_2
    check-cast v11, Lx41/n;

    .line 168
    .line 169
    if-nez v11, :cond_7

    .line 170
    .line 171
    new-instance v2, Lq61/c;

    .line 172
    .line 173
    const/16 v4, 0xb

    .line 174
    .line 175
    invoke-direct {v2, v1, v4}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 176
    .line 177
    .line 178
    const-string v1, "Car2PhonePairing"

    .line 179
    .line 180
    invoke-static {v0, v1, v6, v2}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 181
    .line 182
    .line 183
    invoke-interface {v3, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    return-object v7

    .line 187
    :cond_7
    :try_start_1
    sget-object v1, Lx41/e0;->a:[I

    .line 188
    .line 189
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    aget v1, v1, v2

    .line 194
    .line 195
    if-eq v1, v9, :cond_a

    .line 196
    .line 197
    if-ne v1, v8, :cond_9

    .line 198
    .line 199
    sget-object v1, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 200
    .line 201
    invoke-static {v11, v1}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    if-eqz v1, :cond_8

    .line 206
    .line 207
    iget-object v1, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 208
    .line 209
    invoke-static {v1, v11}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    const/4 v2, 0x3

    .line 214
    invoke-static {v11, v6, v6, v2}, Lx41/p;->b(Lx41/n;Lx41/f;Lx41/f;I)Lx41/n;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    invoke-static {v1, v2}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 219
    .line 220
    .line 221
    move-result-object v1

    .line 222
    goto :goto_3

    .line 223
    :cond_8
    iget-object v1, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 224
    .line 225
    invoke-static {v1, v11}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 226
    .line 227
    .line 228
    move-result-object v1

    .line 229
    goto :goto_3

    .line 230
    :cond_9
    new-instance v0, La8/r0;

    .line 231
    .line 232
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 233
    .line 234
    .line 235
    throw v0

    .line 236
    :cond_a
    sget-object v1, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 237
    .line 238
    invoke-static {v11, v1}, Lx41/p;->c(Lx41/n;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 239
    .line 240
    .line 241
    move-result v1

    .line 242
    if-eqz v1, :cond_b

    .line 243
    .line 244
    iget-object v1, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 245
    .line 246
    invoke-static {v1, v11}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    const/4 v2, 0x5

    .line 251
    invoke-static {v11, v6, v6, v2}, Lx41/p;->b(Lx41/n;Lx41/f;Lx41/f;I)Lx41/n;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    invoke-static {v1, v2}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    goto :goto_3

    .line 260
    :cond_b
    iget-object v1, v0, Lx41/u0;->x:Ljava/util/Set;

    .line 261
    .line 262
    invoke-static {v1, v11}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    :goto_3
    invoke-virtual {v0, v1}, Lx41/u0;->l(Ljava/util/Set;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 267
    .line 268
    .line 269
    invoke-interface {v3, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    iput-object v6, v4, Lx41/n0;->d:Ljava/lang/String;

    .line 273
    .line 274
    iput-object v6, v4, Lx41/n0;->e:Ltechnology/cariad/cat/genx/Antenna;

    .line 275
    .line 276
    iput-object v6, v4, Lx41/n0;->f:Lez0/c;

    .line 277
    .line 278
    iput v8, v4, Lx41/n0;->i:I

    .line 279
    .line 280
    invoke-virtual {v0, v4}, Lx41/u0;->q(Lrx0/c;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    if-ne v0, v5, :cond_c

    .line 285
    .line 286
    :goto_4
    return-object v5

    .line 287
    :cond_c
    return-object v7

    .line 288
    :goto_5
    invoke-interface {v3, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    throw v0
.end method

.method public final l(Ljava/util/Set;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lx41/u0;->x:Ljava/util/Set;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lx41/u0;->f:Lx41/z0;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Lx41/z0;->b(Ljava/util/Set;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iput-object p1, p0, Lx41/u0;->x:Ljava/util/Set;

    .line 15
    .line 16
    return-void
.end method

.method public final q(Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lx41/r0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lx41/r0;

    .line 11
    .line 12
    iget v3, v2, Lx41/r0;->i:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lx41/r0;->i:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lx41/r0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lx41/r0;-><init>(Lx41/u0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lx41/r0;->g:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lx41/r0;->i:I

    .line 34
    .line 35
    iget-object v5, v0, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x1

    .line 39
    const/4 v8, 0x2

    .line 40
    const-string v9, "getName(...)"

    .line 41
    .line 42
    sget-object v12, Lt51/g;->a:Lt51/g;

    .line 43
    .line 44
    const/4 v10, 0x0

    .line 45
    if-eqz v4, :cond_4

    .line 46
    .line 47
    if-eq v4, v7, :cond_3

    .line 48
    .line 49
    if-eq v4, v8, :cond_2

    .line 50
    .line 51
    if-ne v4, v6, :cond_1

    .line 52
    .line 53
    iget-object v3, v2, Lx41/r0;->f:Ljava/util/ArrayList;

    .line 54
    .line 55
    iget-object v4, v2, Lx41/r0;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v4, Ljava/util/Set;

    .line 58
    .line 59
    iget-object v2, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Ljava/util/Set;

    .line 62
    .line 63
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    check-cast v1, Llx0/o;

    .line 67
    .line 68
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v7, v4

    .line 71
    goto/16 :goto_7

    .line 72
    .line 73
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_2
    iget-object v4, v2, Lx41/r0;->e:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v4, Lez0/a;

    .line 84
    .line 85
    iget-object v7, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v7, Ljava/util/Set;

    .line 88
    .line 89
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    move-object v1, v7

    .line 93
    goto :goto_2

    .line 94
    :cond_3
    iget-object v4, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v4, Lez0/a;

    .line 97
    .line 98
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object v4, v0, Lx41/u0;->w:Lez0/c;

    .line 106
    .line 107
    iput-object v4, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 108
    .line 109
    iput v7, v2, Lx41/r0;->i:I

    .line 110
    .line 111
    invoke-virtual {v4, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    if-ne v1, v3, :cond_5

    .line 116
    .line 117
    goto/16 :goto_6

    .line 118
    .line 119
    :cond_5
    :goto_1
    :try_start_0
    iget-object v1, v0, Lx41/u0;->x:Ljava/util/Set;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 120
    .line 121
    invoke-interface {v4, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    iput-object v1, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 125
    .line 126
    iget-object v4, v0, Lx41/u0;->y:Lez0/c;

    .line 127
    .line 128
    iput-object v4, v2, Lx41/r0;->e:Ljava/lang/Object;

    .line 129
    .line 130
    iput v8, v2, Lx41/r0;->i:I

    .line 131
    .line 132
    invoke-virtual {v4, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v7

    .line 136
    if-ne v7, v3, :cond_6

    .line 137
    .line 138
    goto/16 :goto_6

    .line 139
    .line 140
    :cond_6
    :goto_2
    :try_start_1
    iget-object v7, v0, Lx41/u0;->z:Ljava/util/Set;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 141
    .line 142
    invoke-interface {v4, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    new-instance v13, Lvu/d;

    .line 146
    .line 147
    const/16 v4, 0x8

    .line 148
    .line 149
    invoke-direct {v13, v4, v1, v7}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    move-object v4, v10

    .line 153
    new-instance v10, Lt51/j;

    .line 154
    .line 155
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v15

    .line 159
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v16

    .line 163
    const-string v11, "Car2PhonePairing"

    .line 164
    .line 165
    const/4 v14, 0x0

    .line 166
    move-object v8, v4

    .line 167
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 171
    .line 172
    .line 173
    move-object v4, v7

    .line 174
    check-cast v4, Ljava/lang/Iterable;

    .line 175
    .line 176
    invoke-static {v1, v4}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    invoke-static {v4}, Lx41/c;->a(Ljava/util/LinkedHashSet;)Ljava/util/ArrayList;

    .line 181
    .line 182
    .line 183
    move-result-object v4

    .line 184
    new-instance v10, Ljava/util/ArrayList;

    .line 185
    .line 186
    const/16 v11, 0xa

    .line 187
    .line 188
    invoke-static {v4, v11}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 189
    .line 190
    .line 191
    move-result v11

    .line 192
    invoke-direct {v10, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 193
    .line 194
    .line 195
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 200
    .line 201
    .line 202
    move-result v11

    .line 203
    if-eqz v11, :cond_9

    .line 204
    .line 205
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v11

    .line 209
    check-cast v11, Lx41/n;

    .line 210
    .line 211
    const-string v13, "<this>"

    .line 212
    .line 213
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    const-string v13, "pairingKeyPair"

    .line 217
    .line 218
    iget-object v14, v0, Lx41/u0;->h:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 219
    .line 220
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    new-instance v13, Ltechnology/cariad/cat/genx/Vehicle$Information;

    .line 224
    .line 225
    invoke-interface {v11}, Lx41/n;->getVin()Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v15

    .line 229
    invoke-interface {v11}, Lx41/n;->a()Lx41/f;

    .line 230
    .line 231
    .line 232
    move-result-object v8

    .line 233
    if-eqz v8, :cond_7

    .line 234
    .line 235
    invoke-interface {v11}, Lx41/n;->getVin()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v6

    .line 239
    move-object/from16 v16, v4

    .line 240
    .line 241
    sget-object v4, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 242
    .line 243
    invoke-static {v8, v6, v4, v14}, Lx41/c;->b(Lx41/f;Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    goto :goto_4

    .line 248
    :cond_7
    move-object/from16 v16, v4

    .line 249
    .line 250
    const/4 v4, 0x0

    .line 251
    :goto_4
    invoke-interface {v11}, Lx41/n;->b()Lx41/f;

    .line 252
    .line 253
    .line 254
    move-result-object v6

    .line 255
    if-eqz v6, :cond_8

    .line 256
    .line 257
    invoke-interface {v11}, Lx41/n;->getVin()Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object v8

    .line 261
    sget-object v11, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 262
    .line 263
    invoke-static {v6, v8, v11, v14}, Lx41/c;->b(Lx41/f;Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/VehicleAntenna$Information;

    .line 264
    .line 265
    .line 266
    move-result-object v6

    .line 267
    goto :goto_5

    .line 268
    :cond_8
    const/4 v6, 0x0

    .line 269
    :goto_5
    invoke-direct {v13, v15, v4, v6}, Ltechnology/cariad/cat/genx/Vehicle$Information;-><init>(Ljava/lang/String;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;Ltechnology/cariad/cat/genx/VehicleAntenna$Information;)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-object/from16 v4, v16

    .line 276
    .line 277
    const/4 v6, 0x3

    .line 278
    const/4 v8, 0x0

    .line 279
    goto :goto_3

    .line 280
    :cond_9
    new-instance v13, Low0/c0;

    .line 281
    .line 282
    const/4 v4, 0x2

    .line 283
    invoke-direct {v13, v10, v4}, Low0/c0;-><init>(Ljava/util/ArrayList;I)V

    .line 284
    .line 285
    .line 286
    move-object v4, v10

    .line 287
    new-instance v10, Lt51/j;

    .line 288
    .line 289
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v15

    .line 293
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v16

    .line 297
    const-string v11, "Car2PhonePairing"

    .line 298
    .line 299
    const/4 v14, 0x0

    .line 300
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 304
    .line 305
    .line 306
    invoke-static {v4}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 307
    .line 308
    .line 309
    move-result-object v6

    .line 310
    iput-object v1, v2, Lx41/r0;->d:Ljava/lang/Object;

    .line 311
    .line 312
    iput-object v7, v2, Lx41/r0;->e:Ljava/lang/Object;

    .line 313
    .line 314
    iput-object v4, v2, Lx41/r0;->f:Ljava/util/ArrayList;

    .line 315
    .line 316
    const/4 v8, 0x3

    .line 317
    iput v8, v2, Lx41/r0;->i:I

    .line 318
    .line 319
    invoke-interface {v5, v6, v2}, Ltechnology/cariad/cat/genx/VehicleManager;->registerVehicles-gIAlu-s(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    if-ne v2, v3, :cond_a

    .line 324
    .line 325
    :goto_6
    return-object v3

    .line 326
    :cond_a
    move-object v3, v2

    .line 327
    move-object v2, v1

    .line 328
    move-object v1, v3

    .line 329
    move-object v3, v4

    .line 330
    :goto_7
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    const-string v6, "Car2PhonePairing"

    .line 335
    .line 336
    if-eqz v1, :cond_b

    .line 337
    .line 338
    new-instance v4, Lx41/y;

    .line 339
    .line 340
    const/4 v8, 0x4

    .line 341
    invoke-direct {v4, v8}, Lx41/y;-><init>(I)V

    .line 342
    .line 343
    .line 344
    invoke-static {v0, v6, v1, v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 345
    .line 346
    .line 347
    :cond_b
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 348
    .line 349
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 350
    .line 351
    .line 352
    iget-object v4, v0, Lx41/u0;->s:Ljava/util/concurrent/ConcurrentHashMap;

    .line 353
    .line 354
    invoke-virtual {v4}, Ljava/util/concurrent/ConcurrentHashMap;->entrySet()Ljava/util/Set;

    .line 355
    .line 356
    .line 357
    move-result-object v8

    .line 358
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 359
    .line 360
    .line 361
    move-result-object v8

    .line 362
    :cond_c
    :goto_8
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 363
    .line 364
    .line 365
    move-result v10

    .line 366
    if-eqz v10, :cond_d

    .line 367
    .line 368
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v10

    .line 372
    check-cast v10, Ljava/util/Map$Entry;

    .line 373
    .line 374
    invoke-interface {v10}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v11

    .line 378
    check-cast v11, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 379
    .line 380
    invoke-virtual {v11}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getVin()Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v11

    .line 384
    invoke-interface {v10}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v13

    .line 388
    check-cast v13, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 389
    .line 390
    invoke-virtual {v13}, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;->getAntenna()Ltechnology/cariad/cat/genx/Antenna;

    .line 391
    .line 392
    .line 393
    move-result-object v13

    .line 394
    invoke-virtual {v0, v11, v13}, Lx41/u0;->j(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;)Z

    .line 395
    .line 396
    .line 397
    move-result v11

    .line 398
    if-nez v11, :cond_c

    .line 399
    .line 400
    invoke-interface {v10}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v11

    .line 404
    invoke-interface {v10}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v10

    .line 408
    invoke-interface {v1, v11, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    goto :goto_8

    .line 412
    :cond_d
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    :cond_e
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 421
    .line 422
    .line 423
    move-result v8

    .line 424
    if-eqz v8, :cond_f

    .line 425
    .line 426
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v8

    .line 430
    check-cast v8, Ljava/util/Map$Entry;

    .line 431
    .line 432
    invoke-interface {v8}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v8

    .line 436
    check-cast v8, Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;

    .line 437
    .line 438
    new-instance v13, Ltechnology/cariad/cat/genx/keyexchange/f;

    .line 439
    .line 440
    const/4 v10, 0x1

    .line 441
    invoke-direct {v13, v8, v10}, Ltechnology/cariad/cat/genx/keyexchange/f;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;I)V

    .line 442
    .line 443
    .line 444
    new-instance v10, Lt51/j;

    .line 445
    .line 446
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 447
    .line 448
    .line 449
    move-result-object v15

    .line 450
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v16

    .line 454
    const-string v11, "Car2PhonePairing"

    .line 455
    .line 456
    const/4 v14, 0x0

    .line 457
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 458
    .line 459
    .line 460
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 461
    .line 462
    .line 463
    invoke-virtual {v4, v8}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v8

    .line 467
    check-cast v8, Lvy0/i1;

    .line 468
    .line 469
    if-eqz v8, :cond_e

    .line 470
    .line 471
    const-string v10, "Pairing removed"

    .line 472
    .line 473
    invoke-static {v10, v8}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 474
    .line 475
    .line 476
    goto :goto_9

    .line 477
    :cond_f
    iget-object v1, v0, Lx41/u0;->p:Lyy0/c2;

    .line 478
    .line 479
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v4

    .line 483
    move-object v8, v4

    .line 484
    check-cast v8, Ljava/util/Set;

    .line 485
    .line 486
    move-object v8, v7

    .line 487
    check-cast v8, Ljava/lang/Iterable;

    .line 488
    .line 489
    invoke-static {v2, v8}, Ljp/m1;->h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;

    .line 490
    .line 491
    .line 492
    move-result-object v8

    .line 493
    invoke-virtual {v1, v4, v8}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 494
    .line 495
    .line 496
    move-result v1

    .line 497
    if-eqz v1, :cond_f

    .line 498
    .line 499
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 500
    .line 501
    .line 502
    move-result-object v1

    .line 503
    :goto_a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 504
    .line 505
    .line 506
    move-result v3

    .line 507
    if-eqz v3, :cond_12

    .line 508
    .line 509
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v3

    .line 513
    check-cast v3, Ltechnology/cariad/cat/genx/Vehicle$Information;

    .line 514
    .line 515
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v4

    .line 519
    iget-object v7, v0, Lx41/u0;->t:Ljava/util/concurrent/ConcurrentHashMap;

    .line 520
    .line 521
    invoke-virtual {v7, v4}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 522
    .line 523
    .line 524
    move-result v4

    .line 525
    if-nez v4, :cond_11

    .line 526
    .line 527
    new-instance v13, Lx41/y;

    .line 528
    .line 529
    const/4 v4, 0x5

    .line 530
    invoke-direct {v13, v4}, Lx41/y;-><init>(I)V

    .line 531
    .line 532
    .line 533
    new-instance v10, Lt51/j;

    .line 534
    .line 535
    invoke-static {v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 536
    .line 537
    .line 538
    move-result-object v15

    .line 539
    invoke-static {v9}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 540
    .line 541
    .line 542
    move-result-object v16

    .line 543
    const-string v11, "Car2PhonePairing"

    .line 544
    .line 545
    const/4 v14, 0x0

    .line 546
    invoke-direct/range {v10 .. v16}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    invoke-static {v10}, Lt51/a;->a(Lt51/j;)V

    .line 550
    .line 551
    .line 552
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    .line 553
    .line 554
    .line 555
    move-result-object v4

    .line 556
    invoke-interface {v5, v4}, Ltechnology/cariad/cat/genx/VehicleManager;->vehicle(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;

    .line 557
    .line 558
    .line 559
    move-result-object v4

    .line 560
    if-eqz v4, :cond_10

    .line 561
    .line 562
    invoke-interface {v4}, Ltechnology/cariad/cat/genx/Vehicle;->getVin()Ljava/lang/String;

    .line 563
    .line 564
    .line 565
    move-result-object v3

    .line 566
    invoke-interface {v4}, Ltechnology/cariad/cat/genx/Vehicle;->getAntennasChanged()Lyy0/i;

    .line 567
    .line 568
    .line 569
    move-result-object v8

    .line 570
    new-instance v10, Lx41/t0;

    .line 571
    .line 572
    const/4 v11, 0x0

    .line 573
    invoke-direct {v10, v2, v0, v4, v11}, Lx41/t0;-><init>(Ljava/util/Set;Lx41/u0;Ltechnology/cariad/cat/genx/Vehicle;Lkotlin/coroutines/Continuation;)V

    .line 574
    .line 575
    .line 576
    new-instance v4, Lne0/n;

    .line 577
    .line 578
    const/4 v13, 0x5

    .line 579
    invoke-direct {v4, v8, v10, v13}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 580
    .line 581
    .line 582
    invoke-static {v4, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 583
    .line 584
    .line 585
    move-result-object v4

    .line 586
    invoke-virtual {v7, v3, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 587
    .line 588
    .line 589
    goto :goto_a

    .line 590
    :cond_10
    const/4 v11, 0x0

    .line 591
    new-instance v4, Lu2/a;

    .line 592
    .line 593
    const/16 v7, 0x17

    .line 594
    .line 595
    invoke-direct {v4, v3, v7}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 596
    .line 597
    .line 598
    invoke-static {v0, v6, v11, v4}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 599
    .line 600
    .line 601
    goto :goto_a

    .line 602
    :cond_11
    const/4 v11, 0x0

    .line 603
    goto :goto_a

    .line 604
    :cond_12
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 605
    .line 606
    return-object v0

    .line 607
    :catchall_0
    move-exception v0

    .line 608
    move-object v11, v10

    .line 609
    invoke-interface {v4, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 610
    .line 611
    .line 612
    throw v0

    .line 613
    :catchall_1
    move-exception v0

    .line 614
    move-object v11, v10

    .line 615
    invoke-interface {v4, v11}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 616
    .line 617
    .line 618
    throw v0
.end method
