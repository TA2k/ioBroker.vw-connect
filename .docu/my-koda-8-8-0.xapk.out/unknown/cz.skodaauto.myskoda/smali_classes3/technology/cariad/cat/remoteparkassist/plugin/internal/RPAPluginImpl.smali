.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg61/e;
.implements Lvy0/b0;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002\u00a8\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;",
        "Lg61/e;",
        "Lvy0/b0;",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final d:Lg61/d;

.field public final e:Lx41/u0;

.field public final f:Lvy0/x;

.field public final g:Lk61/b;

.field public final h:Lpx0/g;

.field public final i:Z

.field public final j:Ljava/util/concurrent/ConcurrentHashMap;

.field public final k:Lyy0/c2;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lg61/d;Lv51/f;Lh70/d;Lvy0/x;Lk61/b;)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v15, p2

    .line 6
    .line 7
    move-object/from16 v1, p5

    .line 8
    .line 9
    const-string v3, "ioDispatcher"

    .line 10
    .line 11
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sget v4, Lx41/w;->n1:I

    .line 15
    .line 16
    iget-object v7, v15, Lg61/d;->a:Ljava/lang/String;

    .line 17
    .line 18
    sget-object v9, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 19
    .line 20
    const-string v4, "MODEL"

    .line 21
    .line 22
    invoke-static {v9, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    sget-object v8, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 26
    .line 27
    const-string v4, "MANUFACTURER"

    .line 28
    .line 29
    invoke-static {v8, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    const-string v4, "android.permission.BLUETOOTH_CONNECT"

    .line 33
    .line 34
    invoke-static {v2, v4}, Ln5/a;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    const/4 v12, 0x0

    .line 39
    if-eqz v4, :cond_0

    .line 40
    .line 41
    move-object v6, v9

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    const-string v4, "bluetooth"

    .line 44
    .line 45
    invoke-virtual {v2, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    instance-of v5, v4, Landroid/bluetooth/BluetoothManager;

    .line 50
    .line 51
    if-eqz v5, :cond_1

    .line 52
    .line 53
    check-cast v4, Landroid/bluetooth/BluetoothManager;

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_1
    move-object v4, v12

    .line 57
    :goto_0
    if-eqz v4, :cond_2

    .line 58
    .line 59
    invoke-virtual {v4}, Landroid/bluetooth/BluetoothManager;->getAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    if-eqz v4, :cond_2

    .line 64
    .line 65
    invoke-virtual {v4}, Landroid/bluetooth/BluetoothAdapter;->getName()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    if-nez v4, :cond_3

    .line 70
    .line 71
    :cond_2
    move-object v4, v9

    .line 72
    :cond_3
    move-object v6, v4

    .line 73
    :goto_1
    sget-object v4, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 74
    .line 75
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 76
    .line 77
    sget-object v10, Landroid/os/Build$VERSION;->INCREMENTAL:Ljava/lang/String;

    .line 78
    .line 79
    sget-object v11, Landroid/os/Build$VERSION;->CODENAME:Ljava/lang/String;

    .line 80
    .line 81
    new-instance v13, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {v13}, Ljava/lang/StringBuilder;-><init>()V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v13, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    const-string v4, " / "

    .line 90
    .line 91
    invoke-virtual {v13, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v13, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    const-string v4, " ("

    .line 98
    .line 99
    invoke-virtual {v13, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v4, ", "

    .line 106
    .line 107
    const-string v5, ")"

    .line 108
    .line 109
    invoke-static {v13, v4, v11, v5}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v10

    .line 113
    new-instance v4, Ltechnology/cariad/cat/genx/DeviceInformation;

    .line 114
    .line 115
    const-string v11, "8.8.0"

    .line 116
    .line 117
    move-object v5, v4

    .line 118
    invoke-direct/range {v5 .. v11}, Ltechnology/cariad/cat/genx/DeviceInformation;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    sget-object v5, Ltechnology/cariad/cat/genx/TransportType;->BLE:Ltechnology/cariad/cat/genx/TransportType;

    .line 122
    .line 123
    invoke-static {v5}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 124
    .line 125
    .line 126
    move-result-object v5

    .line 127
    new-instance v9, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 128
    .line 129
    const/16 v21, 0xf

    .line 130
    .line 131
    const/16 v22, 0x0

    .line 132
    .line 133
    const/16 v17, 0x0

    .line 134
    .line 135
    const/16 v18, 0x0

    .line 136
    .line 137
    const/16 v19, 0x0

    .line 138
    .line 139
    const/16 v20, 0x0

    .line 140
    .line 141
    move-object/from16 v16, v9

    .line 142
    .line 143
    invoke-direct/range {v16 .. v22}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIIIILkotlin/jvm/internal/g;)V

    .line 144
    .line 145
    .line 146
    sget-object v6, Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;->BALANCED:Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;

    .line 147
    .line 148
    const-string v7, "bluetoothScanMode"

    .line 149
    .line 150
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    sget-object v7, Lvy0/p0;->a:Lcz0/e;

    .line 154
    .line 155
    sget-object v11, Lcz0/d;->e:Lcz0/d;

    .line 156
    .line 157
    invoke-static {v11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    new-instance v3, Lx41/z0;

    .line 161
    .line 162
    const-string v7, "cz.skodaauto.myskoda.feature.remoteparking"

    .line 163
    .line 164
    move-object/from16 v8, p3

    .line 165
    .line 166
    invoke-direct {v3, v8, v7, v11}, Lx41/z0;-><init>(Lv51/f;Ljava/lang/String;Lvy0/x;)V

    .line 167
    .line 168
    .line 169
    new-instance v7, Lx41/w0;

    .line 170
    .line 171
    invoke-direct {v7, v3, v12}, Lx41/w0;-><init>(Lx41/z0;Lkotlin/coroutines/Continuation;)V

    .line 172
    .line 173
    .line 174
    invoke-static {v11, v7}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v7

    .line 178
    check-cast v7, Llx0/o;

    .line 179
    .line 180
    iget-object v7, v7, Llx0/o;->d:Ljava/lang/Object;

    .line 181
    .line 182
    invoke-static {v7}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    sget-object v18, Lt51/g;->a:Lt51/g;

    .line 187
    .line 188
    const-string v13, "getName(...)"

    .line 189
    .line 190
    if-nez v10, :cond_4

    .line 191
    .line 192
    check-cast v7, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 193
    .line 194
    new-instance v10, Lx41/y;

    .line 195
    .line 196
    const/16 v14, 0x10

    .line 197
    .line 198
    invoke-direct {v10, v14}, Lx41/y;-><init>(I)V

    .line 199
    .line 200
    .line 201
    new-instance v16, Lt51/j;

    .line 202
    .line 203
    invoke-static {v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v21

    .line 207
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v22

    .line 211
    const-string v17, "Car2PhonePairing"

    .line 212
    .line 213
    const/16 v20, 0x0

    .line 214
    .line 215
    move-object/from16 v19, v10

    .line 216
    .line 217
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 221
    .line 222
    .line 223
    goto :goto_3

    .line 224
    :cond_4
    instance-of v7, v10, Lu51/d;

    .line 225
    .line 226
    if-eqz v7, :cond_5

    .line 227
    .line 228
    new-instance v7, Lx41/y;

    .line 229
    .line 230
    const/16 v10, 0x11

    .line 231
    .line 232
    invoke-direct {v7, v10}, Lx41/y;-><init>(I)V

    .line 233
    .line 234
    .line 235
    new-instance v16, Lt51/j;

    .line 236
    .line 237
    invoke-static {v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v21

    .line 241
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v22

    .line 245
    const-string v17, "Car2PhonePairing"

    .line 246
    .line 247
    const/16 v20, 0x0

    .line 248
    .line 249
    move-object/from16 v19, v7

    .line 250
    .line 251
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 255
    .line 256
    .line 257
    goto :goto_2

    .line 258
    :cond_5
    new-instance v7, Lx41/y;

    .line 259
    .line 260
    const/16 v14, 0x12

    .line 261
    .line 262
    invoke-direct {v7, v14}, Lx41/y;-><init>(I)V

    .line 263
    .line 264
    .line 265
    const-string v14, "Car2PhonePairing"

    .line 266
    .line 267
    invoke-static {v3, v14, v10, v7}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 268
    .line 269
    .line 270
    :goto_2
    move-object v7, v12

    .line 271
    :goto_3
    const/4 v10, 0x3

    .line 272
    const/4 v14, 0x0

    .line 273
    sget-object v23, Lx41/u0;->A:Lx41/d0;

    .line 274
    .line 275
    if-eqz v7, :cond_6

    .line 276
    .line 277
    new-instance v8, Lx41/c0;

    .line 278
    .line 279
    invoke-direct {v8, v7, v14}, Lx41/c0;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;I)V

    .line 280
    .line 281
    .line 282
    new-instance v16, Lt51/j;

    .line 283
    .line 284
    invoke-static/range {v23 .. v23}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 285
    .line 286
    .line 287
    move-result-object v21

    .line 288
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 289
    .line 290
    .line 291
    move-result-object v22

    .line 292
    const-string v17, "Car2PhonePairing"

    .line 293
    .line 294
    const/16 v20, 0x0

    .line 295
    .line 296
    move-object/from16 v19, v8

    .line 297
    .line 298
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 299
    .line 300
    .line 301
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 302
    .line 303
    .line 304
    const/4 v14, 0x1

    .line 305
    :goto_4
    move v8, v10

    .line 306
    goto :goto_5

    .line 307
    :cond_6
    sget-object v7, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->Companion:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;

    .line 308
    .line 309
    invoke-virtual {v7}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->invoke()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    new-instance v8, Lx41/y;

    .line 317
    .line 318
    const/16 v14, 0xe

    .line 319
    .line 320
    invoke-direct {v8, v14}, Lx41/y;-><init>(I)V

    .line 321
    .line 322
    .line 323
    new-instance v16, Lt51/j;

    .line 324
    .line 325
    invoke-static {v3}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 326
    .line 327
    .line 328
    move-result-object v21

    .line 329
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v22

    .line 333
    const-string v17, "Car2PhonePairing"

    .line 334
    .line 335
    const/16 v20, 0x0

    .line 336
    .line 337
    move-object/from16 v19, v8

    .line 338
    .line 339
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 343
    .line 344
    .line 345
    new-instance v8, Lx41/x0;

    .line 346
    .line 347
    invoke-direct {v8, v3, v7, v12}, Lx41/x0;-><init>(Lx41/z0;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lkotlin/coroutines/Continuation;)V

    .line 348
    .line 349
    .line 350
    iget-object v14, v3, Lx41/z0;->h:Lpw0/a;

    .line 351
    .line 352
    invoke-static {v14, v12, v12, v8, v10}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 353
    .line 354
    .line 355
    new-instance v8, Lx41/c0;

    .line 356
    .line 357
    const/4 v14, 0x1

    .line 358
    invoke-direct {v8, v7, v14}, Lx41/c0;-><init>(Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;I)V

    .line 359
    .line 360
    .line 361
    new-instance v16, Lt51/j;

    .line 362
    .line 363
    invoke-static/range {v23 .. v23}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v21

    .line 367
    invoke-static {v13}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object v22

    .line 371
    const-string v17, "Car2PhonePairing"

    .line 372
    .line 373
    move-object/from16 v19, v8

    .line 374
    .line 375
    invoke-direct/range {v16 .. v22}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    invoke-static/range {v16 .. v16}, Lt51/a;->a(Lt51/j;)V

    .line 379
    .line 380
    .line 381
    goto :goto_4

    .line 382
    :goto_5
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 383
    .line 384
    .line 385
    move-result-object v10

    .line 386
    sget-object v1, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 387
    .line 388
    const/16 v13, 0x60

    .line 389
    .line 390
    move/from16 v24, v14

    .line 391
    .line 392
    const/4 v14, 0x0

    .line 393
    move-object/from16 v16, v3

    .line 394
    .line 395
    move-object v3, v7

    .line 396
    const/4 v7, 0x0

    .line 397
    move/from16 v17, v8

    .line 398
    .line 399
    const/4 v8, 0x0

    .line 400
    move-object v12, v5

    .line 401
    move-object/from16 v5, p3

    .line 402
    .line 403
    invoke-static/range {v1 .. v14}, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->invoke$default(Ltechnology/cariad/cat/genx/VehicleManager$Companion;Landroid/content/Context;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Ltechnology/cariad/cat/genx/DeviceInformation;Lu51/g;Ltechnology/cariad/cat/genx/bluetooth/Bluetooth$ScanMode;IILtechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;Lvy0/i1;Lvy0/x;Ljava/util/Set;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/VehicleManager;

    .line 404
    .line 405
    .line 406
    move-result-object v5

    .line 407
    new-instance v1, Lx41/u0;

    .line 408
    .line 409
    move-object/from16 v2, p1

    .line 410
    .line 411
    move-object v6, v3

    .line 412
    move-object v7, v10

    .line 413
    move-object v8, v11

    .line 414
    move-object/from16 v4, v16

    .line 415
    .line 416
    move-object/from16 v3, p4

    .line 417
    .line 418
    invoke-direct/range {v1 .. v8}, Lx41/u0;-><init>(Landroid/content/Context;Lh70/d;Lx41/z0;Ltechnology/cariad/cat/genx/VehicleManager;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;Lvy0/i1;Lvy0/x;)V

    .line 419
    .line 420
    .line 421
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 422
    .line 423
    .line 424
    iput-object v15, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->d:Lg61/d;

    .line 425
    .line 426
    iput-object v1, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 427
    .line 428
    move-object/from16 v2, p5

    .line 429
    .line 430
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->f:Lvy0/x;

    .line 431
    .line 432
    move-object/from16 v3, p6

    .line 433
    .line 434
    iput-object v3, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->g:Lk61/b;

    .line 435
    .line 436
    const-string v4, "RPAPlugin"

    .line 437
    .line 438
    const/4 v5, 0x0

    .line 439
    invoke-static {v4, v2, v5}, Llp/h1;->a(Ljava/lang/String;Lvy0/x;Lvy0/i1;)Lpx0/g;

    .line 440
    .line 441
    .line 442
    move-result-object v2

    .line 443
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->h:Lpx0/g;

    .line 444
    .line 445
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 446
    .line 447
    invoke-direct {v2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 448
    .line 449
    .line 450
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 451
    .line 452
    sget-object v2, Lmx0/u;->d:Lmx0/u;

    .line 453
    .line 454
    invoke-static {v2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 455
    .line 456
    .line 457
    move-result-object v2

    .line 458
    iput-object v2, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->k:Lyy0/c2;

    .line 459
    .line 460
    new-instance v2, Li61/a;

    .line 461
    .line 462
    const/4 v4, 0x0

    .line 463
    invoke-direct {v2, v0, v5, v4}, Li61/a;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lkotlin/coroutines/Continuation;I)V

    .line 464
    .line 465
    .line 466
    new-instance v4, Lne0/n;

    .line 467
    .line 468
    iget-object v6, v1, Lx41/u0;->o:Lyy0/l1;

    .line 469
    .line 470
    const/4 v7, 0x5

    .line 471
    invoke-direct {v4, v6, v2, v7}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 472
    .line 473
    .line 474
    invoke-static {v4, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 475
    .line 476
    .line 477
    iget-object v2, v3, Lk61/b;->f:Lyy0/l1;

    .line 478
    .line 479
    new-instance v3, Li61/a;

    .line 480
    .line 481
    const/4 v14, 0x1

    .line 482
    invoke-direct {v3, v0, v5, v14}, Li61/a;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lkotlin/coroutines/Continuation;I)V

    .line 483
    .line 484
    .line 485
    new-instance v4, Lne0/n;

    .line 486
    .line 487
    invoke-direct {v4, v2, v3, v7}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 488
    .line 489
    .line 490
    invoke-static {v4, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 491
    .line 492
    .line 493
    new-instance v2, Lhg/q;

    .line 494
    .line 495
    iget-object v1, v1, Lx41/u0;->q:Lyy0/l1;

    .line 496
    .line 497
    const/4 v8, 0x3

    .line 498
    invoke-direct {v2, v1, v8}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 499
    .line 500
    .line 501
    new-instance v1, Li50/p;

    .line 502
    .line 503
    invoke-direct {v1, v0, v5, v14}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 504
    .line 505
    .line 506
    new-instance v3, Lne0/n;

    .line 507
    .line 508
    invoke-direct {v3, v2, v1, v7}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 509
    .line 510
    .line 511
    invoke-static {v3, v0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 512
    .line 513
    .line 514
    iput-boolean v14, v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->i:Z

    .line 515
    .line 516
    return-void
.end method

.method public static final a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "<get-values>(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast p0, Ljava/lang/Iterable;

    .line 13
    .line 14
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Li40/r2;

    .line 19
    .line 20
    const/16 v1, 0x18

    .line 21
    .line 22
    invoke-direct {v0, v1}, Li40/r2;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0, v0}, Lky0/l;->o(Lky0/j;Lay0/k;)Lky0/g;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    new-instance v0, Li40/e1;

    .line 30
    .line 31
    const/4 v1, 0x4

    .line 32
    invoke-direct {v0, p1, v1}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p0, v0}, Lky0/l;->e(Lky0/j;Lay0/k;)Lky0/g;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    new-instance p1, Lky0/f;

    .line 40
    .line 41
    invoke-direct {p1, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 42
    .line 43
    .line 44
    :goto_0
    invoke-virtual {p1}, Lky0/f;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-eqz p0, :cond_0

    .line 49
    .line 50
    invoke-virtual {p1}, Lky0/f;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 55
    .line 56
    const/4 v0, 0x0

    .line 57
    invoke-virtual {p0, v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->updateDisabledStatus$remoteparkassistplugin_release(Lg61/h;)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    return-void
.end method

.method public static final b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lg61/h;)V
    .locals 2

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "<get-values>(...)"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast p0, Ljava/lang/Iterable;

    .line 13
    .line 14
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Li40/r2;

    .line 19
    .line 20
    const/16 v1, 0x19

    .line 21
    .line 22
    invoke-direct {v0, v1}, Li40/r2;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {p0, v0}, Lky0/l;->o(Lky0/j;Lay0/k;)Lky0/g;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    new-instance v0, Lky0/f;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Lky0/f;-><init>(Lky0/g;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    invoke-virtual {v0}, Lky0/f;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    invoke-virtual {v0}, Lky0/f;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->updateDisabledStatus$remoteparkassistplugin_release(Lg61/h;)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    return-void
.end method


# virtual methods
.method public final C()V
    .locals 3

    .line 1
    new-instance v0, Lh40/h;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, v2, v1}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final G(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lx41/u0;->G(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final J(Lss/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lx41/u0;->J(Lss/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    if-ne p0, p1, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final K()Lyy0/a2;
    .locals 1

    .line 1
    new-instance v0, Lyy0/l1;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->k:Lyy0/c2;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final O(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Li61/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Li61/c;

    .line 7
    .line 8
    iget v1, v0, Li61/c;->g:I

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
    iput v1, v0, Li61/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li61/c;

    .line 21
    .line 22
    check-cast p2, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p2}, Li61/c;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v0, Li61/c;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Li61/c;->g:I

    .line 32
    .line 33
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 34
    .line 35
    const/4 v3, 0x2

    .line 36
    const/4 v4, 0x1

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    if-eq v2, v4, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p1, v0, Li61/c;->d:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    sget-object p2, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 65
    .line 66
    iput-object p1, v0, Li61/c;->d:Ljava/lang/String;

    .line 67
    .line 68
    iput v4, v0, Li61/c;->g:I

    .line 69
    .line 70
    invoke-virtual {p0, p1, p2, v0}, Lx41/u0;->k(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Lrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-ne p2, v1, :cond_4

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    :goto_1
    sget-object p2, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 78
    .line 79
    const/4 v2, 0x0

    .line 80
    iput-object v2, v0, Li61/c;->d:Ljava/lang/String;

    .line 81
    .line 82
    iput v3, v0, Li61/c;->g:I

    .line 83
    .line 84
    invoke-virtual {p0, p1, p2, v0}, Lx41/u0;->k(Ljava/lang/String;Ltechnology/cariad/cat/genx/Antenna;Lrx0/c;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_5

    .line 89
    .line 90
    :goto_2
    return-object v1

    .line 91
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0
.end method

.method public final a0(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    new-instance v3, Lx41/y;

    .line 7
    .line 8
    const/4 p1, 0x7

    .line 9
    invoke-direct {v3, p1}, Lx41/y;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lt51/j;

    .line 13
    .line 14
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v5

    .line 18
    const-string p1, "getName(...)"

    .line 19
    .line 20
    invoke-static {p1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v6

    .line 24
    const-string v1, "Car2PhonePairing"

    .line 25
    .line 26
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 36
    .line 37
    if-eqz p1, :cond_0

    .line 38
    .line 39
    invoke-interface {p1}, Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;->close()V

    .line 40
    .line 41
    .line 42
    :cond_0
    const/4 p1, 0x0

    .line 43
    iput-object p1, p0, Lx41/u0;->v:Ltechnology/cariad/cat/genx/ScanningManager$ScanningToken;

    .line 44
    .line 45
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0
.end method

.method public final close()V
    .locals 4

    .line 1
    new-instance v0, Lqf0/d;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqf0/d;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v2, "<get-values>(...)"

    .line 18
    .line 19
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    check-cast v1, Ljava/lang/Iterable;

    .line 23
    .line 24
    new-instance v2, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 27
    .line 28
    .line 29
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Ljava/lang/ref/WeakReference;

    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    check-cast v3, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 50
    .line 51
    if-eqz v3, :cond_0

    .line 52
    .line 53
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    if-eqz v1, :cond_2

    .line 69
    .line 70
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    check-cast v1, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 75
    .line 76
    invoke-virtual {v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->close()V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->g:Lk61/b;

    .line 81
    .line 82
    instance-of v1, v0, Lk61/b;

    .line 83
    .line 84
    if-eqz v1, :cond_3

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_3
    const/4 v0, 0x0

    .line 88
    :goto_2
    if-eqz v0, :cond_4

    .line 89
    .line 90
    invoke-virtual {v0}, Lk61/b;->close()V

    .line 91
    .line 92
    .line 93
    :cond_4
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->i:Z

    .line 94
    .line 95
    if-eqz v0, :cond_5

    .line 96
    .line 97
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 98
    .line 99
    invoke-virtual {v0}, Lx41/u0;->close()V

    .line 100
    .line 101
    .line 102
    :cond_5
    const-string v0, "close()"

    .line 103
    .line 104
    invoke-static {p0, v0}, Lvy0/e0;->l(Lvy0/b0;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    return-void
.end method

.method public final d0(Ljava/lang/String;Lh61/a;)Lg61/q;
    .locals 12

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Li2/t;

    .line 7
    .line 8
    const/16 v1, 0x9

    .line 9
    .line 10
    invoke-direct {v0, v1, p1, p0}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p0, v0}, Llp/i1;->e(Ljava/lang/Object;Lay0/a;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Ljava/lang/ref/WeakReference;

    .line 23
    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 31
    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    return-object v1

    .line 35
    :cond_0
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->e:Lx41/u0;

    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    new-instance v5, Lq61/c;

    .line 41
    .line 42
    const/16 v2, 0xc

    .line 43
    .line 44
    invoke-direct {v5, p1, v2}, Lq61/c;-><init>(Ljava/lang/String;I)V

    .line 45
    .line 46
    .line 47
    new-instance v2, Lt51/j;

    .line 48
    .line 49
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    const-string v3, "getName(...)"

    .line 54
    .line 55
    invoke-static {v3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    const-string v3, "Car2PhonePairing"

    .line 60
    .line 61
    sget-object v4, Lt51/g;->a:Lt51/g;

    .line 62
    .line 63
    const/4 v6, 0x0

    .line 64
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 68
    .line 69
    .line 70
    iget-object v2, v1, Lx41/u0;->g:Ltechnology/cariad/cat/genx/VehicleManager;

    .line 71
    .line 72
    invoke-interface {v2, p1}, Ltechnology/cariad/cat/genx/VehicleManager;->vehicle(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    const/4 v3, 0x0

    .line 77
    if-eqz v2, :cond_2

    .line 78
    .line 79
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/Vehicle;->getInnerAntenna()Ltechnology/cariad/cat/genx/VehicleAntenna$Inner;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    if-eqz v4, :cond_1

    .line 84
    .line 85
    invoke-virtual {v1, v4}, Lx41/u0;->b(Ltechnology/cariad/cat/genx/VehicleAntenna;)V

    .line 86
    .line 87
    .line 88
    :cond_1
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/Vehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    if-eqz v4, :cond_3

    .line 93
    .line 94
    invoke-virtual {v1, v4}, Lx41/u0;->b(Ltechnology/cariad/cat/genx/VehicleAntenna;)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :cond_2
    move-object v2, v3

    .line 99
    :cond_3
    :goto_0
    if-nez v2, :cond_4

    .line 100
    .line 101
    new-instance p2, Lac0/a;

    .line 102
    .line 103
    const/16 v0, 0x14

    .line 104
    .line 105
    invoke-direct {p2, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    invoke-static {p0, p2}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 109
    .line 110
    .line 111
    return-object v3

    .line 112
    :cond_4
    invoke-interface {v2}, Ltechnology/cariad/cat/genx/Vehicle;->getOuterAntenna()Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    if-nez v5, :cond_5

    .line 117
    .line 118
    new-instance p2, Lac0/a;

    .line 119
    .line 120
    const/16 v0, 0x15

    .line 121
    .line 122
    invoke-direct {p2, p1, v0}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 123
    .line 124
    .line 125
    invoke-static {p0, p2}, Llp/i1;->f(Ljava/lang/Object;Lay0/a;)V

    .line 126
    .line 127
    .line 128
    return-object v3

    .line 129
    :cond_5
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->h:Lpx0/g;

    .line 130
    .line 131
    invoke-static {v1}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 132
    .line 133
    .line 134
    move-result-object v9

    .line 135
    new-instance v8, Ljava/lang/ref/WeakReference;

    .line 136
    .line 137
    new-instance v1, Li40/e1;

    .line 138
    .line 139
    const/4 v2, 0x3

    .line 140
    invoke-direct {v1, p0, v2}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 141
    .line 142
    .line 143
    invoke-direct {v8, v1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    new-instance v4, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 147
    .line 148
    iget-object v6, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->d:Lg61/d;

    .line 149
    .line 150
    iget-object v10, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->f:Lvy0/x;

    .line 151
    .line 152
    const/4 v11, 0x0

    .line 153
    move-object v7, p2

    .line 154
    invoke-direct/range {v4 .. v11}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;-><init>(Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;Lg61/d;Lh61/a;Ljava/lang/ref/WeakReference;Lvy0/i1;Lvy0/x;Ln71/a;)V

    .line 155
    .line 156
    .line 157
    new-instance p0, Ljava/lang/ref/WeakReference;

    .line 158
    .line 159
    invoke-direct {p0, v4}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0, p1, p0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    return-object v4
.end method

.method public final getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->h:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isBluetoothEnabled()Lyy0/a2;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->g:Lk61/b;

    .line 2
    .line 3
    iget-object p0, p0, Lk61/b;->f:Lyy0/l1;

    .line 4
    .line 5
    return-object p0
.end method
