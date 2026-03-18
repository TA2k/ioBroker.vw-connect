.class public abstract Lcom/google/crypto/tink/shaded/protobuf/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/logging/Logger;

.field public static final b:Lsun/misc/Unsafe;

.field public static final c:Ljava/lang/Class;

.field public static final d:Lcom/google/crypto/tink/shaded/protobuf/k1;

.field public static final e:Z

.field public static final f:Z

.field public static final g:J

.field public static final h:Z


# direct methods
.method static constructor <clinit>()V
    .locals 18

    .line 1
    const-class v0, Lcom/google/crypto/tink/shaded/protobuf/l1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->a:Ljava/util/logging/Logger;

    .line 12
    .line 13
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/l1;->i()Lsun/misc/Unsafe;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->b:Lsun/misc/Unsafe;

    .line 18
    .line 19
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/c;->a:Ljava/lang/Class;

    .line 20
    .line 21
    sput-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->c:Ljava/lang/Class;

    .line 22
    .line 23
    sget-object v1, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 24
    .line 25
    invoke-static {v1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->e(Ljava/lang/Class;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    sget-object v3, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 30
    .line 31
    invoke-static {v3}, Lcom/google/crypto/tink/shaded/protobuf/l1;->e(Ljava/lang/Class;)Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    const/4 v5, 0x0

    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-eqz v6, :cond_2

    .line 44
    .line 45
    if-eqz v2, :cond_1

    .line 46
    .line 47
    new-instance v5, Lcom/google/crypto/tink/shaded/protobuf/i1;

    .line 48
    .line 49
    const/4 v2, 0x1

    .line 50
    invoke-direct {v5, v0, v2}, Lcom/google/crypto/tink/shaded/protobuf/i1;-><init>(Lsun/misc/Unsafe;I)V

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    if-eqz v4, :cond_3

    .line 55
    .line 56
    new-instance v5, Lcom/google/crypto/tink/shaded/protobuf/i1;

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    invoke-direct {v5, v0, v2}, Lcom/google/crypto/tink/shaded/protobuf/i1;-><init>(Lsun/misc/Unsafe;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    new-instance v5, Lcom/google/crypto/tink/shaded/protobuf/j1;

    .line 64
    .line 65
    invoke-direct {v5, v0}, Lcom/google/crypto/tink/shaded/protobuf/k1;-><init>(Lsun/misc/Unsafe;)V

    .line 66
    .line 67
    .line 68
    :cond_3
    :goto_0
    sput-object v5, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 69
    .line 70
    const-string v2, "copyMemory"

    .line 71
    .line 72
    const-string v4, "platform method missing - proto runtime falling back to safer methods: "

    .line 73
    .line 74
    const-string v5, "putLong"

    .line 75
    .line 76
    const-string v6, "putInt"

    .line 77
    .line 78
    const-string v7, "getInt"

    .line 79
    .line 80
    sget-object v8, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 81
    .line 82
    const-string v9, "putByte"

    .line 83
    .line 84
    const-string v10, "getByte"

    .line 85
    .line 86
    const-class v11, Ljava/lang/reflect/Field;

    .line 87
    .line 88
    const-string v12, "objectFieldOffset"

    .line 89
    .line 90
    const-class v13, Ljava/lang/Object;

    .line 91
    .line 92
    const-string v14, "getLong"

    .line 93
    .line 94
    const/16 v16, 0x1

    .line 95
    .line 96
    if-nez v0, :cond_4

    .line 97
    .line 98
    :goto_1
    move-object/from16 v17, v11

    .line 99
    .line 100
    :goto_2
    const/4 v15, 0x0

    .line 101
    goto/16 :goto_4

    .line 102
    .line 103
    :cond_4
    :try_start_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    filled-new-array {v11}, [Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    move-result-object v15

    .line 111
    invoke-virtual {v0, v12, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 112
    .line 113
    .line 114
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    move-result-object v15

    .line 118
    invoke-virtual {v0, v14, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 119
    .line 120
    .line 121
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/l1;->d()Ljava/lang/reflect/Field;

    .line 122
    .line 123
    .line 124
    move-result-object v15

    .line 125
    if-nez v15, :cond_5

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_5
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 129
    .line 130
    .line 131
    move-result v15

    .line 132
    if-eqz v15, :cond_6

    .line 133
    .line 134
    :goto_3
    move-object/from16 v17, v11

    .line 135
    .line 136
    move/from16 v15, v16

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_6
    filled-new-array {v1}, [Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    move-result-object v15

    .line 143
    invoke-virtual {v0, v10, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 144
    .line 145
    .line 146
    filled-new-array {v1, v8}, [Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    move-result-object v15

    .line 150
    invoke-virtual {v0, v9, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 151
    .line 152
    .line 153
    filled-new-array {v1}, [Ljava/lang/Class;

    .line 154
    .line 155
    .line 156
    move-result-object v15

    .line 157
    invoke-virtual {v0, v7, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 158
    .line 159
    .line 160
    filled-new-array {v1, v3}, [Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    move-result-object v15

    .line 164
    invoke-virtual {v0, v6, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 165
    .line 166
    .line 167
    filled-new-array {v1}, [Ljava/lang/Class;

    .line 168
    .line 169
    .line 170
    move-result-object v15

    .line 171
    invoke-virtual {v0, v14, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 172
    .line 173
    .line 174
    filled-new-array {v1, v1}, [Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    move-result-object v15

    .line 178
    invoke-virtual {v0, v5, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 179
    .line 180
    .line 181
    filled-new-array {v1, v1, v1}, [Ljava/lang/Class;

    .line 182
    .line 183
    .line 184
    move-result-object v15

    .line 185
    invoke-virtual {v0, v2, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 186
    .line 187
    .line 188
    filled-new-array {v13, v1, v13, v1, v1}, [Ljava/lang/Class;

    .line 189
    .line 190
    .line 191
    move-result-object v15

    .line 192
    invoke-virtual {v0, v2, v15}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 193
    .line 194
    .line 195
    goto :goto_3

    .line 196
    :catchall_0
    move-exception v0

    .line 197
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->a:Ljava/util/logging/Logger;

    .line 198
    .line 199
    sget-object v15, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 200
    .line 201
    move-object/from16 v17, v11

    .line 202
    .line 203
    new-instance v11, Ljava/lang/StringBuilder;

    .line 204
    .line 205
    invoke-direct {v11, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    invoke-virtual {v11, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    invoke-virtual {v2, v15, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    goto :goto_2

    .line 219
    :goto_4
    sput-boolean v15, Lcom/google/crypto/tink/shaded/protobuf/l1;->e:Z

    .line 220
    .line 221
    const-class v0, Ljava/lang/Class;

    .line 222
    .line 223
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->b:Lsun/misc/Unsafe;

    .line 224
    .line 225
    if-nez v2, :cond_7

    .line 226
    .line 227
    :goto_5
    const/4 v0, 0x0

    .line 228
    goto/16 :goto_7

    .line 229
    .line 230
    :cond_7
    :try_start_1
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    filled-new-array/range {v17 .. v17}, [Ljava/lang/Class;

    .line 235
    .line 236
    .line 237
    move-result-object v11

    .line 238
    invoke-virtual {v2, v12, v11}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 239
    .line 240
    .line 241
    const-string v11, "arrayBaseOffset"

    .line 242
    .line 243
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 244
    .line 245
    .line 246
    move-result-object v12

    .line 247
    invoke-virtual {v2, v11, v12}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 248
    .line 249
    .line 250
    const-string v11, "arrayIndexScale"

    .line 251
    .line 252
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 253
    .line 254
    .line 255
    move-result-object v0

    .line 256
    invoke-virtual {v2, v11, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 257
    .line 258
    .line 259
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    invoke-virtual {v2, v7, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 264
    .line 265
    .line 266
    filled-new-array {v13, v1, v3}, [Ljava/lang/Class;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    invoke-virtual {v2, v6, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 271
    .line 272
    .line 273
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    invoke-virtual {v2, v14, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 278
    .line 279
    .line 280
    filled-new-array {v13, v1, v1}, [Ljava/lang/Class;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    invoke-virtual {v2, v5, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 285
    .line 286
    .line 287
    const-string v0, "getObject"

    .line 288
    .line 289
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 290
    .line 291
    .line 292
    move-result-object v3

    .line 293
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 294
    .line 295
    .line 296
    const-string v0, "putObject"

    .line 297
    .line 298
    filled-new-array {v13, v1, v13}, [Ljava/lang/Class;

    .line 299
    .line 300
    .line 301
    move-result-object v3

    .line 302
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 303
    .line 304
    .line 305
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 306
    .line 307
    .line 308
    move-result v0

    .line 309
    if-eqz v0, :cond_8

    .line 310
    .line 311
    :goto_6
    move/from16 v0, v16

    .line 312
    .line 313
    goto :goto_7

    .line 314
    :cond_8
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    invoke-virtual {v2, v10, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 319
    .line 320
    .line 321
    filled-new-array {v13, v1, v8}, [Ljava/lang/Class;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    invoke-virtual {v2, v9, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 326
    .line 327
    .line 328
    const-string v0, "getBoolean"

    .line 329
    .line 330
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 331
    .line 332
    .line 333
    move-result-object v3

    .line 334
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 335
    .line 336
    .line 337
    const-string v0, "putBoolean"

    .line 338
    .line 339
    sget-object v3, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 340
    .line 341
    filled-new-array {v13, v1, v3}, [Ljava/lang/Class;

    .line 342
    .line 343
    .line 344
    move-result-object v3

    .line 345
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 346
    .line 347
    .line 348
    const-string v0, "getFloat"

    .line 349
    .line 350
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 351
    .line 352
    .line 353
    move-result-object v3

    .line 354
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 355
    .line 356
    .line 357
    const-string v0, "putFloat"

    .line 358
    .line 359
    sget-object v3, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    .line 360
    .line 361
    filled-new-array {v13, v1, v3}, [Ljava/lang/Class;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 366
    .line 367
    .line 368
    const-string v0, "getDouble"

    .line 369
    .line 370
    filled-new-array {v13, v1}, [Ljava/lang/Class;

    .line 371
    .line 372
    .line 373
    move-result-object v3

    .line 374
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 375
    .line 376
    .line 377
    const-string v0, "putDouble"

    .line 378
    .line 379
    sget-object v3, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 380
    .line 381
    filled-new-array {v13, v1, v3}, [Ljava/lang/Class;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    invoke-virtual {v2, v0, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 386
    .line 387
    .line 388
    goto :goto_6

    .line 389
    :catchall_1
    move-exception v0

    .line 390
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->a:Ljava/util/logging/Logger;

    .line 391
    .line 392
    sget-object v2, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 393
    .line 394
    new-instance v3, Ljava/lang/StringBuilder;

    .line 395
    .line 396
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 400
    .line 401
    .line 402
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    invoke-virtual {v1, v2, v0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    goto/16 :goto_5

    .line 410
    .line 411
    :goto_7
    sput-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->f:Z

    .line 412
    .line 413
    const-class v0, [B

    .line 414
    .line 415
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 416
    .line 417
    .line 418
    move-result v0

    .line 419
    int-to-long v0, v0

    .line 420
    sput-wide v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->g:J

    .line 421
    .line 422
    const-class v0, [Z

    .line 423
    .line 424
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 425
    .line 426
    .line 427
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 428
    .line 429
    .line 430
    const-class v0, [I

    .line 431
    .line 432
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 433
    .line 434
    .line 435
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 436
    .line 437
    .line 438
    const-class v0, [J

    .line 439
    .line 440
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 441
    .line 442
    .line 443
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 444
    .line 445
    .line 446
    const-class v0, [F

    .line 447
    .line 448
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 449
    .line 450
    .line 451
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 452
    .line 453
    .line 454
    const-class v0, [D

    .line 455
    .line 456
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 457
    .line 458
    .line 459
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 460
    .line 461
    .line 462
    const-class v0, [Ljava/lang/Object;

    .line 463
    .line 464
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->b(Ljava/lang/Class;)I

    .line 465
    .line 466
    .line 467
    invoke-static {v0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->c(Ljava/lang/Class;)V

    .line 468
    .line 469
    .line 470
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/l1;->d()Ljava/lang/reflect/Field;

    .line 471
    .line 472
    .line 473
    move-result-object v0

    .line 474
    if-eqz v0, :cond_a

    .line 475
    .line 476
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 477
    .line 478
    if-nez v1, :cond_9

    .line 479
    .line 480
    goto :goto_8

    .line 481
    :cond_9
    invoke-virtual {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/k1;->j(Ljava/lang/reflect/Field;)J

    .line 482
    .line 483
    .line 484
    :cond_a
    :goto_8
    invoke-static {}, Ljava/nio/ByteOrder;->nativeOrder()Ljava/nio/ByteOrder;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    sget-object v1, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 489
    .line 490
    if-ne v0, v1, :cond_b

    .line 491
    .line 492
    move/from16 v15, v16

    .line 493
    .line 494
    goto :goto_9

    .line 495
    :cond_b
    const/4 v15, 0x0

    .line 496
    :goto_9
    sput-boolean v15, Lcom/google/crypto/tink/shaded/protobuf/l1;->h:Z

    .line 497
    .line 498
    return-void
.end method

.method public static a(Ljava/lang/Class;)Ljava/lang/Object;
    .locals 1

    .line 1
    :try_start_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->b:Lsun/misc/Unsafe;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lsun/misc/Unsafe;->allocateInstance(Ljava/lang/Class;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    return-object p0

    .line 8
    :catch_0
    move-exception p0

    .line 9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 12
    .line 13
    .line 14
    throw v0
.end method

.method public static b(Ljava/lang/Class;)I
    .locals 1

    .line 1
    sget-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/k1;->a(Ljava/lang/Class;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, -0x1

    .line 13
    return p0
.end method

.method public static c(Ljava/lang/Class;)V
    .locals 1

    .line 1
    sget-boolean v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/k1;->b(Ljava/lang/Class;)I

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public static d()Ljava/lang/reflect/Field;
    .locals 4

    .line 1
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-class v1, Ljava/nio/Buffer;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const-string v0, "effectiveDirectAddress"

    .line 11
    .line 12
    :try_start_0
    invoke-virtual {v1, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 13
    .line 14
    .line 15
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-object v0, v2

    .line 18
    :goto_0
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_0
    const-string v0, "address"

    .line 22
    .line 23
    :try_start_1
    invoke-virtual {v1, v0}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 24
    .line 25
    .line 26
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 27
    goto :goto_1

    .line 28
    :catchall_1
    move-object v0, v2

    .line 29
    :goto_1
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    sget-object v3, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 36
    .line 37
    if-ne v1, v3, :cond_1

    .line 38
    .line 39
    move-object v2, v0

    .line 40
    :cond_1
    return-object v2
.end method

.method public static e(Ljava/lang/Class;)Z
    .locals 7

    .line 1
    const-class v0, [B

    .line 2
    .line 3
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/c;->a()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    return v2

    .line 11
    :cond_0
    :try_start_0
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/l1;->c:Ljava/lang/Class;

    .line 12
    .line 13
    const-string v3, "peekLong"

    .line 14
    .line 15
    sget-object v4, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 16
    .line 17
    filled-new-array {p0, v4}, [Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    invoke-virtual {v1, v3, v5}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 22
    .line 23
    .line 24
    const-string v3, "pokeLong"

    .line 25
    .line 26
    sget-object v5, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 27
    .line 28
    filled-new-array {p0, v5, v4}, [Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    invoke-virtual {v1, v3, v5}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 33
    .line 34
    .line 35
    const-string v3, "pokeInt"

    .line 36
    .line 37
    sget-object v5, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 38
    .line 39
    filled-new-array {p0, v5, v4}, [Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    invoke-virtual {v1, v3, v6}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 44
    .line 45
    .line 46
    const-string v3, "peekInt"

    .line 47
    .line 48
    filled-new-array {p0, v4}, [Ljava/lang/Class;

    .line 49
    .line 50
    .line 51
    move-result-object v4

    .line 52
    invoke-virtual {v1, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 53
    .line 54
    .line 55
    const-string v3, "pokeByte"

    .line 56
    .line 57
    sget-object v4, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 58
    .line 59
    filled-new-array {p0, v4}, [Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    invoke-virtual {v1, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 64
    .line 65
    .line 66
    const-string v3, "peekByte"

    .line 67
    .line 68
    filled-new-array {p0}, [Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    move-result-object v4

    .line 72
    invoke-virtual {v1, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 73
    .line 74
    .line 75
    const-string v3, "pokeByteArray"

    .line 76
    .line 77
    filled-new-array {p0, v0, v5, v5}, [Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    invoke-virtual {v1, v3, v4}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 82
    .line 83
    .line 84
    const-string v3, "peekByteArray"

    .line 85
    .line 86
    filled-new-array {p0, v0, v5, v5}, [Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-virtual {v1, v3, p0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    .line 92
    .line 93
    const/4 p0, 0x1

    .line 94
    return p0

    .line 95
    :catchall_0
    return v2
.end method

.method public static f([BJ)B
    .locals 2

    .line 1
    sget-wide v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->g:J

    .line 2
    .line 3
    add-long/2addr v0, p1

    .line 4
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {p1, p0, v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/k1;->d(Ljava/lang/Object;J)B

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public static g(JLjava/lang/Object;)B
    .locals 3

    .line 1
    const-wide/16 v0, -0x4

    .line 2
    .line 3
    and-long/2addr v0, p0

    .line 4
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {v2, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    not-long p0, p0

    .line 11
    const-wide/16 v0, 0x3

    .line 12
    .line 13
    and-long/2addr p0, v0

    .line 14
    const/4 v0, 0x3

    .line 15
    shl-long/2addr p0, v0

    .line 16
    long-to-int p0, p0

    .line 17
    ushr-int p0, p2, p0

    .line 18
    .line 19
    and-int/lit16 p0, p0, 0xff

    .line 20
    .line 21
    int-to-byte p0, p0

    .line 22
    return p0
.end method

.method public static h(JLjava/lang/Object;)B
    .locals 3

    .line 1
    const-wide/16 v0, -0x4

    .line 2
    .line 3
    and-long/2addr v0, p0

    .line 4
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {v2, v0, v1, p2}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    const-wide/16 v0, 0x3

    .line 11
    .line 12
    and-long/2addr p0, v0

    .line 13
    const/4 v0, 0x3

    .line 14
    shl-long/2addr p0, v0

    .line 15
    long-to-int p0, p0

    .line 16
    ushr-int p0, p2, p0

    .line 17
    .line 18
    and-int/lit16 p0, p0, 0xff

    .line 19
    .line 20
    int-to-byte p0, p0

    .line 21
    return p0
.end method

.method public static i()Lsun/misc/Unsafe;
    .locals 1

    .line 1
    :try_start_0
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/h1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Ljava/security/AccessController;->doPrivileged(Ljava/security/PrivilegedExceptionAction;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lsun/misc/Unsafe;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    return-object v0

    .line 13
    :catchall_0
    const/4 v0, 0x0

    .line 14
    return-object v0
.end method

.method public static j([BJB)V
    .locals 2

    .line 1
    sget-wide v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->g:J

    .line 2
    .line 3
    add-long/2addr v0, p1

    .line 4
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {p1, p0, v0, v1, p3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->l(Ljava/lang/Object;JB)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static k(Ljava/lang/Object;JB)V
    .locals 4

    .line 1
    const-wide/16 v0, -0x4

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {v2, v0, v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    long-to-int p1, p1

    .line 11
    not-int p1, p1

    .line 12
    and-int/lit8 p1, p1, 0x3

    .line 13
    .line 14
    shl-int/lit8 p1, p1, 0x3

    .line 15
    .line 16
    const/16 p2, 0xff

    .line 17
    .line 18
    shl-int v3, p2, p1

    .line 19
    .line 20
    not-int v3, v3

    .line 21
    and-int/2addr v2, v3

    .line 22
    and-int/2addr p2, p3

    .line 23
    shl-int p1, p2, p1

    .line 24
    .line 25
    or-int/2addr p1, v2

    .line 26
    invoke-static {v0, v1, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public static l(Ljava/lang/Object;JB)V
    .locals 4

    .line 1
    const-wide/16 v0, -0x4

    .line 2
    .line 3
    and-long/2addr v0, p1

    .line 4
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 5
    .line 6
    invoke-virtual {v2, v0, v1, p0}, Lcom/google/crypto/tink/shaded/protobuf/k1;->g(JLjava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    long-to-int p1, p1

    .line 11
    and-int/lit8 p1, p1, 0x3

    .line 12
    .line 13
    shl-int/lit8 p1, p1, 0x3

    .line 14
    .line 15
    const/16 p2, 0xff

    .line 16
    .line 17
    shl-int v3, p2, p1

    .line 18
    .line 19
    not-int v3, v3

    .line 20
    and-int/2addr v2, v3

    .line 21
    and-int/2addr p2, p3

    .line 22
    shl-int p1, p2, p1

    .line 23
    .line 24
    or-int/2addr p1, v2

    .line 25
    invoke-static {v0, v1, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/l1;->m(JLjava/lang/Object;I)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public static m(JLjava/lang/Object;I)V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p0, p1, p2, p3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->o(JLjava/lang/Object;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static n(JLjava/lang/Object;J)V
    .locals 6

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    move-wide v1, p0

    .line 4
    move-object v3, p2

    .line 5
    move-wide v4, p3

    .line 6
    invoke-virtual/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/k1;->p(JLjava/lang/Object;J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public static o(Ljava/lang/Object;JLjava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/l1;->d:Lcom/google/crypto/tink/shaded/protobuf/k1;

    .line 2
    .line 3
    invoke-virtual {v0, p0, p1, p2, p3}, Lcom/google/crypto/tink/shaded/protobuf/k1;->q(Ljava/lang/Object;JLjava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
