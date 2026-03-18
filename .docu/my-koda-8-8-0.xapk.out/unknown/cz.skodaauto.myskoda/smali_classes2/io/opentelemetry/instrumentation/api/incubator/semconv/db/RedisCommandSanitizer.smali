.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;
    }
.end annotation


# static fields
.field private static final DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;

.field private static final SANITIZERS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final statementSanitizationEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 32

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;

    .line 8
    .line 9
    new-instance v0, Ljava/util/HashMap;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;

    .line 15
    .line 16
    const/4 v3, 0x1

    .line 17
    invoke-direct {v2, v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v4, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;

    .line 21
    .line 22
    const/4 v5, 0x2

    .line 23
    invoke-direct {v4, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v6, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;

    .line 27
    .line 28
    invoke-direct {v6, v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;-><init>(I)V

    .line 29
    .line 30
    .line 31
    new-instance v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;

    .line 32
    .line 33
    invoke-direct {v3, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;-><init>(I)V

    .line 34
    .line 35
    .line 36
    const-string v1, "READONLY"

    .line 37
    .line 38
    const-string v7, "READWRITE"

    .line 39
    .line 40
    const-string v8, "CLUSTER"

    .line 41
    .line 42
    const-string v9, "FAILOVER"

    .line 43
    .line 44
    filled-new-array {v8, v9, v1, v7}, [Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    if-eqz v7, :cond_0

    .line 61
    .line 62
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v7

    .line 66
    check-cast v7, Ljava/lang/String;

    .line 67
    .line 68
    sget-object v8, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 69
    .line 70
    invoke-virtual {v0, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_0
    const-string v1, "AUTH"

    .line 75
    .line 76
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;

    .line 77
    .line 78
    invoke-virtual {v0, v1, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    const-string v1, "HELLO"

    .line 82
    .line 83
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    const-string v11, "RESET"

    .line 87
    .line 88
    const-string v12, "SELECT"

    .line 89
    .line 90
    const-string v7, "CLIENT"

    .line 91
    .line 92
    const-string v8, "ECHO"

    .line 93
    .line 94
    const-string v9, "PING"

    .line 95
    .line 96
    const-string v10, "QUIT"

    .line 97
    .line 98
    filled-new-array/range {v7 .. v12}, [Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    if-eqz v7, :cond_1

    .line 115
    .line 116
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    check-cast v7, Ljava/lang/String;

    .line 121
    .line 122
    sget-object v8, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 123
    .line 124
    invoke-virtual {v0, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_1
    const-string v17, "GEOSEARCH"

    .line 129
    .line 130
    const-string v18, "GEOSEARCHSTORE"

    .line 131
    .line 132
    const-string v9, "GEOADD"

    .line 133
    .line 134
    const-string v10, "GEODIST"

    .line 135
    .line 136
    const-string v11, "GEOHASH"

    .line 137
    .line 138
    const-string v12, "GEOPOS"

    .line 139
    .line 140
    const-string v13, "GEORADIUS"

    .line 141
    .line 142
    const-string v14, "GEORADIUS_RO"

    .line 143
    .line 144
    const-string v15, "GEORADIUSBYMEMBER"

    .line 145
    .line 146
    const-string v16, "GEORADIUSBYMEMBER_RO"

    .line 147
    .line 148
    filled-new-array/range {v9 .. v18}, [Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 161
    .line 162
    .line 163
    move-result v7

    .line 164
    if-eqz v7, :cond_2

    .line 165
    .line 166
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v7

    .line 170
    check-cast v7, Ljava/lang/String;

    .line 171
    .line 172
    sget-object v8, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 173
    .line 174
    invoke-virtual {v0, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    goto :goto_2

    .line 178
    :cond_2
    const-string v1, "HMSET"

    .line 179
    .line 180
    invoke-virtual {v0, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    const-string v1, "HSET"

    .line 184
    .line 185
    invoke-virtual {v0, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    const-string v1, "HSETNX"

    .line 189
    .line 190
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    const-string v17, "HSTRLEN"

    .line 194
    .line 195
    const-string v18, "HVALS"

    .line 196
    .line 197
    const-string v6, "HDEL"

    .line 198
    .line 199
    const-string v7, "HEXISTS"

    .line 200
    .line 201
    const-string v8, "HGET"

    .line 202
    .line 203
    const-string v9, "HGETALL"

    .line 204
    .line 205
    const-string v10, "HINCRBY"

    .line 206
    .line 207
    const-string v11, "HINCRBYFLOAT"

    .line 208
    .line 209
    const-string v12, "HKEYS"

    .line 210
    .line 211
    const-string v13, "HLEN"

    .line 212
    .line 213
    const-string v14, "HMGET"

    .line 214
    .line 215
    const-string v15, "HRANDFIELD"

    .line 216
    .line 217
    const-string v16, "HSCAN"

    .line 218
    .line 219
    filled-new-array/range {v6 .. v18}, [Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 232
    .line 233
    .line 234
    move-result v6

    .line 235
    if-eqz v6, :cond_3

    .line 236
    .line 237
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v6

    .line 241
    check-cast v6, Ljava/lang/String;

    .line 242
    .line 243
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 244
    .line 245
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    goto :goto_3

    .line 249
    :cond_3
    const-string v1, "PFADD"

    .line 250
    .line 251
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    const-string v1, "PFCOUNT"

    .line 255
    .line 256
    const-string v6, "PFMERGE"

    .line 257
    .line 258
    filled-new-array {v1, v6}, [Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v1

    .line 262
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 267
    .line 268
    .line 269
    move-result-object v1

    .line 270
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 271
    .line 272
    .line 273
    move-result v6

    .line 274
    if-eqz v6, :cond_4

    .line 275
    .line 276
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object v6

    .line 280
    check-cast v6, Ljava/lang/String;

    .line 281
    .line 282
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 283
    .line 284
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    goto :goto_4

    .line 288
    :cond_4
    new-instance v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;

    .line 289
    .line 290
    const/4 v6, 0x6

    .line 291
    invoke-direct {v1, v6}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandAndNumArgs;-><init>(I)V

    .line 292
    .line 293
    .line 294
    const-string v6, "MIGRATE"

    .line 295
    .line 296
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    const-string v1, "RESTORE"

    .line 300
    .line 301
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    const-string v30, "UNLINK"

    .line 305
    .line 306
    const-string v31, "WAIT"

    .line 307
    .line 308
    const-string v6, "COPY"

    .line 309
    .line 310
    const-string v7, "DEL"

    .line 311
    .line 312
    const-string v8, "DUMP"

    .line 313
    .line 314
    const-string v9, "EXISTS"

    .line 315
    .line 316
    const-string v10, "EXPIRE"

    .line 317
    .line 318
    const-string v11, "EXPIREAT"

    .line 319
    .line 320
    const-string v12, "EXPIRETIME"

    .line 321
    .line 322
    const-string v13, "KEYS"

    .line 323
    .line 324
    const-string v14, "MOVE"

    .line 325
    .line 326
    const-string v15, "OBJECT"

    .line 327
    .line 328
    const-string v16, "PERSIST"

    .line 329
    .line 330
    const-string v17, "PEXPIRE"

    .line 331
    .line 332
    const-string v18, "PEXPIREAT"

    .line 333
    .line 334
    const-string v19, "PEXPIRETIME"

    .line 335
    .line 336
    const-string v20, "PTTL"

    .line 337
    .line 338
    const-string v21, "RANDOMKEY"

    .line 339
    .line 340
    const-string v22, "RENAME"

    .line 341
    .line 342
    const-string v23, "RENAMENX"

    .line 343
    .line 344
    const-string v24, "SCAN"

    .line 345
    .line 346
    const-string v25, "SORT"

    .line 347
    .line 348
    const-string v26, "SORT_RO"

    .line 349
    .line 350
    const-string v27, "TOUCH"

    .line 351
    .line 352
    const-string v28, "TTL"

    .line 353
    .line 354
    const-string v29, "TYPE"

    .line 355
    .line 356
    filled-new-array/range {v6 .. v31}, [Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v1

    .line 360
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 365
    .line 366
    .line 367
    move-result-object v1

    .line 368
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 369
    .line 370
    .line 371
    move-result v6

    .line 372
    if-eqz v6, :cond_5

    .line 373
    .line 374
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v6

    .line 378
    check-cast v6, Ljava/lang/String;

    .line 379
    .line 380
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 381
    .line 382
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    goto :goto_5

    .line 386
    :cond_5
    const-string v1, "LINSERT"

    .line 387
    .line 388
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    const-string v1, "LPOS"

    .line 392
    .line 393
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    const-string v1, "LPUSH"

    .line 397
    .line 398
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    const-string v1, "LPUSHX"

    .line 402
    .line 403
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 404
    .line 405
    .line 406
    const-string v1, "LREM"

    .line 407
    .line 408
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    const-string v1, "LSET"

    .line 412
    .line 413
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    const-string v1, "RPUSH"

    .line 417
    .line 418
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    const-string v1, "RPUSHX"

    .line 422
    .line 423
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    const-string v18, "RPOP"

    .line 427
    .line 428
    const-string v19, "RPOPLPUSH"

    .line 429
    .line 430
    const-string v6, "BLMOVE"

    .line 431
    .line 432
    const-string v7, "BLMPOP"

    .line 433
    .line 434
    const-string v8, "BLPOP"

    .line 435
    .line 436
    const-string v9, "BRPOP"

    .line 437
    .line 438
    const-string v10, "BRPOPLPUSH"

    .line 439
    .line 440
    const-string v11, "LINDEX"

    .line 441
    .line 442
    const-string v12, "LLEN"

    .line 443
    .line 444
    const-string v13, "LMOVE"

    .line 445
    .line 446
    const-string v14, "LMPOP"

    .line 447
    .line 448
    const-string v15, "LPOP"

    .line 449
    .line 450
    const-string v16, "LRANGE"

    .line 451
    .line 452
    const-string v17, "LTRIM"

    .line 453
    .line 454
    filled-new-array/range {v6 .. v19}, [Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    :goto_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 467
    .line 468
    .line 469
    move-result v6

    .line 470
    if-eqz v6, :cond_6

    .line 471
    .line 472
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    check-cast v6, Ljava/lang/String;

    .line 477
    .line 478
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 479
    .line 480
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    goto :goto_6

    .line 484
    :cond_6
    const-string v1, "PUBLISH"

    .line 485
    .line 486
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    const-string v12, "SUNSUBSCRIBE"

    .line 490
    .line 491
    const-string v13, "UNSUBSCRIBE"

    .line 492
    .line 493
    const-string v6, "PSUBSCRIBE"

    .line 494
    .line 495
    const-string v7, "PUBSUB"

    .line 496
    .line 497
    const-string v8, "PUNSUBSCRIBE"

    .line 498
    .line 499
    const-string v9, "SPUBLISH"

    .line 500
    .line 501
    const-string v10, "SSUBSCRIBE"

    .line 502
    .line 503
    const-string v11, "SUBSCRIBE"

    .line 504
    .line 505
    filled-new-array/range {v6 .. v13}, [Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v1

    .line 509
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 510
    .line 511
    .line 512
    move-result-object v1

    .line 513
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 514
    .line 515
    .line 516
    move-result-object v1

    .line 517
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 518
    .line 519
    .line 520
    move-result v6

    .line 521
    if-eqz v6, :cond_7

    .line 522
    .line 523
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 524
    .line 525
    .line 526
    move-result-object v6

    .line 527
    check-cast v6, Ljava/lang/String;

    .line 528
    .line 529
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 530
    .line 531
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    goto :goto_7

    .line 535
    :cond_7
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 536
    .line 537
    const-string v6, "EVAL"

    .line 538
    .line 539
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    const-string v6, "EVAL_RO"

    .line 543
    .line 544
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 545
    .line 546
    .line 547
    const-string v6, "EVALSHA"

    .line 548
    .line 549
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    const-string v6, "EVALSHA_RO"

    .line 553
    .line 554
    invoke-virtual {v0, v6, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    const-string v1, "SCRIPT"

    .line 558
    .line 559
    sget-object v6, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 560
    .line 561
    invoke-virtual {v0, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 562
    .line 563
    .line 564
    const-string v1, "CONFIG"

    .line 565
    .line 566
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 567
    .line 568
    .line 569
    const-string v29, "SYNC"

    .line 570
    .line 571
    const-string v30, "TIME"

    .line 572
    .line 573
    const-string v6, "ACL"

    .line 574
    .line 575
    const-string v7, "BGREWRITEAOF"

    .line 576
    .line 577
    const-string v8, "BGSAVE"

    .line 578
    .line 579
    const-string v9, "COMMAND"

    .line 580
    .line 581
    const-string v10, "DBSIZE"

    .line 582
    .line 583
    const-string v11, "DEBUG"

    .line 584
    .line 585
    const-string v12, "FLUSHALL"

    .line 586
    .line 587
    const-string v13, "FLUSHDB"

    .line 588
    .line 589
    const-string v14, "INFO"

    .line 590
    .line 591
    const-string v15, "LASTSAVE"

    .line 592
    .line 593
    const-string v16, "LATENCY"

    .line 594
    .line 595
    const-string v17, "LOLWUT"

    .line 596
    .line 597
    const-string v18, "MEMORY"

    .line 598
    .line 599
    const-string v19, "MODULE"

    .line 600
    .line 601
    const-string v20, "MONITOR"

    .line 602
    .line 603
    const-string v21, "PSYNC"

    .line 604
    .line 605
    const-string v22, "REPLICAOF"

    .line 606
    .line 607
    const-string v23, "ROLE"

    .line 608
    .line 609
    const-string v24, "SAVE"

    .line 610
    .line 611
    const-string v25, "SHUTDOWN"

    .line 612
    .line 613
    const-string v26, "SLAVEOF"

    .line 614
    .line 615
    const-string v27, "SLOWLOG"

    .line 616
    .line 617
    const-string v28, "SWAPDB"

    .line 618
    .line 619
    filled-new-array/range {v6 .. v30}, [Ljava/lang/String;

    .line 620
    .line 621
    .line 622
    move-result-object v1

    .line 623
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 624
    .line 625
    .line 626
    move-result-object v1

    .line 627
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 628
    .line 629
    .line 630
    move-result-object v1

    .line 631
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 632
    .line 633
    .line 634
    move-result v6

    .line 635
    if-eqz v6, :cond_8

    .line 636
    .line 637
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 638
    .line 639
    .line 640
    move-result-object v6

    .line 641
    check-cast v6, Ljava/lang/String;

    .line 642
    .line 643
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 644
    .line 645
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 646
    .line 647
    .line 648
    goto :goto_8

    .line 649
    :cond_8
    const-string v1, "SADD"

    .line 650
    .line 651
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    const-string v1, "SISMEMBER"

    .line 655
    .line 656
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    const-string v1, "SMISMEMBER"

    .line 660
    .line 661
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 662
    .line 663
    .line 664
    const-string v1, "SMOVE"

    .line 665
    .line 666
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    const-string v1, "SREM"

    .line 670
    .line 671
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 672
    .line 673
    .line 674
    const-string v16, "SUNION"

    .line 675
    .line 676
    const-string v17, "SUNIONSTORE"

    .line 677
    .line 678
    const-string v6, "SCARD"

    .line 679
    .line 680
    const-string v7, "SDIFF"

    .line 681
    .line 682
    const-string v8, "SDIFFSTORE"

    .line 683
    .line 684
    const-string v9, "SINTER"

    .line 685
    .line 686
    const-string v10, "SINTERCARD"

    .line 687
    .line 688
    const-string v11, "SINTERSTORE"

    .line 689
    .line 690
    const-string v12, "SMEMBERS"

    .line 691
    .line 692
    const-string v13, "SPOP"

    .line 693
    .line 694
    const-string v14, "SRANDMEMBER"

    .line 695
    .line 696
    const-string v15, "SSCAN"

    .line 697
    .line 698
    filled-new-array/range {v6 .. v17}, [Ljava/lang/String;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 703
    .line 704
    .line 705
    move-result-object v1

    .line 706
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 707
    .line 708
    .line 709
    move-result-object v1

    .line 710
    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 711
    .line 712
    .line 713
    move-result v6

    .line 714
    if-eqz v6, :cond_9

    .line 715
    .line 716
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v6

    .line 720
    check-cast v6, Ljava/lang/String;

    .line 721
    .line 722
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 723
    .line 724
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 725
    .line 726
    .line 727
    goto :goto_9

    .line 728
    :cond_9
    const-string v1, "ZADD"

    .line 729
    .line 730
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    const-string v1, "ZCOUNT"

    .line 734
    .line 735
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 736
    .line 737
    .line 738
    const-string v1, "ZINCRBY"

    .line 739
    .line 740
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 741
    .line 742
    .line 743
    const-string v1, "ZLEXCOUNT"

    .line 744
    .line 745
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 746
    .line 747
    .line 748
    const-string v1, "ZMSCORE"

    .line 749
    .line 750
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 751
    .line 752
    .line 753
    const-string v1, "ZRANGEBYLEX"

    .line 754
    .line 755
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    const-string v1, "ZRANGEBYSCORE"

    .line 759
    .line 760
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    const-string v1, "ZRANK"

    .line 764
    .line 765
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 766
    .line 767
    .line 768
    const-string v1, "ZREM"

    .line 769
    .line 770
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    const-string v1, "ZREMRANGEBYLEX"

    .line 774
    .line 775
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 776
    .line 777
    .line 778
    const-string v1, "ZREMRANGEBYSCORE"

    .line 779
    .line 780
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 781
    .line 782
    .line 783
    const-string v1, "ZREVRANGEBYLEX"

    .line 784
    .line 785
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    const-string v1, "ZREVRANGEBYSCORE"

    .line 789
    .line 790
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 791
    .line 792
    .line 793
    const-string v1, "ZREVRANK"

    .line 794
    .line 795
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 796
    .line 797
    .line 798
    const-string v1, "ZSCORE"

    .line 799
    .line 800
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 801
    .line 802
    .line 803
    const-string v24, "ZUNION"

    .line 804
    .line 805
    const-string v25, "ZUNIONSTORE"

    .line 806
    .line 807
    const-string v6, "BZMPOP"

    .line 808
    .line 809
    const-string v7, "BZPOPMAX"

    .line 810
    .line 811
    const-string v8, "BZPOPMIN"

    .line 812
    .line 813
    const-string v9, "ZCARD"

    .line 814
    .line 815
    const-string v10, "ZDIFF"

    .line 816
    .line 817
    const-string v11, "ZDIFFSTORE"

    .line 818
    .line 819
    const-string v12, "ZINTER"

    .line 820
    .line 821
    const-string v13, "ZINTERCARD"

    .line 822
    .line 823
    const-string v14, "ZINTERSTORE"

    .line 824
    .line 825
    const-string v15, "ZMPOP"

    .line 826
    .line 827
    const-string v16, "ZPOPMAX"

    .line 828
    .line 829
    const-string v17, "ZPOPMIN"

    .line 830
    .line 831
    const-string v18, "ZRANDMEMBER"

    .line 832
    .line 833
    const-string v19, "ZRANGE"

    .line 834
    .line 835
    const-string v20, "ZRANGESTORE"

    .line 836
    .line 837
    const-string v21, "ZREMRANGEBYRANK"

    .line 838
    .line 839
    const-string v22, "ZREVRANGE"

    .line 840
    .line 841
    const-string v23, "ZSCAN"

    .line 842
    .line 843
    filled-new-array/range {v6 .. v25}, [Ljava/lang/String;

    .line 844
    .line 845
    .line 846
    move-result-object v1

    .line 847
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 848
    .line 849
    .line 850
    move-result-object v1

    .line 851
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 852
    .line 853
    .line 854
    move-result-object v1

    .line 855
    :goto_a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 856
    .line 857
    .line 858
    move-result v6

    .line 859
    if-eqz v6, :cond_a

    .line 860
    .line 861
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 862
    .line 863
    .line 864
    move-result-object v6

    .line 865
    check-cast v6, Ljava/lang/String;

    .line 866
    .line 867
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 868
    .line 869
    invoke-virtual {v0, v6, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 870
    .line 871
    .line 872
    goto :goto_a

    .line 873
    :cond_a
    new-instance v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;

    .line 874
    .line 875
    invoke-direct {v1, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$MultiKeyValue;-><init>(I)V

    .line 876
    .line 877
    .line 878
    const-string v5, "XADD"

    .line 879
    .line 880
    invoke-virtual {v0, v5, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 881
    .line 882
    .line 883
    const-string v17, "XREVRANGE"

    .line 884
    .line 885
    const-string v18, "XTRIM"

    .line 886
    .line 887
    const-string v6, "XACK"

    .line 888
    .line 889
    const-string v7, "XAUTOCLAIM"

    .line 890
    .line 891
    const-string v8, "XCLAIM"

    .line 892
    .line 893
    const-string v9, "XDEL"

    .line 894
    .line 895
    const-string v10, "XGROUP"

    .line 896
    .line 897
    const-string v11, "XINFO"

    .line 898
    .line 899
    const-string v12, "XLEN"

    .line 900
    .line 901
    const-string v13, "XPENDING"

    .line 902
    .line 903
    const-string v14, "XRANGE"

    .line 904
    .line 905
    const-string v15, "XREAD"

    .line 906
    .line 907
    const-string v16, "XREADGROUP"

    .line 908
    .line 909
    filled-new-array/range {v6 .. v18}, [Ljava/lang/String;

    .line 910
    .line 911
    .line 912
    move-result-object v1

    .line 913
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 914
    .line 915
    .line 916
    move-result-object v1

    .line 917
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 918
    .line 919
    .line 920
    move-result-object v1

    .line 921
    :goto_b
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 922
    .line 923
    .line 924
    move-result v5

    .line 925
    if-eqz v5, :cond_b

    .line 926
    .line 927
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v5

    .line 931
    check-cast v5, Ljava/lang/String;

    .line 932
    .line 933
    sget-object v6, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 934
    .line 935
    invoke-virtual {v0, v5, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    goto :goto_b

    .line 939
    :cond_b
    const-string v1, "APPEND"

    .line 940
    .line 941
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 942
    .line 943
    .line 944
    const-string v1, "GETSET"

    .line 945
    .line 946
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 947
    .line 948
    .line 949
    const-string v1, "MSET"

    .line 950
    .line 951
    invoke-virtual {v0, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 952
    .line 953
    .line 954
    const-string v1, "MSETNX"

    .line 955
    .line 956
    invoke-virtual {v0, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 957
    .line 958
    .line 959
    const-string v1, "PSETEX"

    .line 960
    .line 961
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 962
    .line 963
    .line 964
    const-string v1, "SET"

    .line 965
    .line 966
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 967
    .line 968
    .line 969
    const-string v1, "SETEX"

    .line 970
    .line 971
    invoke-virtual {v0, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 972
    .line 973
    .line 974
    const-string v1, "SETNX"

    .line 975
    .line 976
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 977
    .line 978
    .line 979
    const-string v1, "SETRANGE"

    .line 980
    .line 981
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 982
    .line 983
    .line 984
    const-string v21, "STRALGO"

    .line 985
    .line 986
    const-string v22, "STRLEN"

    .line 987
    .line 988
    const-string v3, "BITCOUNT"

    .line 989
    .line 990
    const-string v4, "BITFIELD"

    .line 991
    .line 992
    const-string v5, "BITFIELD_RO"

    .line 993
    .line 994
    const-string v6, "BITOP"

    .line 995
    .line 996
    const-string v7, "BITPOS"

    .line 997
    .line 998
    const-string v8, "DECR"

    .line 999
    .line 1000
    const-string v9, "DECRBY"

    .line 1001
    .line 1002
    const-string v10, "GET"

    .line 1003
    .line 1004
    const-string v11, "GETBIT"

    .line 1005
    .line 1006
    const-string v12, "GETDEL"

    .line 1007
    .line 1008
    const-string v13, "GETEX"

    .line 1009
    .line 1010
    const-string v14, "GETRANGE"

    .line 1011
    .line 1012
    const-string v15, "INCR"

    .line 1013
    .line 1014
    const-string v16, "INCRBY"

    .line 1015
    .line 1016
    const-string v17, "INCRBYFLOAT"

    .line 1017
    .line 1018
    const-string v18, "LCS"

    .line 1019
    .line 1020
    const-string v19, "MGET"

    .line 1021
    .line 1022
    const-string v20, "SETBIT"

    .line 1023
    .line 1024
    filled-new-array/range {v3 .. v22}, [Ljava/lang/String;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v1

    .line 1028
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v1

    .line 1032
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v1

    .line 1036
    :goto_c
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1037
    .line 1038
    .line 1039
    move-result v2

    .line 1040
    if-eqz v2, :cond_c

    .line 1041
    .line 1042
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1043
    .line 1044
    .line 1045
    move-result-object v2

    .line 1046
    check-cast v2, Ljava/lang/String;

    .line 1047
    .line 1048
    sget-object v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 1049
    .line 1050
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1051
    .line 1052
    .line 1053
    goto :goto_c

    .line 1054
    :cond_c
    const-string v1, "UNWATCH"

    .line 1055
    .line 1056
    const-string v2, "WATCH"

    .line 1057
    .line 1058
    const-string v3, "DISCARD"

    .line 1059
    .line 1060
    const-string v4, "EXEC"

    .line 1061
    .line 1062
    const-string v5, "MULTI"

    .line 1063
    .line 1064
    filled-new-array {v3, v4, v5, v1, v2}, [Ljava/lang/String;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v1

    .line 1068
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v1

    .line 1072
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1073
    .line 1074
    .line 1075
    move-result-object v1

    .line 1076
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1077
    .line 1078
    .line 1079
    move-result v2

    .line 1080
    if-eqz v2, :cond_d

    .line 1081
    .line 1082
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1083
    .line 1084
    .line 1085
    move-result-object v2

    .line 1086
    check-cast v2, Ljava/lang/String;

    .line 1087
    .line 1088
    sget-object v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 1089
    .line 1090
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1091
    .line 1092
    .line 1093
    goto :goto_d

    .line 1094
    :cond_d
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v0

    .line 1098
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->SANITIZERS:Ljava/util/Map;

    .line 1099
    .line 1100
    return-void
.end method

.method private constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->statementSanitizationEnabled:Z

    .line 5
    .line 6
    return-void
.end method

.method public static argToString(Ljava/lang/Object;)Ljava/lang/String;
    .locals 2

    .line 1
    instance-of v0, p0, [B

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/lang/String;

    .line 6
    .line 7
    check-cast p0, [B

    .line 8
    .line 9
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 10
    .line 11
    invoke-direct {v0, p0, v1}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static create(Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public sanitize(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "*>;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->statementSanitizationEnabled:Z

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 6
    .line 7
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->sanitize(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->SANITIZERS:Ljava/util/Map;

    .line 13
    .line 14
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;

    .line 21
    .line 22
    invoke-interface {p0, v0, v1}, Ljava/util/Map;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;

    .line 27
    .line 28
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;->sanitize(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
