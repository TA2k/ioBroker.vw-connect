.class public final synthetic Ldu/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/b;


# instance fields
.field public final synthetic d:Lc8/f;

.field public final synthetic e:Laq/t;

.field public final synthetic f:Laq/j;

.field public final synthetic g:J

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lc8/f;Laq/t;Laq/j;JI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldu/a;->d:Lc8/f;

    .line 5
    .line 6
    iput-object p2, p0, Ldu/a;->e:Laq/t;

    .line 7
    .line 8
    iput-object p3, p0, Ldu/a;->f:Laq/j;

    .line 9
    .line 10
    iput-wide p4, p0, Ldu/a;->g:J

    .line 11
    .line 12
    iput p6, p0, Ldu/a;->h:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final w(Laq/j;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object p1, p0, Ldu/a;->d:Lc8/f;

    .line 2
    .line 3
    iget-object v0, p0, Ldu/a;->e:Laq/t;

    .line 4
    .line 5
    iget-object v1, p0, Ldu/a;->f:Laq/j;

    .line 6
    .line 7
    iget-wide v2, p0, Ldu/a;->g:J

    .line 8
    .line 9
    iget p0, p0, Ldu/a;->h:I

    .line 10
    .line 11
    invoke-virtual {v0}, Laq/t;->i()Z

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    if-nez v4, :cond_0

    .line 16
    .line 17
    new-instance p0, Lcu/c;

    .line 18
    .line 19
    const-string p1, "Failed to auto-fetch config update."

    .line 20
    .line 21
    invoke-virtual {v0}, Laq/t;->f()Ljava/lang/Exception;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-direct {p0, p1, v0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0

    .line 33
    :cond_0
    invoke-virtual {v1}, Laq/j;->i()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-nez v4, :cond_1

    .line 38
    .line 39
    new-instance p0, Lcu/c;

    .line 40
    .line 41
    const-string p1, "Failed to get activated config for auto-fetch"

    .line 42
    .line 43
    invoke-virtual {v1}, Laq/j;->f()Ljava/lang/Exception;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-direct {p0, p1, v0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :cond_1
    invoke-virtual {v0}, Laq/t;->g()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    check-cast v0, Ldu/h;

    .line 60
    .line 61
    invoke-virtual {v1}, Laq/j;->g()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    check-cast v1, Ldu/e;

    .line 66
    .line 67
    iget-object v4, v0, Ldu/h;->b:Ldu/e;

    .line 68
    .line 69
    const/4 v5, 0x0

    .line 70
    const/4 v6, 0x1

    .line 71
    if-eqz v4, :cond_3

    .line 72
    .line 73
    iget-wide v7, v4, Ldu/e;->f:J

    .line 74
    .line 75
    cmp-long v4, v7, v2

    .line 76
    .line 77
    if-ltz v4, :cond_2

    .line 78
    .line 79
    move v5, v6

    .line 80
    :cond_2
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    goto :goto_0

    .line 85
    :cond_3
    iget v4, v0, Ldu/h;->a:I

    .line 86
    .line 87
    if-ne v4, v6, :cond_4

    .line 88
    .line 89
    move v5, v6

    .line 90
    :cond_4
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 91
    .line 92
    .line 93
    move-result-object v4

    .line 94
    :goto_0
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    const/4 v5, 0x0

    .line 99
    if-nez v4, :cond_5

    .line 100
    .line 101
    const-string v0, "FirebaseRemoteConfig"

    .line 102
    .line 103
    const-string v1, "Fetched template version is the same as SDK\'s current version. Retrying fetch."

    .line 104
    .line 105
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 106
    .line 107
    .line 108
    invoke-virtual {p1, p0, v2, v3}, Lc8/f;->a(IJ)V

    .line 109
    .line 110
    .line 111
    invoke-static {v5}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :cond_5
    iget-object p0, v0, Ldu/h;->b:Ldu/e;

    .line 117
    .line 118
    if-nez p0, :cond_6

    .line 119
    .line 120
    const-string p0, "FirebaseRemoteConfig"

    .line 121
    .line 122
    const-string p1, "The fetch succeeded, but the backend had no updates."

    .line 123
    .line 124
    invoke-static {p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 125
    .line 126
    .line 127
    invoke-static {v5}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    return-object p0

    .line 132
    :cond_6
    if-nez v1, :cond_7

    .line 133
    .line 134
    invoke-static {}, Ldu/e;->c()Ldu/d;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-virtual {p0}, Ldu/d;->a()Ldu/e;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    :cond_7
    iget-object p0, v0, Ldu/h;->b:Ldu/e;

    .line 143
    .line 144
    iget-object v0, v1, Ldu/e;->e:Lorg/json/JSONObject;

    .line 145
    .line 146
    iget-object v2, p0, Ldu/e;->a:Lorg/json/JSONObject;

    .line 147
    .line 148
    iget-object v3, p0, Ldu/e;->b:Lorg/json/JSONObject;

    .line 149
    .line 150
    iget-object v4, p0, Ldu/e;->e:Lorg/json/JSONObject;

    .line 151
    .line 152
    new-instance v6, Lorg/json/JSONObject;

    .line 153
    .line 154
    invoke-virtual {v2}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    invoke-direct {v6, v2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-static {v6}, Ldu/e;->a(Lorg/json/JSONObject;)Ldu/e;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    iget-object v2, v2, Ldu/e;->b:Lorg/json/JSONObject;

    .line 166
    .line 167
    invoke-virtual {v1}, Ldu/e;->b()Ljava/util/HashMap;

    .line 168
    .line 169
    .line 170
    move-result-object v6

    .line 171
    invoke-virtual {p0}, Ldu/e;->b()Ljava/util/HashMap;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    new-instance v7, Ljava/util/HashSet;

    .line 176
    .line 177
    invoke-direct {v7}, Ljava/util/HashSet;-><init>()V

    .line 178
    .line 179
    .line 180
    iget-object v1, v1, Ldu/e;->b:Lorg/json/JSONObject;

    .line 181
    .line 182
    invoke-virtual {v1}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 183
    .line 184
    .line 185
    move-result-object v8

    .line 186
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v9

    .line 190
    if-eqz v9, :cond_10

    .line 191
    .line 192
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v9

    .line 196
    check-cast v9, Ljava/lang/String;

    .line 197
    .line 198
    invoke-virtual {v3, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 199
    .line 200
    .line 201
    move-result v10

    .line 202
    if-nez v10, :cond_8

    .line 203
    .line 204
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_8
    invoke-virtual {v1, v9}, Lorg/json/JSONObject;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v10

    .line 212
    invoke-virtual {v3, v9}, Lorg/json/JSONObject;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v11

    .line 216
    invoke-virtual {v10, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v10

    .line 220
    if-nez v10, :cond_9

    .line 221
    .line 222
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    goto :goto_1

    .line 226
    :cond_9
    invoke-virtual {v0, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 227
    .line 228
    .line 229
    move-result v10

    .line 230
    if-eqz v10, :cond_a

    .line 231
    .line 232
    invoke-virtual {v4, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 233
    .line 234
    .line 235
    move-result v10

    .line 236
    if-eqz v10, :cond_b

    .line 237
    .line 238
    :cond_a
    invoke-virtual {v0, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 239
    .line 240
    .line 241
    move-result v10

    .line 242
    if-nez v10, :cond_c

    .line 243
    .line 244
    invoke-virtual {v4, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 245
    .line 246
    .line 247
    move-result v10

    .line 248
    if-eqz v10, :cond_c

    .line 249
    .line 250
    :cond_b
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 251
    .line 252
    .line 253
    goto :goto_1

    .line 254
    :cond_c
    invoke-virtual {v0, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 255
    .line 256
    .line 257
    move-result v10

    .line 258
    if-eqz v10, :cond_d

    .line 259
    .line 260
    invoke-virtual {v4, v9}, Lorg/json/JSONObject;->has(Ljava/lang/String;)Z

    .line 261
    .line 262
    .line 263
    move-result v10

    .line 264
    if-eqz v10, :cond_d

    .line 265
    .line 266
    invoke-virtual {v0, v9}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 267
    .line 268
    .line 269
    move-result-object v10

    .line 270
    invoke-virtual {v10}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v10

    .line 274
    invoke-virtual {v4, v9}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 275
    .line 276
    .line 277
    move-result-object v11

    .line 278
    invoke-virtual {v11}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v11

    .line 282
    invoke-virtual {v10, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    move-result v10

    .line 286
    if-nez v10, :cond_d

    .line 287
    .line 288
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    goto :goto_1

    .line 292
    :cond_d
    invoke-virtual {v6, v9}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v10

    .line 296
    invoke-virtual {p0, v9}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v11

    .line 300
    if-eq v10, v11, :cond_e

    .line 301
    .line 302
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    goto :goto_1

    .line 306
    :cond_e
    invoke-virtual {v6, v9}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v10

    .line 310
    if-eqz v10, :cond_f

    .line 311
    .line 312
    invoke-virtual {p0, v9}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result v10

    .line 316
    if-eqz v10, :cond_f

    .line 317
    .line 318
    invoke-virtual {v6, v9}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v10

    .line 322
    check-cast v10, Ljava/util/Map;

    .line 323
    .line 324
    invoke-virtual {p0, v9}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v11

    .line 328
    invoke-interface {v10, v11}, Ljava/util/Map;->equals(Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    move-result v10

    .line 332
    if-nez v10, :cond_f

    .line 333
    .line 334
    invoke-virtual {v7, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    goto/16 :goto_1

    .line 338
    .line 339
    :cond_f
    invoke-virtual {v2, v9}, Lorg/json/JSONObject;->remove(Ljava/lang/String;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    goto/16 :goto_1

    .line 343
    .line 344
    :cond_10
    invoke-virtual {v2}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 349
    .line 350
    .line 351
    move-result v0

    .line 352
    if-eqz v0, :cond_11

    .line 353
    .line 354
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    check-cast v0, Ljava/lang/String;

    .line 359
    .line 360
    invoke-virtual {v7, v0}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    goto :goto_2

    .line 364
    :cond_11
    invoke-virtual {v7}, Ljava/util/HashSet;->isEmpty()Z

    .line 365
    .line 366
    .line 367
    move-result p0

    .line 368
    if-eqz p0, :cond_12

    .line 369
    .line 370
    const-string p0, "FirebaseRemoteConfig"

    .line 371
    .line 372
    const-string p1, "Config was fetched, but no params changed."

    .line 373
    .line 374
    invoke-static {p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 375
    .line 376
    .line 377
    invoke-static {v5}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 378
    .line 379
    .line 380
    move-result-object p0

    .line 381
    return-object p0

    .line 382
    :cond_12
    monitor-enter p1

    .line 383
    :try_start_0
    iget-object p0, p1, Lc8/f;->b:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 386
    .line 387
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 388
    .line 389
    .line 390
    move-result-object p0

    .line 391
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 392
    .line 393
    .line 394
    move-result v0

    .line 395
    if-eqz v0, :cond_13

    .line 396
    .line 397
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v0

    .line 401
    check-cast v0, Ldu/k;

    .line 402
    .line 403
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 404
    .line 405
    .line 406
    goto :goto_3

    .line 407
    :catchall_0
    move-exception p0

    .line 408
    goto :goto_4

    .line 409
    :cond_13
    monitor-exit p1

    .line 410
    invoke-static {v5}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 411
    .line 412
    .line 413
    move-result-object p0

    .line 414
    return-object p0

    .line 415
    :goto_4
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 416
    throw p0
.end method
