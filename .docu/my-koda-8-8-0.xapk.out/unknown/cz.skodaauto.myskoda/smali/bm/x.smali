.class public final synthetic Lbm/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Les/d;Lwq/f;)V
    .locals 0

    .line 1
    const/4 p2, 0x3

    iput p2, p0, Lbm/x;->a:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbm/x;->b:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lbm/x;->a:I

    iput-object p1, p0, Lbm/x;->b:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lbm/x;->a:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    iget-object p0, p0, Lbm/x;->b:Ljava/lang/Object;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p0, Lb81/b;

    .line 12
    .line 13
    iget-object p0, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lqn/s;

    .line 16
    .line 17
    iget-object v0, p0, Lqn/s;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lj51/i;

    .line 20
    .line 21
    iget-object p0, p0, Lqn/s;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lus/c;

    .line 24
    .line 25
    iget-object v2, v0, Lj51/i;->b:Ljava/lang/String;

    .line 26
    .line 27
    const-string v4, "FirebaseCrashlytics"

    .line 28
    .line 29
    const-string v5, "Settings query params were: "

    .line 30
    .line 31
    const-string v6, "Requesting settings from "

    .line 32
    .line 33
    invoke-static {}, Lns/d;->b()V

    .line 34
    .line 35
    .line 36
    :try_start_0
    invoke-static {p0}, Lj51/i;->b(Lus/c;)Ljava/util/HashMap;

    .line 37
    .line 38
    .line 39
    move-result-object v7

    .line 40
    new-instance v8, Lrn/i;

    .line 41
    .line 42
    invoke-direct {v8, v2, v7}, Lrn/i;-><init>(Ljava/lang/String;Ljava/util/HashMap;)V

    .line 43
    .line 44
    .line 45
    const-string v9, "User-Agent"

    .line 46
    .line 47
    const-string v10, "Crashlytics Android SDK/20.0.3"

    .line 48
    .line 49
    invoke-virtual {v8, v9, v10}, Lrn/i;->v(Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string v9, "X-CRASHLYTICS-DEVELOPER-TOKEN"

    .line 53
    .line 54
    const-string v10, "470fa2b4ae81cd56ecbcda9735803434cec591fa"

    .line 55
    .line 56
    invoke-virtual {v8, v9, v10}, Lrn/i;->v(Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-static {v8, p0}, Lj51/i;->a(Lrn/i;Lus/c;)V

    .line 60
    .line 61
    .line 62
    new-instance p0, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    invoke-direct {p0, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    const/4 v2, 0x3

    .line 75
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_0

    .line 80
    .line 81
    invoke-static {v4, p0, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 82
    .line 83
    .line 84
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {p0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    invoke-static {v4, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_1

    .line 101
    .line 102
    invoke-static {v4, p0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 103
    .line 104
    .line 105
    :cond_1
    invoke-virtual {v8}, Lrn/i;->s()Lrs/a;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {v0, p0}, Lj51/i;->c(Lrs/a;)Lorg/json/JSONObject;

    .line 110
    .line 111
    .line 112
    move-result-object v3
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    goto :goto_0

    .line 114
    :catch_0
    move-exception p0

    .line 115
    const-string v0, "Settings request failed."

    .line 116
    .line 117
    invoke-static {v4, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 118
    .line 119
    .line 120
    :goto_0
    return-object v3

    .line 121
    :pswitch_0
    check-cast p0, Lms/p;

    .line 122
    .line 123
    iget-object p0, p0, Lms/p;->h:Lms/l;

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    const-string v0, "FirebaseCrashlytics"

    .line 129
    .line 130
    invoke-static {}, Lns/d;->a()V

    .line 131
    .line 132
    .line 133
    iget-object v4, p0, Lms/l;->c:Lb81/c;

    .line 134
    .line 135
    iget-object v5, v4, Lb81/c;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v5, Lss/b;

    .line 138
    .line 139
    iget-object v6, v4, Lb81/c;->e:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v6, Ljava/lang/String;

    .line 142
    .line 143
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    new-instance v7, Ljava/io/File;

    .line 147
    .line 148
    iget-object v5, v5, Lss/b;->g:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v5, Ljava/io/File;

    .line 151
    .line 152
    invoke-direct {v7, v5, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v7}, Ljava/io/File;->exists()Z

    .line 156
    .line 157
    .line 158
    move-result v5

    .line 159
    const/4 v7, 0x1

    .line 160
    if-nez v5, :cond_2

    .line 161
    .line 162
    invoke-virtual {p0}, Lms/l;->e()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    if-eqz v0, :cond_4

    .line 167
    .line 168
    iget-object p0, p0, Lms/l;->j:Ljs/a;

    .line 169
    .line 170
    invoke-virtual {p0, v0}, Ljs/a;->c(Ljava/lang/String;)Z

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    if-eqz p0, :cond_4

    .line 175
    .line 176
    :goto_1
    move v2, v7

    .line 177
    goto :goto_2

    .line 178
    :cond_2
    const-string p0, "Found previous crash marker."

    .line 179
    .line 180
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 181
    .line 182
    .line 183
    move-result v1

    .line 184
    if-eqz v1, :cond_3

    .line 185
    .line 186
    invoke-static {v0, p0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 187
    .line 188
    .line 189
    :cond_3
    iget-object p0, v4, Lb81/c;->f:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast p0, Lss/b;

    .line 192
    .line 193
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 194
    .line 195
    .line 196
    new-instance v0, Ljava/io/File;

    .line 197
    .line 198
    iget-object p0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast p0, Ljava/io/File;

    .line 201
    .line 202
    invoke-direct {v0, p0, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 206
    .line 207
    .line 208
    goto :goto_1

    .line 209
    :cond_4
    :goto_2
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    return-object p0

    .line 214
    :pswitch_1
    check-cast p0, Les/d;

    .line 215
    .line 216
    iget-object v0, p0, Les/d;->c:Landroidx/lifecycle/c1;

    .line 217
    .line 218
    new-instance v1, Lorg/json/JSONObject;

    .line 219
    .line 220
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v1}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v1

    .line 227
    const-string v4, "UTF-8"

    .line 228
    .line 229
    invoke-virtual {v1, v4}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    iget-object p0, p0, Les/d;->f:Las/e;

    .line 234
    .line 235
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    iget-wide v4, p0, Las/e;->b:J

    .line 239
    .line 240
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 241
    .line 242
    .line 243
    move-result-wide v6

    .line 244
    cmp-long v4, v4, v6

    .line 245
    .line 246
    if-gtz v4, :cond_8

    .line 247
    .line 248
    new-instance v4, Ljava/net/URL;

    .line 249
    .line 250
    iget-object v5, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v5, Ljava/lang/String;

    .line 253
    .line 254
    iget-object v6, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 255
    .line 256
    check-cast v6, Ljava/lang/String;

    .line 257
    .line 258
    iget-object v7, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast v7, Ljava/lang/String;

    .line 261
    .line 262
    const-string v8, "https://firebaseappcheck.googleapis.com/v1/projects/"

    .line 263
    .line 264
    const-string v9, "/apps/"

    .line 265
    .line 266
    const-string v10, ":generatePlayIntegrityChallenge?key="

    .line 267
    .line 268
    invoke-static {v8, v5, v9, v6, v10}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 269
    .line 270
    .line 271
    move-result-object v5

    .line 272
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    invoke-direct {v4, v5}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v4, v1, p0, v2}, Landroidx/lifecycle/c1;->D(Ljava/net/URL;[BLas/e;Z)Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    new-instance v0, Lorg/json/JSONObject;

    .line 287
    .line 288
    invoke-direct {v0, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    const-string p0, "challenge"

    .line 292
    .line 293
    invoke-virtual {v0, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    sget v1, Lto/c;->a:I

    .line 298
    .line 299
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 300
    .line 301
    .line 302
    move-result v1

    .line 303
    if-eqz v1, :cond_5

    .line 304
    .line 305
    move-object p0, v3

    .line 306
    :cond_5
    const-string v1, "ttl"

    .line 307
    .line 308
    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 313
    .line 314
    .line 315
    move-result v1

    .line 316
    if-eqz v1, :cond_6

    .line 317
    .line 318
    goto :goto_3

    .line 319
    :cond_6
    move-object v3, v0

    .line 320
    :goto_3
    if-eqz p0, :cond_7

    .line 321
    .line 322
    if-eqz v3, :cond_7

    .line 323
    .line 324
    new-instance v0, Les/b;

    .line 325
    .line 326
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 327
    .line 328
    .line 329
    iput-object p0, v0, Les/b;->a:Ljava/lang/String;

    .line 330
    .line 331
    return-object v0

    .line 332
    :cond_7
    new-instance p0, Lsr/h;

    .line 333
    .line 334
    const-string v0, "Unexpected server response."

    .line 335
    .line 336
    invoke-direct {p0, v0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    throw p0

    .line 340
    :cond_8
    new-instance p0, Lsr/h;

    .line 341
    .line 342
    const-string v0, "Too many attempts."

    .line 343
    .line 344
    invoke-direct {p0, v0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    throw p0

    .line 348
    :pswitch_2
    check-cast p0, Ldu/o;

    .line 349
    .line 350
    monitor-enter p0

    .line 351
    :try_start_1
    iget-object v0, p0, Ldu/o;->a:Landroid/content/Context;

    .line 352
    .line 353
    iget-object v1, p0, Ldu/o;->b:Ljava/lang/String;

    .line 354
    .line 355
    invoke-virtual {v0, v1}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;

    .line 356
    .line 357
    .line 358
    move-result-object v0
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 359
    :try_start_2
    invoke-virtual {v0}, Ljava/io/FileInputStream;->available()I

    .line 360
    .line 361
    .line 362
    move-result v1

    .line 363
    new-array v4, v1, [B

    .line 364
    .line 365
    invoke-virtual {v0, v4, v2, v1}, Ljava/io/FileInputStream;->read([BII)I

    .line 366
    .line 367
    .line 368
    new-instance v1, Ljava/lang/String;

    .line 369
    .line 370
    const-string v2, "UTF-8"

    .line 371
    .line 372
    invoke-direct {v1, v4, v2}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    .line 373
    .line 374
    .line 375
    new-instance v2, Lorg/json/JSONObject;

    .line 376
    .line 377
    invoke-direct {v2, v1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    invoke-static {v2}, Ldu/e;->a(Lorg/json/JSONObject;)Ldu/e;

    .line 381
    .line 382
    .line 383
    move-result-object v3
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 384
    :try_start_3
    invoke-virtual {v0}, Ljava/io/FileInputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 385
    .line 386
    .line 387
    monitor-exit p0

    .line 388
    goto :goto_8

    .line 389
    :catchall_0
    move-exception v0

    .line 390
    goto :goto_6

    .line 391
    :catchall_1
    move-exception v1

    .line 392
    move-object v3, v0

    .line 393
    goto :goto_4

    .line 394
    :catchall_2
    move-exception v1

    .line 395
    goto :goto_4

    .line 396
    :catch_1
    move-object v0, v3

    .line 397
    goto :goto_5

    .line 398
    :goto_4
    if-eqz v3, :cond_9

    .line 399
    .line 400
    :try_start_4
    invoke-virtual {v3}, Ljava/io/FileInputStream;->close()V

    .line 401
    .line 402
    .line 403
    :cond_9
    throw v1

    .line 404
    :catch_2
    :goto_5
    if-eqz v0, :cond_a

    .line 405
    .line 406
    invoke-virtual {v0}, Ljava/io/FileInputStream;->close()V

    .line 407
    .line 408
    .line 409
    goto :goto_7

    .line 410
    :goto_6
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 411
    throw v0

    .line 412
    :cond_a
    :goto_7
    monitor-exit p0

    .line 413
    :goto_8
    return-object v3

    .line 414
    :pswitch_3
    check-cast p0, Lcu/j;

    .line 415
    .line 416
    const-string v0, "firebase"

    .line 417
    .line 418
    invoke-virtual {p0, v0}, Lcu/j;->a(Ljava/lang/String;)Lcu/b;

    .line 419
    .line 420
    .line 421
    move-result-object p0

    .line 422
    return-object p0

    .line 423
    :pswitch_4
    check-cast p0, Landroid/content/res/AssetFileDescriptor;

    .line 424
    .line 425
    return-object p0

    .line 426
    nop

    .line 427
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
