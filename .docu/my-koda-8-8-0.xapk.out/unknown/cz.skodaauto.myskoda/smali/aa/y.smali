.class public final synthetic Laa/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroid/content/Context;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;I)V
    .locals 0

    .line 1
    iput p2, p0, Laa/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/y;->e:Landroid/content/Context;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Laa/y;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lhi/a;

    .line 7
    .line 8
    const-string v0, "$this$single"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Laa/y;->e:Landroid/content/Context;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string p1, "getApplicationContext(...)"

    .line 20
    .line 21
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    check-cast p1, Lhi/c;

    .line 26
    .line 27
    const-string v0, "$this$module"

    .line 28
    .line 29
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Lt40/a;

    .line 33
    .line 34
    const/16 v1, 0x13

    .line 35
    .line 36
    invoke-direct {v0, v1}, Lt40/a;-><init>(I)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Lii/b;

    .line 40
    .line 41
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 42
    .line 43
    const-class v3, Lrc/b;

    .line 44
    .line 45
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-direct {v1, v4, v0, v3}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p1, Lhi/c;->a:Ljava/util/ArrayList;

    .line 54
    .line 55
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    new-instance v0, Lt40/a;

    .line 59
    .line 60
    const/16 v1, 0x14

    .line 61
    .line 62
    invoke-direct {v0, v1}, Lt40/a;-><init>(I)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lii/b;

    .line 66
    .line 67
    const-class v3, Lvy0/b0;

    .line 68
    .line 69
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    const/4 v5, 0x1

    .line 74
    invoke-direct {v1, v5, v0, v3}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    new-instance v0, Lt40/a;

    .line 81
    .line 82
    const/16 v3, 0x15

    .line 83
    .line 84
    invoke-direct {v0, v3}, Lt40/a;-><init>(I)V

    .line 85
    .line 86
    .line 87
    iput-object v0, v1, Lii/b;->e:Lt40/a;

    .line 88
    .line 89
    new-instance v0, Laa/y;

    .line 90
    .line 91
    const/4 v1, 0x4

    .line 92
    iget-object p0, p0, Laa/y;->e:Landroid/content/Context;

    .line 93
    .line 94
    invoke-direct {v0, p0, v1}, Laa/y;-><init>(Landroid/content/Context;I)V

    .line 95
    .line 96
    .line 97
    new-instance p0, Lii/b;

    .line 98
    .line 99
    const-class v1, Landroid/content/Context;

    .line 100
    .line 101
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-direct {p0, v4, v0, v1}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    new-instance p0, Lt40/a;

    .line 112
    .line 113
    const/16 v0, 0x16

    .line 114
    .line 115
    invoke-direct {p0, v0}, Lt40/a;-><init>(I)V

    .line 116
    .line 117
    .line 118
    new-instance v0, Lii/b;

    .line 119
    .line 120
    const-class v1, Lwi/a;

    .line 121
    .line 122
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    invoke-direct {v0, v4, p0, v1}, Lii/b;-><init>(ZLay0/k;Lhy0/d;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    return-object p0

    .line 135
    :pswitch_1
    check-cast p1, Ljava/io/File;

    .line 136
    .line 137
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    const-string v1, "file"

    .line 140
    .line 141
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    const-string v1, "<this>"

    .line 145
    .line 146
    iget-object p0, p0, Laa/y;->e:Landroid/content/Context;

    .line 147
    .line 148
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    :try_start_0
    const-string v1, "android.intent.action.VIEW"

    .line 152
    .line 153
    invoke-static {p0, v1, p1}, Ljp/jd;->a(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/content/Intent;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    invoke-virtual {p0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 158
    .line 159
    .line 160
    move-object v1, v0

    .line 161
    goto :goto_0

    .line 162
    :catchall_0
    move-exception v1

    .line 163
    invoke-static {v1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    :goto_0
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    if-eqz v1, :cond_0

    .line 172
    .line 173
    :try_start_1
    const-string v1, "android.intent.action.SEND"

    .line 174
    .line 175
    invoke-static {p0, v1, p1}, Ljp/jd;->a(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/content/Intent;

    .line 176
    .line 177
    .line 178
    move-result-object p1

    .line 179
    invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 180
    .line 181
    .line 182
    goto :goto_1

    .line 183
    :catchall_1
    move-exception p0

    .line 184
    invoke-static {p0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 185
    .line 186
    .line 187
    :cond_0
    :goto_1
    return-object v0

    .line 188
    :pswitch_2
    iget-object p0, p0, Laa/y;->e:Landroid/content/Context;

    .line 189
    .line 190
    check-cast p1, Ljava/lang/String;

    .line 191
    .line 192
    const-string v0, "uriString"

    .line 193
    .line 194
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    invoke-virtual {p1}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    if-eqz v0, :cond_5

    .line 206
    .line 207
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 208
    .line 209
    .line 210
    move-result v1

    .line 211
    const v2, -0x40777d8e

    .line 212
    .line 213
    .line 214
    if-eq v1, v2, :cond_3

    .line 215
    .line 216
    const v2, 0x1c01b

    .line 217
    .line 218
    .line 219
    if-eq v1, v2, :cond_1

    .line 220
    .line 221
    goto :goto_2

    .line 222
    :cond_1
    const-string v1, "tel"

    .line 223
    .line 224
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move-result v0

    .line 228
    if-nez v0, :cond_2

    .line 229
    .line 230
    goto :goto_2

    .line 231
    :cond_2
    const-string v0, "android.intent.action.DIAL"

    .line 232
    .line 233
    goto :goto_3

    .line 234
    :cond_3
    const-string v1, "mailto"

    .line 235
    .line 236
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v0

    .line 240
    if-nez v0, :cond_4

    .line 241
    .line 242
    goto :goto_2

    .line 243
    :cond_4
    const-string v0, "android.intent.action.SENDTO"

    .line 244
    .line 245
    goto :goto_3

    .line 246
    :cond_5
    :goto_2
    const-string v0, "android.intent.action.VIEW"

    .line 247
    .line 248
    :goto_3
    new-instance v1, Landroid/content/Intent;

    .line 249
    .line 250
    invoke-direct {v1, v0, p1}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 251
    .line 252
    .line 253
    :try_start_2
    invoke-virtual {p0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 254
    .line 255
    .line 256
    :catch_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 257
    .line 258
    return-object p0

    .line 259
    :pswitch_3
    check-cast p1, Landroid/os/Bundle;

    .line 260
    .line 261
    iget-object p0, p0, Laa/y;->e:Landroid/content/Context;

    .line 262
    .line 263
    invoke-static {p0}, Ljp/t0;->a(Landroid/content/Context;)Lz9/y;

    .line 264
    .line 265
    .line 266
    move-result-object p0

    .line 267
    if-eqz p1, :cond_6

    .line 268
    .line 269
    iget-object v0, p0, Lz9/y;->a:Landroid/content/Context;

    .line 270
    .line 271
    invoke-virtual {v0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 276
    .line 277
    .line 278
    :cond_6
    iget-object v0, p0, Lz9/y;->b:Lca/g;

    .line 279
    .line 280
    iget-object v1, v0, Lca/g;->m:Ljava/util/LinkedHashMap;

    .line 281
    .line 282
    const/4 v2, 0x0

    .line 283
    const/4 v3, 0x0

    .line 284
    if-nez p1, :cond_7

    .line 285
    .line 286
    goto/16 :goto_a

    .line 287
    .line 288
    :cond_7
    const-string v4, "android-support-nav:controller:navigatorState"

    .line 289
    .line 290
    invoke-virtual {p1, v4}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 291
    .line 292
    .line 293
    move-result v5

    .line 294
    if-eqz v5, :cond_8

    .line 295
    .line 296
    invoke-static {v4, p1}, Lkp/t;->e(Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 297
    .line 298
    .line 299
    move-result-object v4

    .line 300
    goto :goto_4

    .line 301
    :cond_8
    move-object v4, v2

    .line 302
    :goto_4
    iput-object v4, v0, Lca/g;->d:Landroid/os/Bundle;

    .line 303
    .line 304
    const-string v4, "android-support-nav:controller:backStack"

    .line 305
    .line 306
    invoke-virtual {p1, v4}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 307
    .line 308
    .line 309
    move-result v5

    .line 310
    if-eqz v5, :cond_9

    .line 311
    .line 312
    invoke-static {v4, p1}, Lkp/t;->f(Ljava/lang/String;Landroid/os/Bundle;)Ljava/util/ArrayList;

    .line 313
    .line 314
    .line 315
    move-result-object v4

    .line 316
    new-array v5, v3, [Landroid/os/Bundle;

    .line 317
    .line 318
    invoke-interface {v4, v5}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 319
    .line 320
    .line 321
    move-result-object v4

    .line 322
    check-cast v4, [Landroid/os/Bundle;

    .line 323
    .line 324
    goto :goto_5

    .line 325
    :cond_9
    move-object v4, v2

    .line 326
    :goto_5
    iput-object v4, v0, Lca/g;->e:[Landroid/os/Bundle;

    .line 327
    .line 328
    invoke-virtual {v1}, Ljava/util/LinkedHashMap;->clear()V

    .line 329
    .line 330
    .line 331
    const-string v4, "android-support-nav:controller:backStackDestIds"

    .line 332
    .line 333
    invoke-virtual {p1, v4}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 334
    .line 335
    .line 336
    move-result v5

    .line 337
    if-eqz v5, :cond_d

    .line 338
    .line 339
    const-string v5, "android-support-nav:controller:backStackIds"

    .line 340
    .line 341
    invoke-virtual {p1, v5}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 342
    .line 343
    .line 344
    move-result v6

    .line 345
    if-eqz v6, :cond_d

    .line 346
    .line 347
    invoke-virtual {p1, v4}, Landroid/os/BaseBundle;->getIntArray(Ljava/lang/String;)[I

    .line 348
    .line 349
    .line 350
    move-result-object v6

    .line 351
    if-eqz v6, :cond_c

    .line 352
    .line 353
    invoke-virtual {p1, v5}, Landroid/os/Bundle;->getStringArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 354
    .line 355
    .line 356
    move-result-object v4

    .line 357
    if-eqz v4, :cond_b

    .line 358
    .line 359
    array-length v5, v6

    .line 360
    move v7, v3

    .line 361
    move v8, v7

    .line 362
    :goto_6
    if-ge v7, v5, :cond_d

    .line 363
    .line 364
    aget v9, v6, v7

    .line 365
    .line 366
    add-int/lit8 v10, v8, 0x1

    .line 367
    .line 368
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 369
    .line 370
    .line 371
    move-result-object v9

    .line 372
    iget-object v11, v0, Lca/g;->l:Ljava/util/LinkedHashMap;

    .line 373
    .line 374
    invoke-interface {v4, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v12

    .line 378
    const-string v13, ""

    .line 379
    .line 380
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 381
    .line 382
    .line 383
    move-result v12

    .line 384
    if-nez v12, :cond_a

    .line 385
    .line 386
    invoke-interface {v4, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v8

    .line 390
    check-cast v8, Ljava/lang/String;

    .line 391
    .line 392
    goto :goto_7

    .line 393
    :cond_a
    move-object v8, v2

    .line 394
    :goto_7
    invoke-interface {v11, v9, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    add-int/lit8 v7, v7, 0x1

    .line 398
    .line 399
    move v8, v10

    .line 400
    goto :goto_6

    .line 401
    :cond_b
    invoke-static {v5}, Lkp/u;->a(Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    throw v2

    .line 405
    :cond_c
    invoke-static {v4}, Lkp/u;->a(Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    throw v2

    .line 409
    :cond_d
    const-string v0, "android-support-nav:controller:backStackStates"

    .line 410
    .line 411
    invoke-virtual {p1, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 412
    .line 413
    .line 414
    move-result v4

    .line 415
    if-eqz v4, :cond_11

    .line 416
    .line 417
    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getStringArrayList(Ljava/lang/String;)Ljava/util/ArrayList;

    .line 418
    .line 419
    .line 420
    move-result-object v4

    .line 421
    if-eqz v4, :cond_10

    .line 422
    .line 423
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    :cond_e
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 428
    .line 429
    .line 430
    move-result v4

    .line 431
    if-eqz v4, :cond_11

    .line 432
    .line 433
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v4

    .line 437
    check-cast v4, Ljava/lang/String;

    .line 438
    .line 439
    new-instance v5, Ljava/lang/StringBuilder;

    .line 440
    .line 441
    const-string v6, "android-support-nav:controller:backStackStates:"

    .line 442
    .line 443
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 447
    .line 448
    .line 449
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v5

    .line 453
    const-string v7, "key"

    .line 454
    .line 455
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    invoke-virtual {p1, v5}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 459
    .line 460
    .line 461
    move-result v5

    .line 462
    if-eqz v5, :cond_e

    .line 463
    .line 464
    new-instance v5, Ljava/lang/StringBuilder;

    .line 465
    .line 466
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 467
    .line 468
    .line 469
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 470
    .line 471
    .line 472
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 473
    .line 474
    .line 475
    move-result-object v5

    .line 476
    invoke-static {v5, p1}, Lkp/t;->f(Ljava/lang/String;Landroid/os/Bundle;)Ljava/util/ArrayList;

    .line 477
    .line 478
    .line 479
    move-result-object v5

    .line 480
    new-instance v6, Lmx0/l;

    .line 481
    .line 482
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 483
    .line 484
    .line 485
    move-result v7

    .line 486
    invoke-direct {v6, v7}, Lmx0/l;-><init>(I)V

    .line 487
    .line 488
    .line 489
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 490
    .line 491
    .line 492
    move-result-object v5

    .line 493
    :goto_9
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 494
    .line 495
    .line 496
    move-result v7

    .line 497
    if-eqz v7, :cond_f

    .line 498
    .line 499
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v7

    .line 503
    check-cast v7, Landroid/os/Bundle;

    .line 504
    .line 505
    new-instance v8, Lz9/l;

    .line 506
    .line 507
    invoke-direct {v8, v7}, Lz9/l;-><init>(Landroid/os/Bundle;)V

    .line 508
    .line 509
    .line 510
    invoke-virtual {v6, v8}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 511
    .line 512
    .line 513
    goto :goto_9

    .line 514
    :cond_f
    invoke-interface {v1, v4, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    goto :goto_8

    .line 518
    :cond_10
    invoke-static {v0}, Lkp/u;->a(Ljava/lang/String;)V

    .line 519
    .line 520
    .line 521
    throw v2

    .line 522
    :cond_11
    :goto_a
    if-eqz p1, :cond_14

    .line 523
    .line 524
    const-string v0, "android-support-nav:controller:deepLinkHandled"

    .line 525
    .line 526
    invoke-virtual {p1, v0, v3}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 527
    .line 528
    .line 529
    move-result v1

    .line 530
    if-nez v1, :cond_12

    .line 531
    .line 532
    const/4 v4, 0x1

    .line 533
    invoke-virtual {p1, v0, v4}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 534
    .line 535
    .line 536
    move-result p1

    .line 537
    if-ne p1, v4, :cond_12

    .line 538
    .line 539
    goto :goto_b

    .line 540
    :cond_12
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 541
    .line 542
    .line 543
    move-result-object v2

    .line 544
    :goto_b
    if-eqz v2, :cond_13

    .line 545
    .line 546
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 547
    .line 548
    .line 549
    move-result v3

    .line 550
    :cond_13
    iput-boolean v3, p0, Lz9/y;->e:Z

    .line 551
    .line 552
    :cond_14
    return-object p0

    .line 553
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
