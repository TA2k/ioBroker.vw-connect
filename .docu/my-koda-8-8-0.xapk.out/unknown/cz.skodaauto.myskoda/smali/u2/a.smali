.class public final synthetic Lu2/a;
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
    iput p2, p0, Lu2/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lu2/a;->e:Ljava/lang/Object;

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
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lu2/a;->d:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v5, 0x2

    .line 8
    iget-object v0, v0, Lu2/a;->e:Ljava/lang/Object;

    .line 9
    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast v0, La2/k;

    .line 14
    .line 15
    invoke-interface {v0}, La2/k;->B()Lw1/c;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    return-object v0

    .line 20
    :pswitch_0
    check-cast v0, Ljava/io/IOException;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    return-object v0

    .line 31
    :pswitch_1
    check-cast v0, Lwk0/d2;

    .line 32
    .line 33
    iget-object v0, v0, Lwk0/d2;->c:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    return-object v0

    .line 44
    :pswitch_2
    check-cast v0, [Lxf0/o3;

    .line 45
    .line 46
    array-length v0, v0

    .line 47
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    return-object v0

    .line 52
    :pswitch_3
    check-cast v0, Lxf0/l2;

    .line 53
    .line 54
    iget-object v0, v0, Lxf0/l2;->c:Lay0/a;

    .line 55
    .line 56
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object v0

    .line 62
    :pswitch_4
    check-cast v0, Ld01/h0;

    .line 63
    .line 64
    return-object v0

    .line 65
    :pswitch_5
    check-cast v0, Ltechnology/cariad/cat/genx/Vehicle$Information;

    .line 66
    .line 67
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/Vehicle$Information;->getVin()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    const-string v1, "updateRegisteredPairings(): Failed to add Job for "

    .line 72
    .line 73
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    return-object v0

    .line 78
    :pswitch_6
    check-cast v0, Lx41/u0;

    .line 79
    .line 80
    iget-object v0, v0, Lx41/u0;->h:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 81
    .line 82
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;->getPublicKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    new-instance v1, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    const-string v2, "scanQRCode(): With new publicKey = "

    .line 89
    .line 90
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    return-object v0

    .line 101
    :pswitch_7
    check-cast v0, Lx30/a;

    .line 102
    .line 103
    iget-object v0, v0, Lx30/a;->a:Lsc0/a;

    .line 104
    .line 105
    invoke-virtual {v0}, Lsc0/a;->invoke()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    check-cast v0, Lbw/c;

    .line 110
    .line 111
    iget-object v0, v0, Lbw/c;->a:Lqy0/b;

    .line 112
    .line 113
    new-instance v1, Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 116
    .line 117
    .line 118
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-eqz v3, :cond_1

    .line 127
    .line 128
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    move-object v4, v3

    .line 133
    check-cast v4, Lcw/i;

    .line 134
    .line 135
    iget-object v5, v4, Lcw/i;->i:Lqy0/c;

    .line 136
    .line 137
    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    if-nez v5, :cond_0

    .line 142
    .line 143
    iget-object v4, v4, Lcw/i;->h:Lcw/r;

    .line 144
    .line 145
    if-eqz v4, :cond_0

    .line 146
    .line 147
    iget-object v4, v4, Lcw/r;->c:Ljava/lang/String;

    .line 148
    .line 149
    if-eqz v4, :cond_0

    .line 150
    .line 151
    invoke-static {v4}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 152
    .line 153
    .line 154
    move-result v4

    .line 155
    xor-int/2addr v4, v2

    .line 156
    if-ne v4, v2, :cond_0

    .line 157
    .line 158
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    goto :goto_0

    .line 162
    :cond_1
    return-object v1

    .line 163
    :pswitch_8
    check-cast v0, Lzh/j;

    .line 164
    .line 165
    iget-object v0, v0, Lzh/j;->a:Ljava/util/ArrayList;

    .line 166
    .line 167
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    return-object v0

    .line 176
    :pswitch_9
    check-cast v0, Lxa0/a;

    .line 177
    .line 178
    iget-object v1, v0, Lxa0/a;->a:Ljava/lang/String;

    .line 179
    .line 180
    iget-object v2, v0, Lxa0/a;->b:Ljava/net/URL;

    .line 181
    .line 182
    iget-object v3, v0, Lxa0/a;->f:Lqr0/l;

    .line 183
    .line 184
    iget-object v0, v0, Lxa0/a;->j:Ljava/time/OffsetDateTime;

    .line 185
    .line 186
    new-instance v4, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    const-string v5, "name="

    .line 189
    .line 190
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const-string v1, ",render="

    .line 197
    .line 198
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    const-string v1, ",battery="

    .line 205
    .line 206
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 210
    .line 211
    .line 212
    const-string v1, ",updated="

    .line 213
    .line 214
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    return-object v0

    .line 225
    :pswitch_a
    check-cast v0, Lwa/g;

    .line 226
    .line 227
    iget-object v1, v0, Lwa/g;->e:Ljava/lang/String;

    .line 228
    .line 229
    const/16 v2, 0x14

    .line 230
    .line 231
    if-eqz v1, :cond_2

    .line 232
    .line 233
    iget-boolean v3, v0, Lwa/g;->g:Z

    .line 234
    .line 235
    if-eqz v3, :cond_2

    .line 236
    .line 237
    new-instance v3, Ljava/io/File;

    .line 238
    .line 239
    iget-object v4, v0, Lwa/g;->d:Landroid/content/Context;

    .line 240
    .line 241
    const-string v5, "context"

    .line 242
    .line 243
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v4}, Landroid/content/Context;->getNoBackupFilesDir()Ljava/io/File;

    .line 247
    .line 248
    .line 249
    move-result-object v4

    .line 250
    const-string v5, "getNoBackupFilesDir(...)"

    .line 251
    .line 252
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    invoke-direct {v3, v4, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    new-instance v6, Lwa/f;

    .line 259
    .line 260
    iget-object v7, v0, Lwa/g;->d:Landroid/content/Context;

    .line 261
    .line 262
    invoke-virtual {v3}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v8

    .line 266
    new-instance v9, Lpv/g;

    .line 267
    .line 268
    invoke-direct {v9, v2}, Lpv/g;-><init>(I)V

    .line 269
    .line 270
    .line 271
    iget-object v10, v0, Lwa/g;->f:Lb11/a;

    .line 272
    .line 273
    iget-boolean v11, v0, Lwa/g;->h:Z

    .line 274
    .line 275
    invoke-direct/range {v6 .. v11}, Lwa/f;-><init>(Landroid/content/Context;Ljava/lang/String;Lpv/g;Lb11/a;Z)V

    .line 276
    .line 277
    .line 278
    goto :goto_1

    .line 279
    :cond_2
    new-instance v7, Lwa/f;

    .line 280
    .line 281
    iget-object v8, v0, Lwa/g;->d:Landroid/content/Context;

    .line 282
    .line 283
    iget-object v9, v0, Lwa/g;->e:Ljava/lang/String;

    .line 284
    .line 285
    new-instance v10, Lpv/g;

    .line 286
    .line 287
    invoke-direct {v10, v2}, Lpv/g;-><init>(I)V

    .line 288
    .line 289
    .line 290
    iget-object v11, v0, Lwa/g;->f:Lb11/a;

    .line 291
    .line 292
    iget-boolean v12, v0, Lwa/g;->h:Z

    .line 293
    .line 294
    invoke-direct/range {v7 .. v12}, Lwa/f;-><init>(Landroid/content/Context;Ljava/lang/String;Lpv/g;Lb11/a;Z)V

    .line 295
    .line 296
    .line 297
    move-object v6, v7

    .line 298
    :goto_1
    iget-boolean v0, v0, Lwa/g;->j:Z

    .line 299
    .line 300
    invoke-virtual {v6, v0}, Landroid/database/sqlite/SQLiteOpenHelper;->setWriteAheadLoggingEnabled(Z)V

    .line 301
    .line 302
    .line 303
    return-object v6

    .line 304
    :pswitch_b
    check-cast v0, Ler0/c;

    .line 305
    .line 306
    new-instance v1, Ldr0/a;

    .line 307
    .line 308
    iget-object v0, v0, Ler0/c;->c:Ljava/lang/String;

    .line 309
    .line 310
    invoke-direct {v1, v0}, Ldr0/a;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    return-object v1

    .line 314
    :pswitch_c
    check-cast v0, Ler0/f;

    .line 315
    .line 316
    new-instance v1, Llj0/a;

    .line 317
    .line 318
    iget-object v0, v0, Ler0/f;->a:Ljava/lang/String;

    .line 319
    .line 320
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    return-object v1

    .line 324
    :pswitch_d
    check-cast v0, Lc/k;

    .line 325
    .line 326
    sget-object v1, Lf/e;->a:Lf/e;

    .line 327
    .line 328
    sget-object v2, Lf/d;->a:Lf/d;

    .line 329
    .line 330
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 331
    .line 332
    const/16 v4, 0x21

    .line 333
    .line 334
    const/16 v6, 0x1e

    .line 335
    .line 336
    if-lt v3, v4, :cond_3

    .line 337
    .line 338
    goto :goto_2

    .line 339
    :cond_3
    if-lt v3, v6, :cond_4

    .line 340
    .line 341
    invoke-static {}, Ld6/t1;->D()I

    .line 342
    .line 343
    .line 344
    move-result v7

    .line 345
    if-lt v7, v5, :cond_4

    .line 346
    .line 347
    :goto_2
    invoke-static {}, Lb/s;->a()I

    .line 348
    .line 349
    .line 350
    move-result v7

    .line 351
    goto :goto_3

    .line 352
    :cond_4
    const v7, 0x7fffffff

    .line 353
    .line 354
    .line 355
    :goto_3
    sget-object v8, Lf/c;->a:Lf/c;

    .line 356
    .line 357
    if-lt v3, v4, :cond_5

    .line 358
    .line 359
    goto :goto_4

    .line 360
    :cond_5
    if-lt v3, v6, :cond_6

    .line 361
    .line 362
    invoke-static {}, Ld6/t1;->D()I

    .line 363
    .line 364
    .line 365
    move-result v9

    .line 366
    if-lt v9, v5, :cond_6

    .line 367
    .line 368
    :goto_4
    invoke-static {}, Lb/s;->a()I

    .line 369
    .line 370
    .line 371
    :cond_6
    new-instance v9, Le/k;

    .line 372
    .line 373
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 374
    .line 375
    .line 376
    iput-object v2, v9, Le/k;->a:Lf/f;

    .line 377
    .line 378
    if-lt v3, v4, :cond_7

    .line 379
    .line 380
    goto :goto_5

    .line 381
    :cond_7
    if-lt v3, v6, :cond_8

    .line 382
    .line 383
    invoke-static {}, Ld6/t1;->D()I

    .line 384
    .line 385
    .line 386
    move-result v2

    .line 387
    if-lt v2, v5, :cond_8

    .line 388
    .line 389
    :goto_5
    invoke-static {}, Lb/s;->a()I

    .line 390
    .line 391
    .line 392
    :cond_8
    iput-object v1, v9, Le/k;->a:Lf/f;

    .line 393
    .line 394
    iput v7, v9, Le/k;->b:I

    .line 395
    .line 396
    iput-object v8, v9, Le/k;->c:Lf/c;

    .line 397
    .line 398
    invoke-virtual {v0, v9}, Lc/k;->a(Ljava/lang/Object;)V

    .line 399
    .line 400
    .line 401
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 402
    .line 403
    return-object v0

    .line 404
    :pswitch_e
    check-cast v0, Ljava/time/OffsetDateTime;

    .line 405
    .line 406
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    invoke-static {v0}, Lkp/l8;->a([Ljava/lang/Object;)Lg21/a;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    return-object v0

    .line 415
    :pswitch_f
    check-cast v0, Llp/v1;

    .line 416
    .line 417
    new-instance v1, Ljava/lang/StringBuilder;

    .line 418
    .line 419
    const-string v2, "Opening flow -> "

    .line 420
    .line 421
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 425
    .line 426
    .line 427
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    return-object v0

    .line 432
    :pswitch_10
    check-cast v0, Lvn0/a;

    .line 433
    .line 434
    new-instance v1, Lc/c;

    .line 435
    .line 436
    invoke-direct {v1, v0, v5}, Lc/c;-><init>(Ljava/lang/Object;I)V

    .line 437
    .line 438
    .line 439
    return-object v1

    .line 440
    :pswitch_11
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;

    .line 441
    .line 442
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;->a(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ScenarioSelectionAndDriveViewModelImpl;)Ljava/lang/String;

    .line 443
    .line 444
    .line 445
    move-result-object v0

    .line 446
    return-object v0

    .line 447
    :pswitch_12
    move-object v1, v0

    .line 448
    check-cast v1, Lv2/r;

    .line 449
    .line 450
    :goto_6
    iget-object v3, v1, Lv2/r;->g:Ljava/lang/Object;

    .line 451
    .line 452
    monitor-enter v3

    .line 453
    :try_start_0
    iget-boolean v0, v1, Lv2/r;->c:Z

    .line 454
    .line 455
    if-nez v0, :cond_f

    .line 456
    .line 457
    iput-boolean v2, v1, Lv2/r;->c:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 458
    .line 459
    :try_start_1
    iget-object v0, v1, Lv2/r;->f:Ln2/b;

    .line 460
    .line 461
    iget-object v6, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 462
    .line 463
    iget v0, v0, Ln2/b;->f:I

    .line 464
    .line 465
    const/4 v7, 0x0

    .line 466
    :goto_7
    if-ge v7, v0, :cond_e

    .line 467
    .line 468
    aget-object v8, v6, v7

    .line 469
    .line 470
    check-cast v8, Lv2/q;

    .line 471
    .line 472
    iget-object v9, v8, Lv2/q;->g:Landroidx/collection/r0;

    .line 473
    .line 474
    iget-object v8, v8, Lv2/q;->a:Lay0/k;

    .line 475
    .line 476
    iget-object v10, v9, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 477
    .line 478
    iget-object v11, v9, Landroidx/collection/r0;->a:[J

    .line 479
    .line 480
    array-length v12, v11

    .line 481
    sub-int/2addr v12, v5

    .line 482
    if-ltz v12, :cond_c

    .line 483
    .line 484
    const/4 v13, 0x0

    .line 485
    :goto_8
    aget-wide v14, v11, v13
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 486
    .line 487
    move-object/from16 p0, v3

    .line 488
    .line 489
    not-long v2, v14

    .line 490
    const/16 v16, 0x7

    .line 491
    .line 492
    shl-long v2, v2, v16

    .line 493
    .line 494
    and-long/2addr v2, v14

    .line 495
    const-wide v16, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 496
    .line 497
    .line 498
    .line 499
    .line 500
    and-long v2, v2, v16

    .line 501
    .line 502
    cmp-long v2, v2, v16

    .line 503
    .line 504
    if-eqz v2, :cond_b

    .line 505
    .line 506
    sub-int v2, v13, v12

    .line 507
    .line 508
    not-int v2, v2

    .line 509
    ushr-int/lit8 v2, v2, 0x1f

    .line 510
    .line 511
    const/16 v3, 0x8

    .line 512
    .line 513
    rsub-int/lit8 v2, v2, 0x8

    .line 514
    .line 515
    const/4 v5, 0x0

    .line 516
    :goto_9
    if-ge v5, v2, :cond_a

    .line 517
    .line 518
    const-wide/16 v17, 0xff

    .line 519
    .line 520
    and-long v17, v14, v17

    .line 521
    .line 522
    const-wide/16 v19, 0x80

    .line 523
    .line 524
    cmp-long v17, v17, v19

    .line 525
    .line 526
    if-gez v17, :cond_9

    .line 527
    .line 528
    shl-int/lit8 v17, v13, 0x3

    .line 529
    .line 530
    add-int v17, v17, v5

    .line 531
    .line 532
    :try_start_2
    aget-object v4, v10, v17

    .line 533
    .line 534
    invoke-interface {v8, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 535
    .line 536
    .line 537
    goto :goto_a

    .line 538
    :catchall_0
    move-exception v0

    .line 539
    goto :goto_b

    .line 540
    :cond_9
    :goto_a
    shr-long/2addr v14, v3

    .line 541
    add-int/lit8 v5, v5, 0x1

    .line 542
    .line 543
    goto :goto_9

    .line 544
    :cond_a
    if-ne v2, v3, :cond_d

    .line 545
    .line 546
    :cond_b
    if-eq v13, v12, :cond_d

    .line 547
    .line 548
    add-int/lit8 v13, v13, 0x1

    .line 549
    .line 550
    const/4 v2, 0x1

    .line 551
    const/4 v5, 0x2

    .line 552
    move-object/from16 v3, p0

    .line 553
    .line 554
    goto :goto_8

    .line 555
    :cond_c
    move-object/from16 p0, v3

    .line 556
    .line 557
    :cond_d
    invoke-virtual {v9}, Landroidx/collection/r0;->b()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 558
    .line 559
    .line 560
    add-int/lit8 v7, v7, 0x1

    .line 561
    .line 562
    const/4 v2, 0x1

    .line 563
    const/4 v5, 0x2

    .line 564
    move-object/from16 v3, p0

    .line 565
    .line 566
    goto :goto_7

    .line 567
    :goto_b
    const/4 v2, 0x0

    .line 568
    goto :goto_c

    .line 569
    :catchall_1
    move-exception v0

    .line 570
    move-object/from16 p0, v3

    .line 571
    .line 572
    goto :goto_b

    .line 573
    :cond_e
    move-object/from16 p0, v3

    .line 574
    .line 575
    const/4 v2, 0x0

    .line 576
    :try_start_3
    iput-boolean v2, v1, Lv2/r;->c:Z

    .line 577
    .line 578
    goto :goto_d

    .line 579
    :catchall_2
    move-exception v0

    .line 580
    goto :goto_e

    .line 581
    :goto_c
    iput-boolean v2, v1, Lv2/r;->c:Z

    .line 582
    .line 583
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 584
    :catchall_3
    move-exception v0

    .line 585
    move-object/from16 p0, v3

    .line 586
    .line 587
    goto :goto_e

    .line 588
    :cond_f
    move-object/from16 p0, v3

    .line 589
    .line 590
    :goto_d
    monitor-exit p0

    .line 591
    invoke-virtual {v1}, Lv2/r;->c()Z

    .line 592
    .line 593
    .line 594
    move-result v0

    .line 595
    if-nez v0, :cond_10

    .line 596
    .line 597
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 598
    .line 599
    return-object v0

    .line 600
    :cond_10
    const/4 v2, 0x1

    .line 601
    const/4 v5, 0x2

    .line 602
    goto/16 :goto_6

    .line 603
    .line 604
    :goto_e
    monitor-exit p0

    .line 605
    throw v0

    .line 606
    :pswitch_13
    check-cast v0, Lv01/g;

    .line 607
    .line 608
    iget-object v1, v0, Lv01/g;->f:Ljava/lang/ClassLoader;

    .line 609
    .line 610
    iget-object v0, v0, Lv01/g;->g:Lu01/k;

    .line 611
    .line 612
    const-string v2, ""

    .line 613
    .line 614
    invoke-virtual {v1, v2}, Ljava/lang/ClassLoader;->getResources(Ljava/lang/String;)Ljava/util/Enumeration;

    .line 615
    .line 616
    .line 617
    move-result-object v2

    .line 618
    const-string v4, "getResources(...)"

    .line 619
    .line 620
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 621
    .line 622
    .line 623
    invoke-static {v2}, Ljava/util/Collections;->list(Ljava/util/Enumeration;)Ljava/util/ArrayList;

    .line 624
    .line 625
    .line 626
    move-result-object v2

    .line 627
    const-string v5, "list(...)"

    .line 628
    .line 629
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 630
    .line 631
    .line 632
    new-instance v6, Ljava/util/ArrayList;

    .line 633
    .line 634
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 635
    .line 636
    .line 637
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 638
    .line 639
    .line 640
    move-result-object v2

    .line 641
    :cond_11
    :goto_f
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 642
    .line 643
    .line 644
    move-result v7

    .line 645
    if-eqz v7, :cond_13

    .line 646
    .line 647
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 648
    .line 649
    .line 650
    move-result-object v7

    .line 651
    check-cast v7, Ljava/net/URL;

    .line 652
    .line 653
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 654
    .line 655
    .line 656
    invoke-virtual {v7}, Ljava/net/URL;->getProtocol()Ljava/lang/String;

    .line 657
    .line 658
    .line 659
    move-result-object v8

    .line 660
    const-string v9, "file"

    .line 661
    .line 662
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 663
    .line 664
    .line 665
    move-result v8

    .line 666
    if-nez v8, :cond_12

    .line 667
    .line 668
    move-object v8, v3

    .line 669
    goto :goto_10

    .line 670
    :cond_12
    sget-object v8, Lu01/y;->e:Ljava/lang/String;

    .line 671
    .line 672
    new-instance v8, Ljava/io/File;

    .line 673
    .line 674
    invoke-virtual {v7}, Ljava/net/URL;->toURI()Ljava/net/URI;

    .line 675
    .line 676
    .line 677
    move-result-object v7

    .line 678
    invoke-direct {v8, v7}, Ljava/io/File;-><init>(Ljava/net/URI;)V

    .line 679
    .line 680
    .line 681
    invoke-static {v8}, Lrb0/a;->b(Ljava/io/File;)Lu01/y;

    .line 682
    .line 683
    .line 684
    move-result-object v7

    .line 685
    new-instance v8, Llx0/l;

    .line 686
    .line 687
    invoke-direct {v8, v0, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 688
    .line 689
    .line 690
    :goto_10
    if-eqz v8, :cond_11

    .line 691
    .line 692
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 693
    .line 694
    .line 695
    goto :goto_f

    .line 696
    :cond_13
    const-string v2, "META-INF/MANIFEST.MF"

    .line 697
    .line 698
    invoke-virtual {v1, v2}, Ljava/lang/ClassLoader;->getResources(Ljava/lang/String;)Ljava/util/Enumeration;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 703
    .line 704
    .line 705
    invoke-static {v1}, Ljava/util/Collections;->list(Ljava/util/Enumeration;)Ljava/util/ArrayList;

    .line 706
    .line 707
    .line 708
    move-result-object v1

    .line 709
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 710
    .line 711
    .line 712
    new-instance v2, Ljava/util/ArrayList;

    .line 713
    .line 714
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 715
    .line 716
    .line 717
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    :cond_14
    :goto_11
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 722
    .line 723
    .line 724
    move-result v4

    .line 725
    if-eqz v4, :cond_17

    .line 726
    .line 727
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 728
    .line 729
    .line 730
    move-result-object v4

    .line 731
    check-cast v4, Ljava/net/URL;

    .line 732
    .line 733
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 734
    .line 735
    .line 736
    invoke-virtual {v4}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 737
    .line 738
    .line 739
    move-result-object v4

    .line 740
    const-string v5, "toString(...)"

    .line 741
    .line 742
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 743
    .line 744
    .line 745
    const-string v5, "jar:file:"

    .line 746
    .line 747
    const/4 v7, 0x0

    .line 748
    invoke-static {v4, v5, v7}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 749
    .line 750
    .line 751
    move-result v5

    .line 752
    if-nez v5, :cond_15

    .line 753
    .line 754
    :goto_12
    move-object v7, v3

    .line 755
    goto :goto_13

    .line 756
    :cond_15
    const-string v5, "!"

    .line 757
    .line 758
    const/4 v8, 0x6

    .line 759
    invoke-static {v4, v5, v7, v8}, Lly0/p;->P(Ljava/lang/String;Ljava/lang/String;II)I

    .line 760
    .line 761
    .line 762
    move-result v5

    .line 763
    const/4 v7, -0x1

    .line 764
    if-ne v5, v7, :cond_16

    .line 765
    .line 766
    goto :goto_12

    .line 767
    :cond_16
    sget-object v7, Lu01/y;->e:Ljava/lang/String;

    .line 768
    .line 769
    new-instance v7, Ljava/io/File;

    .line 770
    .line 771
    const/4 v8, 0x4

    .line 772
    invoke-virtual {v4, v8, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 773
    .line 774
    .line 775
    move-result-object v4

    .line 776
    const-string v5, "substring(...)"

    .line 777
    .line 778
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 779
    .line 780
    .line 781
    invoke-static {v4}, Ljava/net/URI;->create(Ljava/lang/String;)Ljava/net/URI;

    .line 782
    .line 783
    .line 784
    move-result-object v4

    .line 785
    invoke-direct {v7, v4}, Ljava/io/File;-><init>(Ljava/net/URI;)V

    .line 786
    .line 787
    .line 788
    invoke-static {v7}, Lrb0/a;->b(Ljava/io/File;)Lu01/y;

    .line 789
    .line 790
    .line 791
    move-result-object v4

    .line 792
    new-instance v5, Luu/r;

    .line 793
    .line 794
    const/16 v7, 0x15

    .line 795
    .line 796
    invoke-direct {v5, v7}, Luu/r;-><init>(I)V

    .line 797
    .line 798
    .line 799
    invoke-static {v4, v0, v5}, Lv01/b;->e(Lu01/y;Lu01/k;Lay0/k;)Lu01/k0;

    .line 800
    .line 801
    .line 802
    move-result-object v4

    .line 803
    sget-object v5, Lv01/g;->i:Lu01/y;

    .line 804
    .line 805
    new-instance v7, Llx0/l;

    .line 806
    .line 807
    invoke-direct {v7, v4, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 808
    .line 809
    .line 810
    :goto_13
    if-eqz v7, :cond_14

    .line 811
    .line 812
    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 813
    .line 814
    .line 815
    goto :goto_11

    .line 816
    :cond_17
    invoke-static {v2, v6}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 817
    .line 818
    .line 819
    move-result-object v0

    .line 820
    return-object v0

    .line 821
    :pswitch_14
    check-cast v0, Lt61/g;

    .line 822
    .line 823
    invoke-virtual {v0}, Lt61/g;->invoke()Ljava/lang/Object;

    .line 824
    .line 825
    .line 826
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 827
    .line 828
    return-object v0

    .line 829
    :pswitch_15
    check-cast v0, Luu0/x;

    .line 830
    .line 831
    new-instance v1, Llj0/a;

    .line 832
    .line 833
    iget-object v0, v0, Luu0/x;->D:Lij0/a;

    .line 834
    .line 835
    const v2, 0x7f1204b8

    .line 836
    .line 837
    .line 838
    check-cast v0, Ljj0/f;

    .line 839
    .line 840
    invoke-virtual {v0, v2}, Ljj0/f;->b(I)Ljava/lang/String;

    .line 841
    .line 842
    .line 843
    move-result-object v0

    .line 844
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 845
    .line 846
    .line 847
    return-object v1

    .line 848
    :pswitch_16
    check-cast v0, Luu/x;

    .line 849
    .line 850
    invoke-virtual {v0}, Luu/x;->J()V

    .line 851
    .line 852
    .line 853
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 854
    .line 855
    return-object v0

    .line 856
    :pswitch_17
    check-cast v0, Lyr0/e;

    .line 857
    .line 858
    new-instance v1, Lxr0/a;

    .line 859
    .line 860
    iget-object v0, v0, Lyr0/e;->f:Ljava/lang/String;

    .line 861
    .line 862
    if-nez v0, :cond_18

    .line 863
    .line 864
    goto :goto_14

    .line 865
    :cond_18
    move-object v3, v0

    .line 866
    :goto_14
    invoke-direct {v1, v3}, Lxr0/a;-><init>(Ljava/lang/String;)V

    .line 867
    .line 868
    .line 869
    return-object v1

    .line 870
    :pswitch_18
    check-cast v0, Lsg/o;

    .line 871
    .line 872
    iget-object v0, v0, Lsg/o;->a:Ljava/util/ArrayList;

    .line 873
    .line 874
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 875
    .line 876
    .line 877
    move-result v0

    .line 878
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 879
    .line 880
    .line 881
    move-result-object v0

    .line 882
    return-object v0

    .line 883
    :pswitch_19
    check-cast v0, Lss0/g;

    .line 884
    .line 885
    iget-object v0, v0, Lss0/g;->d:Ljava/lang/String;

    .line 886
    .line 887
    const-string v1, "(MDK) Vehicle is in commission. ID="

    .line 888
    .line 889
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 890
    .line 891
    .line 892
    move-result-object v0

    .line 893
    return-object v0

    .line 894
    :pswitch_1a
    check-cast v0, Lt50/e;

    .line 895
    .line 896
    new-instance v1, Ljava/lang/StringBuilder;

    .line 897
    .line 898
    const-string v2, "(MDK) Pairing status="

    .line 899
    .line 900
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 901
    .line 902
    .line 903
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 904
    .line 905
    .line 906
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 907
    .line 908
    .line 909
    move-result-object v0

    .line 910
    return-object v0

    .line 911
    :pswitch_1b
    check-cast v0, Lu2/j;

    .line 912
    .line 913
    const/4 v2, 0x0

    .line 914
    new-array v1, v2, [Llx0/l;

    .line 915
    .line 916
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 917
    .line 918
    .line 919
    move-result-object v1

    .line 920
    check-cast v1, [Llx0/l;

    .line 921
    .line 922
    invoke-static {v1}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 923
    .line 924
    .line 925
    move-result-object v1

    .line 926
    iget-object v0, v0, Lu2/j;->e:Lra/e;

    .line 927
    .line 928
    invoke-virtual {v0, v1}, Lra/e;->c(Landroid/os/Bundle;)V

    .line 929
    .line 930
    .line 931
    invoke-virtual {v1}, Landroid/os/BaseBundle;->isEmpty()Z

    .line 932
    .line 933
    .line 934
    move-result v0

    .line 935
    if-eqz v0, :cond_19

    .line 936
    .line 937
    goto :goto_15

    .line 938
    :cond_19
    move-object v3, v1

    .line 939
    :goto_15
    return-object v3

    .line 940
    :pswitch_1c
    check-cast v0, Lu2/b;

    .line 941
    .line 942
    iget-object v1, v0, Lu2/b;->d:Lu2/k;

    .line 943
    .line 944
    iget-object v2, v0, Lu2/b;->g:Ljava/lang/Object;

    .line 945
    .line 946
    if-eqz v2, :cond_1a

    .line 947
    .line 948
    invoke-interface {v1, v0, v2}, Lu2/k;->b(Lu2/b;Ljava/lang/Object;)Ljava/lang/Object;

    .line 949
    .line 950
    .line 951
    move-result-object v0

    .line 952
    return-object v0

    .line 953
    :cond_1a
    const-string v0, "Value should be initialized"

    .line 954
    .line 955
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 956
    .line 957
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 958
    .line 959
    .line 960
    throw v1

    .line 961
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
