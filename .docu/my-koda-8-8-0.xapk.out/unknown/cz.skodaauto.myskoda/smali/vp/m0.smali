.class public final Lvp/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:I

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/Object;

.field public final h:Ljava/lang/Object;

.field public final i:Ljava/lang/Object;

.field public final j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lvp/q0;ILjava/io/IOException;[BLjava/util/Map;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/m0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p2, p0, Lvp/m0;->g:Ljava/lang/Object;

    iput p3, p0, Lvp/m0;->e:I

    iput-object p4, p0, Lvp/m0;->h:Ljava/lang/Object;

    iput-object p5, p0, Lvp/m0;->i:Ljava/lang/Object;

    iput-object p1, p0, Lvp/m0;->f:Ljava/lang/String;

    iput-object p6, p0, Lvp/m0;->j:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/p0;ILjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/m0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Lvp/m0;->e:I

    iput-object p3, p0, Lvp/m0;->f:Ljava/lang/String;

    iput-object p4, p0, Lvp/m0;->g:Ljava/lang/Object;

    iput-object p5, p0, Lvp/m0;->h:Ljava/lang/Object;

    iput-object p6, p0, Lvp/m0;->i:Ljava/lang/Object;

    iput-object p1, p0, Lvp/m0;->j:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 13

    .line 1
    iget v0, p0, Lvp/m0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/m0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lvp/q0;

    .line 10
    .line 11
    iget-object v2, p0, Lvp/m0;->f:Ljava/lang/String;

    .line 12
    .line 13
    iget v3, p0, Lvp/m0;->e:I

    .line 14
    .line 15
    iget-object v0, p0, Lvp/m0;->h:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v4, v0

    .line 18
    check-cast v4, Ljava/lang/Throwable;

    .line 19
    .line 20
    iget-object v0, p0, Lvp/m0;->i:Ljava/lang/Object;

    .line 21
    .line 22
    move-object v5, v0

    .line 23
    check-cast v5, [B

    .line 24
    .line 25
    iget-object p0, p0, Lvp/m0;->j:Ljava/lang/Object;

    .line 26
    .line 27
    move-object v6, p0

    .line 28
    check-cast v6, Ljava/util/Map;

    .line 29
    .line 30
    invoke-interface/range {v1 .. v6}, Lvp/q0;->l(Ljava/lang/String;ILjava/lang/Throwable;[BLjava/util/Map;)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_0
    iget-object v0, p0, Lvp/m0;->j:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Lvp/p0;

    .line 37
    .line 38
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lvp/g1;

    .line 41
    .line 42
    iget-object v1, v1, Lvp/g1;->h:Lvp/w0;

    .line 43
    .line 44
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 45
    .line 46
    .line 47
    iget-boolean v2, v1, Lvp/n1;->f:Z

    .line 48
    .line 49
    if-eqz v2, :cond_d

    .line 50
    .line 51
    iget-char v2, v0, Lvp/p0;->g:C

    .line 52
    .line 53
    const/4 v3, 0x0

    .line 54
    const/4 v4, 0x1

    .line 55
    if-nez v2, :cond_6

    .line 56
    .line 57
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, Lvp/g1;

    .line 60
    .line 61
    iget-object v2, v2, Lvp/g1;->g:Lvp/h;

    .line 62
    .line 63
    iget-object v5, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 64
    .line 65
    if-nez v5, :cond_4

    .line 66
    .line 67
    monitor-enter v2

    .line 68
    :try_start_0
    iget-object v5, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 69
    .line 70
    if-nez v5, :cond_3

    .line 71
    .line 72
    iget-object v5, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v5, Lvp/g1;

    .line 75
    .line 76
    iget-object v6, v5, Lvp/g1;->d:Landroid/content/Context;

    .line 77
    .line 78
    invoke-virtual {v6}, Landroid/content/Context;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    sget-object v7, Lto/b;->g:Ljava/lang/String;

    .line 83
    .line 84
    if-nez v7, :cond_0

    .line 85
    .line 86
    invoke-static {}, Landroid/app/Application;->getProcessName()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v7

    .line 90
    sput-object v7, Lto/b;->g:Ljava/lang/String;

    .line 91
    .line 92
    :cond_0
    sget-object v7, Lto/b;->g:Ljava/lang/String;

    .line 93
    .line 94
    if-eqz v6, :cond_2

    .line 95
    .line 96
    iget-object v6, v6, Landroid/content/pm/ApplicationInfo;->processName:Ljava/lang/String;

    .line 97
    .line 98
    if-eqz v6, :cond_1

    .line 99
    .line 100
    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    if-eqz v6, :cond_1

    .line 105
    .line 106
    move v6, v4

    .line 107
    goto :goto_0

    .line 108
    :cond_1
    move v6, v3

    .line 109
    goto :goto_0

    .line 110
    :catchall_0
    move-exception v0

    .line 111
    move-object p0, v0

    .line 112
    goto :goto_1

    .line 113
    :goto_0
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 114
    .line 115
    .line 116
    move-result-object v6

    .line 117
    iput-object v6, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 118
    .line 119
    :cond_2
    iget-object v6, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 120
    .line 121
    if-nez v6, :cond_3

    .line 122
    .line 123
    sget-object v6, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 124
    .line 125
    iput-object v6, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 126
    .line 127
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 128
    .line 129
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 133
    .line 134
    const-string v6, "My process not in the list of running processes"

    .line 135
    .line 136
    invoke-virtual {v5, v6}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    :cond_3
    monitor-exit v2

    .line 140
    goto :goto_2

    .line 141
    :goto_1
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 142
    throw p0

    .line 143
    :cond_4
    :goto_2
    iget-object v2, v2, Lvp/h;->i:Ljava/lang/Boolean;

    .line 144
    .line 145
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 146
    .line 147
    .line 148
    move-result v2

    .line 149
    if-eqz v2, :cond_5

    .line 150
    .line 151
    const/16 v2, 0x43

    .line 152
    .line 153
    iput-char v2, v0, Lvp/p0;->g:C

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_5
    const/16 v2, 0x63

    .line 157
    .line 158
    iput-char v2, v0, Lvp/p0;->g:C

    .line 159
    .line 160
    :cond_6
    :goto_3
    iget-wide v5, v0, Lvp/p0;->h:J

    .line 161
    .line 162
    const-wide/16 v7, 0x0

    .line 163
    .line 164
    cmp-long v2, v5, v7

    .line 165
    .line 166
    if-gez v2, :cond_7

    .line 167
    .line 168
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v2, Lvp/g1;

    .line 171
    .line 172
    iget-object v2, v2, Lvp/g1;->g:Lvp/h;

    .line 173
    .line 174
    invoke-virtual {v2}, Lvp/h;->f0()V

    .line 175
    .line 176
    .line 177
    const-wide/32 v5, 0x2078d

    .line 178
    .line 179
    .line 180
    iput-wide v5, v0, Lvp/p0;->h:J

    .line 181
    .line 182
    :cond_7
    iget v2, p0, Lvp/m0;->e:I

    .line 183
    .line 184
    iget-char v5, v0, Lvp/p0;->g:C

    .line 185
    .line 186
    iget-wide v9, v0, Lvp/p0;->h:J

    .line 187
    .line 188
    iget-object v0, p0, Lvp/m0;->f:Ljava/lang/String;

    .line 189
    .line 190
    iget-object v6, p0, Lvp/m0;->g:Ljava/lang/Object;

    .line 191
    .line 192
    iget-object v11, p0, Lvp/m0;->h:Ljava/lang/Object;

    .line 193
    .line 194
    iget-object p0, p0, Lvp/m0;->i:Ljava/lang/Object;

    .line 195
    .line 196
    const-string v12, "01VDIWEA?"

    .line 197
    .line 198
    invoke-virtual {v12, v2}, Ljava/lang/String;->charAt(I)C

    .line 199
    .line 200
    .line 201
    move-result v2

    .line 202
    invoke-static {v4, v0, v6, v11, p0}, Lvp/p0;->l0(ZLjava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    invoke-static {v2}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v6

    .line 210
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 211
    .line 212
    .line 213
    move-result v6

    .line 214
    invoke-static {v5}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v11

    .line 218
    add-int/2addr v6, v4

    .line 219
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 220
    .line 221
    .line 222
    move-result v11

    .line 223
    invoke-static {v9, v10}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v12

    .line 227
    invoke-virtual {v12}, Ljava/lang/String;->length()I

    .line 228
    .line 229
    .line 230
    move-result v12

    .line 231
    add-int/2addr v6, v11

    .line 232
    add-int/2addr v6, v12

    .line 233
    add-int/2addr v6, v4

    .line 234
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 235
    .line 236
    .line 237
    move-result v4

    .line 238
    new-instance v11, Ljava/lang/StringBuilder;

    .line 239
    .line 240
    add-int/2addr v6, v4

    .line 241
    invoke-direct {v11, v6}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 242
    .line 243
    .line 244
    const-string v4, "2"

    .line 245
    .line 246
    invoke-virtual {v11, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 247
    .line 248
    .line 249
    invoke-virtual {v11, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-virtual {v11, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v11, v9, v10}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 256
    .line 257
    .line 258
    const-string v2, ":"

    .line 259
    .line 260
    invoke-virtual {v11, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    invoke-virtual {v11, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 271
    .line 272
    .line 273
    move-result v2

    .line 274
    const/16 v4, 0x400

    .line 275
    .line 276
    if-le v2, v4, :cond_8

    .line 277
    .line 278
    invoke-virtual {v0, v3, v4}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object p0

    .line 282
    :cond_8
    iget-object v0, v1, Lvp/w0;->i:Lgb/d;

    .line 283
    .line 284
    if-eqz v0, :cond_e

    .line 285
    .line 286
    iget-object v1, v0, Lgb/d;->d:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v1, Ljava/lang/String;

    .line 289
    .line 290
    iget-object v2, v0, Lgb/d;->e:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v2, Lvp/w0;

    .line 293
    .line 294
    invoke-virtual {v2}, Lap0/o;->a0()V

    .line 295
    .line 296
    .line 297
    iget-object v3, v0, Lgb/d;->e:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast v3, Lvp/w0;

    .line 300
    .line 301
    invoke-virtual {v3}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 302
    .line 303
    .line 304
    move-result-object v3

    .line 305
    iget-object v4, v0, Lgb/d;->b:Ljava/lang/Object;

    .line 306
    .line 307
    check-cast v4, Ljava/lang/String;

    .line 308
    .line 309
    invoke-interface {v3, v4, v7, v8}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 310
    .line 311
    .line 312
    move-result-wide v3

    .line 313
    cmp-long v3, v3, v7

    .line 314
    .line 315
    if-nez v3, :cond_9

    .line 316
    .line 317
    invoke-virtual {v0}, Lgb/d;->d()V

    .line 318
    .line 319
    .line 320
    :cond_9
    if-nez p0, :cond_a

    .line 321
    .line 322
    const-string p0, ""

    .line 323
    .line 324
    :cond_a
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 325
    .line 326
    .line 327
    move-result-object v3

    .line 328
    iget-object v0, v0, Lgb/d;->c:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast v0, Ljava/lang/String;

    .line 331
    .line 332
    invoke-interface {v3, v0, v7, v8}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 333
    .line 334
    .line 335
    move-result-wide v3

    .line 336
    cmp-long v5, v3, v7

    .line 337
    .line 338
    const-wide/16 v6, 0x1

    .line 339
    .line 340
    if-gtz v5, :cond_b

    .line 341
    .line 342
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 347
    .line 348
    .line 349
    move-result-object v2

    .line 350
    invoke-interface {v2, v1, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 351
    .line 352
    .line 353
    invoke-interface {v2, v0, v6, v7}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 354
    .line 355
    .line 356
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 357
    .line 358
    .line 359
    goto :goto_4

    .line 360
    :cond_b
    iget-object v5, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v5, Lvp/g1;

    .line 363
    .line 364
    iget-object v5, v5, Lvp/g1;->l:Lvp/d4;

    .line 365
    .line 366
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 367
    .line 368
    .line 369
    invoke-virtual {v5}, Lvp/d4;->X0()Ljava/security/SecureRandom;

    .line 370
    .line 371
    .line 372
    move-result-object v5

    .line 373
    invoke-virtual {v5}, Ljava/util/Random;->nextLong()J

    .line 374
    .line 375
    .line 376
    move-result-wide v8

    .line 377
    const-wide v10, 0x7fffffffffffffffL

    .line 378
    .line 379
    .line 380
    .line 381
    .line 382
    and-long/2addr v8, v10

    .line 383
    add-long/2addr v3, v6

    .line 384
    div-long/2addr v10, v3

    .line 385
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 386
    .line 387
    .line 388
    move-result-object v2

    .line 389
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 390
    .line 391
    .line 392
    move-result-object v2

    .line 393
    cmp-long v5, v8, v10

    .line 394
    .line 395
    if-gez v5, :cond_c

    .line 396
    .line 397
    invoke-interface {v2, v1, p0}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 398
    .line 399
    .line 400
    :cond_c
    invoke-interface {v2, v0, v3, v4}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 401
    .line 402
    .line 403
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 404
    .line 405
    .line 406
    goto :goto_4

    .line 407
    :cond_d
    invoke-virtual {v0}, Lvp/p0;->k0()Ljava/lang/String;

    .line 408
    .line 409
    .line 410
    move-result-object p0

    .line 411
    const-string v0, "Persisted config not initialized. Not logging error/warn"

    .line 412
    .line 413
    const/4 v1, 0x6

    .line 414
    invoke-static {v1, p0, v0}, Landroid/util/Log;->println(ILjava/lang/String;Ljava/lang/String;)I

    .line 415
    .line 416
    .line 417
    :cond_e
    :goto_4
    return-void

    .line 418
    nop

    .line 419
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
