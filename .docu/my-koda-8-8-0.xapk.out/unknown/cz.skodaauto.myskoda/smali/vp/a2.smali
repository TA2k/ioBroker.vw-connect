.class public final Lvp/a2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Z

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;Lcom/google/android/gms/internal/measurement/m0;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/a2;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/a2;->h:Ljava/lang/Object;

    iput-object p3, p0, Lvp/a2;->e:Ljava/lang/Object;

    iput-object p4, p0, Lvp/a2;->f:Ljava/lang/Object;

    iput-boolean p5, p0, Lvp/a2;->g:Z

    iput-object p1, p0, Lvp/a2;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/k;ZLandroid/net/Uri;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lvp/a2;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, Lvp/a2;->g:Z

    iput-object p3, p0, Lvp/a2;->h:Ljava/lang/Object;

    iput-object p4, p0, Lvp/a2;->e:Ljava/lang/Object;

    iput-object p5, p0, Lvp/a2;->f:Ljava/lang/Object;

    iput-object p1, p0, Lvp/a2;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/d3;Lvp/f4;ZLvp/s;Landroid/os/Bundle;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lvp/a2;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/a2;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Lvp/a2;->g:Z

    iput-object p4, p0, Lvp/a2;->e:Ljava/lang/Object;

    iput-object p5, p0, Lvp/a2;->f:Ljava/lang/Object;

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/a2;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/a2;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lvp/a2;->h:Ljava/lang/Object;

    iput-object p3, p0, Lvp/a2;->e:Ljava/lang/Object;

    iput-object p4, p0, Lvp/a2;->f:Ljava/lang/Object;

    iput-boolean p5, p0, Lvp/a2;->g:Z

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object p1, p0, Lvp/a2;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvp/a2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lvp/a2;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lvp/f4;

    .line 11
    .line 12
    iget-object v2, v0, Lvp/a2;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lvp/d3;

    .line 15
    .line 16
    iget-object v3, v2, Lvp/d3;->h:Lvp/c0;

    .line 17
    .line 18
    iget-object v4, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v4, Lvp/g1;

    .line 21
    .line 22
    const-string v5, "Failed to send default event parameters to service"

    .line 23
    .line 24
    if-nez v3, :cond_0

    .line 25
    .line 26
    iget-object v0, v4, Lvp/g1;->i:Lvp/p0;

    .line 27
    .line 28
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 32
    .line 33
    invoke-virtual {v0, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_0
    iget-object v6, v4, Lvp/g1;->g:Lvp/h;

    .line 38
    .line 39
    sget-object v7, Lvp/z;->b1:Lvp/y;

    .line 40
    .line 41
    const/4 v8, 0x0

    .line 42
    invoke-virtual {v6, v8, v7}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    iget-boolean v4, v0, Lvp/a2;->g:Z

    .line 49
    .line 50
    if-eqz v4, :cond_1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_1
    iget-object v0, v0, Lvp/a2;->e:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v8, v0

    .line 56
    check-cast v8, Lvp/s;

    .line 57
    .line 58
    :goto_0
    invoke-virtual {v2, v3, v8, v1}, Lvp/d3;->s0(Lvp/c0;Loo/a;Lvp/f4;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    :try_start_0
    iget-object v0, v0, Lvp/a2;->f:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v0, Landroid/os/Bundle;

    .line 65
    .line 66
    invoke-interface {v3, v0, v1}, Lvp/c0;->N(Landroid/os/Bundle;Lvp/f4;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2}, Lvp/d3;->n0()V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :catch_0
    move-exception v0

    .line 74
    iget-object v1, v4, Lvp/g1;->i:Lvp/p0;

    .line 75
    .line 76
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 77
    .line 78
    .line 79
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 80
    .line 81
    invoke-virtual {v1, v0, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :goto_1
    return-void

    .line 85
    :pswitch_0
    const-string v1, "gclid="

    .line 86
    .line 87
    iget-object v2, v0, Lvp/a2;->i:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v2, Lcom/google/firebase/messaging/k;

    .line 90
    .line 91
    iget-object v3, v2, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 92
    .line 93
    move-object v4, v3

    .line 94
    check-cast v4, Lvp/j2;

    .line 95
    .line 96
    invoke-virtual {v4}, Lvp/x;->a0()V

    .line 97
    .line 98
    .line 99
    iget-object v3, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v3, Lvp/g1;

    .line 102
    .line 103
    iget-object v5, v4, Lvp/j2;->v:Lro/f;

    .line 104
    .line 105
    iget-object v6, v0, Lvp/a2;->f:Ljava/lang/Object;

    .line 106
    .line 107
    move-object v7, v6

    .line 108
    check-cast v7, Ljava/lang/String;

    .line 109
    .line 110
    iget-object v6, v0, Lvp/a2;->h:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v6, Landroid/net/Uri;

    .line 113
    .line 114
    :try_start_1
    iget-object v8, v3, Lvp/g1;->l:Lvp/d4;

    .line 115
    .line 116
    iget-object v9, v3, Lvp/g1;->i:Lvp/p0;

    .line 117
    .line 118
    invoke-static {v8}, Lvp/g1;->g(Lap0/o;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_3

    .line 119
    .line 120
    .line 121
    :try_start_2
    const-string v10, "https://google.com/search?"

    .line 122
    .line 123
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 124
    .line 125
    .line 126
    move-result v11
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_2

    .line 127
    const-string v12, "_cis"

    .line 128
    .line 129
    const-string v13, "Activity created with data \'referrer\' without required params"

    .line 130
    .line 131
    const-string v14, "utm_medium"

    .line 132
    .line 133
    const-string v15, "utm_source"

    .line 134
    .line 135
    move/from16 v16, v11

    .line 136
    .line 137
    const-string v11, "utm_campaign"

    .line 138
    .line 139
    move-object/from16 v17, v2

    .line 140
    .line 141
    const-string v2, "gclid"

    .line 142
    .line 143
    if-eqz v16, :cond_3

    .line 144
    .line 145
    move-object/from16 v16, v9

    .line 146
    .line 147
    :goto_2
    const/4 v8, 0x0

    .line 148
    goto :goto_4

    .line 149
    :cond_3
    :try_start_3
    invoke-virtual {v7, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 150
    .line 151
    .line 152
    move-result v16

    .line 153
    if-nez v16, :cond_4

    .line 154
    .line 155
    move-object/from16 v16, v9

    .line 156
    .line 157
    const-string v9, "gbraid"

    .line 158
    .line 159
    invoke-virtual {v7, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 160
    .line 161
    .line 162
    move-result v9

    .line 163
    if-nez v9, :cond_5

    .line 164
    .line 165
    invoke-virtual {v7, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 166
    .line 167
    .line 168
    move-result v9

    .line 169
    if-nez v9, :cond_5

    .line 170
    .line 171
    invoke-virtual {v7, v15}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 172
    .line 173
    .line 174
    move-result v9

    .line 175
    if-nez v9, :cond_5

    .line 176
    .line 177
    invoke-virtual {v7, v14}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 178
    .line 179
    .line 180
    move-result v9

    .line 181
    if-nez v9, :cond_5

    .line 182
    .line 183
    const-string v9, "utm_id"

    .line 184
    .line 185
    invoke-virtual {v7, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 186
    .line 187
    .line 188
    move-result v9

    .line 189
    if-nez v9, :cond_5

    .line 190
    .line 191
    const-string v9, "dclid"

    .line 192
    .line 193
    invoke-virtual {v7, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 194
    .line 195
    .line 196
    move-result v9

    .line 197
    if-nez v9, :cond_5

    .line 198
    .line 199
    const-string v9, "srsltid"

    .line 200
    .line 201
    invoke-virtual {v7, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 202
    .line 203
    .line 204
    move-result v9

    .line 205
    if-nez v9, :cond_5

    .line 206
    .line 207
    const-string v9, "sfmc_id"

    .line 208
    .line 209
    invoke-virtual {v7, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 210
    .line 211
    .line 212
    move-result v9

    .line 213
    if-nez v9, :cond_5

    .line 214
    .line 215
    iget-object v8, v8, Lap0/o;->e:Ljava/lang/Object;

    .line 216
    .line 217
    check-cast v8, Lvp/g1;

    .line 218
    .line 219
    iget-object v8, v8, Lvp/g1;->i:Lvp/p0;

    .line 220
    .line 221
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 222
    .line 223
    .line 224
    iget-object v8, v8, Lvp/p0;->q:Lvp/n0;

    .line 225
    .line 226
    invoke-virtual {v8, v13}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    goto :goto_2

    .line 230
    :catch_1
    move-exception v0

    .line 231
    :goto_3
    move-object/from16 v2, v17

    .line 232
    .line 233
    goto/16 :goto_8

    .line 234
    .line 235
    :cond_4
    move-object/from16 v16, v9

    .line 236
    .line 237
    :cond_5
    invoke-virtual {v10, v7}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v9

    .line 241
    invoke-static {v9}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 242
    .line 243
    .line 244
    move-result-object v9

    .line 245
    invoke-virtual {v8, v9}, Lvp/d4;->Z0(Landroid/net/Uri;)Landroid/os/Bundle;

    .line 246
    .line 247
    .line 248
    move-result-object v8

    .line 249
    if-eqz v8, :cond_6

    .line 250
    .line 251
    const-string v9, "referrer"

    .line 252
    .line 253
    invoke-virtual {v8, v12, v9}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/lang/RuntimeException; {:try_start_3 .. :try_end_3} :catch_1

    .line 254
    .line 255
    .line 256
    :cond_6
    :goto_4
    iget-object v9, v0, Lvp/a2;->e:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast v9, Ljava/lang/String;

    .line 259
    .line 260
    iget-boolean v0, v0, Lvp/a2;->g:Z

    .line 261
    .line 262
    const-string v10, "_cmp"

    .line 263
    .line 264
    if-eqz v0, :cond_8

    .line 265
    .line 266
    :try_start_4
    iget-object v0, v3, Lvp/g1;->l:Lvp/d4;

    .line 267
    .line 268
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 269
    .line 270
    .line 271
    invoke-virtual {v0, v6}, Lvp/d4;->Z0(Landroid/net/Uri;)Landroid/os/Bundle;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    if-eqz v0, :cond_8

    .line 276
    .line 277
    const-string v6, "intent"

    .line 278
    .line 279
    invoke-virtual {v0, v12, v6}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 283
    .line 284
    .line 285
    move-result v6

    .line 286
    if-nez v6, :cond_7

    .line 287
    .line 288
    if-eqz v8, :cond_7

    .line 289
    .line 290
    invoke-virtual {v8, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 291
    .line 292
    .line 293
    move-result v6

    .line 294
    if-eqz v6, :cond_7

    .line 295
    .line 296
    const-string v6, "_cer"

    .line 297
    .line 298
    invoke-virtual {v8, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v12

    .line 302
    move-object/from16 v18, v13

    .line 303
    .line 304
    new-instance v13, Ljava/lang/StringBuilder;

    .line 305
    .line 306
    invoke-direct {v13, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v13, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 310
    .line 311
    .line 312
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    invoke-virtual {v0, v6, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    goto :goto_5

    .line 320
    :cond_7
    move-object/from16 v18, v13

    .line 321
    .line 322
    :goto_5
    invoke-virtual {v4, v9, v10, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v5, v9, v0}, Lro/f;->s(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 326
    .line 327
    .line 328
    goto :goto_6

    .line 329
    :cond_8
    move-object/from16 v18, v13

    .line 330
    .line 331
    :goto_6
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 332
    .line 333
    .line 334
    move-result v0

    .line 335
    if-eqz v0, :cond_9

    .line 336
    .line 337
    goto/16 :goto_9

    .line 338
    .line 339
    :cond_9
    invoke-static/range {v16 .. v16}, Lvp/g1;->k(Lvp/n1;)V

    .line 340
    .line 341
    .line 342
    move-object/from16 v0, v16

    .line 343
    .line 344
    iget-object v1, v0, Lvp/p0;->q:Lvp/n0;

    .line 345
    .line 346
    const-string v6, "Activity created with referrer"

    .line 347
    .line 348
    invoke-virtual {v1, v7, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    iget-object v6, v3, Lvp/g1;->g:Lvp/h;

    .line 352
    .line 353
    sget-object v12, Lvp/z;->G0:Lvp/y;

    .line 354
    .line 355
    const/4 v13, 0x0

    .line 356
    invoke-virtual {v6, v13, v12}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 357
    .line 358
    .line 359
    move-result v6

    .line 360
    if-eqz v6, :cond_b

    .line 361
    .line 362
    if-eqz v8, :cond_a

    .line 363
    .line 364
    invoke-virtual {v4, v9, v10, v8}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v5, v9, v8}, Lro/f;->s(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 368
    .line 369
    .line 370
    goto :goto_7

    .line 371
    :cond_a
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 372
    .line 373
    .line 374
    const-string v0, "Referrer does not contain valid parameters"

    .line 375
    .line 376
    invoke-virtual {v1, v7, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 377
    .line 378
    .line 379
    :goto_7
    iget-object v0, v3, Lvp/g1;->n:Lto/a;

    .line 380
    .line 381
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 382
    .line 383
    .line 384
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 385
    .line 386
    .line 387
    move-result-wide v9

    .line 388
    const-string v5, "auto"

    .line 389
    .line 390
    const-string v6, "_ldl"

    .line 391
    .line 392
    const/4 v8, 0x1

    .line 393
    move-object v7, v13

    .line 394
    invoke-virtual/range {v4 .. v10}, Lvp/j2;->k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V

    .line 395
    .line 396
    .line 397
    goto :goto_9

    .line 398
    :cond_b
    invoke-virtual {v7, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 399
    .line 400
    .line 401
    move-result v2

    .line 402
    if-eqz v2, :cond_d

    .line 403
    .line 404
    invoke-virtual {v7, v11}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 405
    .line 406
    .line 407
    move-result v2

    .line 408
    if-nez v2, :cond_c

    .line 409
    .line 410
    invoke-virtual {v7, v15}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 411
    .line 412
    .line 413
    move-result v2

    .line 414
    if-nez v2, :cond_c

    .line 415
    .line 416
    invoke-virtual {v7, v14}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 417
    .line 418
    .line 419
    move-result v2

    .line 420
    if-nez v2, :cond_c

    .line 421
    .line 422
    const-string v2, "utm_term"

    .line 423
    .line 424
    invoke-virtual {v7, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 425
    .line 426
    .line 427
    move-result v2

    .line 428
    if-nez v2, :cond_c

    .line 429
    .line 430
    const-string v2, "utm_content"

    .line 431
    .line 432
    invoke-virtual {v7, v2}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 433
    .line 434
    .line 435
    move-result v2

    .line 436
    if-eqz v2, :cond_d

    .line 437
    .line 438
    :cond_c
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 439
    .line 440
    .line 441
    move-result v0

    .line 442
    if-nez v0, :cond_e

    .line 443
    .line 444
    iget-object v0, v3, Lvp/g1;->n:Lto/a;

    .line 445
    .line 446
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 447
    .line 448
    .line 449
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 450
    .line 451
    .line 452
    move-result-wide v9

    .line 453
    const-string v5, "auto"

    .line 454
    .line 455
    const-string v6, "_ldl"

    .line 456
    .line 457
    const/4 v8, 0x1

    .line 458
    invoke-virtual/range {v4 .. v10}, Lvp/j2;->k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V

    .line 459
    .line 460
    .line 461
    goto :goto_9

    .line 462
    :cond_d
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 463
    .line 464
    .line 465
    move-object/from16 v0, v18

    .line 466
    .line 467
    invoke-virtual {v1, v0}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_1

    .line 468
    .line 469
    .line 470
    goto :goto_9

    .line 471
    :catch_2
    move-exception v0

    .line 472
    move-object/from16 v17, v2

    .line 473
    .line 474
    goto :goto_8

    .line 475
    :catch_3
    move-exception v0

    .line 476
    move-object/from16 v17, v2

    .line 477
    .line 478
    goto/16 :goto_3

    .line 479
    .line 480
    :goto_8
    iget-object v1, v2, Lcom/google/firebase/messaging/k;->e:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast v1, Lvp/j2;

    .line 483
    .line 484
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v1, Lvp/g1;

    .line 487
    .line 488
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 489
    .line 490
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 491
    .line 492
    .line 493
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 494
    .line 495
    const-string v2, "Throwable caught in handleReferrerForOnActivityCreated"

    .line 496
    .line 497
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    :cond_e
    :goto_9
    return-void

    .line 501
    :pswitch_1
    iget-object v1, v0, Lvp/a2;->e:Ljava/lang/Object;

    .line 502
    .line 503
    move-object v5, v1

    .line 504
    check-cast v5, Ljava/lang/String;

    .line 505
    .line 506
    iget-object v1, v0, Lvp/a2;->f:Ljava/lang/Object;

    .line 507
    .line 508
    move-object v6, v1

    .line 509
    check-cast v6, Ljava/lang/String;

    .line 510
    .line 511
    iget-object v1, v0, Lvp/a2;->i:Ljava/lang/Object;

    .line 512
    .line 513
    check-cast v1, Lvp/j2;

    .line 514
    .line 515
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 516
    .line 517
    check-cast v1, Lvp/g1;

    .line 518
    .line 519
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 520
    .line 521
    .line 522
    move-result-object v3

    .line 523
    iget-object v1, v0, Lvp/a2;->h:Ljava/lang/Object;

    .line 524
    .line 525
    move-object v4, v1

    .line 526
    check-cast v4, Ljava/util/concurrent/atomic/AtomicReference;

    .line 527
    .line 528
    invoke-virtual {v3}, Lvp/x;->a0()V

    .line 529
    .line 530
    .line 531
    invoke-virtual {v3}, Lvp/b0;->b0()V

    .line 532
    .line 533
    .line 534
    const/4 v1, 0x0

    .line 535
    invoke-virtual {v3, v1}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 536
    .line 537
    .line 538
    move-result-object v7

    .line 539
    new-instance v2, Lvp/v2;

    .line 540
    .line 541
    iget-boolean v8, v0, Lvp/a2;->g:Z

    .line 542
    .line 543
    invoke-direct/range {v2 .. v8}, Lvp/v2;-><init>(Lvp/d3;Ljava/util/concurrent/atomic/AtomicReference;Ljava/lang/String;Ljava/lang/String;Lvp/f4;Z)V

    .line 544
    .line 545
    .line 546
    invoke-virtual {v3, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 547
    .line 548
    .line 549
    return-void

    .line 550
    :pswitch_2
    iget-object v1, v0, Lvp/a2;->i:Ljava/lang/Object;

    .line 551
    .line 552
    check-cast v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    .line 553
    .line 554
    iget-object v1, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 555
    .line 556
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 557
    .line 558
    .line 559
    move-result-object v3

    .line 560
    iget-object v1, v0, Lvp/a2;->h:Ljava/lang/Object;

    .line 561
    .line 562
    move-object v8, v1

    .line 563
    check-cast v8, Lcom/google/android/gms/internal/measurement/m0;

    .line 564
    .line 565
    iget-object v1, v0, Lvp/a2;->e:Ljava/lang/Object;

    .line 566
    .line 567
    move-object v4, v1

    .line 568
    check-cast v4, Ljava/lang/String;

    .line 569
    .line 570
    iget-object v1, v0, Lvp/a2;->f:Ljava/lang/Object;

    .line 571
    .line 572
    move-object v5, v1

    .line 573
    check-cast v5, Ljava/lang/String;

    .line 574
    .line 575
    invoke-virtual {v3}, Lvp/x;->a0()V

    .line 576
    .line 577
    .line 578
    invoke-virtual {v3}, Lvp/b0;->b0()V

    .line 579
    .line 580
    .line 581
    const/4 v1, 0x0

    .line 582
    invoke-virtual {v3, v1}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 583
    .line 584
    .line 585
    move-result-object v6

    .line 586
    new-instance v2, Lvp/v2;

    .line 587
    .line 588
    iget-boolean v7, v0, Lvp/a2;->g:Z

    .line 589
    .line 590
    invoke-direct/range {v2 .. v8}, Lvp/v2;-><init>(Lvp/d3;Ljava/lang/String;Ljava/lang/String;Lvp/f4;ZLcom/google/android/gms/internal/measurement/m0;)V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v3, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 594
    .line 595
    .line 596
    return-void

    .line 597
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
