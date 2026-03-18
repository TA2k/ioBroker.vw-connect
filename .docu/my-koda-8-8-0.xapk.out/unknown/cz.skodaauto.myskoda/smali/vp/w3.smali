.class public final Lvp/w3;
.super Lvp/q3;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final d0(Ljava/lang/String;)Z
    .locals 5

    .line 1
    sget-object v0, Lvp/z;->t:Lvp/y;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    return v2

    .line 18
    :cond_0
    const-string v1, ","

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    array-length v1, v0

    .line 25
    move v3, v2

    .line 26
    :goto_0
    if-ge v3, v1, :cond_2

    .line 27
    .line 28
    aget-object v4, v0, v3

    .line 29
    .line 30
    invoke-virtual {v4}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-virtual {p0, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-eqz v4, :cond_1

    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    return p0

    .line 42
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    return v2
.end method


# virtual methods
.method public final b0(Ljava/lang/String;)Lvp/v3;
    .locals 13

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    iget-object v1, p0, Lvp/q3;->f:Lvp/z3;

    .line 6
    .line 7
    iget-object v2, v1, Lvp/z3;->f:Lvp/n;

    .line 8
    .line 9
    iget-object v3, v1, Lvp/z3;->d:Lvp/a1;

    .line 10
    .line 11
    invoke-static {v2}, Lvp/z3;->T(Lvp/u3;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2, p1}, Lvp/n;->c1(Ljava/lang/String;)Lvp/t0;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    sget-object v4, Lvp/q2;->e:Lvp/q2;

    .line 19
    .line 20
    const/4 v5, 0x0

    .line 21
    if-eqz v2, :cond_f

    .line 22
    .line 23
    invoke-virtual {v2}, Lvp/t0;->y()Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    if-nez v6, :cond_0

    .line 28
    .line 29
    goto/16 :goto_5

    .line 30
    .line 31
    :cond_0
    invoke-static {}, Lcom/google/android/gms/internal/measurement/q3;->q()Lcom/google/android/gms/internal/measurement/p3;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 36
    .line 37
    .line 38
    iget-object v7, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 39
    .line 40
    check-cast v7, Lcom/google/android/gms/internal/measurement/q3;

    .line 41
    .line 42
    const/4 v8, 0x2

    .line 43
    invoke-virtual {v7, v8}, Lcom/google/android/gms/internal/measurement/q3;->v(I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v2}, Lvp/t0;->t()I

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    invoke-static {v7}, Lc1/j0;->a(I)I

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    if-eqz v7, :cond_e

    .line 55
    .line 56
    invoke-virtual {v6, v7}, Lcom/google/android/gms/internal/measurement/p3;->i(I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2}, Lvp/t0;->E()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v7

    .line 63
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v3, p1}, Lvp/a1;->m0(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/f2;

    .line 67
    .line 68
    .line 69
    move-result-object v9

    .line 70
    const/4 v10, 0x3

    .line 71
    if-nez v9, :cond_1

    .line 72
    .line 73
    goto/16 :goto_4

    .line 74
    .line 75
    :cond_1
    iget-object v1, v1, Lvp/z3;->f:Lvp/n;

    .line 76
    .line 77
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1, p1}, Lvp/n;->c1(Ljava/lang/String;)Lvp/t0;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    if-eqz v1, :cond_d

    .line 85
    .line 86
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/f2;->D()Z

    .line 87
    .line 88
    .line 89
    move-result v11

    .line 90
    const/16 v12, 0x64

    .line 91
    .line 92
    if-eqz v11, :cond_2

    .line 93
    .line 94
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/f2;->E()Lcom/google/android/gms/internal/measurement/k2;

    .line 95
    .line 96
    .line 97
    move-result-object v11

    .line 98
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/k2;->p()I

    .line 99
    .line 100
    .line 101
    move-result v11

    .line 102
    if-eq v11, v12, :cond_4

    .line 103
    .line 104
    :cond_2
    iget-object v11, v0, Lvp/g1;->l:Lvp/d4;

    .line 105
    .line 106
    invoke-static {v11}, Lvp/g1;->g(Lap0/o;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1}, Lvp/t0;->C()Ljava/lang/String;

    .line 110
    .line 111
    .line 112
    move-result-object v1

    .line 113
    invoke-virtual {v11, p1, v1}, Lvp/d4;->A0(Ljava/lang/String;Ljava/lang/String;)Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-eqz v1, :cond_3

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :cond_3
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-nez v1, :cond_d

    .line 125
    .line 126
    invoke-virtual {v7}, Ljava/lang/String;->hashCode()I

    .line 127
    .line 128
    .line 129
    move-result v1

    .line 130
    rem-int/2addr v1, v12

    .line 131
    invoke-static {v1}, Ljava/lang/Math;->abs(I)I

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/f2;->E()Lcom/google/android/gms/internal/measurement/k2;

    .line 136
    .line 137
    .line 138
    move-result-object v7

    .line 139
    invoke-virtual {v7}, Lcom/google/android/gms/internal/measurement/k2;->p()I

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    if-lt v1, v7, :cond_4

    .line 144
    .line 145
    goto/16 :goto_4

    .line 146
    .line 147
    :cond_4
    :goto_0
    invoke-virtual {v2}, Lvp/t0;->D()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 152
    .line 153
    .line 154
    iget-object v7, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 155
    .line 156
    check-cast v7, Lcom/google/android/gms/internal/measurement/q3;

    .line 157
    .line 158
    invoke-virtual {v7, v8}, Lcom/google/android/gms/internal/measurement/q3;->v(I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v3}, Lvp/z3;->T(Lvp/u3;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v2}, Lvp/t0;->D()Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    invoke-virtual {v3, v7}, Lvp/a1;->m0(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/f2;

    .line 169
    .line 170
    .line 171
    move-result-object v3

    .line 172
    if-eqz v3, :cond_b

    .line 173
    .line 174
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/f2;->D()Z

    .line 175
    .line 176
    .line 177
    move-result v7

    .line 178
    if-nez v7, :cond_5

    .line 179
    .line 180
    goto/16 :goto_2

    .line 181
    .line 182
    :cond_5
    new-instance v7, Ljava/util/HashMap;

    .line 183
    .line 184
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 185
    .line 186
    .line 187
    invoke-virtual {v2}, Lvp/t0;->C()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v9

    .line 191
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 192
    .line 193
    .line 194
    move-result v9

    .line 195
    if-nez v9, :cond_6

    .line 196
    .line 197
    invoke-virtual {v2}, Lvp/t0;->C()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v9

    .line 201
    const-string v11, "x-gtm-server-preview"

    .line 202
    .line 203
    invoke-virtual {v7, v11, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    :cond_6
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/f2;->E()Lcom/google/android/gms/internal/measurement/k2;

    .line 207
    .line 208
    .line 209
    move-result-object v9

    .line 210
    invoke-virtual {v9}, Lcom/google/android/gms/internal/measurement/k2;->q()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v9

    .line 214
    invoke-virtual {v2}, Lvp/t0;->t()I

    .line 215
    .line 216
    .line 217
    move-result v11

    .line 218
    invoke-static {v11}, Lc1/j0;->a(I)I

    .line 219
    .line 220
    .line 221
    move-result v11

    .line 222
    if-eqz v11, :cond_7

    .line 223
    .line 224
    if-eq v11, v8, :cond_7

    .line 225
    .line 226
    invoke-virtual {v6, v11}, Lcom/google/android/gms/internal/measurement/p3;->i(I)V

    .line 227
    .line 228
    .line 229
    goto :goto_1

    .line 230
    :cond_7
    invoke-virtual {v2}, Lvp/t0;->D()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v11

    .line 234
    invoke-static {v11}, Lvp/w3;->d0(Ljava/lang/String;)Z

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    if-eqz v11, :cond_8

    .line 239
    .line 240
    const/16 v10, 0xb

    .line 241
    .line 242
    invoke-virtual {v6, v10}, Lcom/google/android/gms/internal/measurement/p3;->i(I)V

    .line 243
    .line 244
    .line 245
    goto :goto_1

    .line 246
    :cond_8
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 247
    .line 248
    .line 249
    move-result v11

    .line 250
    if-eqz v11, :cond_a

    .line 251
    .line 252
    const/16 v10, 0xc

    .line 253
    .line 254
    invoke-virtual {v6, v10}, Lcom/google/android/gms/internal/measurement/p3;->i(I)V

    .line 255
    .line 256
    .line 257
    :goto_1
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/f2;->E()Lcom/google/android/gms/internal/measurement/k2;

    .line 258
    .line 259
    .line 260
    move-result-object v10

    .line 261
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 262
    .line 263
    .line 264
    invoke-virtual {v3}, Lcom/google/android/gms/internal/measurement/f2;->E()Lcom/google/android/gms/internal/measurement/k2;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 269
    .line 270
    .line 271
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 272
    .line 273
    .line 274
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 275
    .line 276
    invoke-static {v9}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 277
    .line 278
    .line 279
    move-result v3

    .line 280
    if-nez v3, :cond_9

    .line 281
    .line 282
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 283
    .line 284
    .line 285
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 286
    .line 287
    const-string v2, "[sgtm] Eligible for local service direct upload. appId"

    .line 288
    .line 289
    invoke-virtual {v0, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 293
    .line 294
    .line 295
    iget-object v0, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 296
    .line 297
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 298
    .line 299
    const/4 v1, 0x5

    .line 300
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/q3;->v(I)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 304
    .line 305
    .line 306
    iget-object v0, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 307
    .line 308
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 309
    .line 310
    invoke-virtual {v0, v8}, Lcom/google/android/gms/internal/measurement/q3;->w(I)V

    .line 311
    .line 312
    .line 313
    new-instance v5, Lvp/v3;

    .line 314
    .line 315
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 320
    .line 321
    sget-object v1, Lvp/q2;->g:Lvp/q2;

    .line 322
    .line 323
    invoke-direct {v5, v9, v7, v1, v0}, Lvp/v3;-><init>(Ljava/lang/String;Ljava/util/Map;Lvp/q2;Lcom/google/android/gms/internal/measurement/q3;)V

    .line 324
    .line 325
    .line 326
    goto :goto_3

    .line 327
    :cond_9
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 328
    .line 329
    .line 330
    iget-object v1, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 331
    .line 332
    check-cast v1, Lcom/google/android/gms/internal/measurement/q3;

    .line 333
    .line 334
    const/4 v3, 0x6

    .line 335
    invoke-virtual {v1, v3}, Lcom/google/android/gms/internal/measurement/q3;->w(I)V

    .line 336
    .line 337
    .line 338
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 339
    .line 340
    .line 341
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 342
    .line 343
    invoke-virtual {v2}, Lvp/t0;->D()Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    const-string v2, "[sgtm] Local service, missing sgtm_server_url"

    .line 348
    .line 349
    invoke-virtual {v0, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    goto :goto_3

    .line 353
    :cond_a
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 354
    .line 355
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 356
    .line 357
    .line 358
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 359
    .line 360
    const-string v2, "[sgtm] Eligible for client side upload. appId"

    .line 361
    .line 362
    invoke-virtual {v0, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 363
    .line 364
    .line 365
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 366
    .line 367
    .line 368
    iget-object v0, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 369
    .line 370
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 371
    .line 372
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/measurement/q3;->v(I)V

    .line 373
    .line 374
    .line 375
    invoke-virtual {v6, v8}, Lcom/google/android/gms/internal/measurement/p3;->i(I)V

    .line 376
    .line 377
    .line 378
    new-instance v5, Lvp/v3;

    .line 379
    .line 380
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 381
    .line 382
    .line 383
    move-result-object v0

    .line 384
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 385
    .line 386
    sget-object v1, Lvp/q2;->h:Lvp/q2;

    .line 387
    .line 388
    invoke-direct {v5, v9, v7, v1, v0}, Lvp/v3;-><init>(Ljava/lang/String;Ljava/util/Map;Lvp/q2;Lcom/google/android/gms/internal/measurement/q3;)V

    .line 389
    .line 390
    .line 391
    goto :goto_3

    .line 392
    :cond_b
    :goto_2
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 393
    .line 394
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 395
    .line 396
    .line 397
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 398
    .line 399
    const-string v2, "[sgtm] Missing sgtm_setting in remote config. appId"

    .line 400
    .line 401
    invoke-virtual {v0, v1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 405
    .line 406
    .line 407
    iget-object v0, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 408
    .line 409
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 410
    .line 411
    const/4 v1, 0x4

    .line 412
    invoke-virtual {v0, v1}, Lcom/google/android/gms/internal/measurement/q3;->w(I)V

    .line 413
    .line 414
    .line 415
    :goto_3
    if-eqz v5, :cond_c

    .line 416
    .line 417
    return-object v5

    .line 418
    :cond_c
    new-instance v0, Lvp/v3;

    .line 419
    .line 420
    invoke-virtual {p0, p1}, Lvp/w3;->c0(Ljava/lang/String;)Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object p0

    .line 424
    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 425
    .line 426
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 427
    .line 428
    .line 429
    move-result-object v1

    .line 430
    check-cast v1, Lcom/google/android/gms/internal/measurement/q3;

    .line 431
    .line 432
    invoke-direct {v0, p0, p1, v4, v1}, Lvp/v3;-><init>(Ljava/lang/String;Ljava/util/Map;Lvp/q2;Lcom/google/android/gms/internal/measurement/q3;)V

    .line 433
    .line 434
    .line 435
    return-object v0

    .line 436
    :cond_d
    :goto_4
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 437
    .line 438
    .line 439
    iget-object v0, v6, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 440
    .line 441
    check-cast v0, Lcom/google/android/gms/internal/measurement/q3;

    .line 442
    .line 443
    invoke-virtual {v0, v10}, Lcom/google/android/gms/internal/measurement/q3;->w(I)V

    .line 444
    .line 445
    .line 446
    new-instance v0, Lvp/v3;

    .line 447
    .line 448
    invoke-virtual {p0, p1}, Lvp/w3;->c0(Ljava/lang/String;)Ljava/lang/String;

    .line 449
    .line 450
    .line 451
    move-result-object p0

    .line 452
    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 453
    .line 454
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    check-cast v1, Lcom/google/android/gms/internal/measurement/q3;

    .line 459
    .line 460
    invoke-direct {v0, p0, p1, v4, v1}, Lvp/v3;-><init>(Ljava/lang/String;Ljava/util/Map;Lvp/q2;Lcom/google/android/gms/internal/measurement/q3;)V

    .line 461
    .line 462
    .line 463
    return-object v0

    .line 464
    :cond_e
    new-instance p0, Ljava/lang/NullPointerException;

    .line 465
    .line 466
    const-string p1, "null reference"

    .line 467
    .line 468
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 469
    .line 470
    .line 471
    throw p0

    .line 472
    :cond_f
    :goto_5
    new-instance v0, Lvp/v3;

    .line 473
    .line 474
    invoke-virtual {p0, p1}, Lvp/w3;->c0(Ljava/lang/String;)Ljava/lang/String;

    .line 475
    .line 476
    .line 477
    move-result-object p0

    .line 478
    sget-object p1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 479
    .line 480
    invoke-direct {v0, p0, p1, v4, v5}, Lvp/v3;-><init>(Ljava/lang/String;Ljava/util/Map;Lvp/q2;Lcom/google/android/gms/internal/measurement/q3;)V

    .line 481
    .line 482
    .line 483
    return-object v0
.end method

.method public final c0(Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    .line 1
    iget-object p0, p0, Lvp/q3;->f:Lvp/z3;

    .line 2
    .line 3
    iget-object p0, p0, Lvp/z3;->d:Lvp/a1;

    .line 4
    .line 5
    invoke-static {p0}, Lvp/z3;->T(Lvp/u3;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lvp/a1;->n0(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    const/4 v0, 0x0

    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    sget-object p1, Lvp/z;->r:Lvp/y;

    .line 20
    .line 21
    invoke-virtual {p1, v0}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    check-cast p1, Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {p1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Landroid/net/Uri;->buildUpon()Landroid/net/Uri$Builder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p1}, Landroid/net/Uri;->getAuthority()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    add-int/lit8 v1, v1, 0x1

    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    new-instance v3, Ljava/lang/StringBuilder;

    .line 58
    .line 59
    add-int/2addr v1, v2

    .line 60
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string p0, "."

    .line 67
    .line 68
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {v0, p0}, Landroid/net/Uri$Builder;->authority(Ljava/lang/String;)Landroid/net/Uri$Builder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Landroid/net/Uri$Builder;->build()Landroid/net/Uri;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {p0}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :cond_0
    sget-object p0, Lvp/z;->r:Lvp/y;

    .line 91
    .line 92
    invoke-virtual {p0, v0}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Ljava/lang/String;

    .line 97
    .line 98
    return-object p0
.end method
