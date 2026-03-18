.class public final Lvp/b;
.super Lvp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic g:I

.field public final synthetic h:Lvp/d;

.field public final i:Lcom/google/android/gms/internal/measurement/l5;


# direct methods
.method public synthetic constructor <init>(Lvp/d;Ljava/lang/String;ILcom/google/android/gms/internal/measurement/l5;I)V
    .locals 0

    .line 1
    iput p5, p0, Lvp/b;->g:I

    .line 2
    .line 3
    iput-object p1, p0, Lvp/b;->h:Lvp/d;

    .line 4
    .line 5
    invoke-direct {p0, p2, p3}, Lvp/c;-><init>(Ljava/lang/String;I)V

    .line 6
    .line 7
    .line 8
    iput-object p4, p0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 1

    .line 1
    iget v0, p0, Lvp/b;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/gms/internal/measurement/v1;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 16
    .line 17
    check-cast p0, Lcom/google/android/gms/internal/measurement/o1;

    .line 18
    .line 19
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d()Z
    .locals 0

    .line 1
    iget p0, p0, Lvp/b;->g:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e()Z
    .locals 1

    .line 1
    iget v0, p0, Lvp/b;->g:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :pswitch_0
    iget-object p0, p0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 9
    .line 10
    check-cast p0, Lcom/google/android/gms/internal/measurement/o1;

    .line 11
    .line 12
    invoke-virtual {p0}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public i(Ljava/lang/Long;Ljava/lang/Long;Lcom/google/android/gms/internal/measurement/b3;JLvp/r;Z)Z
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Lvp/b;->h:Lvp/d;

    .line 7
    .line 8
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v2, Lvp/g1;

    .line 11
    .line 12
    iget-object v3, v2, Lvp/g1;->g:Lvp/h;

    .line 13
    .line 14
    iget-object v4, v2, Lvp/g1;->i:Lvp/p0;

    .line 15
    .line 16
    iget-object v2, v2, Lvp/g1;->m:Lvp/k0;

    .line 17
    .line 18
    sget-object v5, Lvp/z;->F0:Lvp/y;

    .line 19
    .line 20
    iget-object v6, v0, Lvp/c;->b:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v3, v6, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    iget-object v5, v0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 27
    .line 28
    check-cast v5, Lcom/google/android/gms/internal/measurement/o1;

    .line 29
    .line 30
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->A()Z

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    if-eqz v7, :cond_0

    .line 35
    .line 36
    move-object/from16 v7, p6

    .line 37
    .line 38
    iget-wide v7, v7, Lvp/r;->e:J

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move-wide/from16 v7, p4

    .line 42
    .line 43
    :goto_0
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    iget-object v9, v4, Lvp/p0;->r:Lvp/n0;

    .line 47
    .line 48
    iget-object v10, v4, Lvp/p0;->m:Lvp/n0;

    .line 49
    .line 50
    invoke-virtual {v4}, Lvp/p0;->k0()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v11

    .line 54
    const/4 v12, 0x2

    .line 55
    invoke-static {v11, v12}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 56
    .line 57
    .line 58
    move-result v11

    .line 59
    iget v13, v0, Lvp/c;->a:I

    .line 60
    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    if-eqz v11, :cond_6

    .line 64
    .line 65
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 66
    .line 67
    .line 68
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v11

    .line 72
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->p()Z

    .line 73
    .line 74
    .line 75
    move-result v17

    .line 76
    if-eqz v17, :cond_1

    .line 77
    .line 78
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 79
    .line 80
    .line 81
    move-result v17

    .line 82
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 83
    .line 84
    .line 85
    move-result-object v17

    .line 86
    move-object/from16 v12, v17

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    move-object/from16 v12, v16

    .line 90
    .line 91
    :goto_1
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->r()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v15

    .line 95
    invoke-virtual {v2, v15}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v15

    .line 99
    const-string v14, "Evaluating filter. audience, filter, event"

    .line 100
    .line 101
    invoke-virtual {v9, v14, v11, v12, v15}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, v1, Lvp/q3;->f:Lvp/z3;

    .line 108
    .line 109
    iget-object v1, v1, Lvp/z3;->j:Lvp/s0;

    .line 110
    .line 111
    invoke-static {v1}, Lvp/z3;->T(Lvp/u3;)V

    .line 112
    .line 113
    .line 114
    new-instance v11, Ljava/lang/StringBuilder;

    .line 115
    .line 116
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 117
    .line 118
    .line 119
    const-string v12, "\nevent_filter {\n"

    .line 120
    .line 121
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->p()Z

    .line 125
    .line 126
    .line 127
    move-result v12

    .line 128
    if-eqz v12, :cond_2

    .line 129
    .line 130
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 131
    .line 132
    .line 133
    move-result v12

    .line 134
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v12

    .line 138
    const-string v14, "filter_id"

    .line 139
    .line 140
    const/4 v15, 0x0

    .line 141
    invoke-static {v11, v15, v14, v12}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_2
    const/4 v15, 0x0

    .line 146
    :goto_2
    iget-object v12, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v12, Lvp/g1;

    .line 149
    .line 150
    iget-object v12, v12, Lvp/g1;->m:Lvp/k0;

    .line 151
    .line 152
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->r()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v14

    .line 156
    invoke-virtual {v12, v14}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v12

    .line 160
    const-string v14, "event_name"

    .line 161
    .line 162
    invoke-static {v11, v15, v14, v12}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->x()Z

    .line 166
    .line 167
    .line 168
    move-result v12

    .line 169
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->y()Z

    .line 170
    .line 171
    .line 172
    move-result v14

    .line 173
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->A()Z

    .line 174
    .line 175
    .line 176
    move-result v15

    .line 177
    invoke-static {v12, v14, v15}, Lvp/s0;->o0(ZZZ)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v12

    .line 181
    invoke-virtual {v12}, Ljava/lang/String;->isEmpty()Z

    .line 182
    .line 183
    .line 184
    move-result v14

    .line 185
    if-nez v14, :cond_3

    .line 186
    .line 187
    const-string v14, "filter_type"

    .line 188
    .line 189
    const/4 v15, 0x0

    .line 190
    invoke-static {v11, v15, v14, v12}, Lvp/s0;->s0(Ljava/lang/StringBuilder;ILjava/lang/String;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_3
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 194
    .line 195
    .line 196
    move-result v12

    .line 197
    if-eqz v12, :cond_4

    .line 198
    .line 199
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->w()Lcom/google/android/gms/internal/measurement/t1;

    .line 200
    .line 201
    .line 202
    move-result-object v12

    .line 203
    const-string v14, "event_count_filter"

    .line 204
    .line 205
    const/4 v15, 0x1

    .line 206
    invoke-static {v11, v15, v14, v12}, Lvp/s0;->t0(Ljava/lang/StringBuilder;ILjava/lang/String;Lcom/google/android/gms/internal/measurement/t1;)V

    .line 207
    .line 208
    .line 209
    :cond_4
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->t()I

    .line 210
    .line 211
    .line 212
    move-result v12

    .line 213
    if-lez v12, :cond_5

    .line 214
    .line 215
    const-string v12, "  filters {\n"

    .line 216
    .line 217
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 218
    .line 219
    .line 220
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->s()Ljava/util/List;

    .line 221
    .line 222
    .line 223
    move-result-object v12

    .line 224
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 225
    .line 226
    .line 227
    move-result-object v12

    .line 228
    :goto_3
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 229
    .line 230
    .line 231
    move-result v14

    .line 232
    if-eqz v14, :cond_5

    .line 233
    .line 234
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v14

    .line 238
    check-cast v14, Lcom/google/android/gms/internal/measurement/q1;

    .line 239
    .line 240
    const/4 v15, 0x2

    .line 241
    invoke-virtual {v1, v11, v15, v14}, Lvp/s0;->l0(Ljava/lang/StringBuilder;ILcom/google/android/gms/internal/measurement/q1;)V

    .line 242
    .line 243
    .line 244
    goto :goto_3

    .line 245
    :cond_5
    const/4 v15, 0x1

    .line 246
    invoke-static {v15, v11}, Lvp/s0;->m0(ILjava/lang/StringBuilder;)V

    .line 247
    .line 248
    .line 249
    const-string v1, "}\n}\n"

    .line 250
    .line 251
    invoke-virtual {v11, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 252
    .line 253
    .line 254
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    const-string v11, "Filter definition"

    .line 259
    .line 260
    invoke-virtual {v9, v1, v11}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 261
    .line 262
    .line 263
    :cond_6
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->p()Z

    .line 264
    .line 265
    .line 266
    move-result v1

    .line 267
    if-eqz v1, :cond_7

    .line 268
    .line 269
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 270
    .line 271
    .line 272
    move-result v1

    .line 273
    const/16 v11, 0x100

    .line 274
    .line 275
    if-le v1, v11, :cond_8

    .line 276
    .line 277
    :cond_7
    move-object/from16 v19, v4

    .line 278
    .line 279
    goto/16 :goto_17

    .line 280
    .line 281
    :cond_8
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->x()Z

    .line 282
    .line 283
    .line 284
    move-result v1

    .line 285
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->y()Z

    .line 286
    .line 287
    .line 288
    move-result v6

    .line 289
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->A()Z

    .line 290
    .line 291
    .line 292
    move-result v11

    .line 293
    if-nez v1, :cond_9

    .line 294
    .line 295
    if-nez v6, :cond_9

    .line 296
    .line 297
    if-eqz v11, :cond_a

    .line 298
    .line 299
    :cond_9
    const/4 v1, 0x1

    .line 300
    goto :goto_4

    .line 301
    :cond_a
    const/4 v1, 0x0

    .line 302
    :goto_4
    if-eqz p7, :cond_c

    .line 303
    .line 304
    if-nez v1, :cond_c

    .line 305
    .line 306
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 307
    .line 308
    .line 309
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->p()Z

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    if-eqz v1, :cond_b

    .line 318
    .line 319
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 320
    .line 321
    .line 322
    move-result v1

    .line 323
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 324
    .line 325
    .line 326
    move-result-object v16

    .line 327
    :cond_b
    move-object/from16 v1, v16

    .line 328
    .line 329
    const-string v2, "Event filter already evaluated true and it is not associated with an enhanced audience. audience ID, filter ID"

    .line 330
    .line 331
    invoke-virtual {v9, v0, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    const/4 v15, 0x1

    .line 335
    return v15

    .line 336
    :cond_c
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v6

    .line 340
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 341
    .line 342
    .line 343
    move-result v11

    .line 344
    const-wide/16 v12, 0x0

    .line 345
    .line 346
    if-eqz v11, :cond_e

    .line 347
    .line 348
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->w()Lcom/google/android/gms/internal/measurement/t1;

    .line 349
    .line 350
    .line 351
    move-result-object v11

    .line 352
    :try_start_0
    new-instance v14, Ljava/math/BigDecimal;

    .line 353
    .line 354
    invoke-direct {v14, v7, v8}, Ljava/math/BigDecimal;-><init>(J)V

    .line 355
    .line 356
    .line 357
    invoke-static {v14, v11, v12, v13}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 358
    .line 359
    .line 360
    move-result-object v7
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 361
    goto :goto_5

    .line 362
    :catch_0
    move-object/from16 v7, v16

    .line 363
    .line 364
    :goto_5
    if-nez v7, :cond_d

    .line 365
    .line 366
    :goto_6
    move/from16 v20, v3

    .line 367
    .line 368
    move-object/from16 v19, v4

    .line 369
    .line 370
    goto/16 :goto_11

    .line 371
    .line 372
    :cond_d
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 373
    .line 374
    .line 375
    move-result v7

    .line 376
    if-nez v7, :cond_e

    .line 377
    .line 378
    sget-object v16, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 379
    .line 380
    goto :goto_6

    .line 381
    :cond_e
    new-instance v7, Ljava/util/HashSet;

    .line 382
    .line 383
    invoke-direct {v7}, Ljava/util/HashSet;-><init>()V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->s()Ljava/util/List;

    .line 387
    .line 388
    .line 389
    move-result-object v8

    .line 390
    invoke-interface {v8}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 391
    .line 392
    .line 393
    move-result-object v8

    .line 394
    :goto_7
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 395
    .line 396
    .line 397
    move-result v11

    .line 398
    if-eqz v11, :cond_10

    .line 399
    .line 400
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    move-result-object v11

    .line 404
    check-cast v11, Lcom/google/android/gms/internal/measurement/q1;

    .line 405
    .line 406
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->w()Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v14

    .line 410
    invoke-virtual {v14}, Ljava/lang/String;->isEmpty()Z

    .line 411
    .line 412
    .line 413
    move-result v14

    .line 414
    if-eqz v14, :cond_f

    .line 415
    .line 416
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 420
    .line 421
    .line 422
    move-result-object v2

    .line 423
    const-string v6, "null or empty param name in filter. event"

    .line 424
    .line 425
    invoke-virtual {v10, v2, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 426
    .line 427
    .line 428
    goto :goto_6

    .line 429
    :cond_f
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->w()Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v11

    .line 433
    invoke-virtual {v7, v11}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    goto :goto_7

    .line 437
    :cond_10
    new-instance v8, Landroidx/collection/f;

    .line 438
    .line 439
    const/4 v15, 0x0

    .line 440
    invoke-direct {v8, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 441
    .line 442
    .line 443
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 444
    .line 445
    .line 446
    move-result-object v11

    .line 447
    invoke-interface {v11}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 448
    .line 449
    .line 450
    move-result-object v11

    .line 451
    :cond_11
    :goto_8
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 452
    .line 453
    .line 454
    move-result v14

    .line 455
    if-eqz v14, :cond_17

    .line 456
    .line 457
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v14

    .line 461
    check-cast v14, Lcom/google/android/gms/internal/measurement/e3;

    .line 462
    .line 463
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v15

    .line 467
    invoke-virtual {v7, v15}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v15

    .line 471
    if-eqz v15, :cond_11

    .line 472
    .line 473
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 474
    .line 475
    .line 476
    move-result v15

    .line 477
    if-eqz v15, :cond_13

    .line 478
    .line 479
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v15

    .line 483
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->t()Z

    .line 484
    .line 485
    .line 486
    move-result v17

    .line 487
    if-eqz v17, :cond_12

    .line 488
    .line 489
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->u()J

    .line 490
    .line 491
    .line 492
    move-result-wide v17

    .line 493
    invoke-static/range {v17 .. v18}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 494
    .line 495
    .line 496
    move-result-object v14

    .line 497
    goto :goto_9

    .line 498
    :cond_12
    move-object/from16 v14, v16

    .line 499
    .line 500
    :goto_9
    invoke-interface {v8, v15, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 501
    .line 502
    .line 503
    goto :goto_8

    .line 504
    :cond_13
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 505
    .line 506
    .line 507
    move-result v15

    .line 508
    if-eqz v15, :cond_15

    .line 509
    .line 510
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 511
    .line 512
    .line 513
    move-result-object v15

    .line 514
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->x()Z

    .line 515
    .line 516
    .line 517
    move-result v17

    .line 518
    if-eqz v17, :cond_14

    .line 519
    .line 520
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->y()D

    .line 521
    .line 522
    .line 523
    move-result-wide v17

    .line 524
    invoke-static/range {v17 .. v18}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 525
    .line 526
    .line 527
    move-result-object v14

    .line 528
    goto :goto_a

    .line 529
    :cond_14
    move-object/from16 v14, v16

    .line 530
    .line 531
    :goto_a
    invoke-interface {v8, v15, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    goto :goto_8

    .line 535
    :cond_15
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->r()Z

    .line 536
    .line 537
    .line 538
    move-result v15

    .line 539
    if-eqz v15, :cond_16

    .line 540
    .line 541
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 542
    .line 543
    .line 544
    move-result-object v15

    .line 545
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->s()Ljava/lang/String;

    .line 546
    .line 547
    .line 548
    move-result-object v14

    .line 549
    invoke-interface {v8, v15, v14}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    goto :goto_8

    .line 553
    :cond_16
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 554
    .line 555
    .line 556
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 557
    .line 558
    .line 559
    move-result-object v6

    .line 560
    invoke-virtual {v14}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 561
    .line 562
    .line 563
    move-result-object v7

    .line 564
    invoke-virtual {v2, v7}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 565
    .line 566
    .line 567
    move-result-object v2

    .line 568
    const-string v7, "Unknown value for param. event, param"

    .line 569
    .line 570
    invoke-virtual {v10, v6, v2, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 571
    .line 572
    .line 573
    goto/16 :goto_6

    .line 574
    .line 575
    :cond_17
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->s()Ljava/util/List;

    .line 576
    .line 577
    .line 578
    move-result-object v7

    .line 579
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 580
    .line 581
    .line 582
    move-result-object v7

    .line 583
    :goto_b
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 584
    .line 585
    .line 586
    move-result v11

    .line 587
    if-eqz v11, :cond_29

    .line 588
    .line 589
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v11

    .line 593
    check-cast v11, Lcom/google/android/gms/internal/measurement/q1;

    .line 594
    .line 595
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->t()Z

    .line 596
    .line 597
    .line 598
    move-result v14

    .line 599
    if-eqz v14, :cond_18

    .line 600
    .line 601
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->u()Z

    .line 602
    .line 603
    .line 604
    move-result v14

    .line 605
    if-eqz v14, :cond_18

    .line 606
    .line 607
    const/4 v14, 0x1

    .line 608
    goto :goto_c

    .line 609
    :cond_18
    const/4 v14, 0x0

    .line 610
    :goto_c
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->w()Ljava/lang/String;

    .line 611
    .line 612
    .line 613
    move-result-object v15

    .line 614
    invoke-virtual {v15}, Ljava/lang/String;->isEmpty()Z

    .line 615
    .line 616
    .line 617
    move-result v17

    .line 618
    if-eqz v17, :cond_19

    .line 619
    .line 620
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 621
    .line 622
    .line 623
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 624
    .line 625
    .line 626
    move-result-object v2

    .line 627
    const-string v6, "Event has empty param name. event"

    .line 628
    .line 629
    invoke-virtual {v10, v2, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 630
    .line 631
    .line 632
    goto/16 :goto_6

    .line 633
    .line 634
    :cond_19
    invoke-interface {v8, v15}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 635
    .line 636
    .line 637
    move-result-object v12

    .line 638
    instance-of v13, v12, Ljava/lang/Long;

    .line 639
    .line 640
    if-eqz v13, :cond_1d

    .line 641
    .line 642
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 643
    .line 644
    .line 645
    move-result v13

    .line 646
    if-nez v13, :cond_1a

    .line 647
    .line 648
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 649
    .line 650
    .line 651
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v6

    .line 655
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 656
    .line 657
    .line 658
    move-result-object v2

    .line 659
    const-string v7, "No number filter for long param. event, param"

    .line 660
    .line 661
    invoke-virtual {v10, v6, v2, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 662
    .line 663
    .line 664
    goto/16 :goto_6

    .line 665
    .line 666
    :cond_1a
    check-cast v12, Ljava/lang/Long;

    .line 667
    .line 668
    invoke-virtual {v12}, Ljava/lang/Long;->longValue()J

    .line 669
    .line 670
    .line 671
    move-result-wide v12

    .line 672
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 673
    .line 674
    .line 675
    move-result-object v11

    .line 676
    :try_start_1
    new-instance v15, Ljava/math/BigDecimal;

    .line 677
    .line 678
    invoke-direct {v15, v12, v13}, Ljava/math/BigDecimal;-><init>(J)V

    .line 679
    .line 680
    .line 681
    const-wide/16 v12, 0x0

    .line 682
    .line 683
    invoke-static {v15, v11, v12, v13}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 684
    .line 685
    .line 686
    move-result-object v11
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 687
    goto :goto_d

    .line 688
    :catch_1
    move-object/from16 v11, v16

    .line 689
    .line 690
    :goto_d
    if-nez v11, :cond_1b

    .line 691
    .line 692
    goto/16 :goto_6

    .line 693
    .line 694
    :cond_1b
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 695
    .line 696
    .line 697
    move-result v11

    .line 698
    if-ne v11, v14, :cond_1c

    .line 699
    .line 700
    sget-object v16, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 701
    .line 702
    goto/16 :goto_6

    .line 703
    .line 704
    :cond_1c
    const-wide/16 v12, 0x0

    .line 705
    .line 706
    goto :goto_b

    .line 707
    :cond_1d
    instance-of v13, v12, Ljava/lang/Double;

    .line 708
    .line 709
    if-eqz v13, :cond_20

    .line 710
    .line 711
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 712
    .line 713
    .line 714
    move-result v13

    .line 715
    if-nez v13, :cond_1e

    .line 716
    .line 717
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 718
    .line 719
    .line 720
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 721
    .line 722
    .line 723
    move-result-object v6

    .line 724
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 725
    .line 726
    .line 727
    move-result-object v2

    .line 728
    const-string v7, "No number filter for double param. event, param"

    .line 729
    .line 730
    invoke-virtual {v10, v6, v2, v7}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 731
    .line 732
    .line 733
    goto/16 :goto_6

    .line 734
    .line 735
    :cond_1e
    check-cast v12, Ljava/lang/Double;

    .line 736
    .line 737
    invoke-virtual {v12}, Ljava/lang/Double;->doubleValue()D

    .line 738
    .line 739
    .line 740
    move-result-wide v12

    .line 741
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 742
    .line 743
    .line 744
    move-result-object v11

    .line 745
    :try_start_2
    new-instance v15, Ljava/math/BigDecimal;

    .line 746
    .line 747
    invoke-direct {v15, v12, v13}, Ljava/math/BigDecimal;-><init>(D)V

    .line 748
    .line 749
    .line 750
    invoke-static {v12, v13}, Ljava/lang/Math;->ulp(D)D

    .line 751
    .line 752
    .line 753
    move-result-wide v12

    .line 754
    invoke-static {v15, v11, v12, v13}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 755
    .line 756
    .line 757
    move-result-object v11
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 758
    goto :goto_e

    .line 759
    :catch_2
    move-object/from16 v11, v16

    .line 760
    .line 761
    :goto_e
    if-nez v11, :cond_1f

    .line 762
    .line 763
    goto/16 :goto_6

    .line 764
    .line 765
    :cond_1f
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 766
    .line 767
    .line 768
    move-result v11

    .line 769
    if-ne v11, v14, :cond_1c

    .line 770
    .line 771
    sget-object v16, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 772
    .line 773
    goto/16 :goto_6

    .line 774
    .line 775
    :cond_20
    instance-of v13, v12, Ljava/lang/String;

    .line 776
    .line 777
    if-eqz v13, :cond_27

    .line 778
    .line 779
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->p()Z

    .line 780
    .line 781
    .line 782
    move-result v13

    .line 783
    if-eqz v13, :cond_21

    .line 784
    .line 785
    check-cast v12, Ljava/lang/String;

    .line 786
    .line 787
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->q()Lcom/google/android/gms/internal/measurement/w1;

    .line 788
    .line 789
    .line 790
    move-result-object v11

    .line 791
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 792
    .line 793
    .line 794
    invoke-static {v12, v11, v4}, Lvp/c;->g(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/w1;Lvp/p0;)Ljava/lang/Boolean;

    .line 795
    .line 796
    .line 797
    move-result-object v11

    .line 798
    move/from16 v20, v3

    .line 799
    .line 800
    move-object/from16 v19, v4

    .line 801
    .line 802
    :goto_f
    const-wide/16 v3, 0x0

    .line 803
    .line 804
    goto :goto_10

    .line 805
    :cond_21
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 806
    .line 807
    .line 808
    move-result v13

    .line 809
    if-eqz v13, :cond_26

    .line 810
    .line 811
    check-cast v12, Ljava/lang/String;

    .line 812
    .line 813
    invoke-static {v12}, Lvp/s0;->G0(Ljava/lang/String;)Z

    .line 814
    .line 815
    .line 816
    move-result v13

    .line 817
    if-eqz v13, :cond_25

    .line 818
    .line 819
    invoke-virtual {v11}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 820
    .line 821
    .line 822
    move-result-object v11

    .line 823
    invoke-static {v12}, Lvp/s0;->G0(Ljava/lang/String;)Z

    .line 824
    .line 825
    .line 826
    move-result v13

    .line 827
    if-nez v13, :cond_22

    .line 828
    .line 829
    move/from16 v20, v3

    .line 830
    .line 831
    move-object/from16 v19, v4

    .line 832
    .line 833
    move-object/from16 v11, v16

    .line 834
    .line 835
    goto :goto_f

    .line 836
    :cond_22
    :try_start_3
    new-instance v13, Ljava/math/BigDecimal;

    .line 837
    .line 838
    invoke-direct {v13, v12}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/lang/NumberFormatException; {:try_start_3 .. :try_end_3} :catch_3

    .line 839
    .line 840
    .line 841
    move/from16 v20, v3

    .line 842
    .line 843
    move-object/from16 v19, v4

    .line 844
    .line 845
    const-wide/16 v3, 0x0

    .line 846
    .line 847
    :try_start_4
    invoke-static {v13, v11, v3, v4}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 848
    .line 849
    .line 850
    move-result-object v11
    :try_end_4
    .catch Ljava/lang/NumberFormatException; {:try_start_4 .. :try_end_4} :catch_4

    .line 851
    goto :goto_10

    .line 852
    :catch_3
    move/from16 v20, v3

    .line 853
    .line 854
    move-object/from16 v19, v4

    .line 855
    .line 856
    const-wide/16 v3, 0x0

    .line 857
    .line 858
    :catch_4
    move-object/from16 v11, v16

    .line 859
    .line 860
    :goto_10
    if-nez v11, :cond_23

    .line 861
    .line 862
    goto/16 :goto_11

    .line 863
    .line 864
    :cond_23
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 865
    .line 866
    .line 867
    move-result v11

    .line 868
    if-ne v11, v14, :cond_24

    .line 869
    .line 870
    sget-object v16, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 871
    .line 872
    goto :goto_11

    .line 873
    :cond_24
    move-wide v12, v3

    .line 874
    move-object/from16 v4, v19

    .line 875
    .line 876
    move/from16 v3, v20

    .line 877
    .line 878
    goto/16 :goto_b

    .line 879
    .line 880
    :cond_25
    move/from16 v20, v3

    .line 881
    .line 882
    move-object/from16 v19, v4

    .line 883
    .line 884
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 885
    .line 886
    .line 887
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 888
    .line 889
    .line 890
    move-result-object v3

    .line 891
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 892
    .line 893
    .line 894
    move-result-object v2

    .line 895
    const-string v4, "Invalid param value for number filter. event, param"

    .line 896
    .line 897
    invoke-virtual {v10, v3, v2, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    goto :goto_11

    .line 901
    :cond_26
    move/from16 v20, v3

    .line 902
    .line 903
    move-object/from16 v19, v4

    .line 904
    .line 905
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 906
    .line 907
    .line 908
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 909
    .line 910
    .line 911
    move-result-object v3

    .line 912
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 913
    .line 914
    .line 915
    move-result-object v2

    .line 916
    const-string v4, "No filter for String param. event, param"

    .line 917
    .line 918
    invoke-virtual {v10, v3, v2, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 919
    .line 920
    .line 921
    goto :goto_11

    .line 922
    :cond_27
    move/from16 v20, v3

    .line 923
    .line 924
    move-object/from16 v19, v4

    .line 925
    .line 926
    if-nez v12, :cond_28

    .line 927
    .line 928
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 929
    .line 930
    .line 931
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 932
    .line 933
    .line 934
    move-result-object v3

    .line 935
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 936
    .line 937
    .line 938
    move-result-object v2

    .line 939
    const-string v4, "Missing param for filter. event, param"

    .line 940
    .line 941
    invoke-virtual {v9, v3, v2, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 942
    .line 943
    .line 944
    sget-object v16, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 945
    .line 946
    goto :goto_11

    .line 947
    :cond_28
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 948
    .line 949
    .line 950
    invoke-virtual {v2, v6}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 951
    .line 952
    .line 953
    move-result-object v3

    .line 954
    invoke-virtual {v2, v15}, Lvp/k0;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 955
    .line 956
    .line 957
    move-result-object v2

    .line 958
    const-string v4, "Unknown param type. event, param"

    .line 959
    .line 960
    invoke-virtual {v10, v3, v2, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 961
    .line 962
    .line 963
    goto :goto_11

    .line 964
    :cond_29
    move/from16 v20, v3

    .line 965
    .line 966
    move-object/from16 v19, v4

    .line 967
    .line 968
    sget-object v16, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 969
    .line 970
    :goto_11
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 971
    .line 972
    .line 973
    if-nez v16, :cond_2a

    .line 974
    .line 975
    const-string v2, "null"

    .line 976
    .line 977
    goto :goto_12

    .line 978
    :cond_2a
    move-object/from16 v2, v16

    .line 979
    .line 980
    :goto_12
    const-string v3, "Event filter result"

    .line 981
    .line 982
    invoke-virtual {v9, v2, v3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 983
    .line 984
    .line 985
    if-nez v16, :cond_2b

    .line 986
    .line 987
    const/4 v15, 0x0

    .line 988
    return v15

    .line 989
    :cond_2b
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 990
    .line 991
    iput-object v2, v0, Lvp/c;->c:Ljava/lang/Object;

    .line 992
    .line 993
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Boolean;->booleanValue()Z

    .line 994
    .line 995
    .line 996
    move-result v3

    .line 997
    if-nez v3, :cond_2d

    .line 998
    .line 999
    :cond_2c
    :goto_13
    const/4 v15, 0x1

    .line 1000
    goto :goto_16

    .line 1001
    :cond_2d
    iput-object v2, v0, Lvp/c;->d:Ljava/io/Serializable;

    .line 1002
    .line 1003
    if-eqz v1, :cond_2c

    .line 1004
    .line 1005
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/b3;->t()Z

    .line 1006
    .line 1007
    .line 1008
    move-result v1

    .line 1009
    if-eqz v1, :cond_2c

    .line 1010
    .line 1011
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/b3;->u()J

    .line 1012
    .line 1013
    .line 1014
    move-result-wide v1

    .line 1015
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v1

    .line 1019
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->y()Z

    .line 1020
    .line 1021
    .line 1022
    move-result v2

    .line 1023
    if-eqz v2, :cond_30

    .line 1024
    .line 1025
    if-eqz v20, :cond_2f

    .line 1026
    .line 1027
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 1028
    .line 1029
    .line 1030
    move-result v2

    .line 1031
    if-nez v2, :cond_2e

    .line 1032
    .line 1033
    goto :goto_14

    .line 1034
    :cond_2e
    move-object/from16 v1, p1

    .line 1035
    .line 1036
    :cond_2f
    :goto_14
    iput-object v1, v0, Lvp/c;->f:Ljava/io/Serializable;

    .line 1037
    .line 1038
    goto :goto_13

    .line 1039
    :cond_30
    if-eqz v20, :cond_32

    .line 1040
    .line 1041
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->v()Z

    .line 1042
    .line 1043
    .line 1044
    move-result v2

    .line 1045
    if-nez v2, :cond_31

    .line 1046
    .line 1047
    goto :goto_15

    .line 1048
    :cond_31
    move-object/from16 v1, p2

    .line 1049
    .line 1050
    :cond_32
    :goto_15
    iput-object v1, v0, Lvp/c;->e:Ljava/io/Serializable;

    .line 1051
    .line 1052
    goto :goto_13

    .line 1053
    :goto_16
    return v15

    .line 1054
    :goto_17
    invoke-static/range {v19 .. v19}, Lvp/g1;->k(Lvp/n1;)V

    .line 1055
    .line 1056
    .line 1057
    invoke-static {v6}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 1058
    .line 1059
    .line 1060
    move-result-object v0

    .line 1061
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->p()Z

    .line 1062
    .line 1063
    .line 1064
    move-result v1

    .line 1065
    if-eqz v1, :cond_33

    .line 1066
    .line 1067
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/o1;->q()I

    .line 1068
    .line 1069
    .line 1070
    move-result v1

    .line 1071
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v16

    .line 1075
    :cond_33
    invoke-static/range {v16 .. v16}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v1

    .line 1079
    const-string v2, "Invalid event filter ID. appId, id"

    .line 1080
    .line 1081
    invoke-virtual {v10, v0, v1, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 1082
    .line 1083
    .line 1084
    const/4 v15, 0x0

    .line 1085
    return v15
.end method

.method public j(Ljava/lang/Long;Ljava/lang/Long;Lcom/google/android/gms/internal/measurement/s3;Z)Z
    .locals 15

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/z7;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v1, p0, Lvp/b;->h:Lvp/d;

    .line 5
    .line 6
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lvp/g1;

    .line 9
    .line 10
    iget-object v2, v1, Lvp/g1;->g:Lvp/h;

    .line 11
    .line 12
    iget-object v3, v1, Lvp/g1;->m:Lvp/k0;

    .line 13
    .line 14
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 15
    .line 16
    iget-object v4, p0, Lvp/c;->b:Ljava/lang/String;

    .line 17
    .line 18
    sget-object v5, Lvp/z;->D0:Lvp/y;

    .line 19
    .line 20
    invoke-virtual {v2, v4, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v4, p0, Lvp/b;->i:Lcom/google/android/gms/internal/measurement/l5;

    .line 25
    .line 26
    check-cast v4, Lcom/google/android/gms/internal/measurement/v1;

    .line 27
    .line 28
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->t()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->u()Z

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->w()Z

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    const/4 v8, 0x0

    .line 41
    const/4 v9, 0x1

    .line 42
    if-nez v5, :cond_0

    .line 43
    .line 44
    if-nez v6, :cond_0

    .line 45
    .line 46
    if-eqz v7, :cond_1

    .line 47
    .line 48
    :cond_0
    move v5, v9

    .line 49
    goto :goto_0

    .line 50
    :cond_1
    move v5, v8

    .line 51
    :goto_0
    if-eqz p4, :cond_3

    .line 52
    .line 53
    if-nez v5, :cond_3

    .line 54
    .line 55
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 56
    .line 57
    .line 58
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 59
    .line 60
    iget v0, p0, Lvp/c;->a:I

    .line 61
    .line 62
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->p()Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    if-eqz v2, :cond_2

    .line 71
    .line 72
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->q()I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    goto :goto_1

    .line 81
    :cond_2
    const/4 v6, 0x0

    .line 82
    :goto_1
    const-string v2, "Property filter already evaluated true and it is not associated with an enhanced audience. audience ID, filter ID"

    .line 83
    .line 84
    invoke-virtual {v1, v0, v6, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    return v9

    .line 88
    :cond_3
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->s()Lcom/google/android/gms/internal/measurement/q1;

    .line 89
    .line 90
    .line 91
    move-result-object v10

    .line 92
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->u()Z

    .line 93
    .line 94
    .line 95
    move-result v11

    .line 96
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->u()Z

    .line 97
    .line 98
    .line 99
    move-result v12

    .line 100
    const-wide/16 v13, 0x0

    .line 101
    .line 102
    if-eqz v12, :cond_5

    .line 103
    .line 104
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 105
    .line 106
    .line 107
    move-result v12

    .line 108
    if-nez v12, :cond_4

    .line 109
    .line 110
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 111
    .line 112
    .line 113
    iget-object v10, v1, Lvp/p0;->m:Lvp/n0;

    .line 114
    .line 115
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v11

    .line 119
    invoke-virtual {v3, v11}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    const-string v11, "No number filter for long property. property"

    .line 124
    .line 125
    invoke-virtual {v10, v3, v11}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    move v12, v7

    .line 129
    :goto_2
    const/4 v6, 0x0

    .line 130
    goto/16 :goto_6

    .line 131
    .line 132
    :cond_4
    move v12, v7

    .line 133
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->v()J

    .line 134
    .line 135
    .line 136
    move-result-wide v6

    .line 137
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    :try_start_0
    new-instance v10, Ljava/math/BigDecimal;

    .line 142
    .line 143
    invoke-direct {v10, v6, v7}, Ljava/math/BigDecimal;-><init>(J)V

    .line 144
    .line 145
    .line 146
    invoke-static {v10, v3, v13, v14}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 147
    .line 148
    .line 149
    move-result-object v6
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 150
    goto :goto_3

    .line 151
    :catch_0
    const/4 v6, 0x0

    .line 152
    :goto_3
    invoke-static {v6, v11}, Lvp/c;->f(Ljava/lang/Boolean;Z)Ljava/lang/Boolean;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    goto/16 :goto_6

    .line 157
    .line 158
    :cond_5
    move v12, v7

    .line 159
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->y()Z

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    if-eqz v6, :cond_7

    .line 164
    .line 165
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 166
    .line 167
    .line 168
    move-result v6

    .line 169
    if-nez v6, :cond_6

    .line 170
    .line 171
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 172
    .line 173
    .line 174
    iget-object v6, v1, Lvp/p0;->m:Lvp/n0;

    .line 175
    .line 176
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v7

    .line 180
    invoke-virtual {v3, v7}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    const-string v7, "No number filter for double property. property"

    .line 185
    .line 186
    invoke-virtual {v6, v3, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    goto :goto_2

    .line 190
    :cond_6
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->z()D

    .line 191
    .line 192
    .line 193
    move-result-wide v6

    .line 194
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    :try_start_1
    new-instance v10, Ljava/math/BigDecimal;

    .line 199
    .line 200
    invoke-direct {v10, v6, v7}, Ljava/math/BigDecimal;-><init>(D)V

    .line 201
    .line 202
    .line 203
    invoke-static {v6, v7}, Ljava/lang/Math;->ulp(D)D

    .line 204
    .line 205
    .line 206
    move-result-wide v6

    .line 207
    invoke-static {v10, v3, v6, v7}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 208
    .line 209
    .line 210
    move-result-object v6
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 211
    goto :goto_4

    .line 212
    :catch_1
    const/4 v6, 0x0

    .line 213
    :goto_4
    invoke-static {v6, v11}, Lvp/c;->f(Ljava/lang/Boolean;Z)Ljava/lang/Boolean;

    .line 214
    .line 215
    .line 216
    move-result-object v6

    .line 217
    goto/16 :goto_6

    .line 218
    .line 219
    :cond_7
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->s()Z

    .line 220
    .line 221
    .line 222
    move-result v6

    .line 223
    if-eqz v6, :cond_c

    .line 224
    .line 225
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->p()Z

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    if-nez v6, :cond_b

    .line 230
    .line 231
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->r()Z

    .line 232
    .line 233
    .line 234
    move-result v6

    .line 235
    if-nez v6, :cond_8

    .line 236
    .line 237
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 238
    .line 239
    .line 240
    iget-object v6, v1, Lvp/p0;->m:Lvp/n0;

    .line 241
    .line 242
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v7

    .line 246
    invoke-virtual {v3, v7}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v3

    .line 250
    const-string v7, "No string or number filter defined. property"

    .line 251
    .line 252
    invoke-virtual {v6, v3, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_8
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object v6

    .line 260
    invoke-static {v6}, Lvp/s0;->G0(Ljava/lang/String;)Z

    .line 261
    .line 262
    .line 263
    move-result v6

    .line 264
    if-eqz v6, :cond_a

    .line 265
    .line 266
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v3

    .line 270
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->s()Lcom/google/android/gms/internal/measurement/t1;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    invoke-static {v3}, Lvp/s0;->G0(Ljava/lang/String;)Z

    .line 275
    .line 276
    .line 277
    move-result v7

    .line 278
    if-nez v7, :cond_9

    .line 279
    .line 280
    :catch_2
    const/4 v6, 0x0

    .line 281
    goto :goto_5

    .line 282
    :cond_9
    :try_start_2
    new-instance v7, Ljava/math/BigDecimal;

    .line 283
    .line 284
    invoke-direct {v7, v3}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    invoke-static {v7, v6, v13, v14}, Lvp/c;->h(Ljava/math/BigDecimal;Lcom/google/android/gms/internal/measurement/t1;D)Ljava/lang/Boolean;

    .line 288
    .line 289
    .line 290
    move-result-object v6
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 291
    :goto_5
    invoke-static {v6, v11}, Lvp/c;->f(Ljava/lang/Boolean;Z)Ljava/lang/Boolean;

    .line 292
    .line 293
    .line 294
    move-result-object v6

    .line 295
    goto :goto_6

    .line 296
    :cond_a
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 297
    .line 298
    .line 299
    iget-object v6, v1, Lvp/p0;->m:Lvp/n0;

    .line 300
    .line 301
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v7

    .line 305
    invoke-virtual {v3, v7}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v3

    .line 309
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    const-string v10, "Invalid user property value for Numeric number filter. property, value"

    .line 314
    .line 315
    invoke-virtual {v6, v3, v7, v10}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    goto/16 :goto_2

    .line 319
    .line 320
    :cond_b
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->t()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/q1;->q()Lcom/google/android/gms/internal/measurement/w1;

    .line 325
    .line 326
    .line 327
    move-result-object v6

    .line 328
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 329
    .line 330
    .line 331
    invoke-static {v3, v6, v1}, Lvp/c;->g(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/w1;Lvp/p0;)Ljava/lang/Boolean;

    .line 332
    .line 333
    .line 334
    move-result-object v3

    .line 335
    invoke-static {v3, v11}, Lvp/c;->f(Ljava/lang/Boolean;Z)Ljava/lang/Boolean;

    .line 336
    .line 337
    .line 338
    move-result-object v6

    .line 339
    goto :goto_6

    .line 340
    :cond_c
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 341
    .line 342
    .line 343
    iget-object v6, v1, Lvp/p0;->m:Lvp/n0;

    .line 344
    .line 345
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->r()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object v7

    .line 349
    invoke-virtual {v3, v7}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 350
    .line 351
    .line 352
    move-result-object v3

    .line 353
    const-string v7, "User property has no value, property"

    .line 354
    .line 355
    invoke-virtual {v6, v3, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    goto/16 :goto_2

    .line 359
    .line 360
    :goto_6
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 361
    .line 362
    .line 363
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 364
    .line 365
    if-nez v6, :cond_d

    .line 366
    .line 367
    const-string v3, "null"

    .line 368
    .line 369
    goto :goto_7

    .line 370
    :cond_d
    move-object v3, v6

    .line 371
    :goto_7
    const-string v7, "Property filter result"

    .line 372
    .line 373
    invoke-virtual {v1, v3, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    if-nez v6, :cond_e

    .line 377
    .line 378
    return v8

    .line 379
    :cond_e
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 380
    .line 381
    iput-object v1, p0, Lvp/c;->c:Ljava/lang/Object;

    .line 382
    .line 383
    if-eqz v12, :cond_f

    .line 384
    .line 385
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 386
    .line 387
    .line 388
    move-result v1

    .line 389
    if-eqz v1, :cond_15

    .line 390
    .line 391
    :cond_f
    if-eqz p4, :cond_10

    .line 392
    .line 393
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->t()Z

    .line 394
    .line 395
    .line 396
    move-result v1

    .line 397
    if-eqz v1, :cond_11

    .line 398
    .line 399
    :cond_10
    iput-object v6, p0, Lvp/c;->d:Ljava/io/Serializable;

    .line 400
    .line 401
    :cond_11
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 402
    .line 403
    .line 404
    move-result v1

    .line 405
    if-eqz v1, :cond_15

    .line 406
    .line 407
    if-eqz v5, :cond_15

    .line 408
    .line 409
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->p()Z

    .line 410
    .line 411
    .line 412
    move-result v1

    .line 413
    if-eqz v1, :cond_15

    .line 414
    .line 415
    invoke-virtual/range {p3 .. p3}, Lcom/google/android/gms/internal/measurement/s3;->q()J

    .line 416
    .line 417
    .line 418
    move-result-wide v5

    .line 419
    if-eqz p1, :cond_12

    .line 420
    .line 421
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Long;->longValue()J

    .line 422
    .line 423
    .line 424
    move-result-wide v5

    .line 425
    :cond_12
    if-eqz v2, :cond_13

    .line 426
    .line 427
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->t()Z

    .line 428
    .line 429
    .line 430
    move-result v1

    .line 431
    if-eqz v1, :cond_13

    .line 432
    .line 433
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->u()Z

    .line 434
    .line 435
    .line 436
    move-result v1

    .line 437
    if-nez v1, :cond_13

    .line 438
    .line 439
    if-eqz p2, :cond_13

    .line 440
    .line 441
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Long;->longValue()J

    .line 442
    .line 443
    .line 444
    move-result-wide v5

    .line 445
    :cond_13
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/v1;->u()Z

    .line 446
    .line 447
    .line 448
    move-result v1

    .line 449
    if-eqz v1, :cond_14

    .line 450
    .line 451
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 452
    .line 453
    .line 454
    move-result-object v1

    .line 455
    iput-object v1, p0, Lvp/c;->f:Ljava/io/Serializable;

    .line 456
    .line 457
    goto :goto_8

    .line 458
    :cond_14
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 459
    .line 460
    .line 461
    move-result-object v1

    .line 462
    iput-object v1, p0, Lvp/c;->e:Ljava/io/Serializable;

    .line 463
    .line 464
    :cond_15
    :goto_8
    return v9
.end method
