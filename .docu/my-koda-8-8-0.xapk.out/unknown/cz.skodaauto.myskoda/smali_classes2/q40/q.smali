.class public final Lq40/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lq40/t;


# direct methods
.method public synthetic constructor <init>(Lq40/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lq40/q;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq40/q;->e:Lq40/t;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget v2, v0, Lq40/q;->d:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v2, p1

    .line 11
    .line 12
    check-cast v2, Lne0/s;

    .line 13
    .line 14
    instance-of v3, v2, Lne0/c;

    .line 15
    .line 16
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    iget-object v0, v0, Lq40/q;->e:Lq40/t;

    .line 19
    .line 20
    if-eqz v3, :cond_3

    .line 21
    .line 22
    check-cast v2, Lne0/c;

    .line 23
    .line 24
    const v1, 0x7f120373

    .line 25
    .line 26
    .line 27
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    sget-object v3, Lon0/o;->h:Lon0/o;

    .line 32
    .line 33
    sget-object v5, Lon0/o;->i:Lon0/o;

    .line 34
    .line 35
    filled-new-array {v3, v5}, [Lon0/o;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-static {v3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    invoke-static {v2, v3}, Lq40/t;->l(Lne0/c;Ljava/util/List;)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    const v5, 0x7f12038b

    .line 48
    .line 49
    .line 50
    if-eqz v3, :cond_0

    .line 51
    .line 52
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    move-object v6, v2

    .line 57
    check-cast v6, Lq40/p;

    .line 58
    .line 59
    const v2, 0x7f120e2d

    .line 60
    .line 61
    .line 62
    const v3, 0x7f120e2c

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v2, v3, v5, v1}, Lq40/t;->k(IIILjava/lang/Integer;)Lql0/g;

    .line 66
    .line 67
    .line 68
    move-result-object v15

    .line 69
    const/16 v16, 0x0

    .line 70
    .line 71
    const/16 v17, 0x6fd

    .line 72
    .line 73
    const/4 v7, 0x0

    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v9, 0x0

    .line 76
    const/4 v10, 0x0

    .line 77
    const/4 v11, 0x0

    .line 78
    const/4 v12, 0x0

    .line 79
    const/4 v13, 0x0

    .line 80
    const/4 v14, 0x0

    .line 81
    invoke-static/range {v6 .. v17}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    goto/16 :goto_0

    .line 86
    .line 87
    :cond_0
    sget-object v3, Lon0/o;->f:Lon0/o;

    .line 88
    .line 89
    sget-object v6, Lon0/o;->g:Lon0/o;

    .line 90
    .line 91
    filled-new-array {v3, v6}, [Lon0/o;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-static {v3}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    invoke-static {v2, v3}, Lq40/t;->l(Lne0/c;Ljava/util/List;)Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eqz v3, :cond_1

    .line 104
    .line 105
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    move-object v6, v2

    .line 110
    check-cast v6, Lq40/p;

    .line 111
    .line 112
    const v2, 0x7f120e5c

    .line 113
    .line 114
    .line 115
    const v3, 0x7f120e5b

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, v2, v3, v5, v1}, Lq40/t;->k(IIILjava/lang/Integer;)Lql0/g;

    .line 119
    .line 120
    .line 121
    move-result-object v15

    .line 122
    const/16 v16, 0x0

    .line 123
    .line 124
    const/16 v17, 0x6fd

    .line 125
    .line 126
    const/4 v7, 0x0

    .line 127
    const/4 v8, 0x0

    .line 128
    const/4 v9, 0x0

    .line 129
    const/4 v10, 0x0

    .line 130
    const/4 v11, 0x0

    .line 131
    const/4 v12, 0x0

    .line 132
    const/4 v13, 0x0

    .line 133
    const/4 v14, 0x0

    .line 134
    invoke-static/range {v6 .. v17}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    goto :goto_0

    .line 139
    :cond_1
    sget-object v1, Lon0/o;->e:Lon0/o;

    .line 140
    .line 141
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    invoke-static {v2, v1}, Lq40/t;->l(Lne0/c;Ljava/util/List;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-eqz v1, :cond_2

    .line 150
    .line 151
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    move-object v5, v1

    .line 156
    check-cast v5, Lq40/p;

    .line 157
    .line 158
    const v1, 0x7f120e5d

    .line 159
    .line 160
    .line 161
    const v2, 0x7f120382

    .line 162
    .line 163
    .line 164
    const v3, 0x7f120e5e

    .line 165
    .line 166
    .line 167
    const/4 v6, 0x0

    .line 168
    invoke-virtual {v0, v3, v1, v2, v6}, Lq40/t;->k(IIILjava/lang/Integer;)Lql0/g;

    .line 169
    .line 170
    .line 171
    move-result-object v14

    .line 172
    const/4 v15, 0x1

    .line 173
    const/16 v16, 0x4fd

    .line 174
    .line 175
    const/4 v7, 0x0

    .line 176
    const/4 v8, 0x0

    .line 177
    const/4 v9, 0x0

    .line 178
    const/4 v10, 0x0

    .line 179
    const/4 v11, 0x0

    .line 180
    const/4 v12, 0x0

    .line 181
    const/4 v13, 0x0

    .line 182
    invoke-static/range {v5 .. v16}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 183
    .line 184
    .line 185
    move-result-object v1

    .line 186
    goto :goto_0

    .line 187
    :cond_2
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 188
    .line 189
    .line 190
    move-result-object v1

    .line 191
    move-object v5, v1

    .line 192
    check-cast v5, Lq40/p;

    .line 193
    .line 194
    iget-object v1, v0, Lq40/t;->o:Lij0/a;

    .line 195
    .line 196
    invoke-static {v2, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 197
    .line 198
    .line 199
    move-result-object v14

    .line 200
    const/4 v15, 0x0

    .line 201
    const/16 v16, 0x2fd

    .line 202
    .line 203
    const/4 v6, 0x0

    .line 204
    const/4 v7, 0x0

    .line 205
    const/4 v8, 0x0

    .line 206
    const/4 v9, 0x0

    .line 207
    const/4 v10, 0x0

    .line 208
    const/4 v11, 0x0

    .line 209
    const/4 v12, 0x0

    .line 210
    const/4 v13, 0x0

    .line 211
    invoke-static/range {v5 .. v16}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    :goto_0
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 216
    .line 217
    .line 218
    goto :goto_1

    .line 219
    :cond_3
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 220
    .line 221
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    if-eqz v3, :cond_4

    .line 226
    .line 227
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    move-object v5, v1

    .line 232
    check-cast v5, Lq40/p;

    .line 233
    .line 234
    const/4 v15, 0x0

    .line 235
    const/16 v16, 0x7fd

    .line 236
    .line 237
    const/4 v6, 0x0

    .line 238
    const/4 v7, 0x1

    .line 239
    const/4 v8, 0x0

    .line 240
    const/4 v9, 0x0

    .line 241
    const/4 v10, 0x0

    .line 242
    const/4 v11, 0x0

    .line 243
    const/4 v12, 0x0

    .line 244
    const/4 v13, 0x0

    .line 245
    const/4 v14, 0x0

    .line 246
    invoke-static/range {v5 .. v16}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 251
    .line 252
    .line 253
    goto :goto_1

    .line 254
    :cond_4
    instance-of v3, v2, Lne0/e;

    .line 255
    .line 256
    if-eqz v3, :cond_6

    .line 257
    .line 258
    check-cast v2, Lne0/e;

    .line 259
    .line 260
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast v2, Lp40/a;

    .line 263
    .line 264
    invoke-static {v0, v2, v1}, Lq40/t;->h(Lq40/t;Lp40/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 269
    .line 270
    if-ne v0, v1, :cond_5

    .line 271
    .line 272
    move-object v4, v0

    .line 273
    :cond_5
    :goto_1
    return-object v4

    .line 274
    :cond_6
    new-instance v0, La8/r0;

    .line 275
    .line 276
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 277
    .line 278
    .line 279
    throw v0

    .line 280
    :pswitch_0
    move-object/from16 v2, p1

    .line 281
    .line 282
    check-cast v2, Lne0/s;

    .line 283
    .line 284
    instance-of v3, v2, Lne0/c;

    .line 285
    .line 286
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    iget-object v0, v0, Lq40/q;->e:Lq40/t;

    .line 289
    .line 290
    if-eqz v3, :cond_7

    .line 291
    .line 292
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    move-object v5, v1

    .line 297
    check-cast v5, Lq40/p;

    .line 298
    .line 299
    check-cast v2, Lne0/c;

    .line 300
    .line 301
    iget-object v1, v0, Lq40/t;->o:Lij0/a;

    .line 302
    .line 303
    invoke-static {v2, v1}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 304
    .line 305
    .line 306
    move-result-object v14

    .line 307
    const/4 v15, 0x0

    .line 308
    const/16 v16, 0x6fd

    .line 309
    .line 310
    const/4 v6, 0x0

    .line 311
    const/4 v7, 0x0

    .line 312
    const/4 v8, 0x0

    .line 313
    const/4 v9, 0x0

    .line 314
    const/4 v10, 0x0

    .line 315
    const/4 v11, 0x0

    .line 316
    const/4 v12, 0x0

    .line 317
    const/4 v13, 0x0

    .line 318
    invoke-static/range {v5 .. v16}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 319
    .line 320
    .line 321
    move-result-object v1

    .line 322
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 323
    .line 324
    .line 325
    goto :goto_2

    .line 326
    :cond_7
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 327
    .line 328
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    move-result v3

    .line 332
    if-eqz v3, :cond_8

    .line 333
    .line 334
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    move-object v5, v1

    .line 339
    check-cast v5, Lq40/p;

    .line 340
    .line 341
    const/4 v15, 0x0

    .line 342
    const/16 v16, 0x7fd

    .line 343
    .line 344
    const/4 v6, 0x0

    .line 345
    const/4 v7, 0x1

    .line 346
    const/4 v8, 0x0

    .line 347
    const/4 v9, 0x0

    .line 348
    const/4 v10, 0x0

    .line 349
    const/4 v11, 0x0

    .line 350
    const/4 v12, 0x0

    .line 351
    const/4 v13, 0x0

    .line 352
    const/4 v14, 0x0

    .line 353
    invoke-static/range {v5 .. v16}, Lq40/p;->a(Lq40/p;Ljava/lang/String;ZLon0/w;Lon0/x;Ljava/lang/String;Lon0/y;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZI)Lq40/p;

    .line 354
    .line 355
    .line 356
    move-result-object v1

    .line 357
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 358
    .line 359
    .line 360
    goto :goto_2

    .line 361
    :cond_8
    instance-of v3, v2, Lne0/e;

    .line 362
    .line 363
    if-eqz v3, :cond_a

    .line 364
    .line 365
    check-cast v2, Lne0/e;

    .line 366
    .line 367
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v2, Lon0/q;

    .line 370
    .line 371
    invoke-static {v0, v2, v1}, Lq40/t;->j(Lq40/t;Lon0/q;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v0

    .line 375
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 376
    .line 377
    if-ne v0, v1, :cond_9

    .line 378
    .line 379
    move-object v4, v0

    .line 380
    :cond_9
    :goto_2
    return-object v4

    .line 381
    :cond_a
    new-instance v0, La8/r0;

    .line 382
    .line 383
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 384
    .line 385
    .line 386
    throw v0

    .line 387
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
