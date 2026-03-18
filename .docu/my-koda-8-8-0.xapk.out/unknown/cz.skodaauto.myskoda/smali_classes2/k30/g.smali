.class public final Lk30/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk30/h;


# direct methods
.method public synthetic constructor <init>(Lk30/h;I)V
    .locals 0

    .line 1
    iput p2, p0, Lk30/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk30/g;->e:Lk30/h;

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
    iget v1, v0, Lk30/g;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lne0/s;

    .line 11
    .line 12
    iget-object v0, v0, Lk30/g;->e:Lk30/h;

    .line 13
    .line 14
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    move-object v3, v2

    .line 19
    check-cast v3, Lk30/e;

    .line 20
    .line 21
    instance-of v11, v1, Lne0/d;

    .line 22
    .line 23
    instance-of v2, v1, Lne0/c;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    check-cast v1, Lne0/c;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move-object v1, v4

    .line 32
    :goto_0
    if-eqz v1, :cond_1

    .line 33
    .line 34
    iget-object v2, v0, Lk30/h;->m:Lij0/a;

    .line 35
    .line 36
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    :cond_1
    move-object v13, v4

    .line 41
    const/4 v15, 0x0

    .line 42
    const/16 v16, 0xd7f

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    const/4 v5, 0x0

    .line 46
    const/4 v6, 0x0

    .line 47
    const/4 v7, 0x0

    .line 48
    const/4 v8, 0x0

    .line 49
    const/4 v9, 0x0

    .line 50
    const/4 v10, 0x0

    .line 51
    const/4 v12, 0x0

    .line 52
    const/4 v14, 0x0

    .line 53
    invoke-static/range {v3 .. v16}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 58
    .line 59
    .line 60
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object v0

    .line 63
    :pswitch_0
    move-object/from16 v1, p1

    .line 64
    .line 65
    check-cast v1, Lne0/s;

    .line 66
    .line 67
    instance-of v2, v1, Lne0/d;

    .line 68
    .line 69
    iget-object v0, v0, Lk30/g;->e:Lk30/h;

    .line 70
    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    move-object v2, v1

    .line 78
    check-cast v2, Lk30/e;

    .line 79
    .line 80
    const/4 v14, 0x0

    .line 81
    const/16 v15, 0xffb

    .line 82
    .line 83
    const/4 v3, 0x0

    .line 84
    const/4 v4, 0x0

    .line 85
    const/4 v5, 0x1

    .line 86
    const/4 v6, 0x0

    .line 87
    const/4 v7, 0x0

    .line 88
    const/4 v8, 0x0

    .line 89
    const/4 v9, 0x0

    .line 90
    const/4 v10, 0x0

    .line 91
    const/4 v11, 0x0

    .line 92
    const/4 v12, 0x0

    .line 93
    const/4 v13, 0x0

    .line 94
    invoke-static/range {v2 .. v15}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 99
    .line 100
    .line 101
    goto/16 :goto_6

    .line 102
    .line 103
    :cond_2
    instance-of v2, v1, Lne0/e;

    .line 104
    .line 105
    const/16 v3, 0xa

    .line 106
    .line 107
    if-eqz v2, :cond_5

    .line 108
    .line 109
    check-cast v1, Lne0/e;

    .line 110
    .line 111
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v1, Lj30/c;

    .line 114
    .line 115
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    move-object v4, v2

    .line 120
    check-cast v4, Lk30/e;

    .line 121
    .line 122
    iget-object v2, v0, Lk30/h;->h:Li30/b;

    .line 123
    .line 124
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    check-cast v2, Ljava/lang/Boolean;

    .line 129
    .line 130
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    iget-object v2, v1, Lj30/c;->a:Ljava/time/OffsetDateTime;

    .line 135
    .line 136
    iget-object v1, v1, Lj30/c;->c:Ljava/util/ArrayList;

    .line 137
    .line 138
    if-eqz v2, :cond_3

    .line 139
    .line 140
    invoke-static {v2}, Lvo/a;->j(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    iget-object v5, v0, Lk30/h;->m:Lij0/a;

    .line 145
    .line 146
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    check-cast v5, Ljj0/f;

    .line 151
    .line 152
    const v7, 0x7f121567

    .line 153
    .line 154
    .line 155
    invoke-virtual {v5, v7, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    :goto_1
    move-object v8, v2

    .line 160
    goto :goto_2

    .line 161
    :cond_3
    const-string v2, ""

    .line 162
    .line 163
    goto :goto_1

    .line 164
    :goto_2
    invoke-static {v1}, Lk30/h;->k(Ljava/util/ArrayList;)Z

    .line 165
    .line 166
    .line 167
    move-result v10

    .line 168
    invoke-virtual {v0, v1}, Lk30/h;->j(Ljava/util/ArrayList;)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v9

    .line 172
    new-instance v11, Ljava/util/ArrayList;

    .line 173
    .line 174
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    invoke-direct {v11, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    if-eqz v2, :cond_4

    .line 190
    .line 191
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    check-cast v2, Lj30/b;

    .line 196
    .line 197
    invoke-virtual {v0, v2}, Lk30/h;->q(Lj30/b;)Lk30/d;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_4
    const/16 v16, 0x0

    .line 206
    .line 207
    const/16 v17, 0xe81

    .line 208
    .line 209
    const/4 v5, 0x0

    .line 210
    const/4 v7, 0x0

    .line 211
    const/4 v12, 0x0

    .line 212
    const/4 v13, 0x0

    .line 213
    const/4 v14, 0x0

    .line 214
    const/4 v15, 0x0

    .line 215
    invoke-static/range {v4 .. v17}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 220
    .line 221
    .line 222
    goto/16 :goto_6

    .line 223
    .line 224
    :cond_5
    instance-of v2, v1, Lne0/c;

    .line 225
    .line 226
    if-eqz v2, :cond_8

    .line 227
    .line 228
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 229
    .line 230
    .line 231
    move-result-object v2

    .line 232
    move-object v4, v2

    .line 233
    check-cast v4, Lk30/e;

    .line 234
    .line 235
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    check-cast v2, Lk30/e;

    .line 240
    .line 241
    iget-object v2, v2, Lk30/e;->a:Lss0/e;

    .line 242
    .line 243
    sget-object v5, Lk30/f;->a:[I

    .line 244
    .line 245
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    aget v2, v5, v2

    .line 250
    .line 251
    const/4 v5, 0x1

    .line 252
    if-ne v2, v5, :cond_6

    .line 253
    .line 254
    sget-object v6, Lj30/a;->d:Lj30/a;

    .line 255
    .line 256
    sget-object v7, Lj30/a;->e:Lj30/a;

    .line 257
    .line 258
    sget-object v8, Lj30/a;->f:Lj30/a;

    .line 259
    .line 260
    sget-object v9, Lj30/a;->h:Lj30/a;

    .line 261
    .line 262
    sget-object v10, Lj30/a;->i:Lj30/a;

    .line 263
    .line 264
    sget-object v11, Lj30/a;->j:Lj30/a;

    .line 265
    .line 266
    sget-object v12, Lj30/a;->k:Lj30/a;

    .line 267
    .line 268
    filled-new-array/range {v6 .. v12}, [Lj30/a;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    goto :goto_4

    .line 277
    :cond_6
    sget-object v5, Lj30/a;->d:Lj30/a;

    .line 278
    .line 279
    sget-object v6, Lj30/a;->e:Lj30/a;

    .line 280
    .line 281
    sget-object v7, Lj30/a;->f:Lj30/a;

    .line 282
    .line 283
    sget-object v8, Lj30/a;->g:Lj30/a;

    .line 284
    .line 285
    sget-object v9, Lj30/a;->i:Lj30/a;

    .line 286
    .line 287
    sget-object v10, Lj30/a;->j:Lj30/a;

    .line 288
    .line 289
    sget-object v11, Lj30/a;->k:Lj30/a;

    .line 290
    .line 291
    filled-new-array/range {v5 .. v11}, [Lj30/a;

    .line 292
    .line 293
    .line 294
    move-result-object v2

    .line 295
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 296
    .line 297
    .line 298
    move-result-object v2

    .line 299
    :goto_4
    check-cast v2, Ljava/lang/Iterable;

    .line 300
    .line 301
    new-instance v11, Ljava/util/ArrayList;

    .line 302
    .line 303
    invoke-static {v2, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 304
    .line 305
    .line 306
    move-result v3

    .line 307
    invoke-direct {v11, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 308
    .line 309
    .line 310
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 311
    .line 312
    .line 313
    move-result-object v2

    .line 314
    :goto_5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 315
    .line 316
    .line 317
    move-result v3

    .line 318
    if-eqz v3, :cond_7

    .line 319
    .line 320
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v3

    .line 324
    check-cast v3, Lj30/a;

    .line 325
    .line 326
    new-instance v5, Lj30/b;

    .line 327
    .line 328
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 329
    .line 330
    invoke-direct {v5, v3, v6}, Lj30/b;-><init>(Lj30/a;Ljava/util/List;)V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v0, v5}, Lk30/h;->q(Lj30/b;)Lk30/d;

    .line 334
    .line 335
    .line 336
    move-result-object v3

    .line 337
    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    goto :goto_5

    .line 341
    :cond_7
    const/16 v16, 0x0

    .line 342
    .line 343
    const/16 v17, 0xebf

    .line 344
    .line 345
    const/4 v5, 0x0

    .line 346
    const/4 v6, 0x0

    .line 347
    const/4 v7, 0x0

    .line 348
    const/4 v8, 0x0

    .line 349
    const/4 v9, 0x0

    .line 350
    const/4 v10, 0x0

    .line 351
    const/4 v12, 0x0

    .line 352
    const/4 v13, 0x1

    .line 353
    const/4 v14, 0x0

    .line 354
    const/4 v15, 0x0

    .line 355
    invoke-static/range {v4 .. v17}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 360
    .line 361
    .line 362
    check-cast v1, Lne0/c;

    .line 363
    .line 364
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 365
    .line 366
    .line 367
    move-result-object v2

    .line 368
    new-instance v3, Lif0/d0;

    .line 369
    .line 370
    const/16 v4, 0x1a

    .line 371
    .line 372
    invoke-direct {v3, v4, v0, v1, v5}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 373
    .line 374
    .line 375
    const/4 v0, 0x3

    .line 376
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 377
    .line 378
    .line 379
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 380
    .line 381
    return-object v0

    .line 382
    :cond_8
    new-instance v0, La8/r0;

    .line 383
    .line 384
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 385
    .line 386
    .line 387
    throw v0

    .line 388
    nop

    .line 389
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
