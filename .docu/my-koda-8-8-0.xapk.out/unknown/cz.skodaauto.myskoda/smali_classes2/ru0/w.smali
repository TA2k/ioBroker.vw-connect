.class public final Lru0/w;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public d:Ljava/time/OffsetDateTime;

.field public e:Z

.field public f:I

.field public synthetic g:Lyy0/j;

.field public synthetic h:Ljava/time/OffsetDateTime;

.field public synthetic i:Lne0/s;

.field public synthetic j:Ltu0/h;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Ljava/time/OffsetDateTime;

    .line 4
    .line 5
    check-cast p3, Lne0/s;

    .line 6
    .line 7
    check-cast p4, Ltu0/h;

    .line 8
    .line 9
    check-cast p5, Lkotlin/coroutines/Continuation;

    .line 10
    .line 11
    new-instance p0, Lru0/w;

    .line 12
    .line 13
    const/4 v0, 0x5

    .line 14
    invoke-direct {p0, v0, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lru0/w;->g:Lyy0/j;

    .line 18
    .line 19
    iput-object p2, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    iput-object p3, p0, Lru0/w;->i:Lne0/s;

    .line 22
    .line 23
    iput-object p4, p0, Lru0/w;->j:Ltu0/h;

    .line 24
    .line 25
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lru0/w;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget-object v0, p0, Lru0/w;->g:Lyy0/j;

    .line 2
    .line 3
    iget-object v1, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 4
    .line 5
    iget-object v2, p0, Lru0/w;->i:Lne0/s;

    .line 6
    .line 7
    iget-object v3, p0, Lru0/w;->j:Ltu0/h;

    .line 8
    .line 9
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    iget v5, p0, Lru0/w;->f:I

    .line 12
    .line 13
    const-wide/16 v6, 0x78

    .line 14
    .line 15
    const/4 v8, 0x2

    .line 16
    const-wide/16 v9, 0x2

    .line 17
    .line 18
    sget-object v11, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    const/4 v12, 0x0

    .line 21
    packed-switch v5, :pswitch_data_0

    .line 22
    .line 23
    .line 24
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    return-object v11

    .line 36
    :pswitch_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-object v11

    .line 40
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-object v11

    .line 44
    :pswitch_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v11

    .line 48
    :pswitch_4
    iget-boolean v1, p0, Lru0/w;->e:Z

    .line 49
    .line 50
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto/16 :goto_7

    .line 54
    .line 55
    :pswitch_5
    iget-boolean v1, p0, Lru0/w;->e:Z

    .line 56
    .line 57
    iget-object v2, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto/16 :goto_6

    .line 63
    .line 64
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-object v11

    .line 68
    :pswitch_7
    iget-boolean v1, p0, Lru0/w;->e:Z

    .line 69
    .line 70
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :pswitch_8
    iget-boolean v2, p0, Lru0/w;->e:Z

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_0

    .line 80
    :pswitch_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x1

    .line 84
    if-eqz v1, :cond_2

    .line 85
    .line 86
    invoke-virtual {v1, v9, v10}, Ljava/time/OffsetDateTime;->plusMinutes(J)Ljava/time/OffsetDateTime;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 91
    .line 92
    .line 93
    move-result-object v13

    .line 94
    invoke-virtual {v5, v13}, Ljava/time/OffsetDateTime;->isAfter(Ljava/time/OffsetDateTime;)Z

    .line 95
    .line 96
    .line 97
    move-result v5

    .line 98
    if-eqz v5, :cond_2

    .line 99
    .line 100
    sget-object v2, Lra0/c;->d:Lra0/c;

    .line 101
    .line 102
    iput-object v0, p0, Lru0/w;->g:Lyy0/j;

    .line 103
    .line 104
    iput-object v1, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 105
    .line 106
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 107
    .line 108
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 109
    .line 110
    iput-boolean v5, p0, Lru0/w;->e:Z

    .line 111
    .line 112
    iput p1, p0, Lru0/w;->f:I

    .line 113
    .line 114
    invoke-interface {v0, v2, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    if-ne p1, v4, :cond_0

    .line 119
    .line 120
    goto/16 :goto_8

    .line 121
    .line 122
    :cond_0
    move v2, v5

    .line 123
    :goto_0
    invoke-virtual {v1, v9, v10}, Ljava/time/OffsetDateTime;->plusMinutes(J)Ljava/time/OffsetDateTime;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    invoke-virtual {v1}, Ljava/time/OffsetDateTime;->toEpochSecond()J

    .line 132
    .line 133
    .line 134
    move-result-wide v5

    .line 135
    invoke-virtual {p1, v5, v6}, Ljava/time/OffsetDateTime;->minusSeconds(J)Ljava/time/OffsetDateTime;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    sget v1, Lmy0/c;->g:I

    .line 140
    .line 141
    invoke-virtual {p1}, Ljava/time/OffsetDateTime;->toEpochSecond()J

    .line 142
    .line 143
    .line 144
    move-result-wide v5

    .line 145
    sget-object p1, Lmy0/e;->h:Lmy0/e;

    .line 146
    .line 147
    invoke-static {v5, v6, p1}, Lmy0/h;->t(JLmy0/e;)J

    .line 148
    .line 149
    .line 150
    move-result-wide v5

    .line 151
    invoke-static {v5, v6}, Lmy0/c;->e(J)J

    .line 152
    .line 153
    .line 154
    move-result-wide v5

    .line 155
    iput-object v0, p0, Lru0/w;->g:Lyy0/j;

    .line 156
    .line 157
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 158
    .line 159
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 160
    .line 161
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 162
    .line 163
    iput-boolean v2, p0, Lru0/w;->e:Z

    .line 164
    .line 165
    iput v8, p0, Lru0/w;->f:I

    .line 166
    .line 167
    invoke-static {v5, v6, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    if-ne p1, v4, :cond_1

    .line 172
    .line 173
    goto/16 :goto_8

    .line 174
    .line 175
    :cond_1
    move v1, v2

    .line 176
    :goto_1
    sget-object p1, Lra0/c;->f:Lra0/c;

    .line 177
    .line 178
    iput-object v12, p0, Lru0/w;->g:Lyy0/j;

    .line 179
    .line 180
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 181
    .line 182
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 183
    .line 184
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 185
    .line 186
    iput-boolean v1, p0, Lru0/w;->e:Z

    .line 187
    .line 188
    const/4 v1, 0x3

    .line 189
    iput v1, p0, Lru0/w;->f:I

    .line 190
    .line 191
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    if-ne p0, v4, :cond_c

    .line 196
    .line 197
    goto/16 :goto_8

    .line 198
    .line 199
    :cond_2
    instance-of v1, v2, Lne0/e;

    .line 200
    .line 201
    if-eqz v1, :cond_3

    .line 202
    .line 203
    check-cast v2, Lne0/e;

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_3
    move-object v2, v12

    .line 207
    :goto_2
    if-eqz v2, :cond_4

    .line 208
    .line 209
    iget-object v1, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 210
    .line 211
    check-cast v1, Lrd0/j;

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_4
    move-object v1, v12

    .line 215
    :goto_3
    if-eqz v1, :cond_5

    .line 216
    .line 217
    iget-object v2, v1, Lrd0/j;->h:Ljava/time/OffsetDateTime;

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_5
    move-object v2, v12

    .line 221
    :goto_4
    if-eqz v1, :cond_9

    .line 222
    .line 223
    if-eqz v2, :cond_9

    .line 224
    .line 225
    invoke-static {v1}, Lkp/z;->e(Lrd0/j;)Z

    .line 226
    .line 227
    .line 228
    move-result v1

    .line 229
    if-eqz v1, :cond_6

    .line 230
    .line 231
    invoke-virtual {v2, v6, v7}, Ljava/time/OffsetDateTime;->plusMinutes(J)Ljava/time/OffsetDateTime;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 236
    .line 237
    .line 238
    move-result-object v5

    .line 239
    invoke-virtual {v1, v5}, Ljava/time/OffsetDateTime;->isAfter(Ljava/time/OffsetDateTime;)Z

    .line 240
    .line 241
    .line 242
    move-result v1

    .line 243
    if-eqz v1, :cond_6

    .line 244
    .line 245
    move v1, p1

    .line 246
    goto :goto_5

    .line 247
    :cond_6
    const/4 v1, 0x0

    .line 248
    :goto_5
    if-eqz v1, :cond_9

    .line 249
    .line 250
    sget-object p1, Lra0/c;->d:Lra0/c;

    .line 251
    .line 252
    iput-object v0, p0, Lru0/w;->g:Lyy0/j;

    .line 253
    .line 254
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 255
    .line 256
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 257
    .line 258
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 259
    .line 260
    iput-object v2, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 261
    .line 262
    iput-boolean v1, p0, Lru0/w;->e:Z

    .line 263
    .line 264
    const/4 v3, 0x4

    .line 265
    iput v3, p0, Lru0/w;->f:I

    .line 266
    .line 267
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object p1

    .line 271
    if-ne p1, v4, :cond_7

    .line 272
    .line 273
    goto/16 :goto_8

    .line 274
    .line 275
    :cond_7
    :goto_6
    invoke-virtual {v2, v6, v7}, Ljava/time/OffsetDateTime;->plusMinutes(J)Ljava/time/OffsetDateTime;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 280
    .line 281
    .line 282
    move-result-object v2

    .line 283
    invoke-virtual {v2}, Ljava/time/OffsetDateTime;->toEpochSecond()J

    .line 284
    .line 285
    .line 286
    move-result-wide v2

    .line 287
    invoke-virtual {p1, v2, v3}, Ljava/time/OffsetDateTime;->minusSeconds(J)Ljava/time/OffsetDateTime;

    .line 288
    .line 289
    .line 290
    move-result-object p1

    .line 291
    sget v2, Lmy0/c;->g:I

    .line 292
    .line 293
    invoke-virtual {p1}, Ljava/time/OffsetDateTime;->toEpochSecond()J

    .line 294
    .line 295
    .line 296
    move-result-wide v2

    .line 297
    sget-object p1, Lmy0/e;->h:Lmy0/e;

    .line 298
    .line 299
    invoke-static {v2, v3, p1}, Lmy0/h;->t(JLmy0/e;)J

    .line 300
    .line 301
    .line 302
    move-result-wide v2

    .line 303
    invoke-static {v2, v3}, Lmy0/c;->e(J)J

    .line 304
    .line 305
    .line 306
    move-result-wide v2

    .line 307
    iput-object v0, p0, Lru0/w;->g:Lyy0/j;

    .line 308
    .line 309
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 310
    .line 311
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 312
    .line 313
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 314
    .line 315
    iput-object v12, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 316
    .line 317
    iput-boolean v1, p0, Lru0/w;->e:Z

    .line 318
    .line 319
    const/4 p1, 0x5

    .line 320
    iput p1, p0, Lru0/w;->f:I

    .line 321
    .line 322
    invoke-static {v2, v3, p0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object p1

    .line 326
    if-ne p1, v4, :cond_8

    .line 327
    .line 328
    goto :goto_8

    .line 329
    :cond_8
    :goto_7
    sget-object p1, Lra0/c;->f:Lra0/c;

    .line 330
    .line 331
    iput-object v12, p0, Lru0/w;->g:Lyy0/j;

    .line 332
    .line 333
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 334
    .line 335
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 336
    .line 337
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 338
    .line 339
    iput-object v12, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 340
    .line 341
    iput-boolean v1, p0, Lru0/w;->e:Z

    .line 342
    .line 343
    const/4 v1, 0x6

    .line 344
    iput v1, p0, Lru0/w;->f:I

    .line 345
    .line 346
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    if-ne p0, v4, :cond_c

    .line 351
    .line 352
    goto :goto_8

    .line 353
    :cond_9
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 354
    .line 355
    .line 356
    move-result v1

    .line 357
    if-eq v1, p1, :cond_b

    .line 358
    .line 359
    if-eq v1, v8, :cond_a

    .line 360
    .line 361
    sget-object p1, Lra0/c;->f:Lra0/c;

    .line 362
    .line 363
    iput-object v12, p0, Lru0/w;->g:Lyy0/j;

    .line 364
    .line 365
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 366
    .line 367
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 368
    .line 369
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 370
    .line 371
    iput-object v12, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 372
    .line 373
    const/16 v1, 0x9

    .line 374
    .line 375
    iput v1, p0, Lru0/w;->f:I

    .line 376
    .line 377
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object p0

    .line 381
    if-ne p0, v4, :cond_c

    .line 382
    .line 383
    goto :goto_8

    .line 384
    :cond_a
    sget-object p1, Lra0/c;->d:Lra0/c;

    .line 385
    .line 386
    iput-object v12, p0, Lru0/w;->g:Lyy0/j;

    .line 387
    .line 388
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 389
    .line 390
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 391
    .line 392
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 393
    .line 394
    iput-object v12, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 395
    .line 396
    const/4 v1, 0x7

    .line 397
    iput v1, p0, Lru0/w;->f:I

    .line 398
    .line 399
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object p0

    .line 403
    if-ne p0, v4, :cond_c

    .line 404
    .line 405
    goto :goto_8

    .line 406
    :cond_b
    sget-object p1, Lra0/c;->e:Lra0/c;

    .line 407
    .line 408
    iput-object v12, p0, Lru0/w;->g:Lyy0/j;

    .line 409
    .line 410
    iput-object v12, p0, Lru0/w;->h:Ljava/time/OffsetDateTime;

    .line 411
    .line 412
    iput-object v12, p0, Lru0/w;->i:Lne0/s;

    .line 413
    .line 414
    iput-object v12, p0, Lru0/w;->j:Ltu0/h;

    .line 415
    .line 416
    iput-object v12, p0, Lru0/w;->d:Ljava/time/OffsetDateTime;

    .line 417
    .line 418
    const/16 v1, 0x8

    .line 419
    .line 420
    iput v1, p0, Lru0/w;->f:I

    .line 421
    .line 422
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object p0

    .line 426
    if-ne p0, v4, :cond_c

    .line 427
    .line 428
    :goto_8
    return-object v4

    .line 429
    :cond_c
    return-object v11

    .line 430
    nop

    .line 431
    :pswitch_data_0
    .packed-switch 0x0
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
