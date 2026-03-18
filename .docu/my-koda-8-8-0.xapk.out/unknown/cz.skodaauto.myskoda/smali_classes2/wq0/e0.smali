.class public final Lwq0/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwq0/r;

.field public final b:Lwq0/m0;

.field public final c:Lzd0/c;

.field public final d:Lwq0/g;

.field public final e:Lwq0/o;

.field public final f:Lwq0/p;

.field public final g:Lwq0/l0;


# direct methods
.method public constructor <init>(Lwq0/r;Lwq0/m0;Lzd0/c;Lwq0/g;Lwq0/o;Lwq0/p;Lwq0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/e0;->a:Lwq0/r;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/e0;->b:Lwq0/m0;

    .line 7
    .line 8
    iput-object p3, p0, Lwq0/e0;->c:Lzd0/c;

    .line 9
    .line 10
    iput-object p4, p0, Lwq0/e0;->d:Lwq0/g;

    .line 11
    .line 12
    iput-object p5, p0, Lwq0/e0;->e:Lwq0/o;

    .line 13
    .line 14
    iput-object p6, p0, Lwq0/e0;->f:Lwq0/p;

    .line 15
    .line 16
    iput-object p7, p0, Lwq0/e0;->g:Lwq0/l0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyq0/n;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lwq0/e0;->b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lyq0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    instance-of v0, p2, Lwq0/b0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lwq0/b0;

    .line 7
    .line 8
    iget v1, v0, Lwq0/b0;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lwq0/b0;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/b0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lwq0/b0;-><init>(Lwq0/e0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lwq0/b0;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/b0;->k:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x5

    .line 33
    const/4 v5, 0x4

    .line 34
    const/4 v6, 0x3

    .line 35
    const/4 v7, 0x2

    .line 36
    const/4 v8, 0x1

    .line 37
    iget-object v9, p0, Lwq0/e0;->a:Lwq0/r;

    .line 38
    .line 39
    const/4 v10, 0x0

    .line 40
    if-eqz v2, :cond_6

    .line 41
    .line 42
    if-eq v2, v8, :cond_5

    .line 43
    .line 44
    if-eq v2, v7, :cond_4

    .line 45
    .line 46
    if-eq v2, v6, :cond_3

    .line 47
    .line 48
    if-eq v2, v5, :cond_2

    .line 49
    .line 50
    if-ne v2, v4, :cond_1

    .line 51
    .line 52
    iget-object p0, v0, Lwq0/b0;->f:Lne0/e;

    .line 53
    .line 54
    iget-object p1, v0, Lwq0/b0;->e:Lez0/a;

    .line 55
    .line 56
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 57
    .line 58
    .line 59
    goto/16 :goto_6

    .line 60
    .line 61
    :catchall_0
    move-exception v0

    .line 62
    move-object p0, v0

    .line 63
    goto/16 :goto_a

    .line 64
    .line 65
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_2
    iget p1, v0, Lwq0/b0;->h:I

    .line 74
    .line 75
    iget v2, v0, Lwq0/b0;->g:I

    .line 76
    .line 77
    iget-object v3, v0, Lwq0/b0;->e:Lez0/a;

    .line 78
    .line 79
    iget-object v5, v0, Lwq0/b0;->d:Lyq0/n;

    .line 80
    .line 81
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 82
    .line 83
    .line 84
    move-object v12, v3

    .line 85
    move v3, p1

    .line 86
    move-object p1, v12

    .line 87
    goto/16 :goto_4

    .line 88
    .line 89
    :catchall_1
    move-exception v0

    .line 90
    move-object p0, v0

    .line 91
    move-object p1, v3

    .line 92
    goto/16 :goto_a

    .line 93
    .line 94
    :cond_3
    iget p1, v0, Lwq0/b0;->h:I

    .line 95
    .line 96
    iget v2, v0, Lwq0/b0;->g:I

    .line 97
    .line 98
    iget-object v3, v0, Lwq0/b0;->e:Lez0/a;

    .line 99
    .line 100
    iget-object v6, v0, Lwq0/b0;->d:Lyq0/n;

    .line 101
    .line 102
    :try_start_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 103
    .line 104
    .line 105
    move-object v12, v3

    .line 106
    move v3, p1

    .line 107
    move-object p1, v12

    .line 108
    goto/16 :goto_3

    .line 109
    .line 110
    :cond_4
    iget v3, v0, Lwq0/b0;->h:I

    .line 111
    .line 112
    iget p1, v0, Lwq0/b0;->g:I

    .line 113
    .line 114
    iget-object v2, v0, Lwq0/b0;->e:Lez0/a;

    .line 115
    .line 116
    iget-object v7, v0, Lwq0/b0;->d:Lyq0/n;

    .line 117
    .line 118
    :try_start_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 119
    .line 120
    .line 121
    move-object v12, v2

    .line 122
    move v2, p1

    .line 123
    move-object p1, v12

    .line 124
    goto :goto_2

    .line 125
    :catchall_2
    move-exception v0

    .line 126
    move-object p0, v0

    .line 127
    move-object p1, v2

    .line 128
    goto/16 :goto_a

    .line 129
    .line 130
    :cond_5
    iget p1, v0, Lwq0/b0;->g:I

    .line 131
    .line 132
    iget-object v2, v0, Lwq0/b0;->e:Lez0/a;

    .line 133
    .line 134
    iget-object v8, v0, Lwq0/b0;->d:Lyq0/n;

    .line 135
    .line 136
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    move-object p2, v2

    .line 140
    move v2, p1

    .line 141
    move-object p1, v8

    .line 142
    goto :goto_1

    .line 143
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    move-object p2, v9

    .line 147
    check-cast p2, Ltq0/a;

    .line 148
    .line 149
    iget-object p2, p2, Ltq0/a;->a:Lez0/c;

    .line 150
    .line 151
    iput-object p1, v0, Lwq0/b0;->d:Lyq0/n;

    .line 152
    .line 153
    iput-object p2, v0, Lwq0/b0;->e:Lez0/a;

    .line 154
    .line 155
    iput v3, v0, Lwq0/b0;->g:I

    .line 156
    .line 157
    iput v8, v0, Lwq0/b0;->k:I

    .line 158
    .line 159
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    if-ne v2, v1, :cond_7

    .line 164
    .line 165
    goto/16 :goto_5

    .line 166
    .line 167
    :cond_7
    move v2, v3

    .line 168
    :goto_1
    :try_start_4
    move-object v8, v9

    .line 169
    check-cast v8, Ltq0/a;

    .line 170
    .line 171
    iput-object p1, v8, Ltq0/a;->d:Lyq0/n;

    .line 172
    .line 173
    iget-object v8, p0, Lwq0/e0;->f:Lwq0/p;

    .line 174
    .line 175
    iput-object p1, v0, Lwq0/b0;->d:Lyq0/n;

    .line 176
    .line 177
    iput-object p2, v0, Lwq0/b0;->e:Lez0/a;

    .line 178
    .line 179
    iput v2, v0, Lwq0/b0;->g:I

    .line 180
    .line 181
    iput v3, v0, Lwq0/b0;->h:I

    .line 182
    .line 183
    iput v7, v0, Lwq0/b0;->k:I

    .line 184
    .line 185
    iget-object v7, v8, Lwq0/p;->a:Lwq0/q;

    .line 186
    .line 187
    check-cast v7, Ltq0/d;

    .line 188
    .line 189
    sget-object v8, Lge0/b;->a:Lcz0/e;

    .line 190
    .line 191
    new-instance v11, Ltq0/b;

    .line 192
    .line 193
    invoke-direct {v11, p1, v7, v10}, Ltq0/b;-><init>(Lyq0/n;Ltq0/d;Lkotlin/coroutines/Continuation;)V

    .line 194
    .line 195
    .line 196
    invoke-static {v8, v11, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v7
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 200
    if-ne v7, v1, :cond_8

    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_8
    move-object v12, v7

    .line 204
    move-object v7, p1

    .line 205
    move-object p1, p2

    .line 206
    move-object p2, v12

    .line 207
    :goto_2
    :try_start_5
    check-cast p2, Ljava/lang/Boolean;

    .line 208
    .line 209
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 210
    .line 211
    .line 212
    move-result p2

    .line 213
    if-nez p2, :cond_a

    .line 214
    .line 215
    iget-object p2, p0, Lwq0/e0;->c:Lzd0/c;

    .line 216
    .line 217
    sget-object v8, Lyq0/x;->a:Lyq0/x;

    .line 218
    .line 219
    iput-object v7, v0, Lwq0/b0;->d:Lyq0/n;

    .line 220
    .line 221
    iput-object p1, v0, Lwq0/b0;->e:Lez0/a;

    .line 222
    .line 223
    iput v2, v0, Lwq0/b0;->g:I

    .line 224
    .line 225
    iput v3, v0, Lwq0/b0;->h:I

    .line 226
    .line 227
    iput v6, v0, Lwq0/b0;->k:I

    .line 228
    .line 229
    iget-object p2, p2, Lzd0/c;->a:Lxd0/b;

    .line 230
    .line 231
    invoke-virtual {p2, v8, v0}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p2

    .line 235
    if-ne p2, v1, :cond_9

    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_9
    move-object v6, v7

    .line 239
    :goto_3
    check-cast p2, Lne0/t;

    .line 240
    .line 241
    instance-of v7, p2, Lne0/c;

    .line 242
    .line 243
    if-eqz v7, :cond_b

    .line 244
    .line 245
    check-cast p2, Lne0/c;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 246
    .line 247
    invoke-interface {p1, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    return-object p2

    .line 251
    :cond_a
    move-object v6, v7

    .line 252
    :cond_b
    :try_start_6
    iput-object v6, v0, Lwq0/b0;->d:Lyq0/n;

    .line 253
    .line 254
    iput-object p1, v0, Lwq0/b0;->e:Lez0/a;

    .line 255
    .line 256
    iput v2, v0, Lwq0/b0;->g:I

    .line 257
    .line 258
    iput v3, v0, Lwq0/b0;->h:I

    .line 259
    .line 260
    iput v5, v0, Lwq0/b0;->k:I

    .line 261
    .line 262
    invoke-virtual {p0, v0}, Lwq0/e0;->d(Lrx0/c;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p2

    .line 266
    if-ne p2, v1, :cond_c

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_c
    move-object v5, v6

    .line 270
    :goto_4
    check-cast p2, Lne0/t;

    .line 271
    .line 272
    instance-of v6, p2, Lne0/e;

    .line 273
    .line 274
    if-eqz v6, :cond_e

    .line 275
    .line 276
    iput-object v10, v0, Lwq0/b0;->d:Lyq0/n;

    .line 277
    .line 278
    iput-object p1, v0, Lwq0/b0;->e:Lez0/a;

    .line 279
    .line 280
    move-object v6, p2

    .line 281
    check-cast v6, Lne0/e;

    .line 282
    .line 283
    iput-object v6, v0, Lwq0/b0;->f:Lne0/e;

    .line 284
    .line 285
    iput v2, v0, Lwq0/b0;->g:I

    .line 286
    .line 287
    iput v3, v0, Lwq0/b0;->h:I

    .line 288
    .line 289
    iput v4, v0, Lwq0/b0;->k:I

    .line 290
    .line 291
    invoke-virtual {p0, v5, v0}, Lwq0/e0;->c(Lyq0/n;Lrx0/c;)Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object p0

    .line 295
    if-ne p0, v1, :cond_d

    .line 296
    .line 297
    :goto_5
    return-object v1

    .line 298
    :cond_d
    move-object p0, p2

    .line 299
    :goto_6
    move-object p2, p0

    .line 300
    :cond_e
    move-object p0, v9

    .line 301
    check-cast p0, Ltq0/a;

    .line 302
    .line 303
    iget-object p0, p0, Ltq0/a;->b:Ljava/lang/String;

    .line 304
    .line 305
    move-object v0, v9

    .line 306
    check-cast v0, Ltq0/a;

    .line 307
    .line 308
    iput-object v10, v0, Ltq0/a;->b:Ljava/lang/String;

    .line 309
    .line 310
    check-cast v9, Ltq0/a;

    .line 311
    .line 312
    iput-object v10, v9, Ltq0/a;->d:Lyq0/n;

    .line 313
    .line 314
    instance-of v0, p2, Lne0/e;

    .line 315
    .line 316
    if-eqz v0, :cond_f

    .line 317
    .line 318
    if-eqz p0, :cond_f

    .line 319
    .line 320
    new-instance p2, Lne0/e;

    .line 321
    .line 322
    new-instance v0, Lyq0/k;

    .line 323
    .line 324
    invoke-direct {v0, p0}, Lyq0/k;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    invoke-direct {p2, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    goto :goto_8

    .line 331
    :cond_f
    new-instance v0, Lne0/c;

    .line 332
    .line 333
    new-instance v1, Laq/c;

    .line 334
    .line 335
    const-string p0, "Unable to get the SPIN from SPIN input."

    .line 336
    .line 337
    const/16 v2, 0xa

    .line 338
    .line 339
    invoke-direct {v1, p0, v2}, Laq/c;-><init>(Ljava/lang/String;I)V

    .line 340
    .line 341
    .line 342
    instance-of p0, p2, Lne0/c;

    .line 343
    .line 344
    if-eqz p0, :cond_10

    .line 345
    .line 346
    check-cast p2, Lne0/c;

    .line 347
    .line 348
    move-object v2, p2

    .line 349
    goto :goto_7

    .line 350
    :cond_10
    move-object v2, v10

    .line 351
    :goto_7
    const/4 v4, 0x0

    .line 352
    const/16 v5, 0x1c

    .line 353
    .line 354
    const/4 v3, 0x0

    .line 355
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 356
    .line 357
    .line 358
    move-object p2, v0

    .line 359
    :goto_8
    invoke-interface {p1, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 360
    .line 361
    .line 362
    return-object p2

    .line 363
    :goto_9
    move-object p1, p2

    .line 364
    goto :goto_a

    .line 365
    :catchall_3
    move-exception v0

    .line 366
    move-object p0, v0

    .line 367
    goto :goto_9

    .line 368
    :goto_a
    invoke-interface {p1, v10}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    throw p0
.end method

.method public final c(Lyq0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Lwq0/e0;->c:Lzd0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lzd0/c;->a:Lxd0/b;

    .line 4
    .line 5
    instance-of v1, p2, Lwq0/c0;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p2

    .line 10
    check-cast v1, Lwq0/c0;

    .line 11
    .line 12
    iget v2, v1, Lwq0/c0;->j:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lwq0/c0;->j:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lwq0/c0;

    .line 25
    .line 26
    invoke-direct {v1, p0, p2}, Lwq0/c0;-><init>(Lwq0/e0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p2, v1, Lwq0/c0;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lwq0/c0;->j:I

    .line 34
    .line 35
    const-string v4, "BIOMETRIC_SUGGESTION_ENABLED_KEY"

    .line 36
    .line 37
    iget-object v5, p0, Lwq0/e0;->b:Lwq0/m0;

    .line 38
    .line 39
    const/4 v6, 0x1

    .line 40
    const/4 v7, 0x0

    .line 41
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    packed-switch v3, :pswitch_data_0

    .line 44
    .line 45
    .line 46
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :pswitch_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    return-object v8

    .line 58
    :pswitch_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object v8

    .line 62
    :pswitch_2
    iget-boolean p0, v1, Lwq0/c0;->g:Z

    .line 63
    .line 64
    iget-boolean p1, v1, Lwq0/c0;->f:Z

    .line 65
    .line 66
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_4

    .line 70
    .line 71
    :pswitch_3
    iget-boolean p0, v1, Lwq0/c0;->f:Z

    .line 72
    .line 73
    iget-object p1, v1, Lwq0/c0;->e:Lyq0/d;

    .line 74
    .line 75
    iget-object v3, v1, Lwq0/c0;->d:Lyq0/n;

    .line 76
    .line 77
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto :goto_3

    .line 81
    :pswitch_4
    iget-object p1, v1, Lwq0/c0;->e:Lyq0/d;

    .line 82
    .line 83
    iget-object v3, v1, Lwq0/c0;->d:Lyq0/n;

    .line 84
    .line 85
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :pswitch_5
    iget-object p1, v1, Lwq0/c0;->d:Lyq0/n;

    .line 90
    .line 91
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    goto :goto_1

    .line 95
    :pswitch_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    iput-object p1, v1, Lwq0/c0;->d:Lyq0/n;

    .line 99
    .line 100
    iput v6, v1, Lwq0/c0;->j:I

    .line 101
    .line 102
    iget-object p2, p0, Lwq0/e0;->d:Lwq0/g;

    .line 103
    .line 104
    iget-object p2, p2, Lwq0/g;->a:Lwq0/a;

    .line 105
    .line 106
    check-cast p2, Luq0/a;

    .line 107
    .line 108
    iget-object v3, p2, Luq0/a;->c:Lyy0/q1;

    .line 109
    .line 110
    invoke-virtual {v3}, Lyy0/q1;->q()V

    .line 111
    .line 112
    .line 113
    iget-object p2, p2, Luq0/a;->a:Lyy0/q1;

    .line 114
    .line 115
    invoke-virtual {p2, v8}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    invoke-static {v3, v1}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p2

    .line 122
    if-ne p2, v2, :cond_1

    .line 123
    .line 124
    goto/16 :goto_6

    .line 125
    .line 126
    :cond_1
    :goto_1
    check-cast p2, Lyq0/d;

    .line 127
    .line 128
    iput-object p1, v1, Lwq0/c0;->d:Lyq0/n;

    .line 129
    .line 130
    iput-object p2, v1, Lwq0/c0;->e:Lyq0/d;

    .line 131
    .line 132
    const/4 v3, 0x2

    .line 133
    iput v3, v1, Lwq0/c0;->j:I

    .line 134
    .line 135
    move-object v3, v5

    .line 136
    check-cast v3, Ltq0/i;

    .line 137
    .line 138
    iget-object v3, v3, Ltq0/i;->a:Lve0/u;

    .line 139
    .line 140
    invoke-virtual {v3, v6, v4, v1}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v3

    .line 144
    if-ne v3, v2, :cond_2

    .line 145
    .line 146
    goto/16 :goto_6

    .line 147
    .line 148
    :cond_2
    move-object v11, v3

    .line 149
    move-object v3, p1

    .line 150
    move-object p1, p2

    .line 151
    move-object p2, v11

    .line 152
    :goto_2
    check-cast p2, Ljava/lang/Boolean;

    .line 153
    .line 154
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    iput-object v3, v1, Lwq0/c0;->d:Lyq0/n;

    .line 159
    .line 160
    iput-object p1, v1, Lwq0/c0;->e:Lyq0/d;

    .line 161
    .line 162
    iput-boolean p2, v1, Lwq0/c0;->f:Z

    .line 163
    .line 164
    const/4 v6, 0x3

    .line 165
    iput v6, v1, Lwq0/c0;->j:I

    .line 166
    .line 167
    iget-object p0, p0, Lwq0/e0;->e:Lwq0/o;

    .line 168
    .line 169
    invoke-virtual {p0, v1}, Lwq0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-ne p0, v2, :cond_3

    .line 174
    .line 175
    goto/16 :goto_6

    .line 176
    .line 177
    :cond_3
    move v11, p2

    .line 178
    move-object p2, p0

    .line 179
    move p0, v11

    .line 180
    :goto_3
    check-cast p2, Ljava/lang/Boolean;

    .line 181
    .line 182
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 183
    .line 184
    .line 185
    move-result p2

    .line 186
    sget-object v6, Lyq0/f;->a:Lyq0/f;

    .line 187
    .line 188
    sget-object v9, Lyq0/a;->a:Lyq0/a;

    .line 189
    .line 190
    if-nez p2, :cond_6

    .line 191
    .line 192
    invoke-static {p1, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result v10

    .line 196
    if-eqz v10, :cond_6

    .line 197
    .line 198
    if-eqz p0, :cond_6

    .line 199
    .line 200
    iput-object v7, v1, Lwq0/c0;->d:Lyq0/n;

    .line 201
    .line 202
    iput-object v7, v1, Lwq0/c0;->e:Lyq0/d;

    .line 203
    .line 204
    iput-boolean p0, v1, Lwq0/c0;->f:Z

    .line 205
    .line 206
    iput-boolean p2, v1, Lwq0/c0;->g:Z

    .line 207
    .line 208
    const/4 p1, 0x4

    .line 209
    iput p1, v1, Lwq0/c0;->j:I

    .line 210
    .line 211
    invoke-virtual {v0, v6, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    if-ne p1, v2, :cond_4

    .line 216
    .line 217
    goto :goto_6

    .line 218
    :cond_4
    move p1, p0

    .line 219
    move p0, p2

    .line 220
    :goto_4
    iput-object v7, v1, Lwq0/c0;->d:Lyq0/n;

    .line 221
    .line 222
    iput-object v7, v1, Lwq0/c0;->e:Lyq0/d;

    .line 223
    .line 224
    iput-boolean p1, v1, Lwq0/c0;->f:Z

    .line 225
    .line 226
    iput-boolean p0, v1, Lwq0/c0;->g:Z

    .line 227
    .line 228
    const/4 p0, 0x5

    .line 229
    iput p0, v1, Lwq0/c0;->j:I

    .line 230
    .line 231
    check-cast v5, Ltq0/i;

    .line 232
    .line 233
    iget-object p0, v5, Ltq0/i;->a:Lve0/u;

    .line 234
    .line 235
    const/4 p1, 0x0

    .line 236
    invoke-virtual {p0, p1, v4, v1}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    if-ne p0, v2, :cond_5

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_5
    move-object p0, v8

    .line 244
    :goto_5
    if-ne p0, v2, :cond_7

    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_6
    if-nez p2, :cond_7

    .line 248
    .line 249
    invoke-static {p1, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    move-result p1

    .line 253
    if-eqz p1, :cond_7

    .line 254
    .line 255
    sget-object p1, Lyq0/n;->d:Lyq0/n;

    .line 256
    .line 257
    if-ne v3, p1, :cond_7

    .line 258
    .line 259
    iput-object v7, v1, Lwq0/c0;->d:Lyq0/n;

    .line 260
    .line 261
    iput-object v7, v1, Lwq0/c0;->e:Lyq0/d;

    .line 262
    .line 263
    iput-boolean p0, v1, Lwq0/c0;->f:Z

    .line 264
    .line 265
    iput-boolean p2, v1, Lwq0/c0;->g:Z

    .line 266
    .line 267
    const/4 p0, 0x6

    .line 268
    iput p0, v1, Lwq0/c0;->j:I

    .line 269
    .line 270
    invoke-virtual {v0, v6, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    if-ne p0, v2, :cond_7

    .line 275
    .line 276
    :goto_6
    return-object v2

    .line 277
    :cond_7
    return-object v8

    .line 278
    nop

    .line 279
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lwq0/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwq0/d0;

    .line 7
    .line 8
    iget v1, v0, Lwq0/d0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lwq0/d0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/d0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwq0/d0;-><init>(Lwq0/e0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwq0/d0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/d0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget-object v2, v0, Lwq0/d0;->d:Lne0/t;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_5

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :cond_4
    iput-object v3, v0, Lwq0/d0;->d:Lne0/t;

    .line 62
    .line 63
    iput v5, v0, Lwq0/d0;->g:I

    .line 64
    .line 65
    iget-object p1, p0, Lwq0/e0;->c:Lzd0/c;

    .line 66
    .line 67
    iget-object p1, p1, Lzd0/c;->a:Lxd0/b;

    .line 68
    .line 69
    sget-object v2, Lyq0/o;->a:Lyq0/o;

    .line 70
    .line 71
    invoke-virtual {p1, v2, v0}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_5

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_5
    :goto_1
    move-object v2, p1

    .line 79
    check-cast v2, Lne0/t;

    .line 80
    .line 81
    instance-of p1, v2, Lne0/c;

    .line 82
    .line 83
    if-eqz p1, :cond_6

    .line 84
    .line 85
    move-object p1, v2

    .line 86
    check-cast p1, Lne0/c;

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_6
    move-object p1, v3

    .line 90
    :goto_2
    if-eqz p1, :cond_7

    .line 91
    .line 92
    iget-object p1, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_7
    move-object p1, v3

    .line 96
    :goto_3
    instance-of p1, p1, Lyq0/j;

    .line 97
    .line 98
    if-eqz p1, :cond_9

    .line 99
    .line 100
    iput-object v2, v0, Lwq0/d0;->d:Lne0/t;

    .line 101
    .line 102
    iput v4, v0, Lwq0/d0;->g:I

    .line 103
    .line 104
    iget-object p1, p0, Lwq0/e0;->g:Lwq0/l0;

    .line 105
    .line 106
    invoke-virtual {p1, v0}, Lwq0/l0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    if-ne p1, v1, :cond_8

    .line 111
    .line 112
    :goto_4
    return-object v1

    .line 113
    :cond_8
    :goto_5
    instance-of p1, p1, Lne0/e;

    .line 114
    .line 115
    if-eqz p1, :cond_9

    .line 116
    .line 117
    return-object v2

    .line 118
    :cond_9
    instance-of p1, v2, Lne0/c;

    .line 119
    .line 120
    if-eqz p1, :cond_a

    .line 121
    .line 122
    move-object p1, v2

    .line 123
    check-cast p1, Lne0/c;

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_a
    move-object p1, v3

    .line 127
    :goto_6
    if-eqz p1, :cond_b

    .line 128
    .line 129
    iget-object p1, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_b
    move-object p1, v3

    .line 133
    :goto_7
    instance-of p1, p1, Lyq0/j;

    .line 134
    .line 135
    if-nez p1, :cond_4

    .line 136
    .line 137
    return-object v2
.end method
