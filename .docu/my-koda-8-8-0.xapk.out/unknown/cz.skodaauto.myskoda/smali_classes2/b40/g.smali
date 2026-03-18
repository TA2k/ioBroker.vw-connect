.class public final Lb40/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/b;

.field public final i:Lz30/h;

.field public final j:Lkc0/t0;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/b;Lz30/h;Lkc0/t0;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Lb40/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lb40/e;-><init>(Lae0/a;Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lb40/g;->h:Lzd0/b;

    .line 11
    .line 12
    iput-object p2, p0, Lb40/g;->i:Lz30/h;

    .line 13
    .line 14
    iput-object p3, p0, Lb40/g;->j:Lkc0/t0;

    .line 15
    .line 16
    iput-object p4, p0, Lb40/g;->k:Lij0/a;

    .line 17
    .line 18
    new-instance p1, Lb40/d;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-direct {p1, p0, v1, p2}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lb40/d;

    .line 32
    .line 33
    const/4 p3, 0x1

    .line 34
    invoke-direct {p2, p0, v1, p3}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lb40/g;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lb40/g;->k:Lij0/a;

    .line 6
    .line 7
    instance-of v3, v1, Lb40/f;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lb40/f;

    .line 13
    .line 14
    iget v4, v3, Lb40/f;->f:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lb40/f;->f:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lb40/f;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lb40/f;-><init>(Lb40/g;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lb40/f;->d:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lb40/f;->f:I

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    if-ne v5, v6, :cond_1

    .line 41
    .line 42
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_3
    iget-object v1, v0, Lb40/g;->i:Lz30/h;

    .line 58
    .line 59
    iput v6, v3, Lb40/f;->f:I

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v3}, Lz30/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    if-ne v1, v4, :cond_4

    .line 69
    .line 70
    return-object v4

    .line 71
    :cond_4
    :goto_1
    check-cast v1, Lne0/t;

    .line 72
    .line 73
    instance-of v5, v1, Lne0/c;

    .line 74
    .line 75
    const/4 v7, 0x0

    .line 76
    if-eqz v5, :cond_5

    .line 77
    .line 78
    move-object v8, v1

    .line 79
    check-cast v8, Lne0/c;

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_5
    move-object v8, v7

    .line 83
    :goto_2
    if-eqz v8, :cond_6

    .line 84
    .line 85
    iget-object v8, v8, Lne0/c;->a:Ljava/lang/Throwable;

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_6
    move-object v8, v7

    .line 89
    :goto_3
    instance-of v8, v8, Lcd0/a;

    .line 90
    .line 91
    if-nez v8, :cond_3

    .line 92
    .line 93
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    if-eqz v5, :cond_b

    .line 96
    .line 97
    move-object v8, v1

    .line 98
    check-cast v8, Lne0/c;

    .line 99
    .line 100
    iget-object v1, v8, Lne0/c;->e:Lne0/b;

    .line 101
    .line 102
    iget-object v4, v8, Lne0/c;->a:Ljava/lang/Throwable;

    .line 103
    .line 104
    instance-of v5, v4, Lcd0/b;

    .line 105
    .line 106
    if-eqz v5, :cond_7

    .line 107
    .line 108
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    check-cast v1, Lb40/e;

    .line 113
    .line 114
    iget-object v2, v0, Lb40/g;->k:Lij0/a;

    .line 115
    .line 116
    const/4 v4, 0x2

    .line 117
    invoke-static {v8, v2, v4}, Lkp/h6;->b(Lne0/c;Lij0/a;I)Lql0/g;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    invoke-static {v1, v7, v2, v6}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    goto/16 :goto_4

    .line 126
    .line 127
    :cond_7
    instance-of v4, v4, Lbm0/a;

    .line 128
    .line 129
    const v5, 0x7f120380

    .line 130
    .line 131
    .line 132
    const v9, 0x7f12038c

    .line 133
    .line 134
    .line 135
    const/4 v10, 0x0

    .line 136
    if-eqz v4, :cond_8

    .line 137
    .line 138
    sget-object v11, Lne0/b;->g:Lne0/b;

    .line 139
    .line 140
    if-ne v1, v11, :cond_8

    .line 141
    .line 142
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    check-cast v1, Lb40/e;

    .line 147
    .line 148
    iget-object v4, v0, Lb40/g;->k:Lij0/a;

    .line 149
    .line 150
    new-array v11, v10, [Ljava/lang/Object;

    .line 151
    .line 152
    move-object v12, v4

    .line 153
    check-cast v12, Ljj0/f;

    .line 154
    .line 155
    const v13, 0x7f1202c3

    .line 156
    .line 157
    .line 158
    invoke-virtual {v12, v13, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v11

    .line 162
    new-array v12, v10, [Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v2, Ljj0/f;

    .line 165
    .line 166
    const v13, 0x7f1202c2

    .line 167
    .line 168
    .line 169
    invoke-virtual {v2, v13, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v12

    .line 173
    new-array v13, v10, [Ljava/lang/Object;

    .line 174
    .line 175
    invoke-virtual {v2, v9, v13}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v9

    .line 179
    new-array v10, v10, [Ljava/lang/Object;

    .line 180
    .line 181
    invoke-virtual {v2, v5, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v13

    .line 185
    const/4 v15, 0x0

    .line 186
    const/16 v16, 0x60

    .line 187
    .line 188
    const/4 v14, 0x0

    .line 189
    move-object v10, v11

    .line 190
    move-object v11, v12

    .line 191
    move-object v12, v9

    .line 192
    move-object v9, v4

    .line 193
    invoke-static/range {v8 .. v16}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    invoke-static {v1, v7, v2, v6}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    goto/16 :goto_4

    .line 202
    .line 203
    :cond_8
    if-eqz v4, :cond_9

    .line 204
    .line 205
    sget-object v11, Lne0/b;->f:Lne0/b;

    .line 206
    .line 207
    if-ne v1, v11, :cond_9

    .line 208
    .line 209
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    check-cast v1, Lb40/e;

    .line 214
    .line 215
    iget-object v4, v0, Lb40/g;->k:Lij0/a;

    .line 216
    .line 217
    new-array v11, v10, [Ljava/lang/Object;

    .line 218
    .line 219
    move-object v12, v4

    .line 220
    check-cast v12, Ljj0/f;

    .line 221
    .line 222
    const v13, 0x7f1202c9

    .line 223
    .line 224
    .line 225
    invoke-virtual {v12, v13, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v11

    .line 229
    new-array v12, v10, [Ljava/lang/Object;

    .line 230
    .line 231
    check-cast v2, Ljj0/f;

    .line 232
    .line 233
    const v13, 0x7f1202c8

    .line 234
    .line 235
    .line 236
    invoke-virtual {v2, v13, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v12

    .line 240
    new-array v13, v10, [Ljava/lang/Object;

    .line 241
    .line 242
    invoke-virtual {v2, v9, v13}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v9

    .line 246
    new-array v10, v10, [Ljava/lang/Object;

    .line 247
    .line 248
    invoke-virtual {v2, v5, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v13

    .line 252
    const/4 v15, 0x0

    .line 253
    const/16 v16, 0x60

    .line 254
    .line 255
    const/4 v14, 0x0

    .line 256
    move-object v10, v11

    .line 257
    move-object v11, v12

    .line 258
    move-object v12, v9

    .line 259
    move-object v9, v4

    .line 260
    invoke-static/range {v8 .. v16}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 261
    .line 262
    .line 263
    move-result-object v2

    .line 264
    invoke-static {v1, v7, v2, v6}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    goto :goto_4

    .line 269
    :cond_9
    if-eqz v4, :cond_a

    .line 270
    .line 271
    sget-object v4, Lne0/b;->e:Lne0/b;

    .line 272
    .line 273
    if-ne v1, v4, :cond_a

    .line 274
    .line 275
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    check-cast v1, Lb40/e;

    .line 280
    .line 281
    iget-object v4, v0, Lb40/g;->k:Lij0/a;

    .line 282
    .line 283
    new-array v11, v10, [Ljava/lang/Object;

    .line 284
    .line 285
    move-object v12, v4

    .line 286
    check-cast v12, Ljj0/f;

    .line 287
    .line 288
    const v13, 0x7f1202be

    .line 289
    .line 290
    .line 291
    invoke-virtual {v12, v13, v11}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v11

    .line 295
    new-array v12, v10, [Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v2, Ljj0/f;

    .line 298
    .line 299
    const v13, 0x7f1202bc

    .line 300
    .line 301
    .line 302
    invoke-virtual {v2, v13, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    new-array v13, v10, [Ljava/lang/Object;

    .line 307
    .line 308
    invoke-virtual {v2, v9, v13}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 309
    .line 310
    .line 311
    move-result-object v9

    .line 312
    new-array v10, v10, [Ljava/lang/Object;

    .line 313
    .line 314
    invoke-virtual {v2, v5, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v13

    .line 318
    const/4 v15, 0x0

    .line 319
    const/16 v16, 0x60

    .line 320
    .line 321
    const/4 v14, 0x0

    .line 322
    move-object v10, v11

    .line 323
    move-object v11, v12

    .line 324
    move-object v12, v9

    .line 325
    move-object v9, v4

    .line 326
    invoke-static/range {v8 .. v16}, Ljp/rf;->d(Lne0/c;Lij0/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLql0/f;I)Lql0/g;

    .line 327
    .line 328
    .line 329
    move-result-object v2

    .line 330
    invoke-static {v1, v7, v2, v6}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    goto :goto_4

    .line 335
    :cond_a
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 336
    .line 337
    .line 338
    move-result-object v1

    .line 339
    check-cast v1, Lb40/e;

    .line 340
    .line 341
    invoke-static {v8, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 342
    .line 343
    .line 344
    move-result-object v2

    .line 345
    invoke-static {v1, v7, v2, v6}, Lb40/e;->a(Lb40/e;Lae0/a;Lql0/g;I)Lb40/e;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    :goto_4
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 350
    .line 351
    .line 352
    :cond_b
    return-object v3
.end method
