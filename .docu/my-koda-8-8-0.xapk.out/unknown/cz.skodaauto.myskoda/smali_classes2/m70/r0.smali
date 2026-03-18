.class public final Lm70/r0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lkf0/e0;

.field public final i:Lk70/p0;

.field public final j:Lk70/w0;

.field public final k:Lcs0/l;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Lkf0/e0;Lk70/p0;Lk70/w0;Lcs0/l;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lm70/p0;

    .line 2
    .line 3
    const/16 v1, 0xff

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lm70/p0;-><init>(Llf0/i;I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lm70/r0;->h:Lkf0/e0;

    .line 13
    .line 14
    iput-object p2, p0, Lm70/r0;->i:Lk70/p0;

    .line 15
    .line 16
    iput-object p3, p0, Lm70/r0;->j:Lk70/w0;

    .line 17
    .line 18
    iput-object p4, p0, Lm70/r0;->k:Lcs0/l;

    .line 19
    .line 20
    iput-object p5, p0, Lm70/r0;->l:Lij0/a;

    .line 21
    .line 22
    new-instance p1, Lk20/a;

    .line 23
    .line 24
    const/16 p2, 0x13

    .line 25
    .line 26
    invoke-direct {p1, p0, v2, p2}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 30
    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final h(Ll70/z;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lm70/q0;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lm70/q0;

    .line 11
    .line 12
    iget v3, v2, Lm70/q0;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lm70/q0;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lm70/q0;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lm70/q0;-><init>(Lm70/r0;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lm70/q0;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lm70/q0;->g:I

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v4, :cond_2

    .line 37
    .line 38
    if-ne v4, v5, :cond_1

    .line 39
    .line 40
    iget-object v2, v2, Lm70/q0;->d:Ll70/z;

    .line 41
    .line 42
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object/from16 v16, v2

    .line 46
    .line 47
    move-object v2, v1

    .line 48
    move-object/from16 v1, v16

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    move-object/from16 v1, p1

    .line 63
    .line 64
    iput-object v1, v2, Lm70/q0;->d:Ll70/z;

    .line 65
    .line 66
    iput v5, v2, Lm70/q0;->g:I

    .line 67
    .line 68
    iget-object v4, v0, Lm70/r0;->k:Lcs0/l;

    .line 69
    .line 70
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v4, v2}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    if-ne v2, v3, :cond_3

    .line 78
    .line 79
    return-object v3

    .line 80
    :cond_3
    :goto_1
    move-object v11, v2

    .line 81
    check-cast v11, Lqr0/s;

    .line 82
    .line 83
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    move-object v6, v2

    .line 88
    check-cast v6, Lm70/p0;

    .line 89
    .line 90
    iget-object v2, v1, Ll70/z;->a:Ll70/a0;

    .line 91
    .line 92
    iget-object v3, v1, Ll70/z;->d:Lqr0/g;

    .line 93
    .line 94
    iget-object v4, v1, Ll70/z;->c:Lqr0/i;

    .line 95
    .line 96
    sget-object v7, Ll70/a0;->h:Ll70/a0;

    .line 97
    .line 98
    const/4 v8, 0x0

    .line 99
    if-ne v2, v7, :cond_4

    .line 100
    .line 101
    move v10, v5

    .line 102
    goto :goto_2

    .line 103
    :cond_4
    move v10, v8

    .line 104
    :goto_2
    const-string v7, "unitsType"

    .line 105
    .line 106
    invoke-static {v11, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iget-object v7, v0, Lm70/r0;->l:Lij0/a;

    .line 110
    .line 111
    const-string v9, "stringResource"

    .line 112
    .line 113
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    iget-object v9, v1, Ll70/z;->b:Lqr0/d;

    .line 117
    .line 118
    const-string v12, " "

    .line 119
    .line 120
    const v13, 0x7f1201aa

    .line 121
    .line 122
    .line 123
    if-eqz v9, :cond_5

    .line 124
    .line 125
    iget-wide v14, v9, Lqr0/d;->a:D

    .line 126
    .line 127
    sget-object v9, Lqr0/e;->d:Lqr0/e;

    .line 128
    .line 129
    invoke-static {v14, v15, v11, v9}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    if-nez v9, :cond_7

    .line 134
    .line 135
    :cond_5
    new-array v9, v8, [Ljava/lang/Object;

    .line 136
    .line 137
    move-object v14, v7

    .line 138
    check-cast v14, Ljj0/f;

    .line 139
    .line 140
    invoke-virtual {v14, v13, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v9

    .line 144
    sget-object v14, Lqr0/s;->d:Lqr0/s;

    .line 145
    .line 146
    if-ne v11, v14, :cond_6

    .line 147
    .line 148
    sget-object v14, Lqr0/f;->e:Lqr0/f;

    .line 149
    .line 150
    invoke-static {v14}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v14

    .line 154
    goto :goto_3

    .line 155
    :cond_6
    sget-object v14, Lqr0/f;->h:Lqr0/f;

    .line 156
    .line 157
    invoke-static {v14}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v14

    .line 161
    :goto_3
    invoke-static {v9, v12, v14}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    :cond_7
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 166
    .line 167
    .line 168
    move-result v14

    .line 169
    const/4 v15, 0x3

    .line 170
    const/4 v13, 0x2

    .line 171
    if-eqz v14, :cond_e

    .line 172
    .line 173
    if-eq v14, v5, :cond_d

    .line 174
    .line 175
    if-eq v14, v13, :cond_a

    .line 176
    .line 177
    if-eq v14, v15, :cond_9

    .line 178
    .line 179
    const/4 v1, 0x4

    .line 180
    if-ne v14, v1, :cond_8

    .line 181
    .line 182
    const/4 v13, 0x0

    .line 183
    :goto_4
    const v14, 0x7f1201aa

    .line 184
    .line 185
    .line 186
    goto :goto_7

    .line 187
    :cond_8
    new-instance v0, La8/r0;

    .line 188
    .line 189
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw v0

    .line 193
    :cond_9
    new-array v1, v8, [Ljava/lang/Object;

    .line 194
    .line 195
    move-object v5, v7

    .line 196
    check-cast v5, Ljj0/f;

    .line 197
    .line 198
    const v14, 0x7f1201aa

    .line 199
    .line 200
    .line 201
    invoke-virtual {v5, v14, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    invoke-static {v4, v11, v1, v8}, Lis0/b;->d(Lqr0/i;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    :goto_5
    move-object v13, v1

    .line 210
    goto :goto_7

    .line 211
    :cond_a
    const v14, 0x7f1201aa

    .line 212
    .line 213
    .line 214
    iget-object v1, v1, Ll70/z;->e:Lqr0/j;

    .line 215
    .line 216
    new-array v15, v8, [Ljava/lang/Object;

    .line 217
    .line 218
    move-object v13, v7

    .line 219
    check-cast v13, Ljj0/f;

    .line 220
    .line 221
    invoke-virtual {v13, v14, v15}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v13

    .line 225
    if-eqz v1, :cond_b

    .line 226
    .line 227
    iget-wide v13, v1, Lqr0/j;->a:D

    .line 228
    .line 229
    invoke-static {v5, v13, v14}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v13

    .line 233
    :cond_b
    sget-object v1, Lqr0/s;->d:Lqr0/s;

    .line 234
    .line 235
    if-ne v11, v1, :cond_c

    .line 236
    .line 237
    sget-object v1, Lqr0/k;->d:Lqr0/k;

    .line 238
    .line 239
    invoke-static {v1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    goto :goto_6

    .line 244
    :cond_c
    sget-object v1, Lqr0/k;->e:Lqr0/k;

    .line 245
    .line 246
    invoke-static {v1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    :goto_6
    invoke-static {v13, v12, v1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    move-object v13, v1

    .line 255
    goto :goto_4

    .line 256
    :cond_d
    new-array v1, v8, [Ljava/lang/Object;

    .line 257
    .line 258
    move-object v12, v7

    .line 259
    check-cast v12, Ljj0/f;

    .line 260
    .line 261
    const v14, 0x7f1201aa

    .line 262
    .line 263
    .line 264
    invoke-virtual {v12, v14, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    invoke-static {v4, v11, v1, v5}, Lis0/b;->d(Lqr0/i;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    goto :goto_5

    .line 273
    :cond_e
    const v14, 0x7f1201aa

    .line 274
    .line 275
    .line 276
    new-array v1, v8, [Ljava/lang/Object;

    .line 277
    .line 278
    move-object v12, v7

    .line 279
    check-cast v12, Ljj0/f;

    .line 280
    .line 281
    invoke-virtual {v12, v14, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    invoke-static {v3, v11, v1, v5}, Lis0/b;->e(Lqr0/g;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    goto :goto_5

    .line 290
    :goto_7
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 291
    .line 292
    .line 293
    move-result v1

    .line 294
    const/4 v2, 0x2

    .line 295
    if-eq v1, v2, :cond_10

    .line 296
    .line 297
    const/4 v2, 0x3

    .line 298
    if-eq v1, v2, :cond_f

    .line 299
    .line 300
    move-object v12, v9

    .line 301
    const/4 v14, 0x0

    .line 302
    goto :goto_9

    .line 303
    :cond_f
    new-array v1, v8, [Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v7, Ljj0/f;

    .line 306
    .line 307
    invoke-virtual {v7, v14, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v1

    .line 311
    invoke-static {v3, v11, v1, v8}, Lis0/b;->e(Lqr0/g;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v15

    .line 315
    :goto_8
    move-object v12, v9

    .line 316
    move-object v14, v15

    .line 317
    goto :goto_9

    .line 318
    :cond_10
    new-array v1, v8, [Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v7, Ljj0/f;

    .line 321
    .line 322
    invoke-virtual {v7, v14, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 323
    .line 324
    .line 325
    move-result-object v1

    .line 326
    invoke-static {v4, v11, v1, v8}, Lis0/b;->d(Lqr0/i;Lqr0/s;Ljava/lang/String;Z)Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v15

    .line 330
    goto :goto_8

    .line 331
    :goto_9
    const/4 v9, 0x0

    .line 332
    const/4 v15, 0x1

    .line 333
    const/4 v7, 0x0

    .line 334
    const/4 v8, 0x0

    .line 335
    invoke-static/range {v6 .. v15}, Lm70/p0;->a(Lm70/p0;Llf0/i;ZZZLqr0/s;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lm70/p0;

    .line 336
    .line 337
    .line 338
    move-result-object v1

    .line 339
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 340
    .line 341
    .line 342
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 343
    .line 344
    return-object v0
.end method
