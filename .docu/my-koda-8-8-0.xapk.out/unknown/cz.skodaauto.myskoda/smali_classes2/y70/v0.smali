.class public final Ly70/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/j1;


# direct methods
.method public synthetic constructor <init>(Ly70/j1;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/v0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/v0;->e:Ly70/j1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Ly70/w0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ly70/w0;

    .line 7
    .line 8
    iget v1, v0, Ly70/w0;->g:I

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
    iput v1, v0, Ly70/w0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ly70/w0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ly70/w0;-><init>(Ly70/v0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ly70/w0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ly70/w0;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    iget-object p0, p0, Ly70/v0;->e:Ly70/j1;

    .line 34
    .line 35
    const/4 v4, 0x2

    .line 36
    const/4 v5, 0x1

    .line 37
    const/4 v6, 0x0

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v3

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-boolean p1, v0, Ly70/w0;->d:Z

    .line 57
    .line 58
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    if-eqz p1, :cond_5

    .line 66
    .line 67
    iget-object p2, p0, Ly70/j1;->H:Lrq0/f;

    .line 68
    .line 69
    new-instance v2, Lsq0/c;

    .line 70
    .line 71
    iget-object v7, p0, Ly70/j1;->j:Lij0/a;

    .line 72
    .line 73
    new-array v8, v6, [Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v7, Ljj0/f;

    .line 76
    .line 77
    const v9, 0x7f121154

    .line 78
    .line 79
    .line 80
    invoke-virtual {v7, v9, v8}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    const/4 v8, 0x6

    .line 85
    const/4 v9, 0x0

    .line 86
    invoke-direct {v2, v8, v7, v9, v9}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    iput-boolean p1, v0, Ly70/w0;->d:Z

    .line 90
    .line 91
    iput v5, v0, Ly70/w0;->g:I

    .line 92
    .line 93
    invoke-virtual {p2, v2, v6, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    if-ne p2, v1, :cond_4

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_4
    :goto_1
    iget-object p0, p0, Ly70/j1;->J:Lw70/u0;

    .line 101
    .line 102
    iput-boolean p1, v0, Ly70/w0;->d:Z

    .line 103
    .line 104
    iput v4, v0, Ly70/w0;->g:I

    .line 105
    .line 106
    invoke-virtual {p0, v6, v0}, Lw70/u0;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-ne p0, v1, :cond_5

    .line 111
    .line 112
    :goto_2
    return-object v1

    .line 113
    :cond_5
    return-object v3
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ly70/v0;->d:I

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
    iget-object v0, v0, Ly70/v0;->e:Ly70/j1;

    .line 13
    .line 14
    invoke-static {v0, v1}, Ly70/j1;->B(Ly70/j1;Lne0/s;)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    move-object/from16 v1, p1

    .line 21
    .line 22
    check-cast v1, Lne0/s;

    .line 23
    .line 24
    instance-of v2, v1, Lne0/c;

    .line 25
    .line 26
    iget-object v0, v0, Ly70/v0;->e:Ly70/j1;

    .line 27
    .line 28
    if-eqz v2, :cond_0

    .line 29
    .line 30
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    move-object v3, v2

    .line 35
    check-cast v3, Ly70/a1;

    .line 36
    .line 37
    check-cast v1, Lne0/c;

    .line 38
    .line 39
    iget-object v2, v0, Ly70/j1;->j:Lij0/a;

    .line 40
    .line 41
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 42
    .line 43
    .line 44
    move-result-object v11

    .line 45
    const/16 v29, 0x0

    .line 46
    .line 47
    const v30, 0x7ffff3f

    .line 48
    .line 49
    .line 50
    const/4 v4, 0x0

    .line 51
    const/4 v5, 0x0

    .line 52
    const/4 v6, 0x0

    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x0

    .line 56
    const/4 v10, 0x0

    .line 57
    const/4 v12, 0x0

    .line 58
    const/4 v13, 0x0

    .line 59
    const/4 v14, 0x0

    .line 60
    const/4 v15, 0x0

    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    const/16 v17, 0x0

    .line 64
    .line 65
    const/16 v18, 0x0

    .line 66
    .line 67
    const/16 v19, 0x0

    .line 68
    .line 69
    const/16 v20, 0x0

    .line 70
    .line 71
    const/16 v21, 0x0

    .line 72
    .line 73
    const/16 v22, 0x0

    .line 74
    .line 75
    const/16 v23, 0x0

    .line 76
    .line 77
    const/16 v24, 0x0

    .line 78
    .line 79
    const/16 v25, 0x0

    .line 80
    .line 81
    const/16 v26, 0x0

    .line 82
    .line 83
    const/16 v27, 0x0

    .line 84
    .line 85
    const/16 v28, 0x0

    .line 86
    .line 87
    invoke-static/range {v3 .. v30}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    goto :goto_0

    .line 92
    :cond_0
    instance-of v2, v1, Lne0/e;

    .line 93
    .line 94
    if-eqz v2, :cond_1

    .line 95
    .line 96
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    move-object v2, v1

    .line 101
    check-cast v2, Ly70/a1;

    .line 102
    .line 103
    const/16 v28, 0x0

    .line 104
    .line 105
    const v29, 0x7ffffbf

    .line 106
    .line 107
    .line 108
    const/4 v3, 0x0

    .line 109
    const/4 v4, 0x0

    .line 110
    const/4 v5, 0x0

    .line 111
    const/4 v6, 0x0

    .line 112
    const/4 v7, 0x0

    .line 113
    const/4 v8, 0x0

    .line 114
    const/4 v9, 0x0

    .line 115
    const/4 v10, 0x0

    .line 116
    const/4 v11, 0x0

    .line 117
    const/4 v12, 0x0

    .line 118
    const/4 v13, 0x0

    .line 119
    const/4 v14, 0x0

    .line 120
    const/4 v15, 0x0

    .line 121
    const/16 v16, 0x0

    .line 122
    .line 123
    const/16 v17, 0x0

    .line 124
    .line 125
    const/16 v18, 0x0

    .line 126
    .line 127
    const/16 v19, 0x0

    .line 128
    .line 129
    const/16 v20, 0x0

    .line 130
    .line 131
    const/16 v21, 0x0

    .line 132
    .line 133
    const/16 v22, 0x0

    .line 134
    .line 135
    const/16 v23, 0x0

    .line 136
    .line 137
    const/16 v24, 0x0

    .line 138
    .line 139
    const/16 v25, 0x0

    .line 140
    .line 141
    const/16 v26, 0x0

    .line 142
    .line 143
    const/16 v27, 0x0

    .line 144
    .line 145
    invoke-static/range {v2 .. v29}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    goto :goto_0

    .line 150
    :cond_1
    instance-of v1, v1, Lne0/d;

    .line 151
    .line 152
    if-eqz v1, :cond_2

    .line 153
    .line 154
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    move-object v2, v1

    .line 159
    check-cast v2, Ly70/a1;

    .line 160
    .line 161
    const/16 v28, 0x0

    .line 162
    .line 163
    const v29, 0x7ffffbf

    .line 164
    .line 165
    .line 166
    const/4 v3, 0x0

    .line 167
    const/4 v4, 0x0

    .line 168
    const/4 v5, 0x0

    .line 169
    const/4 v6, 0x0

    .line 170
    const/4 v7, 0x0

    .line 171
    const/4 v8, 0x0

    .line 172
    const/4 v9, 0x1

    .line 173
    const/4 v10, 0x0

    .line 174
    const/4 v11, 0x0

    .line 175
    const/4 v12, 0x0

    .line 176
    const/4 v13, 0x0

    .line 177
    const/4 v14, 0x0

    .line 178
    const/4 v15, 0x0

    .line 179
    const/16 v16, 0x0

    .line 180
    .line 181
    const/16 v17, 0x0

    .line 182
    .line 183
    const/16 v18, 0x0

    .line 184
    .line 185
    const/16 v19, 0x0

    .line 186
    .line 187
    const/16 v20, 0x0

    .line 188
    .line 189
    const/16 v21, 0x0

    .line 190
    .line 191
    const/16 v22, 0x0

    .line 192
    .line 193
    const/16 v23, 0x0

    .line 194
    .line 195
    const/16 v24, 0x0

    .line 196
    .line 197
    const/16 v25, 0x0

    .line 198
    .line 199
    const/16 v26, 0x0

    .line 200
    .line 201
    const/16 v27, 0x0

    .line 202
    .line 203
    invoke-static/range {v2 .. v29}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    :goto_0
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 208
    .line 209
    .line 210
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    return-object v0

    .line 213
    :cond_2
    new-instance v0, La8/r0;

    .line 214
    .line 215
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 216
    .line 217
    .line 218
    throw v0

    .line 219
    :pswitch_1
    move-object/from16 v1, p1

    .line 220
    .line 221
    check-cast v1, Ljava/lang/Boolean;

    .line 222
    .line 223
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 224
    .line 225
    .line 226
    move-result v1

    .line 227
    move-object/from16 v2, p2

    .line 228
    .line 229
    invoke-virtual {v0, v1, v2}, Ly70/v0;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    return-object v0

    .line 234
    :pswitch_2
    move-object/from16 v1, p1

    .line 235
    .line 236
    check-cast v1, Lne0/s;

    .line 237
    .line 238
    iget-object v0, v0, Ly70/v0;->e:Ly70/j1;

    .line 239
    .line 240
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 241
    .line 242
    .line 243
    move-result-object v2

    .line 244
    move-object v3, v2

    .line 245
    check-cast v3, Ly70/a1;

    .line 246
    .line 247
    instance-of v2, v1, Lne0/e;

    .line 248
    .line 249
    const/4 v4, 0x0

    .line 250
    if-eqz v2, :cond_3

    .line 251
    .line 252
    move-object v5, v1

    .line 253
    check-cast v5, Lne0/e;

    .line 254
    .line 255
    goto :goto_1

    .line 256
    :cond_3
    move-object v5, v4

    .line 257
    :goto_1
    if-eqz v5, :cond_5

    .line 258
    .line 259
    iget-object v5, v5, Lne0/e;->a:Ljava/lang/Object;

    .line 260
    .line 261
    check-cast v5, Lyr0/e;

    .line 262
    .line 263
    if-eqz v5, :cond_5

    .line 264
    .line 265
    iget-object v5, v5, Lyr0/e;->f:Ljava/lang/String;

    .line 266
    .line 267
    if-nez v5, :cond_4

    .line 268
    .line 269
    goto :goto_2

    .line 270
    :cond_4
    move-object/from16 v21, v5

    .line 271
    .line 272
    goto :goto_3

    .line 273
    :cond_5
    :goto_2
    move-object/from16 v21, v4

    .line 274
    .line 275
    :goto_3
    if-eqz v2, :cond_6

    .line 276
    .line 277
    check-cast v1, Lne0/e;

    .line 278
    .line 279
    goto :goto_4

    .line 280
    :cond_6
    move-object v1, v4

    .line 281
    :goto_4
    if-eqz v1, :cond_7

    .line 282
    .line 283
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v1, Lyr0/e;

    .line 286
    .line 287
    if-eqz v1, :cond_7

    .line 288
    .line 289
    iget-object v1, v1, Lyr0/e;->f:Ljava/lang/String;

    .line 290
    .line 291
    if-eqz v1, :cond_7

    .line 292
    .line 293
    invoke-static {v1}, Lcom/google/android/gms/internal/measurement/j4;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object v4

    .line 297
    :cond_7
    move-object/from16 v22, v4

    .line 298
    .line 299
    const/16 v29, 0x0

    .line 300
    .line 301
    const v30, 0x7f3ffff

    .line 302
    .line 303
    .line 304
    const/4 v4, 0x0

    .line 305
    const/4 v5, 0x0

    .line 306
    const/4 v6, 0x0

    .line 307
    const/4 v7, 0x0

    .line 308
    const/4 v8, 0x0

    .line 309
    const/4 v9, 0x0

    .line 310
    const/4 v10, 0x0

    .line 311
    const/4 v11, 0x0

    .line 312
    const/4 v12, 0x0

    .line 313
    const/4 v13, 0x0

    .line 314
    const/4 v14, 0x0

    .line 315
    const/4 v15, 0x0

    .line 316
    const/16 v16, 0x0

    .line 317
    .line 318
    const/16 v17, 0x0

    .line 319
    .line 320
    const/16 v18, 0x0

    .line 321
    .line 322
    const/16 v19, 0x0

    .line 323
    .line 324
    const/16 v20, 0x0

    .line 325
    .line 326
    const/16 v23, 0x0

    .line 327
    .line 328
    const/16 v24, 0x0

    .line 329
    .line 330
    const/16 v25, 0x0

    .line 331
    .line 332
    const/16 v26, 0x0

    .line 333
    .line 334
    const/16 v27, 0x0

    .line 335
    .line 336
    const/16 v28, 0x0

    .line 337
    .line 338
    invoke-static/range {v3 .. v30}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 343
    .line 344
    .line 345
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 346
    .line 347
    return-object v0

    .line 348
    :pswitch_3
    move-object/from16 v1, p1

    .line 349
    .line 350
    check-cast v1, Lne0/s;

    .line 351
    .line 352
    iget-object v0, v0, Ly70/v0;->e:Ly70/j1;

    .line 353
    .line 354
    invoke-static {v0, v1}, Ly70/j1;->B(Ly70/j1;Lne0/s;)V

    .line 355
    .line 356
    .line 357
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 358
    .line 359
    return-object v0

    .line 360
    nop

    .line 361
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
