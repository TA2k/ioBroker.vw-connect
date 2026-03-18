.class public final Lg70/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lg70/j;


# direct methods
.method public synthetic constructor <init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lg70/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg70/h;->f:Lg70/j;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lg70/h;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lg70/h;

    .line 7
    .line 8
    iget-object p0, p0, Lg70/h;->f:Lg70/j;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lg70/h;

    .line 16
    .line 17
    iget-object p0, p0, Lg70/h;->f:Lg70/j;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lg70/h;

    .line 25
    .line 26
    iget-object p0, p0, Lg70/h;->f:Lg70/j;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lg70/h;

    .line 34
    .line 35
    iget-object p0, p0, Lg70/h;->f:Lg70/j;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg70/h;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg70/h;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lg70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lg70/h;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lg70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lg70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lg70/h;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lg70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lg70/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lg70/h;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lg70/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lg70/h;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lg70/h;->e:I

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    if-ne v2, v3, :cond_0

    .line 16
    .line 17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, v0, Lg70/h;->f:Lg70/j;

    .line 33
    .line 34
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object v4

    .line 38
    move-object v5, v4

    .line 39
    check-cast v5, Lg70/i;

    .line 40
    .line 41
    const/4 v15, 0x0

    .line 42
    const/16 v16, 0x6ff

    .line 43
    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x0

    .line 46
    const/4 v8, 0x0

    .line 47
    const/4 v9, 0x0

    .line 48
    const/4 v10, 0x0

    .line 49
    const/4 v11, 0x0

    .line 50
    const/4 v12, 0x0

    .line 51
    const/4 v13, 0x0

    .line 52
    const/4 v14, 0x0

    .line 53
    invoke-static/range {v5 .. v16}, Lg70/i;->a(Lg70/i;Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;I)Lg70/i;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    invoke-virtual {v2, v4}, Lql0/j;->g(Lql0/h;)V

    .line 58
    .line 59
    .line 60
    iget-object v4, v2, Lg70/j;->m:Lrq0/f;

    .line 61
    .line 62
    new-instance v5, Lsq0/c;

    .line 63
    .line 64
    iget-object v2, v2, Lg70/j;->o:Lij0/a;

    .line 65
    .line 66
    const/4 v6, 0x0

    .line 67
    new-array v7, v6, [Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v2, Ljj0/f;

    .line 70
    .line 71
    const v8, 0x7f120f57

    .line 72
    .line 73
    .line 74
    invoke-virtual {v2, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    const/4 v7, 0x6

    .line 79
    const/4 v8, 0x0

    .line 80
    invoke-direct {v5, v7, v2, v8, v8}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iput v3, v0, Lg70/h;->e:I

    .line 84
    .line 85
    invoke-virtual {v4, v5, v6, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    if-ne v0, v1, :cond_2

    .line 90
    .line 91
    goto :goto_1

    .line 92
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_1
    return-object v1

    .line 95
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v2, v0, Lg70/h;->e:I

    .line 98
    .line 99
    const/4 v3, 0x1

    .line 100
    if-eqz v2, :cond_4

    .line 101
    .line 102
    if-ne v2, v3, :cond_3

    .line 103
    .line 104
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw v0

    .line 116
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object v2, v0, Lg70/h;->f:Lg70/j;

    .line 120
    .line 121
    iget-object v4, v2, Lg70/j;->m:Lrq0/f;

    .line 122
    .line 123
    new-instance v5, Lsq0/c;

    .line 124
    .line 125
    iget-object v2, v2, Lg70/j;->o:Lij0/a;

    .line 126
    .line 127
    const/4 v6, 0x0

    .line 128
    new-array v7, v6, [Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v2, Ljj0/f;

    .line 131
    .line 132
    const v8, 0x7f120f5e

    .line 133
    .line 134
    .line 135
    invoke-virtual {v2, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v2

    .line 139
    const/4 v7, 0x6

    .line 140
    const/4 v8, 0x0

    .line 141
    invoke-direct {v5, v7, v2, v8, v8}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    iput v3, v0, Lg70/h;->e:I

    .line 145
    .line 146
    invoke-virtual {v4, v5, v6, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    if-ne v0, v1, :cond_5

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    :goto_3
    return-object v1

    .line 156
    :pswitch_1
    iget-object v1, v0, Lg70/h;->f:Lg70/j;

    .line 157
    .line 158
    iget-object v2, v1, Lg70/j;->i:Ltn0/b;

    .line 159
    .line 160
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 161
    .line 162
    iget v4, v0, Lg70/h;->e:I

    .line 163
    .line 164
    const/4 v5, 0x2

    .line 165
    const/4 v6, 0x1

    .line 166
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    if-eqz v4, :cond_8

    .line 169
    .line 170
    if-eq v4, v6, :cond_7

    .line 171
    .line 172
    if-ne v4, v5, :cond_6

    .line 173
    .line 174
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    move-object/from16 v0, p1

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 181
    .line 182
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 183
    .line 184
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw v0

    .line 188
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object/from16 v4, p1

    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    sget-object v4, Lun0/a;->e:Lun0/a;

    .line 198
    .line 199
    iput v6, v0, Lg70/h;->e:I

    .line 200
    .line 201
    invoke-virtual {v2, v4, v0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v4

    .line 205
    if-ne v4, v3, :cond_9

    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_9
    :goto_4
    check-cast v4, Lun0/b;

    .line 209
    .line 210
    iget-boolean v4, v4, Lun0/b;->b:Z

    .line 211
    .line 212
    if-nez v4, :cond_b

    .line 213
    .line 214
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    move-object v8, v0

    .line 219
    check-cast v8, Lg70/i;

    .line 220
    .line 221
    const/16 v18, 0x0

    .line 222
    .line 223
    const/16 v19, 0x7bf

    .line 224
    .line 225
    const/4 v9, 0x0

    .line 226
    const/4 v10, 0x0

    .line 227
    const/4 v11, 0x0

    .line 228
    const/4 v12, 0x0

    .line 229
    const/4 v13, 0x0

    .line 230
    const/4 v14, 0x0

    .line 231
    const/4 v15, 0x1

    .line 232
    const/16 v16, 0x0

    .line 233
    .line 234
    const/16 v17, 0x0

    .line 235
    .line 236
    invoke-static/range {v8 .. v19}, Lg70/i;->a(Lg70/i;Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;I)Lg70/i;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-virtual {v1, v0}, Lql0/j;->g(Lql0/h;)V

    .line 241
    .line 242
    .line 243
    :cond_a
    :goto_5
    move-object v3, v7

    .line 244
    goto :goto_7

    .line 245
    :cond_b
    sget-object v4, Lun0/a;->f:Lun0/a;

    .line 246
    .line 247
    iput v5, v0, Lg70/h;->e:I

    .line 248
    .line 249
    invoke-virtual {v2, v4, v0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    if-ne v0, v3, :cond_c

    .line 254
    .line 255
    goto :goto_7

    .line 256
    :cond_c
    :goto_6
    check-cast v0, Lun0/b;

    .line 257
    .line 258
    iget-boolean v0, v0, Lun0/b;->b:Z

    .line 259
    .line 260
    if-nez v0, :cond_a

    .line 261
    .line 262
    invoke-virtual {v1}, Lql0/j;->a()Lql0/h;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    move-object v8, v0

    .line 267
    check-cast v8, Lg70/i;

    .line 268
    .line 269
    const/16 v18, 0x0

    .line 270
    .line 271
    const/16 v19, 0x77f

    .line 272
    .line 273
    const/4 v9, 0x0

    .line 274
    const/4 v10, 0x0

    .line 275
    const/4 v11, 0x0

    .line 276
    const/4 v12, 0x0

    .line 277
    const/4 v13, 0x0

    .line 278
    const/4 v14, 0x0

    .line 279
    const/4 v15, 0x0

    .line 280
    const/16 v16, 0x1

    .line 281
    .line 282
    const/16 v17, 0x0

    .line 283
    .line 284
    invoke-static/range {v8 .. v19}, Lg70/i;->a(Lg70/i;Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;I)Lg70/i;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    invoke-virtual {v1, v0}, Lql0/j;->g(Lql0/h;)V

    .line 289
    .line 290
    .line 291
    goto :goto_5

    .line 292
    :goto_7
    return-object v3

    .line 293
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 294
    .line 295
    iget v2, v0, Lg70/h;->e:I

    .line 296
    .line 297
    const/4 v3, 0x1

    .line 298
    if-eqz v2, :cond_e

    .line 299
    .line 300
    if-ne v2, v3, :cond_d

    .line 301
    .line 302
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    goto :goto_8

    .line 306
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 307
    .line 308
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 309
    .line 310
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 311
    .line 312
    .line 313
    throw v0

    .line 314
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    iget-object v2, v0, Lg70/h;->f:Lg70/j;

    .line 318
    .line 319
    iget-object v4, v2, Lg70/j;->l:Lkf0/z;

    .line 320
    .line 321
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v4

    .line 325
    check-cast v4, Lyy0/i;

    .line 326
    .line 327
    new-instance v5, Lac0/e;

    .line 328
    .line 329
    const/16 v6, 0x18

    .line 330
    .line 331
    invoke-direct {v5, v2, v6}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 332
    .line 333
    .line 334
    iput v3, v0, Lg70/h;->e:I

    .line 335
    .line 336
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    if-ne v0, v1, :cond_f

    .line 341
    .line 342
    goto :goto_9

    .line 343
    :cond_f
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 344
    .line 345
    :goto_9
    return-object v1

    .line 346
    nop

    .line 347
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
