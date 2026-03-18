.class public final Lh40/z3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/i4;


# direct methods
.method public synthetic constructor <init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/z3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/z3;->f:Lh40/i4;

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
    iget p1, p0, Lh40/z3;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/z3;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/z3;->f:Lh40/i4;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/z3;-><init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/z3;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/z3;->f:Lh40/i4;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/z3;-><init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh40/z3;

    .line 25
    .line 26
    iget-object p0, p0, Lh40/z3;->f:Lh40/i4;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh40/z3;-><init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh40/z3;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/z3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/z3;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/z3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/z3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/z3;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/z3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh40/z3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh40/z3;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh40/z3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/z3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lh40/z3;->e:I

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    const/4 v4, 0x2

    .line 14
    iget-object v5, v0, Lh40/z3;->f:Lh40/i4;

    .line 15
    .line 16
    const/4 v6, 0x1

    .line 17
    if-eqz v2, :cond_3

    .line 18
    .line 19
    if-eq v2, v6, :cond_2

    .line 20
    .line 21
    if-eq v2, v4, :cond_1

    .line 22
    .line 23
    if-ne v2, v3, :cond_0

    .line 24
    .line 25
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_2

    .line 29
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    move-object/from16 v2, p1

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object/from16 v2, p1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object v2, v5, Lh40/i4;->E:Lcr0/e;

    .line 53
    .line 54
    new-instance v7, Lcr0/c;

    .line 55
    .line 56
    invoke-direct {v7, v6}, Lcr0/c;-><init>(Z)V

    .line 57
    .line 58
    .line 59
    iput v6, v0, Lh40/z3;->e:I

    .line 60
    .line 61
    invoke-virtual {v2, v7, v0}, Lcr0/e;->b(Lcr0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    if-ne v2, v1, :cond_4

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    :goto_0
    check-cast v2, Ljava/lang/String;

    .line 69
    .line 70
    iget-object v6, v5, Lh40/i4;->F:Lkc0/h0;

    .line 71
    .line 72
    new-instance v7, Ldd0/a;

    .line 73
    .line 74
    const/16 v8, 0x1e

    .line 75
    .line 76
    invoke-direct {v7, v2, v8}, Ldd0/a;-><init>(Ljava/lang/String;I)V

    .line 77
    .line 78
    .line 79
    iput v4, v0, Lh40/z3;->e:I

    .line 80
    .line 81
    invoke-virtual {v6, v7, v0}, Lkc0/h0;->b(Ldd0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-ne v2, v1, :cond_5

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    :goto_1
    check-cast v2, Lyy0/i;

    .line 89
    .line 90
    new-instance v4, Lh40/g4;

    .line 91
    .line 92
    const/4 v6, 0x1

    .line 93
    invoke-direct {v4, v5, v6}, Lh40/g4;-><init>(Lh40/i4;I)V

    .line 94
    .line 95
    .line 96
    iput v3, v0, Lh40/z3;->e:I

    .line 97
    .line 98
    invoke-interface {v2, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    if-ne v0, v1, :cond_6

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_6
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    :goto_3
    return-object v1

    .line 108
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 109
    .line 110
    iget v2, v0, Lh40/z3;->e:I

    .line 111
    .line 112
    const/4 v3, 0x1

    .line 113
    iget-object v4, v0, Lh40/z3;->f:Lh40/i4;

    .line 114
    .line 115
    if-eqz v2, :cond_8

    .line 116
    .line 117
    if-ne v2, v3, :cond_7

    .line 118
    .line 119
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 126
    .line 127
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v0

    .line 131
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    move-object v5, v2

    .line 139
    check-cast v5, Lh40/d4;

    .line 140
    .line 141
    const/16 v24, 0x0

    .line 142
    .line 143
    const v25, 0xffffb

    .line 144
    .line 145
    .line 146
    const/4 v6, 0x0

    .line 147
    const/4 v7, 0x0

    .line 148
    const/4 v8, 0x1

    .line 149
    const/4 v9, 0x0

    .line 150
    const/4 v10, 0x0

    .line 151
    const/4 v11, 0x0

    .line 152
    const/4 v12, 0x0

    .line 153
    const/4 v13, 0x0

    .line 154
    const/4 v14, 0x0

    .line 155
    const/4 v15, 0x0

    .line 156
    const/16 v16, 0x0

    .line 157
    .line 158
    const/16 v17, 0x0

    .line 159
    .line 160
    const/16 v18, 0x0

    .line 161
    .line 162
    const/16 v19, 0x0

    .line 163
    .line 164
    const/16 v20, 0x0

    .line 165
    .line 166
    const/16 v21, 0x0

    .line 167
    .line 168
    const/16 v22, 0x0

    .line 169
    .line 170
    const/16 v23, 0x0

    .line 171
    .line 172
    invoke-static/range {v5 .. v25}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    invoke-virtual {v4, v2}, Lql0/j;->g(Lql0/h;)V

    .line 177
    .line 178
    .line 179
    iget-object v2, v4, Lh40/i4;->k:Lf40/w;

    .line 180
    .line 181
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    check-cast v2, Lyy0/i;

    .line 186
    .line 187
    iput v3, v0, Lh40/z3;->e:I

    .line 188
    .line 189
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    if-ne v0, v1, :cond_9

    .line 194
    .line 195
    goto :goto_5

    .line 196
    :cond_9
    :goto_4
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    move-object v5, v0

    .line 201
    check-cast v5, Lh40/d4;

    .line 202
    .line 203
    const/16 v24, 0x0

    .line 204
    .line 205
    const v25, 0xffffb

    .line 206
    .line 207
    .line 208
    const/4 v6, 0x0

    .line 209
    const/4 v7, 0x0

    .line 210
    const/4 v8, 0x0

    .line 211
    const/4 v9, 0x0

    .line 212
    const/4 v10, 0x0

    .line 213
    const/4 v11, 0x0

    .line 214
    const/4 v12, 0x0

    .line 215
    const/4 v13, 0x0

    .line 216
    const/4 v14, 0x0

    .line 217
    const/4 v15, 0x0

    .line 218
    const/16 v16, 0x0

    .line 219
    .line 220
    const/16 v17, 0x0

    .line 221
    .line 222
    const/16 v18, 0x0

    .line 223
    .line 224
    const/16 v19, 0x0

    .line 225
    .line 226
    const/16 v20, 0x0

    .line 227
    .line 228
    const/16 v21, 0x0

    .line 229
    .line 230
    const/16 v22, 0x0

    .line 231
    .line 232
    const/16 v23, 0x0

    .line 233
    .line 234
    invoke-static/range {v5 .. v25}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 235
    .line 236
    .line 237
    move-result-object v0

    .line 238
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 239
    .line 240
    .line 241
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 242
    .line 243
    :goto_5
    return-object v1

    .line 244
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 245
    .line 246
    iget v2, v0, Lh40/z3;->e:I

    .line 247
    .line 248
    const/4 v3, 0x1

    .line 249
    if-eqz v2, :cond_b

    .line 250
    .line 251
    if-ne v2, v3, :cond_a

    .line 252
    .line 253
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 258
    .line 259
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 260
    .line 261
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw v0

    .line 265
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iget-object v2, v0, Lh40/z3;->f:Lh40/i4;

    .line 269
    .line 270
    iget-object v4, v2, Lh40/i4;->j:Lf40/m1;

    .line 271
    .line 272
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v4

    .line 276
    check-cast v4, Lyy0/i;

    .line 277
    .line 278
    new-instance v5, Lh40/y3;

    .line 279
    .line 280
    const/4 v6, 0x0

    .line 281
    invoke-direct {v5, v2, v6}, Lh40/y3;-><init>(Lh40/i4;I)V

    .line 282
    .line 283
    .line 284
    iput v3, v0, Lh40/z3;->e:I

    .line 285
    .line 286
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v0

    .line 290
    if-ne v0, v1, :cond_c

    .line 291
    .line 292
    goto :goto_7

    .line 293
    :cond_c
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 294
    .line 295
    :goto_7
    return-object v1

    .line 296
    nop

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
