.class public final Lnz/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lnz/j;


# direct methods
.method public synthetic constructor <init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnz/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnz/b;->f:Lnz/j;

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
    iget p1, p0, Lnz/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnz/b;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/b;->f:Lnz/j;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lnz/b;

    .line 16
    .line 17
    iget-object p0, p0, Lnz/b;->f:Lnz/j;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lnz/b;

    .line 25
    .line 26
    iget-object p0, p0, Lnz/b;->f:Lnz/j;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lnz/b;

    .line 34
    .line 35
    iget-object p0, p0, Lnz/b;->f:Lnz/j;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lnz/b;

    .line 43
    .line 44
    iget-object p0, p0, Lnz/b;->f:Lnz/j;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lnz/b;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnz/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lnz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lnz/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lnz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lnz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lnz/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lnz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lnz/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lnz/b;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lnz/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lnz/b;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x0

    .line 7
    const/4 v4, 0x0

    .line 8
    iget-object v5, v0, Lnz/b;->f:Lnz/j;

    .line 9
    .line 10
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v8, 0x1

    .line 15
    packed-switch v1, :pswitch_data_0

    .line 16
    .line 17
    .line 18
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v2, v0, Lnz/b;->e:I

    .line 21
    .line 22
    if-eqz v2, :cond_1

    .line 23
    .line 24
    if-ne v2, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw v0

    .line 36
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iput v8, v0, Lnz/b;->e:I

    .line 40
    .line 41
    iget-object v2, v5, Lnz/j;->u:Llb0/g;

    .line 42
    .line 43
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    check-cast v2, Lyy0/i;

    .line 48
    .line 49
    new-instance v3, Lgb0/z;

    .line 50
    .line 51
    const/16 v6, 0x1b

    .line 52
    .line 53
    invoke-direct {v3, v4, v5, v6}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v2, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-ne v0, v1, :cond_2

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_2
    move-object v0, v7

    .line 68
    :goto_0
    if-ne v0, v1, :cond_3

    .line 69
    .line 70
    move-object v7, v1

    .line 71
    :cond_3
    :goto_1
    return-object v7

    .line 72
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 73
    .line 74
    iget v2, v0, Lnz/b;->e:I

    .line 75
    .line 76
    if-eqz v2, :cond_5

    .line 77
    .line 78
    if-ne v2, v8, :cond_4

    .line 79
    .line 80
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v0

    .line 90
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iput v8, v0, Lnz/b;->e:I

    .line 94
    .line 95
    iget-object v2, v5, Lnz/j;->j:Llz/k;

    .line 96
    .line 97
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    check-cast v2, Lyy0/i;

    .line 102
    .line 103
    iget-object v6, v5, Lnz/j;->s:Llz/i;

    .line 104
    .line 105
    sget-object v9, Lmz/h;->f:Lmz/h;

    .line 106
    .line 107
    invoke-virtual {v6, v9}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 108
    .line 109
    .line 110
    move-result-object v9

    .line 111
    sget-object v10, Lmz/h;->h:Lmz/h;

    .line 112
    .line 113
    invoke-virtual {v6, v10}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 114
    .line 115
    .line 116
    move-result-object v6

    .line 117
    new-instance v10, Lga0/z;

    .line 118
    .line 119
    const/4 v11, 0x4

    .line 120
    invoke-direct {v10, v11, v4, v8}, Lga0/z;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 121
    .line 122
    .line 123
    invoke-static {v2, v9, v6, v10}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 124
    .line 125
    .line 126
    move-result-object v2

    .line 127
    invoke-static {v2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    new-instance v6, Lnz/f;

    .line 132
    .line 133
    invoke-direct {v6, v5, v4, v3}, Lnz/f;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 134
    .line 135
    .line 136
    invoke-static {v6, v0, v2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    if-ne v0, v1, :cond_6

    .line 141
    .line 142
    goto :goto_2

    .line 143
    :cond_6
    move-object v0, v7

    .line 144
    :goto_2
    if-ne v0, v1, :cond_7

    .line 145
    .line 146
    move-object v7, v1

    .line 147
    :cond_7
    :goto_3
    return-object v7

    .line 148
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 149
    .line 150
    iget v3, v0, Lnz/b;->e:I

    .line 151
    .line 152
    if-eqz v3, :cond_a

    .line 153
    .line 154
    if-eq v3, v8, :cond_9

    .line 155
    .line 156
    if-ne v3, v2, :cond_8

    .line 157
    .line 158
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw v0

    .line 168
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-object/from16 v3, p1

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    iget-object v3, v5, Lnz/j;->x:Lcf0/e;

    .line 178
    .line 179
    iput v8, v0, Lnz/b;->e:I

    .line 180
    .line 181
    invoke-virtual {v3, v7, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    if-ne v3, v1, :cond_b

    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_b
    :goto_4
    check-cast v3, Ljava/lang/Boolean;

    .line 189
    .line 190
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 191
    .line 192
    .line 193
    move-result v19

    .line 194
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 195
    .line 196
    .line 197
    move-result-object v3

    .line 198
    move-object v9, v3

    .line 199
    check-cast v9, Lnz/e;

    .line 200
    .line 201
    const/16 v21, 0x0

    .line 202
    .line 203
    const/16 v22, 0x37ff

    .line 204
    .line 205
    const/4 v10, 0x0

    .line 206
    const/4 v11, 0x0

    .line 207
    const/4 v12, 0x0

    .line 208
    const/4 v13, 0x0

    .line 209
    const/4 v14, 0x0

    .line 210
    const/4 v15, 0x0

    .line 211
    const/16 v16, 0x0

    .line 212
    .line 213
    const/16 v17, 0x0

    .line 214
    .line 215
    const/16 v18, 0x0

    .line 216
    .line 217
    const/16 v20, 0x0

    .line 218
    .line 219
    invoke-static/range {v9 .. v22}, Lnz/e;->a(Lnz/e;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLnz/d;Llf0/i;ZZZI)Lnz/e;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    invoke-virtual {v5, v3}, Lql0/j;->g(Lql0/h;)V

    .line 224
    .line 225
    .line 226
    if-eqz v19, :cond_c

    .line 227
    .line 228
    iget-object v3, v5, Lnz/j;->w:Llz/j;

    .line 229
    .line 230
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v3

    .line 234
    check-cast v3, Lyy0/i;

    .line 235
    .line 236
    new-instance v4, Lnz/c;

    .line 237
    .line 238
    invoke-direct {v4, v5, v8}, Lnz/c;-><init>(Lnz/j;I)V

    .line 239
    .line 240
    .line 241
    iput v2, v0, Lnz/b;->e:I

    .line 242
    .line 243
    invoke-interface {v3, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    if-ne v0, v1, :cond_c

    .line 248
    .line 249
    :goto_5
    move-object v7, v1

    .line 250
    :cond_c
    :goto_6
    return-object v7

    .line 251
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 252
    .line 253
    iget v2, v0, Lnz/b;->e:I

    .line 254
    .line 255
    if-eqz v2, :cond_e

    .line 256
    .line 257
    if-ne v2, v8, :cond_d

    .line 258
    .line 259
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    goto :goto_7

    .line 263
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 266
    .line 267
    .line 268
    throw v0

    .line 269
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 270
    .line 271
    .line 272
    iget-object v2, v5, Lnz/j;->k:Lkf0/b0;

    .line 273
    .line 274
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    check-cast v2, Lyy0/i;

    .line 279
    .line 280
    new-instance v4, Lnz/c;

    .line 281
    .line 282
    invoke-direct {v4, v5, v3}, Lnz/c;-><init>(Lnz/j;I)V

    .line 283
    .line 284
    .line 285
    iput v8, v0, Lnz/b;->e:I

    .line 286
    .line 287
    invoke-interface {v2, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    if-ne v0, v1, :cond_f

    .line 292
    .line 293
    move-object v7, v1

    .line 294
    :cond_f
    :goto_7
    return-object v7

    .line 295
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 296
    .line 297
    iget v9, v0, Lnz/b;->e:I

    .line 298
    .line 299
    if-eqz v9, :cond_11

    .line 300
    .line 301
    if-ne v9, v8, :cond_10

    .line 302
    .line 303
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    goto :goto_a

    .line 307
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 308
    .line 309
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    throw v0

    .line 313
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iget-object v6, v5, Lnz/j;->i:Lkf0/e0;

    .line 317
    .line 318
    sget-object v9, Lss0/e;->m:Lss0/e;

    .line 319
    .line 320
    invoke-virtual {v6, v9}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 321
    .line 322
    .line 323
    move-result-object v6

    .line 324
    iget-object v9, v5, Lnz/j;->y:Lkf0/v;

    .line 325
    .line 326
    invoke-static {v9}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v9

    .line 330
    check-cast v9, Lyy0/i;

    .line 331
    .line 332
    new-instance v10, Lac/k;

    .line 333
    .line 334
    const/16 v11, 0x1d

    .line 335
    .line 336
    invoke-direct {v10, v5, v4, v11}, Lac/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 337
    .line 338
    .line 339
    iput v8, v0, Lnz/b;->e:I

    .line 340
    .line 341
    new-array v2, v2, [Lyy0/i;

    .line 342
    .line 343
    aput-object v6, v2, v3

    .line 344
    .line 345
    aput-object v9, v2, v8

    .line 346
    .line 347
    new-instance v3, Lyy0/g1;

    .line 348
    .line 349
    invoke-direct {v3, v10, v4}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 350
    .line 351
    .line 352
    sget-object v4, Lyy0/h1;->d:Lyy0/h1;

    .line 353
    .line 354
    sget-object v5, Lzy0/q;->d:Lzy0/q;

    .line 355
    .line 356
    invoke-static {v4, v3, v0, v5, v2}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 361
    .line 362
    if-ne v0, v2, :cond_12

    .line 363
    .line 364
    goto :goto_8

    .line 365
    :cond_12
    move-object v0, v7

    .line 366
    :goto_8
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 367
    .line 368
    if-ne v0, v2, :cond_13

    .line 369
    .line 370
    goto :goto_9

    .line 371
    :cond_13
    move-object v0, v7

    .line 372
    :goto_9
    if-ne v0, v1, :cond_14

    .line 373
    .line 374
    move-object v7, v1

    .line 375
    :cond_14
    :goto_a
    return-object v7

    .line 376
    nop

    .line 377
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
