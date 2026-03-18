.class public final Lnz/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lnz/z;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnz/z;)V
    .locals 0

    .line 1
    iput p1, p0, Lnz/n;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnz/n;->f:Lnz/z;

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
    iget p1, p0, Lnz/n;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnz/n;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/n;->f:Lnz/z;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, v0, p2, p0}, Lnz/n;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lnz/n;

    .line 16
    .line 17
    iget-object p0, p0, Lnz/n;->f:Lnz/z;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, v0, p2, p0}, Lnz/n;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lnz/n;

    .line 25
    .line 26
    iget-object p0, p0, Lnz/n;->f:Lnz/z;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, v0, p2, p0}, Lnz/n;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

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
    iget v0, p0, Lnz/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnz/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnz/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnz/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnz/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lnz/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lnz/n;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lnz/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lnz/n;->d:I

    .line 4
    .line 5
    const/4 v2, 0x3

    .line 6
    const/4 v3, 0x0

    .line 7
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    iget-object v6, v0, Lnz/n;->f:Lnz/z;

    .line 12
    .line 13
    const/4 v7, 0x0

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
    iget v9, v0, Lnz/n;->e:I

    .line 21
    .line 22
    if-eqz v9, :cond_1

    .line 23
    .line 24
    if-ne v9, v8, :cond_0

    .line 25
    .line 26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    sget v5, Lnz/z;->B:I

    .line 40
    .line 41
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    move-object v9, v5

    .line 46
    check-cast v9, Lnz/s;

    .line 47
    .line 48
    const/16 v33, 0x0

    .line 49
    .line 50
    const v34, 0xffffffb

    .line 51
    .line 52
    .line 53
    const/4 v10, 0x0

    .line 54
    const/4 v11, 0x0

    .line 55
    const/4 v12, 0x1

    .line 56
    const/4 v13, 0x0

    .line 57
    const/4 v14, 0x0

    .line 58
    const/4 v15, 0x0

    .line 59
    const/16 v16, 0x0

    .line 60
    .line 61
    const/16 v17, 0x0

    .line 62
    .line 63
    const/16 v18, 0x0

    .line 64
    .line 65
    const/16 v19, 0x0

    .line 66
    .line 67
    const/16 v20, 0x0

    .line 68
    .line 69
    const/16 v21, 0x0

    .line 70
    .line 71
    const/16 v22, 0x0

    .line 72
    .line 73
    const/16 v23, 0x0

    .line 74
    .line 75
    const/16 v24, 0x0

    .line 76
    .line 77
    const/16 v25, 0x0

    .line 78
    .line 79
    const/16 v26, 0x0

    .line 80
    .line 81
    const/16 v27, 0x0

    .line 82
    .line 83
    const/16 v28, 0x0

    .line 84
    .line 85
    const/16 v29, 0x0

    .line 86
    .line 87
    const/16 v30, 0x0

    .line 88
    .line 89
    const/16 v31, 0x0

    .line 90
    .line 91
    const/16 v32, 0x0

    .line 92
    .line 93
    invoke-static/range {v9 .. v34}, Lnz/s;->a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    invoke-virtual {v6, v5}, Lql0/j;->g(Lql0/h;)V

    .line 98
    .line 99
    .line 100
    iget-object v5, v6, Lnz/z;->l:Llz/e;

    .line 101
    .line 102
    new-instance v9, Llz/b;

    .line 103
    .line 104
    invoke-direct {v9, v3}, Llz/b;-><init>(Z)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v5, v9}, Llz/e;->a(Llz/b;)Lzy0/j;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    invoke-static {v3}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    new-instance v5, Lnz/m;

    .line 116
    .line 117
    invoke-direct {v5, v2, v7, v6}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 118
    .line 119
    .line 120
    invoke-static {v5, v3}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    new-instance v3, Lnz/x;

    .line 125
    .line 126
    invoke-direct {v3, v6, v8}, Lnz/x;-><init>(Lnz/z;I)V

    .line 127
    .line 128
    .line 129
    iput v8, v0, Lnz/n;->e:I

    .line 130
    .line 131
    invoke-virtual {v2, v3, v0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    if-ne v0, v1, :cond_2

    .line 136
    .line 137
    move-object v4, v1

    .line 138
    :cond_2
    :goto_0
    return-object v4

    .line 139
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 140
    .line 141
    iget v2, v0, Lnz/n;->e:I

    .line 142
    .line 143
    if-eqz v2, :cond_4

    .line 144
    .line 145
    if-ne v2, v8, :cond_3

    .line 146
    .line 147
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 152
    .line 153
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    throw v0

    .line 157
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iput v8, v0, Lnz/n;->e:I

    .line 161
    .line 162
    iget-object v2, v6, Lnz/z;->w:Llb0/g;

    .line 163
    .line 164
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v2

    .line 168
    check-cast v2, Lyy0/i;

    .line 169
    .line 170
    new-instance v5, Lnz/u;

    .line 171
    .line 172
    invoke-direct {v5, v3, v7, v6}, Lnz/u;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 173
    .line 174
    .line 175
    invoke-static {v2, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    if-ne v0, v1, :cond_5

    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_5
    move-object v0, v4

    .line 187
    :goto_1
    if-ne v0, v1, :cond_6

    .line 188
    .line 189
    move-object v4, v1

    .line 190
    :cond_6
    :goto_2
    return-object v4

    .line 191
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    iget v3, v0, Lnz/n;->e:I

    .line 194
    .line 195
    if-eqz v3, :cond_8

    .line 196
    .line 197
    if-ne v3, v8, :cond_7

    .line 198
    .line 199
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 204
    .line 205
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v0

    .line 209
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    iput v8, v0, Lnz/n;->e:I

    .line 213
    .line 214
    iget-object v3, v6, Lnz/z;->k:Llz/k;

    .line 215
    .line 216
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v3

    .line 220
    check-cast v3, Lyy0/i;

    .line 221
    .line 222
    iget-object v5, v6, Lnz/z;->t:Llz/i;

    .line 223
    .line 224
    sget-object v9, Lmz/h;->f:Lmz/h;

    .line 225
    .line 226
    invoke-virtual {v5, v9}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 227
    .line 228
    .line 229
    move-result-object v9

    .line 230
    sget-object v10, Lmz/h;->g:Lmz/h;

    .line 231
    .line 232
    invoke-virtual {v5, v10}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 233
    .line 234
    .line 235
    move-result-object v10

    .line 236
    sget-object v11, Lmz/h;->h:Lmz/h;

    .line 237
    .line 238
    invoke-virtual {v5, v11}, Llz/i;->b(Lmz/h;)Lyy0/x;

    .line 239
    .line 240
    .line 241
    move-result-object v5

    .line 242
    new-instance v11, Lc00/f;

    .line 243
    .line 244
    const/4 v12, 0x5

    .line 245
    invoke-direct {v11, v12, v7, v2}, Lc00/f;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 246
    .line 247
    .line 248
    invoke-static {v3, v9, v10, v5, v11}, Lyy0/u;->l(Lyy0/i;Lyy0/i;Lyy0/i;Lyy0/i;Lay0/q;)Llb0/y;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    invoke-static {v2}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    new-instance v3, Lnz/o;

    .line 257
    .line 258
    invoke-direct {v3, v8, v7, v6}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 259
    .line 260
    .line 261
    invoke-static {v3, v0, v2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    if-ne v0, v1, :cond_9

    .line 266
    .line 267
    goto :goto_3

    .line 268
    :cond_9
    move-object v0, v4

    .line 269
    :goto_3
    if-ne v0, v1, :cond_a

    .line 270
    .line 271
    move-object v4, v1

    .line 272
    :cond_a
    :goto_4
    return-object v4

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
