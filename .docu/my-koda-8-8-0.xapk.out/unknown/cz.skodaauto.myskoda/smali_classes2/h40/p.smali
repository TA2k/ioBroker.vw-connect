.class public final Lh40/p;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/t;


# direct methods
.method public synthetic constructor <init>(Lh40/t;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/p;->f:Lh40/t;

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
    iget p1, p0, Lh40/p;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/p;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/p;->f:Lh40/t;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/p;-><init>(Lh40/t;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/p;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/p;->f:Lh40/t;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/p;-><init>(Lh40/t;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh40/p;

    .line 25
    .line 26
    iget-object p0, p0, Lh40/p;->f:Lh40/t;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh40/p;-><init>(Lh40/t;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh40/p;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/p;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/p;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh40/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh40/p;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh40/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/p;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lh40/p;->e:I

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
    iget-object v2, v0, Lh40/p;->f:Lh40/t;

    .line 33
    .line 34
    iget-object v4, v2, Lh40/t;->q:Lbq0/b;

    .line 35
    .line 36
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    check-cast v4, Lyy0/i;

    .line 41
    .line 42
    new-instance v5, Lgt0/c;

    .line 43
    .line 44
    const/4 v6, 0x1

    .line 45
    invoke-direct {v5, v2, v6}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 46
    .line 47
    .line 48
    iput v3, v0, Lh40/p;->e:I

    .line 49
    .line 50
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    if-ne v0, v1, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    :goto_1
    return-object v1

    .line 60
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    iget v2, v0, Lh40/p;->e:I

    .line 63
    .line 64
    const/4 v3, 0x1

    .line 65
    iget-object v4, v0, Lh40/p;->f:Lh40/t;

    .line 66
    .line 67
    if-eqz v2, :cond_4

    .line 68
    .line 69
    if-ne v2, v3, :cond_3

    .line 70
    .line 71
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 78
    .line 79
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0

    .line 83
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    move-object v5, v2

    .line 91
    check-cast v5, Lh40/q;

    .line 92
    .line 93
    const/16 v17, 0x0

    .line 94
    .line 95
    const/16 v18, 0xffb

    .line 96
    .line 97
    const/4 v6, 0x0

    .line 98
    const/4 v7, 0x0

    .line 99
    const/4 v8, 0x1

    .line 100
    const/4 v9, 0x0

    .line 101
    const/4 v10, 0x0

    .line 102
    const/4 v11, 0x0

    .line 103
    const/4 v12, 0x0

    .line 104
    const/4 v13, 0x0

    .line 105
    const/4 v14, 0x0

    .line 106
    const/4 v15, 0x0

    .line 107
    const/16 v16, 0x0

    .line 108
    .line 109
    invoke-static/range {v5 .. v18}, Lh40/q;->a(Lh40/q;IZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZI)Lh40/q;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-virtual {v4, v2}, Lql0/j;->g(Lql0/h;)V

    .line 114
    .line 115
    .line 116
    iget-object v2, v4, Lh40/t;->i:Lf40/r;

    .line 117
    .line 118
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    check-cast v2, Lyy0/i;

    .line 123
    .line 124
    iput v3, v0, Lh40/p;->e:I

    .line 125
    .line 126
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    if-ne v0, v1, :cond_5

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_5
    :goto_2
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    move-object v5, v0

    .line 138
    check-cast v5, Lh40/q;

    .line 139
    .line 140
    const/16 v17, 0x0

    .line 141
    .line 142
    const/16 v18, 0xffb

    .line 143
    .line 144
    const/4 v6, 0x0

    .line 145
    const/4 v7, 0x0

    .line 146
    const/4 v8, 0x0

    .line 147
    const/4 v9, 0x0

    .line 148
    const/4 v10, 0x0

    .line 149
    const/4 v11, 0x0

    .line 150
    const/4 v12, 0x0

    .line 151
    const/4 v13, 0x0

    .line 152
    const/4 v14, 0x0

    .line 153
    const/4 v15, 0x0

    .line 154
    const/16 v16, 0x0

    .line 155
    .line 156
    invoke-static/range {v5 .. v18}, Lh40/q;->a(Lh40/q;IZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZI)Lh40/q;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 161
    .line 162
    .line 163
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 164
    .line 165
    :goto_3
    return-object v1

    .line 166
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 167
    .line 168
    iget v2, v0, Lh40/p;->e:I

    .line 169
    .line 170
    iget-object v3, v0, Lh40/p;->f:Lh40/t;

    .line 171
    .line 172
    const/4 v4, 0x2

    .line 173
    const/4 v5, 0x1

    .line 174
    if-eqz v2, :cond_8

    .line 175
    .line 176
    if-eq v2, v5, :cond_7

    .line 177
    .line 178
    if-ne v2, v4, :cond_6

    .line 179
    .line 180
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    goto :goto_5

    .line 184
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 185
    .line 186
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 187
    .line 188
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw v0

    .line 192
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    move-object/from16 v2, p1

    .line 196
    .line 197
    goto :goto_4

    .line 198
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    iget-object v2, v3, Lh40/t;->h:Lf40/i1;

    .line 202
    .line 203
    iput v5, v0, Lh40/p;->e:I

    .line 204
    .line 205
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 206
    .line 207
    .line 208
    iget-object v10, v2, Lf40/i1;->a:Lf40/z0;

    .line 209
    .line 210
    move-object v5, v10

    .line 211
    check-cast v5, Ld40/b;

    .line 212
    .line 213
    iget-object v13, v5, Ld40/b;->e:Lyy0/l1;

    .line 214
    .line 215
    iget-object v5, v5, Ld40/b;->c:Lez0/c;

    .line 216
    .line 217
    new-instance v6, La90/r;

    .line 218
    .line 219
    const/4 v7, 0x0

    .line 220
    const/4 v8, 0x7

    .line 221
    const-class v9, Lf40/z0;

    .line 222
    .line 223
    const-string v11, "isDataValid"

    .line 224
    .line 225
    const-string v12, "isDataValid()Z"

    .line 226
    .line 227
    invoke-direct/range {v6 .. v12}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    new-instance v7, Lbq0/i;

    .line 231
    .line 232
    const/4 v8, 0x0

    .line 233
    const/16 v9, 0xa

    .line 234
    .line 235
    invoke-direct {v7, v2, v8, v9}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 236
    .line 237
    .line 238
    invoke-static {v13, v5, v6, v7}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    if-ne v2, v1, :cond_9

    .line 243
    .line 244
    goto :goto_6

    .line 245
    :cond_9
    :goto_4
    check-cast v2, Lyy0/i;

    .line 246
    .line 247
    new-instance v5, La60/b;

    .line 248
    .line 249
    const/16 v6, 0x11

    .line 250
    .line 251
    invoke-direct {v5, v3, v6}, La60/b;-><init>(Lql0/j;I)V

    .line 252
    .line 253
    .line 254
    iput v4, v0, Lh40/p;->e:I

    .line 255
    .line 256
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v0

    .line 260
    if-ne v0, v1, :cond_a

    .line 261
    .line 262
    goto :goto_6

    .line 263
    :cond_a
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 264
    .line 265
    :goto_6
    return-object v1

    .line 266
    nop

    .line 267
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
