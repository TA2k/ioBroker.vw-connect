.class public final Lga0/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lga0/o;


# direct methods
.method public synthetic constructor <init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lga0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lga0/c;->f:Lga0/o;

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
    iget p1, p0, Lga0/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lga0/c;

    .line 7
    .line 8
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 9
    .line 10
    const/4 v0, 0x5

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lga0/c;

    .line 16
    .line 17
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lga0/c;

    .line 25
    .line 26
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lga0/c;

    .line 34
    .line 35
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lga0/c;

    .line 43
    .line 44
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lga0/c;

    .line 52
    .line 53
    iget-object p0, p0, Lga0/c;->f:Lga0/o;

    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lga0/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lga0/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lga0/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lga0/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lga0/c;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lga0/c;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lga0/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lga0/c;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lga0/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
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
    iget v1, v0, Lga0/c;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    iget-object v5, v0, Lga0/c;->f:Lga0/o;

    .line 10
    .line 11
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v7, 0x1

    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    iget v2, v0, Lga0/c;->e:I

    .line 20
    .line 21
    if-eqz v2, :cond_1

    .line 22
    .line 23
    if-ne v2, v7, :cond_0

    .line 24
    .line 25
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, v5, Lga0/o;->n:Lcs0/z;

    .line 39
    .line 40
    iput v7, v0, Lga0/c;->e:I

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v2, v0}, Lcs0/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-ne v0, v1, :cond_2

    .line 50
    .line 51
    move-object v6, v1

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    :goto_0
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    move-object v7, v0

    .line 58
    check-cast v7, Lga0/i;

    .line 59
    .line 60
    const/16 v16, 0x0

    .line 61
    .line 62
    const/16 v17, 0x1fe

    .line 63
    .line 64
    const/4 v8, 0x0

    .line 65
    const/4 v9, 0x0

    .line 66
    const/4 v10, 0x0

    .line 67
    const/4 v11, 0x0

    .line 68
    const/4 v12, 0x0

    .line 69
    const/4 v13, 0x0

    .line 70
    const/4 v14, 0x0

    .line 71
    const/4 v15, 0x0

    .line 72
    invoke-static/range {v7 .. v17}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 77
    .line 78
    .line 79
    :goto_1
    return-object v6

    .line 80
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 81
    .line 82
    iget v2, v0, Lga0/c;->e:I

    .line 83
    .line 84
    if-eqz v2, :cond_4

    .line 85
    .line 86
    if-ne v2, v7, :cond_3

    .line 87
    .line 88
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw v0

    .line 98
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iput v7, v0, Lga0/c;->e:I

    .line 102
    .line 103
    iget-object v2, v5, Lga0/o;->o:Lrt0/u;

    .line 104
    .line 105
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, Lyy0/i;

    .line 110
    .line 111
    iget-object v4, v5, Lga0/o;->r:Lrt0/o;

    .line 112
    .line 113
    sget-object v7, Lst0/h;->d:[Lst0/h;

    .line 114
    .line 115
    invoke-virtual {v4}, Lrt0/o;->b()Lyy0/x;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    new-instance v7, Lc00/q;

    .line 120
    .line 121
    const/4 v8, 0x3

    .line 122
    invoke-direct {v7, v8, v3, v8}, Lc00/q;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 123
    .line 124
    .line 125
    new-instance v8, Lbn0/f;

    .line 126
    .line 127
    const/4 v9, 0x5

    .line 128
    invoke-direct {v8, v2, v4, v7, v9}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 129
    .line 130
    .line 131
    invoke-static {v8}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    new-instance v4, La7/k;

    .line 136
    .line 137
    const/16 v7, 0x19

    .line 138
    .line 139
    invoke-direct {v4, v5, v3, v7}, La7/k;-><init>(Landroidx/lifecycle/b1;Lkotlin/coroutines/Continuation;I)V

    .line 140
    .line 141
    .line 142
    invoke-static {v4, v0, v2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    if-ne v0, v1, :cond_5

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_5
    move-object v0, v6

    .line 150
    :goto_2
    if-ne v0, v1, :cond_6

    .line 151
    .line 152
    move-object v6, v1

    .line 153
    :cond_6
    :goto_3
    return-object v6

    .line 154
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    iget v2, v0, Lga0/c;->e:I

    .line 157
    .line 158
    if-eqz v2, :cond_8

    .line 159
    .line 160
    if-ne v2, v7, :cond_7

    .line 161
    .line 162
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 167
    .line 168
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw v0

    .line 172
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    iput v7, v0, Lga0/c;->e:I

    .line 176
    .line 177
    iget-object v2, v5, Lga0/o;->v:Lrt0/q;

    .line 178
    .line 179
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    check-cast v2, Lyy0/i;

    .line 184
    .line 185
    new-instance v4, Lzv0/a;

    .line 186
    .line 187
    invoke-direct {v4, v3, v5}, Lzv0/a;-><init>(Lkotlin/coroutines/Continuation;Lga0/o;)V

    .line 188
    .line 189
    .line 190
    invoke-static {v2, v4}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    if-ne v0, v1, :cond_9

    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_9
    move-object v0, v6

    .line 202
    :goto_4
    if-ne v0, v1, :cond_a

    .line 203
    .line 204
    move-object v6, v1

    .line 205
    :cond_a
    :goto_5
    return-object v6

    .line 206
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 207
    .line 208
    iget v2, v0, Lga0/c;->e:I

    .line 209
    .line 210
    const/4 v3, 0x2

    .line 211
    if-eqz v2, :cond_d

    .line 212
    .line 213
    if-eq v2, v7, :cond_c

    .line 214
    .line 215
    if-ne v2, v3, :cond_b

    .line 216
    .line 217
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    goto :goto_8

    .line 221
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 222
    .line 223
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw v0

    .line 227
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    move-object/from16 v2, p1

    .line 231
    .line 232
    goto :goto_6

    .line 233
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    iget-object v2, v5, Lga0/o;->z:Lcf0/e;

    .line 237
    .line 238
    iput v7, v0, Lga0/c;->e:I

    .line 239
    .line 240
    invoke-virtual {v2, v6, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v2

    .line 244
    if-ne v2, v1, :cond_e

    .line 245
    .line 246
    goto :goto_7

    .line 247
    :cond_e
    :goto_6
    check-cast v2, Ljava/lang/Boolean;

    .line 248
    .line 249
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 250
    .line 251
    .line 252
    move-result v16

    .line 253
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 254
    .line 255
    .line 256
    move-result-object v2

    .line 257
    move-object v8, v2

    .line 258
    check-cast v8, Lga0/i;

    .line 259
    .line 260
    const/16 v17, 0x0

    .line 261
    .line 262
    const/16 v18, 0x17f

    .line 263
    .line 264
    const/4 v9, 0x0

    .line 265
    const/4 v10, 0x0

    .line 266
    const/4 v11, 0x0

    .line 267
    const/4 v12, 0x0

    .line 268
    const/4 v13, 0x0

    .line 269
    const/4 v14, 0x0

    .line 270
    const/4 v15, 0x0

    .line 271
    invoke-static/range {v8 .. v18}, Lga0/i;->a(Lga0/i;Lql0/g;ZLlf0/i;Lga0/e;Ljava/util/List;ZZZZI)Lga0/i;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    invoke-virtual {v5, v2}, Lql0/j;->g(Lql0/h;)V

    .line 276
    .line 277
    .line 278
    if-eqz v16, :cond_f

    .line 279
    .line 280
    iget-object v2, v5, Lga0/o;->y:Lrt0/t;

    .line 281
    .line 282
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v2

    .line 286
    check-cast v2, Lyy0/i;

    .line 287
    .line 288
    new-instance v4, Lga0/d;

    .line 289
    .line 290
    invoke-direct {v4, v5, v7}, Lga0/d;-><init>(Lga0/o;I)V

    .line 291
    .line 292
    .line 293
    iput v3, v0, Lga0/c;->e:I

    .line 294
    .line 295
    invoke-interface {v2, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    if-ne v0, v1, :cond_f

    .line 300
    .line 301
    :goto_7
    move-object v6, v1

    .line 302
    :cond_f
    :goto_8
    return-object v6

    .line 303
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 304
    .line 305
    iget v3, v0, Lga0/c;->e:I

    .line 306
    .line 307
    if-eqz v3, :cond_11

    .line 308
    .line 309
    if-ne v3, v7, :cond_10

    .line 310
    .line 311
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    goto :goto_9

    .line 315
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 316
    .line 317
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 318
    .line 319
    .line 320
    throw v0

    .line 321
    :cond_11
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 322
    .line 323
    .line 324
    iget-object v3, v5, Lga0/o;->k:Lkf0/b0;

    .line 325
    .line 326
    invoke-static {v3}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v3

    .line 330
    check-cast v3, Lyy0/i;

    .line 331
    .line 332
    new-instance v4, Lga0/d;

    .line 333
    .line 334
    invoke-direct {v4, v5, v2}, Lga0/d;-><init>(Lga0/o;I)V

    .line 335
    .line 336
    .line 337
    iput v7, v0, Lga0/c;->e:I

    .line 338
    .line 339
    invoke-interface {v3, v4, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    if-ne v0, v1, :cond_12

    .line 344
    .line 345
    move-object v6, v1

    .line 346
    :cond_12
    :goto_9
    return-object v6

    .line 347
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 348
    .line 349
    iget v8, v0, Lga0/c;->e:I

    .line 350
    .line 351
    if-eqz v8, :cond_14

    .line 352
    .line 353
    if-ne v8, v7, :cond_13

    .line 354
    .line 355
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    goto :goto_a

    .line 359
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 360
    .line 361
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    throw v0

    .line 365
    :cond_14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 366
    .line 367
    .line 368
    iget-object v4, v5, Lga0/o;->j:Lkf0/e0;

    .line 369
    .line 370
    sget-object v8, Lss0/e;->G1:Lss0/e;

    .line 371
    .line 372
    invoke-virtual {v4, v8}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 373
    .line 374
    .line 375
    move-result-object v4

    .line 376
    new-instance v8, Lga0/b;

    .line 377
    .line 378
    invoke-direct {v8, v5, v3, v2}, Lga0/b;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 379
    .line 380
    .line 381
    iput v7, v0, Lga0/c;->e:I

    .line 382
    .line 383
    invoke-static {v8, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v0

    .line 387
    if-ne v0, v1, :cond_15

    .line 388
    .line 389
    move-object v6, v1

    .line 390
    :cond_15
    :goto_a
    return-object v6

    .line 391
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
