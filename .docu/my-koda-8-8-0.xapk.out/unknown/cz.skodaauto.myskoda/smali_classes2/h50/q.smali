.class public final Lh50/q;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh50/d0;


# direct methods
.method public synthetic constructor <init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lh50/q;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lh50/q;->f:Lh50/d0;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lh50/q;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh50/q;

    .line 7
    .line 8
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 9
    .line 10
    const/4 v0, 0x5

    .line 11
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh50/q;

    .line 16
    .line 17
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh50/q;

    .line 25
    .line 26
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lh50/q;

    .line 34
    .line 35
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lh50/q;

    .line 43
    .line 44
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lh50/q;

    .line 52
    .line 53
    iget-object p0, p0, Lh50/q;->f:Lh50/d0;

    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    invoke-direct {p1, v0, p0, p2}, Lh50/q;-><init>(ILh50/d0;Lkotlin/coroutines/Continuation;)V

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
    iget v0, p0, Lh50/q;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh50/q;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh50/q;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh50/q;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lh50/q;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lh50/q;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lh50/q;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lh50/q;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lh50/q;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh50/q;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x0

    .line 7
    iget-object v4, v0, Lh50/q;->f:Lh50/d0;

    .line 8
    .line 9
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    const-string v6, "call to \'resume\' before \'invoke\' with coroutine"

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
    iget v8, v0, Lh50/q;->e:I

    .line 20
    .line 21
    if-eqz v8, :cond_1

    .line 22
    .line 23
    if-ne v8, v7, :cond_0

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
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    iget-object v6, v4, Lh50/d0;->F:Lrq0/f;

    .line 39
    .line 40
    new-instance v8, Lsq0/c;

    .line 41
    .line 42
    iget-object v4, v4, Lh50/d0;->I:Lij0/a;

    .line 43
    .line 44
    const/4 v9, 0x0

    .line 45
    new-array v9, v9, [Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v4, Ljj0/f;

    .line 48
    .line 49
    const v10, 0x7f1206f1

    .line 50
    .line 51
    .line 52
    invoke-virtual {v4, v10, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const-string v9, "route_detail_route_sent"

    .line 57
    .line 58
    invoke-direct {v8, v2, v4, v3, v9}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iput v7, v0, Lh50/q;->e:I

    .line 62
    .line 63
    invoke-virtual {v6, v8, v7, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    if-ne v0, v1, :cond_2

    .line 68
    .line 69
    move-object v5, v1

    .line 70
    :cond_2
    :goto_0
    return-object v5

    .line 71
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v2, v0, Lh50/q;->e:I

    .line 74
    .line 75
    if-eqz v2, :cond_4

    .line 76
    .line 77
    if-ne v2, v7, :cond_3

    .line 78
    .line 79
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    sget-object v2, Lh50/d0;->O:Ljava/util/List;

    .line 93
    .line 94
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    check-cast v2, Lh50/v;

    .line 99
    .line 100
    iget-boolean v2, v2, Lh50/v;->F:Z

    .line 101
    .line 102
    if-eqz v2, :cond_5

    .line 103
    .line 104
    sget-object v2, Lss0/e;->E:Lss0/e;

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_5
    sget-object v2, Lss0/e;->D:Lss0/e;

    .line 108
    .line 109
    :goto_1
    iget-object v6, v4, Lh50/d0;->n:Lkf0/v;

    .line 110
    .line 111
    invoke-static {v6}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    check-cast v6, Lyy0/i;

    .line 116
    .line 117
    new-instance v8, La50/h;

    .line 118
    .line 119
    const/16 v9, 0x1c

    .line 120
    .line 121
    invoke-direct {v8, v6, v9}, La50/h;-><init>(Lyy0/i;I)V

    .line 122
    .line 123
    .line 124
    invoke-static {v8, v7}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    new-instance v8, La50/d;

    .line 129
    .line 130
    const/4 v14, 0x4

    .line 131
    const/16 v15, 0xb

    .line 132
    .line 133
    const/4 v9, 0x2

    .line 134
    iget-object v10, v0, Lh50/q;->f:Lh50/d0;

    .line 135
    .line 136
    const-class v11, Lh50/d0;

    .line 137
    .line 138
    const-string v12, "onSubscriptionNeededState"

    .line 139
    .line 140
    const-string v13, "onSubscriptionNeededState(Lcz/skodaauto/myskoda/library/vehicle/model/Capabilities;)V"

    .line 141
    .line 142
    invoke-direct/range {v8 .. v15}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 143
    .line 144
    .line 145
    invoke-static {v6, v2, v8}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    new-instance v8, La10/a;

    .line 150
    .line 151
    const/16 v9, 0x10

    .line 152
    .line 153
    invoke-direct {v8, v4, v3, v9}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 154
    .line 155
    .line 156
    invoke-static {v6, v2, v8}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    new-instance v3, Lgt0/c;

    .line 161
    .line 162
    const/16 v6, 0x8

    .line 163
    .line 164
    invoke-direct {v3, v4, v6}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 165
    .line 166
    .line 167
    iput v7, v0, Lh50/q;->e:I

    .line 168
    .line 169
    invoke-virtual {v2, v3, v0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    if-ne v0, v1, :cond_6

    .line 174
    .line 175
    move-object v5, v1

    .line 176
    :cond_6
    :goto_2
    return-object v5

    .line 177
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    iget v2, v0, Lh50/q;->e:I

    .line 180
    .line 181
    if-eqz v2, :cond_8

    .line 182
    .line 183
    if-ne v2, v7, :cond_7

    .line 184
    .line 185
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 190
    .line 191
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    throw v0

    .line 195
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    iget-object v2, v4, Lh50/d0;->s:Lf50/l;

    .line 199
    .line 200
    iput v7, v0, Lh50/q;->e:I

    .line 201
    .line 202
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 203
    .line 204
    .line 205
    invoke-virtual {v2, v0}, Lf50/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    if-ne v0, v1, :cond_9

    .line 210
    .line 211
    move-object v5, v1

    .line 212
    :cond_9
    :goto_3
    return-object v5

    .line 213
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 214
    .line 215
    iget v2, v0, Lh50/q;->e:I

    .line 216
    .line 217
    if-eqz v2, :cond_b

    .line 218
    .line 219
    if-ne v2, v7, :cond_a

    .line 220
    .line 221
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    goto :goto_4

    .line 225
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 226
    .line 227
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 228
    .line 229
    .line 230
    throw v0

    .line 231
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    iget-object v10, v0, Lh50/q;->f:Lh50/d0;

    .line 235
    .line 236
    iget-object v2, v10, Lh50/d0;->v:Lwj0/r;

    .line 237
    .line 238
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v2

    .line 242
    check-cast v2, Lyy0/i;

    .line 243
    .line 244
    new-instance v8, La50/d;

    .line 245
    .line 246
    const/4 v14, 0x4

    .line 247
    const/16 v15, 0xa

    .line 248
    .line 249
    const/4 v9, 0x2

    .line 250
    const-class v11, Lh50/d0;

    .line 251
    .line 252
    const-string v12, "onSelectedPin"

    .line 253
    .line 254
    const-string v13, "onSelectedPin(Lcz/skodaauto/myskoda/library/map/model/Pin;)V"

    .line 255
    .line 256
    invoke-direct/range {v8 .. v15}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 257
    .line 258
    .line 259
    iput v7, v0, Lh50/q;->e:I

    .line 260
    .line 261
    invoke-static {v8, v0, v2}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    if-ne v0, v1, :cond_c

    .line 266
    .line 267
    move-object v5, v1

    .line 268
    :cond_c
    :goto_4
    return-object v5

    .line 269
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 270
    .line 271
    iget v4, v0, Lh50/q;->e:I

    .line 272
    .line 273
    iget-object v10, v0, Lh50/q;->f:Lh50/d0;

    .line 274
    .line 275
    if-eqz v4, :cond_f

    .line 276
    .line 277
    if-eq v4, v7, :cond_e

    .line 278
    .line 279
    if-ne v4, v2, :cond_d

    .line 280
    .line 281
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    goto :goto_7

    .line 285
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 286
    .line 287
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    throw v0

    .line 291
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    move-object/from16 v3, p1

    .line 295
    .line 296
    goto :goto_5

    .line 297
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 298
    .line 299
    .line 300
    iget-object v4, v10, Lh50/d0;->w:Luk0/e0;

    .line 301
    .line 302
    iput v7, v0, Lh50/q;->e:I

    .line 303
    .line 304
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 305
    .line 306
    .line 307
    iget-object v6, v4, Luk0/e0;->a:Lpp0/n0;

    .line 308
    .line 309
    invoke-virtual {v6}, Lpp0/n0;->invoke()Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v6

    .line 313
    check-cast v6, Lyy0/i;

    .line 314
    .line 315
    new-instance v7, Ltr0/e;

    .line 316
    .line 317
    const/16 v8, 0xf

    .line 318
    .line 319
    invoke-direct {v7, v6, v3, v4, v8}, Ltr0/e;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;Ltr0/c;I)V

    .line 320
    .line 321
    .line 322
    new-instance v3, Lyy0/m1;

    .line 323
    .line 324
    invoke-direct {v3, v7}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 325
    .line 326
    .line 327
    if-ne v3, v1, :cond_10

    .line 328
    .line 329
    goto :goto_6

    .line 330
    :cond_10
    :goto_5
    check-cast v3, Lyy0/i;

    .line 331
    .line 332
    new-instance v8, La50/d;

    .line 333
    .line 334
    const/4 v14, 0x4

    .line 335
    const/16 v15, 0x9

    .line 336
    .line 337
    const/4 v9, 0x2

    .line 338
    const-class v11, Lh50/d0;

    .line 339
    .line 340
    const-string v12, "onSelectedWaypointDetail"

    .line 341
    .line 342
    const-string v13, "onSelectedWaypointDetail(Lcz/skodaauto/myskoda/library/route/model/Waypoint;)V"

    .line 343
    .line 344
    invoke-direct/range {v8 .. v15}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 345
    .line 346
    .line 347
    iput v2, v0, Lh50/q;->e:I

    .line 348
    .line 349
    invoke-static {v8, v0, v3}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    if-ne v0, v1, :cond_11

    .line 354
    .line 355
    :goto_6
    move-object v5, v1

    .line 356
    :cond_11
    :goto_7
    return-object v5

    .line 357
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 358
    .line 359
    iget v3, v0, Lh50/q;->e:I

    .line 360
    .line 361
    if-eqz v3, :cond_14

    .line 362
    .line 363
    if-eq v3, v7, :cond_13

    .line 364
    .line 365
    if-ne v3, v2, :cond_12

    .line 366
    .line 367
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 368
    .line 369
    .line 370
    move-object/from16 v0, p1

    .line 371
    .line 372
    goto :goto_a

    .line 373
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 374
    .line 375
    invoke-direct {v0, v6}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    throw v0

    .line 379
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    move-object/from16 v3, p1

    .line 383
    .line 384
    goto :goto_8

    .line 385
    :cond_14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 386
    .line 387
    .line 388
    iget-object v3, v4, Lh50/d0;->l:Lpp0/t;

    .line 389
    .line 390
    iput v7, v0, Lh50/q;->e:I

    .line 391
    .line 392
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 393
    .line 394
    .line 395
    iget-object v3, v3, Lpp0/t;->a:Lpp0/c0;

    .line 396
    .line 397
    check-cast v3, Lnp0/b;

    .line 398
    .line 399
    iget-object v3, v3, Lnp0/b;->c:Lyy0/l1;

    .line 400
    .line 401
    invoke-static {v3, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v3

    .line 405
    if-ne v3, v1, :cond_15

    .line 406
    .line 407
    goto :goto_9

    .line 408
    :cond_15
    :goto_8
    check-cast v3, Lqp0/p;

    .line 409
    .line 410
    if-eqz v3, :cond_16

    .line 411
    .line 412
    iget-boolean v3, v3, Lqp0/p;->b:Z

    .line 413
    .line 414
    if-ne v3, v7, :cond_16

    .line 415
    .line 416
    goto :goto_b

    .line 417
    :cond_16
    iget-object v3, v4, Lh50/d0;->r:Lf50/g;

    .line 418
    .line 419
    iput v2, v0, Lh50/q;->e:I

    .line 420
    .line 421
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 422
    .line 423
    .line 424
    invoke-virtual {v3, v0}, Lf50/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    if-ne v0, v1, :cond_17

    .line 429
    .line 430
    :goto_9
    move-object v5, v1

    .line 431
    goto :goto_b

    .line 432
    :cond_17
    :goto_a
    check-cast v0, Lhl0/i;

    .line 433
    .line 434
    if-nez v0, :cond_18

    .line 435
    .line 436
    sget-object v0, Lh50/d0;->O:Ljava/util/List;

    .line 437
    .line 438
    invoke-virtual {v4}, Lh50/d0;->k()V

    .line 439
    .line 440
    .line 441
    :cond_18
    :goto_b
    return-object v5

    .line 442
    nop

    .line 443
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
