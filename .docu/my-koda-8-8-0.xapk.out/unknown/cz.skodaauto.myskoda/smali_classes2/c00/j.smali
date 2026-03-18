.class public final Lc00/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc00/p;


# direct methods
.method public synthetic constructor <init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc00/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/j;->f:Lc00/p;

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
    iget p1, p0, Lc00/j;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc00/j;

    .line 7
    .line 8
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 9
    .line 10
    const/4 v0, 0x6

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc00/j;

    .line 16
    .line 17
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 18
    .line 19
    const/4 v0, 0x5

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc00/j;

    .line 25
    .line 26
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lc00/j;

    .line 34
    .line 35
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 36
    .line 37
    const/4 v0, 0x3

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lc00/j;

    .line 43
    .line 44
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 45
    .line 46
    const/4 v0, 0x2

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lc00/j;

    .line 52
    .line 53
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Lc00/j;

    .line 61
    .line 62
    iget-object p0, p0, Lc00/j;->f:Lc00/p;

    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    invoke-direct {p1, p0, p2, v0}, Lc00/j;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
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
    iget v0, p0, Lc00/j;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc00/j;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc00/j;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc00/j;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lc00/j;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lc00/j;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lc00/j;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Lc00/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lc00/j;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Lc00/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc00/j;->d:I

    .line 4
    .line 5
    const/16 v2, 0xd

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x2

    .line 10
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const-string v7, "call to \'resume\' before \'invoke\' with coroutine"

    .line 13
    .line 14
    iget-object v8, v0, Lc00/j;->f:Lc00/p;

    .line 15
    .line 16
    const/4 v9, 0x1

    .line 17
    packed-switch v1, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v2, v0, Lc00/j;->e:I

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    if-ne v2, v9, :cond_0

    .line 27
    .line 28
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object v2, v8, Lc00/p;->k:Lkf0/b0;

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
    new-instance v3, Lc00/m;

    .line 50
    .line 51
    invoke-direct {v3, v8, v9}, Lc00/m;-><init>(Lc00/p;I)V

    .line 52
    .line 53
    .line 54
    iput v9, v0, Lc00/j;->e:I

    .line 55
    .line 56
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-ne v0, v1, :cond_2

    .line 61
    .line 62
    move-object v6, v1

    .line 63
    :cond_2
    :goto_0
    return-object v6

    .line 64
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v2, v0, Lc00/j;->e:I

    .line 67
    .line 68
    if-eqz v2, :cond_5

    .line 69
    .line 70
    if-eq v2, v9, :cond_4

    .line 71
    .line 72
    if-ne v2, v5, :cond_3

    .line 73
    .line 74
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw v0

    .line 84
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    move-object/from16 v2, p1

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    iget-object v2, v8, Lc00/p;->w:Lcf0/e;

    .line 94
    .line 95
    iput v9, v0, Lc00/j;->e:I

    .line 96
    .line 97
    invoke-virtual {v2, v6, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v2

    .line 101
    if-ne v2, v1, :cond_6

    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_6
    :goto_1
    check-cast v2, Ljava/lang/Boolean;

    .line 105
    .line 106
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 107
    .line 108
    .line 109
    move-result v15

    .line 110
    invoke-virtual {v8}, Lql0/j;->a()Lql0/h;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    move-object v9, v2

    .line 115
    check-cast v9, Lc00/n;

    .line 116
    .line 117
    const/16 v20, 0x0

    .line 118
    .line 119
    const/16 v21, 0xfbf

    .line 120
    .line 121
    const/4 v10, 0x0

    .line 122
    const/4 v11, 0x0

    .line 123
    const/4 v12, 0x0

    .line 124
    const/4 v13, 0x0

    .line 125
    const/4 v14, 0x0

    .line 126
    const/16 v16, 0x0

    .line 127
    .line 128
    const/16 v17, 0x0

    .line 129
    .line 130
    const/16 v18, 0x0

    .line 131
    .line 132
    const/16 v19, 0x0

    .line 133
    .line 134
    invoke-static/range {v9 .. v21}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {v8, v2}, Lql0/j;->g(Lql0/h;)V

    .line 139
    .line 140
    .line 141
    if-eqz v15, :cond_7

    .line 142
    .line 143
    iget-object v2, v8, Lc00/p;->v:Llb0/j;

    .line 144
    .line 145
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Lyy0/i;

    .line 150
    .line 151
    new-instance v3, Lc00/m;

    .line 152
    .line 153
    invoke-direct {v3, v8, v4}, Lc00/m;-><init>(Lc00/p;I)V

    .line 154
    .line 155
    .line 156
    iput v5, v0, Lc00/j;->e:I

    .line 157
    .line 158
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    if-ne v0, v1, :cond_7

    .line 163
    .line 164
    :goto_2
    move-object v6, v1

    .line 165
    :cond_7
    :goto_3
    return-object v6

    .line 166
    :pswitch_1
    iget-object v1, v8, Lc00/p;->h:Lkf0/e0;

    .line 167
    .line 168
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 169
    .line 170
    iget v10, v0, Lc00/j;->e:I

    .line 171
    .line 172
    if-eqz v10, :cond_a

    .line 173
    .line 174
    if-eq v10, v9, :cond_9

    .line 175
    .line 176
    if-ne v10, v5, :cond_8

    .line 177
    .line 178
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    goto :goto_8

    .line 182
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 183
    .line 184
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    throw v0

    .line 188
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    iget-object v7, v8, Lc00/p;->x:Lkf0/v;

    .line 196
    .line 197
    invoke-static {v7}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v7

    .line 201
    check-cast v7, Lyy0/i;

    .line 202
    .line 203
    sget-object v10, Lss0/e;->g:Lss0/e;

    .line 204
    .line 205
    invoke-virtual {v1, v10}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 206
    .line 207
    .line 208
    move-result-object v10

    .line 209
    new-instance v11, La90/c;

    .line 210
    .line 211
    const/16 v12, 0xc

    .line 212
    .line 213
    invoke-direct {v11, v8, v3, v12}, La90/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 214
    .line 215
    .line 216
    iput v9, v0, Lc00/j;->e:I

    .line 217
    .line 218
    new-array v12, v5, [Lyy0/i;

    .line 219
    .line 220
    aput-object v7, v12, v4

    .line 221
    .line 222
    aput-object v10, v12, v9

    .line 223
    .line 224
    new-instance v7, Lyy0/g1;

    .line 225
    .line 226
    invoke-direct {v7, v11, v3}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 227
    .line 228
    .line 229
    sget-object v9, Lyy0/h1;->d:Lyy0/h1;

    .line 230
    .line 231
    sget-object v10, Lzy0/q;->d:Lzy0/q;

    .line 232
    .line 233
    invoke-static {v9, v7, v0, v10, v12}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v7

    .line 237
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 238
    .line 239
    if-ne v7, v9, :cond_b

    .line 240
    .line 241
    goto :goto_4

    .line 242
    :cond_b
    move-object v7, v6

    .line 243
    :goto_4
    sget-object v9, Lqx0/a;->d:Lqx0/a;

    .line 244
    .line 245
    if-ne v7, v9, :cond_c

    .line 246
    .line 247
    goto :goto_5

    .line 248
    :cond_c
    move-object v7, v6

    .line 249
    :goto_5
    if-ne v7, v2, :cond_d

    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_d
    :goto_6
    sget-object v7, Lss0/e;->g:Lss0/e;

    .line 253
    .line 254
    invoke-virtual {v1, v7}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    new-instance v7, Lc00/l;

    .line 259
    .line 260
    invoke-direct {v7, v8, v3, v4}, Lc00/l;-><init>(Lc00/p;Lkotlin/coroutines/Continuation;I)V

    .line 261
    .line 262
    .line 263
    iput v5, v0, Lc00/j;->e:I

    .line 264
    .line 265
    invoke-static {v7, v0, v1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v0

    .line 269
    if-ne v0, v2, :cond_e

    .line 270
    .line 271
    :goto_7
    move-object v6, v2

    .line 272
    :cond_e
    :goto_8
    return-object v6

    .line 273
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 274
    .line 275
    iget v4, v0, Lc00/j;->e:I

    .line 276
    .line 277
    if-eqz v4, :cond_10

    .line 278
    .line 279
    if-ne v4, v9, :cond_f

    .line 280
    .line 281
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    goto :goto_a

    .line 285
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 286
    .line 287
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    throw v0

    .line 291
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    iput v9, v0, Lc00/j;->e:I

    .line 295
    .line 296
    iget-object v4, v8, Lc00/p;->u:Llb0/g;

    .line 297
    .line 298
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    move-result-object v4

    .line 302
    check-cast v4, Lyy0/i;

    .line 303
    .line 304
    new-instance v5, La90/c;

    .line 305
    .line 306
    invoke-direct {v5, v3, v8, v2}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 307
    .line 308
    .line 309
    invoke-static {v4, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    move-result-object v0

    .line 317
    if-ne v0, v1, :cond_11

    .line 318
    .line 319
    goto :goto_9

    .line 320
    :cond_11
    move-object v0, v6

    .line 321
    :goto_9
    if-ne v0, v1, :cond_12

    .line 322
    .line 323
    move-object v6, v1

    .line 324
    :cond_12
    :goto_a
    return-object v6

    .line 325
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 326
    .line 327
    iget v2, v0, Lc00/j;->e:I

    .line 328
    .line 329
    if-eqz v2, :cond_14

    .line 330
    .line 331
    if-ne v2, v9, :cond_13

    .line 332
    .line 333
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 334
    .line 335
    .line 336
    goto :goto_b

    .line 337
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw v0

    .line 343
    :cond_14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    iput v9, v0, Lc00/j;->e:I

    .line 347
    .line 348
    invoke-static {v8, v0}, Lc00/p;->h(Lc00/p;Lrx0/i;)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    if-ne v0, v1, :cond_15

    .line 353
    .line 354
    move-object v6, v1

    .line 355
    :cond_15
    :goto_b
    return-object v6

    .line 356
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 357
    .line 358
    iget v4, v0, Lc00/j;->e:I

    .line 359
    .line 360
    if-eqz v4, :cond_17

    .line 361
    .line 362
    if-ne v4, v9, :cond_16

    .line 363
    .line 364
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 365
    .line 366
    .line 367
    goto :goto_d

    .line 368
    :cond_16
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 369
    .line 370
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    throw v0

    .line 374
    :cond_17
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 375
    .line 376
    .line 377
    iput v9, v0, Lc00/j;->e:I

    .line 378
    .line 379
    iget-object v4, v8, Lc00/p;->u:Llb0/g;

    .line 380
    .line 381
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v4

    .line 385
    check-cast v4, Lyy0/i;

    .line 386
    .line 387
    new-instance v5, La90/c;

    .line 388
    .line 389
    invoke-direct {v5, v3, v8, v2}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 390
    .line 391
    .line 392
    invoke-static {v4, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 393
    .line 394
    .line 395
    move-result-object v2

    .line 396
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object v0

    .line 400
    if-ne v0, v1, :cond_18

    .line 401
    .line 402
    goto :goto_c

    .line 403
    :cond_18
    move-object v0, v6

    .line 404
    :goto_c
    if-ne v0, v1, :cond_19

    .line 405
    .line 406
    move-object v6, v1

    .line 407
    :cond_19
    :goto_d
    return-object v6

    .line 408
    :pswitch_5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 409
    .line 410
    iget v2, v0, Lc00/j;->e:I

    .line 411
    .line 412
    if-eqz v2, :cond_1b

    .line 413
    .line 414
    if-ne v2, v9, :cond_1a

    .line 415
    .line 416
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 417
    .line 418
    .line 419
    goto :goto_e

    .line 420
    :cond_1a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 421
    .line 422
    invoke-direct {v0, v7}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    throw v0

    .line 426
    :cond_1b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 427
    .line 428
    .line 429
    iput v9, v0, Lc00/j;->e:I

    .line 430
    .line 431
    invoke-static {v8, v0}, Lc00/p;->h(Lc00/p;Lrx0/i;)Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v0

    .line 435
    if-ne v0, v1, :cond_1c

    .line 436
    .line 437
    move-object v6, v1

    .line 438
    :cond_1c
    :goto_e
    return-object v6

    .line 439
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
