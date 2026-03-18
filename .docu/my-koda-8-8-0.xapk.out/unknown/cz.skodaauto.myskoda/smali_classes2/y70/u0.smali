.class public final Ly70/u0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ly70/j1;


# direct methods
.method public synthetic constructor <init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ly70/u0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/u0;->f:Ly70/j1;

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
    iget p1, p0, Ly70/u0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ly70/u0;

    .line 7
    .line 8
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 9
    .line 10
    const/4 v0, 0x5

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ly70/u0;

    .line 16
    .line 17
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ly70/u0;

    .line 25
    .line 26
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 27
    .line 28
    const/4 v0, 0x3

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ly70/u0;

    .line 34
    .line 35
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 36
    .line 37
    const/4 v0, 0x2

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ly70/u0;

    .line 43
    .line 44
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Ly70/u0;

    .line 52
    .line 53
    iget-object p0, p0, Ly70/u0;->f:Ly70/j1;

    .line 54
    .line 55
    const/4 v0, 0x0

    .line 56
    invoke-direct {p1, p0, p2, v0}, Ly70/u0;-><init>(Ly70/j1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ly70/u0;->d:I

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
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ly70/u0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ly70/u0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ly70/u0;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ly70/u0;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ly70/u0;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Ly70/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Ly70/u0;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Ly70/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ly70/u0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Ly70/u0;->e:I

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
    iget-object v2, v0, Ly70/u0;->f:Ly70/j1;

    .line 33
    .line 34
    iget-object v4, v2, Ly70/j1;->k:Lbq0/c;

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
    invoke-static {v4}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    new-instance v5, Ly70/v0;

    .line 47
    .line 48
    const/4 v6, 0x4

    .line 49
    invoke-direct {v5, v2, v6}, Ly70/v0;-><init>(Ly70/j1;I)V

    .line 50
    .line 51
    .line 52
    iput v3, v0, Ly70/u0;->e:I

    .line 53
    .line 54
    invoke-virtual {v4, v5, v0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    if-ne v0, v1, :cond_2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    :goto_1
    return-object v1

    .line 64
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 65
    .line 66
    iget v2, v0, Ly70/u0;->e:I

    .line 67
    .line 68
    iget-object v3, v0, Ly70/u0;->f:Ly70/j1;

    .line 69
    .line 70
    const/4 v4, 0x2

    .line 71
    const/4 v5, 0x1

    .line 72
    if-eqz v2, :cond_5

    .line 73
    .line 74
    if-eq v2, v5, :cond_4

    .line 75
    .line 76
    if-ne v2, v4, :cond_3

    .line 77
    .line 78
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 83
    .line 84
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 85
    .line 86
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw v0

    .line 90
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    move-object/from16 v2, p1

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object v2, v3, Ly70/j1;->E:Lcb0/d;

    .line 100
    .line 101
    sget-object v6, Ldb0/a;->e:Ldb0/a;

    .line 102
    .line 103
    iput v5, v0, Ly70/u0;->e:I

    .line 104
    .line 105
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    new-instance v5, Lcb0/c;

    .line 109
    .line 110
    const/4 v7, 0x0

    .line 111
    invoke-direct {v5, v2, v6, v7}, Lcb0/c;-><init>(Lcb0/d;Ldb0/a;Lkotlin/coroutines/Continuation;)V

    .line 112
    .line 113
    .line 114
    new-instance v2, Lyy0/m1;

    .line 115
    .line 116
    invoke-direct {v2, v5}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 117
    .line 118
    .line 119
    if-ne v2, v1, :cond_6

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_6
    :goto_2
    check-cast v2, Lyy0/i;

    .line 123
    .line 124
    new-instance v5, Ly70/v0;

    .line 125
    .line 126
    const/4 v6, 0x3

    .line 127
    invoke-direct {v5, v3, v6}, Ly70/v0;-><init>(Ly70/j1;I)V

    .line 128
    .line 129
    .line 130
    iput v4, v0, Ly70/u0;->e:I

    .line 131
    .line 132
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    if-ne v0, v1, :cond_7

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_7
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    :goto_4
    return-object v1

    .line 142
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 143
    .line 144
    iget v2, v0, Ly70/u0;->e:I

    .line 145
    .line 146
    iget-object v3, v0, Ly70/u0;->f:Ly70/j1;

    .line 147
    .line 148
    const/4 v4, 0x2

    .line 149
    const/4 v5, 0x1

    .line 150
    if-eqz v2, :cond_a

    .line 151
    .line 152
    if-eq v2, v5, :cond_9

    .line 153
    .line 154
    if-ne v2, v4, :cond_8

    .line 155
    .line 156
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    goto :goto_6

    .line 160
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 161
    .line 162
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 163
    .line 164
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    move-object/from16 v2, p1

    .line 172
    .line 173
    goto :goto_5

    .line 174
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    iget-object v2, v3, Ly70/j1;->I:Lw70/v0;

    .line 178
    .line 179
    iput v5, v0, Ly70/u0;->e:I

    .line 180
    .line 181
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 182
    .line 183
    .line 184
    iget-object v2, v2, Lw70/v0;->a:Lu70/a;

    .line 185
    .line 186
    iget-object v2, v2, Lu70/a;->c:Lyy0/c2;

    .line 187
    .line 188
    if-ne v2, v1, :cond_b

    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_b
    :goto_5
    check-cast v2, Lyy0/i;

    .line 192
    .line 193
    new-instance v5, Ly70/v0;

    .line 194
    .line 195
    const/4 v6, 0x2

    .line 196
    invoke-direct {v5, v3, v6}, Ly70/v0;-><init>(Ly70/j1;I)V

    .line 197
    .line 198
    .line 199
    iput v4, v0, Ly70/u0;->e:I

    .line 200
    .line 201
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v0

    .line 205
    if-ne v0, v1, :cond_c

    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_c
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    :goto_7
    return-object v1

    .line 211
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 212
    .line 213
    iget v2, v0, Ly70/u0;->e:I

    .line 214
    .line 215
    const/4 v3, 0x1

    .line 216
    if-eqz v2, :cond_e

    .line 217
    .line 218
    if-ne v2, v3, :cond_d

    .line 219
    .line 220
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    goto :goto_8

    .line 224
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 225
    .line 226
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 227
    .line 228
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    throw v0

    .line 232
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    iget-object v2, v0, Ly70/u0;->f:Ly70/j1;

    .line 236
    .line 237
    iget-object v4, v2, Ly70/j1;->s:Lwr0/i;

    .line 238
    .line 239
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v4

    .line 243
    check-cast v4, Lyy0/i;

    .line 244
    .line 245
    new-instance v5, Ly70/v0;

    .line 246
    .line 247
    const/4 v6, 0x1

    .line 248
    invoke-direct {v5, v2, v6}, Ly70/v0;-><init>(Ly70/j1;I)V

    .line 249
    .line 250
    .line 251
    iput v3, v0, Ly70/u0;->e:I

    .line 252
    .line 253
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    if-ne v0, v1, :cond_f

    .line 258
    .line 259
    goto :goto_9

    .line 260
    :cond_f
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 261
    .line 262
    :goto_9
    return-object v1

    .line 263
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 264
    .line 265
    iget v2, v0, Ly70/u0;->e:I

    .line 266
    .line 267
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    iget-object v4, v0, Ly70/u0;->f:Ly70/j1;

    .line 270
    .line 271
    const/4 v5, 0x2

    .line 272
    const/4 v6, 0x1

    .line 273
    if-eqz v2, :cond_13

    .line 274
    .line 275
    if-eq v2, v6, :cond_12

    .line 276
    .line 277
    if-ne v2, v5, :cond_11

    .line 278
    .line 279
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    :cond_10
    move-object v1, v3

    .line 283
    goto :goto_b

    .line 284
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 285
    .line 286
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 287
    .line 288
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    throw v0

    .line 292
    :cond_12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 293
    .line 294
    .line 295
    move-object/from16 v2, p1

    .line 296
    .line 297
    goto :goto_a

    .line 298
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    iget-object v2, v4, Ly70/j1;->r:Lbq0/o;

    .line 302
    .line 303
    iput v6, v0, Ly70/u0;->e:I

    .line 304
    .line 305
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 306
    .line 307
    .line 308
    invoke-virtual {v2, v0}, Lbq0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v2

    .line 312
    if-ne v2, v1, :cond_14

    .line 313
    .line 314
    goto :goto_b

    .line 315
    :cond_14
    :goto_a
    check-cast v2, Lyy0/i;

    .line 316
    .line 317
    new-instance v6, Ly70/v0;

    .line 318
    .line 319
    const/4 v7, 0x0

    .line 320
    invoke-direct {v6, v4, v7}, Ly70/v0;-><init>(Ly70/j1;I)V

    .line 321
    .line 322
    .line 323
    iput v5, v0, Ly70/u0;->e:I

    .line 324
    .line 325
    invoke-interface {v2, v6, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    if-ne v0, v1, :cond_10

    .line 330
    .line 331
    :goto_b
    return-object v1

    .line 332
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 333
    .line 334
    iget v2, v0, Ly70/u0;->e:I

    .line 335
    .line 336
    iget-object v3, v0, Ly70/u0;->f:Ly70/j1;

    .line 337
    .line 338
    const/4 v4, 0x1

    .line 339
    if-eqz v2, :cond_16

    .line 340
    .line 341
    if-ne v2, v4, :cond_15

    .line 342
    .line 343
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 344
    .line 345
    .line 346
    move-object/from16 v0, p1

    .line 347
    .line 348
    goto :goto_c

    .line 349
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 350
    .line 351
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 352
    .line 353
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    throw v0

    .line 357
    :cond_16
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 358
    .line 359
    .line 360
    iget-object v2, v3, Ly70/j1;->v:Lkf0/k;

    .line 361
    .line 362
    iput v4, v0, Ly70/u0;->e:I

    .line 363
    .line 364
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 365
    .line 366
    .line 367
    invoke-virtual {v2, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object v0

    .line 371
    if-ne v0, v1, :cond_17

    .line 372
    .line 373
    goto :goto_d

    .line 374
    :cond_17
    :goto_c
    check-cast v0, Lss0/b;

    .line 375
    .line 376
    sget-object v1, Lss0/e;->e:Lss0/e;

    .line 377
    .line 378
    invoke-static {v0, v1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 379
    .line 380
    .line 381
    move-result v27

    .line 382
    sget-object v1, Lss0/e;->E1:Lss0/e;

    .line 383
    .line 384
    invoke-static {v0, v1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 385
    .line 386
    .line 387
    move-result v28

    .line 388
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    move-object v4, v0

    .line 393
    check-cast v4, Ly70/a1;

    .line 394
    .line 395
    const/16 v30, 0x0

    .line 396
    .line 397
    const v31, 0x67fffff

    .line 398
    .line 399
    .line 400
    const/4 v5, 0x0

    .line 401
    const/4 v6, 0x0

    .line 402
    const/4 v7, 0x0

    .line 403
    const/4 v8, 0x0

    .line 404
    const/4 v9, 0x0

    .line 405
    const/4 v10, 0x0

    .line 406
    const/4 v11, 0x0

    .line 407
    const/4 v12, 0x0

    .line 408
    const/4 v13, 0x0

    .line 409
    const/4 v14, 0x0

    .line 410
    const/4 v15, 0x0

    .line 411
    const/16 v16, 0x0

    .line 412
    .line 413
    const/16 v17, 0x0

    .line 414
    .line 415
    const/16 v18, 0x0

    .line 416
    .line 417
    const/16 v19, 0x0

    .line 418
    .line 419
    const/16 v20, 0x0

    .line 420
    .line 421
    const/16 v21, 0x0

    .line 422
    .line 423
    const/16 v22, 0x0

    .line 424
    .line 425
    const/16 v23, 0x0

    .line 426
    .line 427
    const/16 v24, 0x0

    .line 428
    .line 429
    const/16 v25, 0x0

    .line 430
    .line 431
    const/16 v26, 0x0

    .line 432
    .line 433
    const/16 v29, 0x0

    .line 434
    .line 435
    invoke-static/range {v4 .. v31}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 440
    .line 441
    .line 442
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 443
    .line 444
    :goto_d
    return-object v1

    .line 445
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
