.class public final Ln90/n;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ln90/q;


# direct methods
.method public synthetic constructor <init>(Ln90/q;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln90/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln90/n;->f:Ln90/q;

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
    iget p1, p0, Ln90/n;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ln90/n;

    .line 7
    .line 8
    iget-object p0, p0, Ln90/n;->f:Ln90/q;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ln90/n;-><init>(Ln90/q;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ln90/n;

    .line 16
    .line 17
    iget-object p0, p0, Ln90/n;->f:Ln90/q;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ln90/n;-><init>(Ln90/q;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ln90/n;

    .line 25
    .line 26
    iget-object p0, p0, Ln90/n;->f:Ln90/q;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ln90/n;-><init>(Ln90/q;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ln90/n;->d:I

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
    invoke-virtual {p0, p1, p2}, Ln90/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ln90/n;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ln90/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ln90/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ln90/n;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln90/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ln90/n;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ln90/n;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ln90/n;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ln90/n;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Ln90/n;->e:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    iget-object v6, v0, Ln90/n;->f:Ln90/q;

    .line 17
    .line 18
    if-eqz v2, :cond_2

    .line 19
    .line 20
    if-eq v2, v5, :cond_1

    .line 21
    .line 22
    if-ne v2, v4, :cond_0

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    move-object/from16 v2, p1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object v2, v6, Ln90/q;->p:Lk90/h;

    .line 46
    .line 47
    iput v5, v0, Ln90/n;->e:I

    .line 48
    .line 49
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2, v0}, Lk90/h;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    if-ne v2, v1, :cond_3

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    :goto_0
    check-cast v2, Ljava/lang/Boolean;

    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-nez v2, :cond_5

    .line 66
    .line 67
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    move-object v7, v2

    .line 72
    check-cast v7, Ln90/p;

    .line 73
    .line 74
    const/16 v23, 0x0

    .line 75
    .line 76
    const v24, 0x9fff

    .line 77
    .line 78
    .line 79
    const/4 v8, 0x0

    .line 80
    const/4 v9, 0x0

    .line 81
    const/4 v10, 0x0

    .line 82
    const/4 v11, 0x0

    .line 83
    const/4 v12, 0x0

    .line 84
    const/4 v13, 0x0

    .line 85
    const/4 v14, 0x0

    .line 86
    const/4 v15, 0x0

    .line 87
    const/16 v16, 0x0

    .line 88
    .line 89
    const/16 v17, 0x0

    .line 90
    .line 91
    const/16 v18, 0x0

    .line 92
    .line 93
    const/16 v19, 0x0

    .line 94
    .line 95
    const/16 v20, 0x0

    .line 96
    .line 97
    const/16 v21, 0x1

    .line 98
    .line 99
    const/16 v22, 0x1

    .line 100
    .line 101
    invoke-static/range {v7 .. v24}, Ln90/p;->a(Ln90/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZIZZLql0/g;I)Ln90/p;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    invoke-virtual {v6, v2}, Lql0/j;->g(Lql0/h;)V

    .line 106
    .line 107
    .line 108
    iput v4, v0, Ln90/n;->e:I

    .line 109
    .line 110
    const-wide/16 v4, 0xbb8

    .line 111
    .line 112
    invoke-static {v4, v5, v0}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    if-ne v0, v1, :cond_4

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_4
    :goto_1
    invoke-virtual {v6}, Ln90/q;->h()V

    .line 120
    .line 121
    .line 122
    :cond_5
    move-object v1, v3

    .line 123
    :goto_2
    return-object v1

    .line 124
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 125
    .line 126
    iget v2, v0, Ln90/n;->e:I

    .line 127
    .line 128
    const/4 v3, 0x1

    .line 129
    if-eqz v2, :cond_7

    .line 130
    .line 131
    if-ne v2, v3, :cond_6

    .line 132
    .line 133
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 138
    .line 139
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 140
    .line 141
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw v0

    .line 145
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iget-object v2, v0, Ln90/n;->f:Ln90/q;

    .line 149
    .line 150
    iget-object v4, v2, Ln90/q;->o:Lrq0/f;

    .line 151
    .line 152
    new-instance v5, Lsq0/c;

    .line 153
    .line 154
    iget-object v2, v2, Ln90/q;->k:Lij0/a;

    .line 155
    .line 156
    const/4 v6, 0x0

    .line 157
    new-array v7, v6, [Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v2, Ljj0/f;

    .line 160
    .line 161
    const v8, 0x7f12019c

    .line 162
    .line 163
    .line 164
    invoke-virtual {v2, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v2

    .line 168
    const/4 v7, 0x6

    .line 169
    const/4 v8, 0x0

    .line 170
    invoke-direct {v5, v7, v2, v8, v8}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    iput v3, v0, Ln90/n;->e:I

    .line 174
    .line 175
    invoke-virtual {v4, v5, v6, v0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    if-ne v0, v1, :cond_8

    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_8
    :goto_3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 183
    .line 184
    :goto_4
    return-object v1

    .line 185
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 186
    .line 187
    iget v2, v0, Ln90/n;->e:I

    .line 188
    .line 189
    const/4 v3, 0x1

    .line 190
    if-eqz v2, :cond_a

    .line 191
    .line 192
    if-ne v2, v3, :cond_9

    .line 193
    .line 194
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    goto :goto_5

    .line 198
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 199
    .line 200
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 201
    .line 202
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    throw v0

    .line 206
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    iget-object v2, v0, Ln90/n;->f:Ln90/q;

    .line 210
    .line 211
    iget-object v4, v2, Ln90/q;->i:Lgn0/i;

    .line 212
    .line 213
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    check-cast v4, Lyy0/i;

    .line 218
    .line 219
    new-instance v5, Lma0/c;

    .line 220
    .line 221
    const/4 v6, 0x7

    .line 222
    invoke-direct {v5, v2, v6}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    iput v3, v0, Ln90/n;->e:I

    .line 226
    .line 227
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    if-ne v0, v1, :cond_b

    .line 232
    .line 233
    goto :goto_6

    .line 234
    :cond_b
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    :goto_6
    return-object v1

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
