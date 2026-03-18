.class public final Lc70/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc70/i;


# direct methods
.method public synthetic constructor <init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc70/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc70/f;->f:Lc70/i;

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
    iget p1, p0, Lc70/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc70/f;

    .line 7
    .line 8
    iget-object p0, p0, Lc70/f;->f:Lc70/i;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc70/f;

    .line 16
    .line 17
    iget-object p0, p0, Lc70/f;->f:Lc70/i;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc70/f;

    .line 25
    .line 26
    iget-object p0, p0, Lc70/f;->f:Lc70/i;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lc70/f;

    .line 34
    .line 35
    iget-object p0, p0, Lc70/f;->f:Lc70/i;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lc70/f;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lc70/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc70/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc70/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc70/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc70/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc70/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc70/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc70/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc70/f;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc70/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lc70/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lc70/f;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lc70/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc70/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lc70/f;->e:I

    .line 11
    .line 12
    iget-object v3, v0, Lc70/f;->f:Lc70/i;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v4, :cond_0

    .line 18
    .line 19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw v0

    .line 31
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object v2, v3, Lc70/i;->p:Ltn0/b;

    .line 35
    .line 36
    sget-object v5, Lun0/a;->e:Lun0/a;

    .line 37
    .line 38
    iput v4, v0, Lc70/f;->e:I

    .line 39
    .line 40
    invoke-virtual {v2, v5, v0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    if-ne v0, v1, :cond_2

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_2
    :goto_0
    iget-object v0, v3, Lc70/i;->n:La70/c;

    .line 48
    .line 49
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v1, Lc70/h;

    .line 54
    .line 55
    iget-object v1, v1, Lc70/h;->g:Lb70/c;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, La70/c;->a(Lb70/c;)V

    .line 58
    .line 59
    .line 60
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    :goto_1
    return-object v1

    .line 63
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    iget v2, v0, Lc70/f;->e:I

    .line 66
    .line 67
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    if-eqz v2, :cond_5

    .line 71
    .line 72
    if-ne v2, v4, :cond_4

    .line 73
    .line 74
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    :cond_3
    move-object v1, v3

    .line 78
    goto :goto_3

    .line 79
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 80
    .line 81
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 82
    .line 83
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0

    .line 87
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    iput v4, v0, Lc70/f;->e:I

    .line 91
    .line 92
    iget-object v2, v0, Lc70/f;->f:Lc70/i;

    .line 93
    .line 94
    iget-object v4, v2, Lc70/i;->r:Lep0/e;

    .line 95
    .line 96
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    check-cast v4, Lyy0/i;

    .line 101
    .line 102
    new-instance v5, Lc70/g;

    .line 103
    .line 104
    const/4 v6, 0x0

    .line 105
    const/4 v7, 0x2

    .line 106
    invoke-direct {v5, v2, v6, v7}, Lc70/g;-><init>(Lc70/i;Lkotlin/coroutines/Continuation;I)V

    .line 107
    .line 108
    .line 109
    invoke-static {v5, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    if-ne v0, v1, :cond_6

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_6
    move-object v0, v3

    .line 117
    :goto_2
    if-ne v0, v1, :cond_3

    .line 118
    .line 119
    :goto_3
    return-object v1

    .line 120
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 121
    .line 122
    iget v2, v0, Lc70/f;->e:I

    .line 123
    .line 124
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    const/4 v4, 0x1

    .line 127
    if-eqz v2, :cond_9

    .line 128
    .line 129
    if-ne v2, v4, :cond_8

    .line 130
    .line 131
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    :cond_7
    move-object v1, v3

    .line 135
    goto :goto_5

    .line 136
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 137
    .line 138
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 139
    .line 140
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw v0

    .line 144
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    iput v4, v0, Lc70/f;->e:I

    .line 148
    .line 149
    iget-object v2, v0, Lc70/f;->f:Lc70/i;

    .line 150
    .line 151
    iget-object v4, v2, Lc70/i;->h:Lep0/g;

    .line 152
    .line 153
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    check-cast v4, Lyy0/i;

    .line 158
    .line 159
    new-instance v5, Lac0/e;

    .line 160
    .line 161
    const/16 v6, 0x9

    .line 162
    .line 163
    invoke-direct {v5, v2, v6}, Lac0/e;-><init>(Ljava/lang/Object;I)V

    .line 164
    .line 165
    .line 166
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    if-ne v0, v1, :cond_a

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_a
    move-object v0, v3

    .line 174
    :goto_4
    if-ne v0, v1, :cond_7

    .line 175
    .line 176
    :goto_5
    return-object v1

    .line 177
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    iget v2, v0, Lc70/f;->e:I

    .line 180
    .line 181
    iget-object v3, v0, Lc70/f;->f:Lc70/i;

    .line 182
    .line 183
    const/4 v4, 0x1

    .line 184
    if-eqz v2, :cond_c

    .line 185
    .line 186
    if-ne v2, v4, :cond_b

    .line 187
    .line 188
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object/from16 v0, p1

    .line 192
    .line 193
    goto :goto_6

    .line 194
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 195
    .line 196
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 197
    .line 198
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    throw v0

    .line 202
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    iget-object v2, v3, Lc70/i;->k:Lcs0/l;

    .line 206
    .line 207
    iput v4, v0, Lc70/f;->e:I

    .line 208
    .line 209
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    invoke-virtual {v2, v0}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    if-ne v0, v1, :cond_d

    .line 217
    .line 218
    goto :goto_7

    .line 219
    :cond_d
    :goto_6
    move-object v12, v0

    .line 220
    check-cast v12, Lqr0/s;

    .line 221
    .line 222
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    move-object v4, v0

    .line 227
    check-cast v4, Lc70/h;

    .line 228
    .line 229
    const/4 v14, 0x0

    .line 230
    const/16 v15, 0x6ff

    .line 231
    .line 232
    const/4 v5, 0x0

    .line 233
    const/4 v6, 0x0

    .line 234
    const/4 v7, 0x0

    .line 235
    const/4 v8, 0x0

    .line 236
    const/4 v9, 0x0

    .line 237
    const/4 v10, 0x0

    .line 238
    const/4 v11, 0x0

    .line 239
    const/4 v13, 0x0

    .line 240
    invoke-static/range {v4 .. v15}, Lc70/h;->a(Lc70/h;Ler0/g;Llf0/i;ZLjava/lang/String;Ljava/lang/Integer;Lb70/c;Llp/mb;Lqr0/s;ZLjava/time/OffsetDateTime;I)Lc70/h;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 245
    .line 246
    .line 247
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 248
    .line 249
    :goto_7
    return-object v1

    .line 250
    nop

    .line 251
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
