.class public final Lb1/c1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:J

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(JLay0/n;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lb1/c1;->d:I

    .line 1
    iput-wide p1, p0, Lb1/c1;->f:J

    check-cast p3, Lrx0/i;

    iput-object p3, p0, Lb1/c1;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lb1/b1;JLb1/e1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lb1/c1;->d:I

    .line 2
    iput-object p1, p0, Lb1/c1;->g:Ljava/lang/Object;

    iput-wide p2, p0, Lb1/c1;->f:J

    iput-object p4, p0, Lb1/c1;->h:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 3
    iput p5, p0, Lb1/c1;->d:I

    iput-object p1, p0, Lb1/c1;->h:Ljava/lang/Object;

    iput-wide p2, p0, Lb1/c1;->f:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 11

    .line 1
    iget v0, p0, Lb1/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb1/c1;

    .line 7
    .line 8
    iget-object v1, p0, Lb1/c1;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lrx0/i;

    .line 11
    .line 12
    iget-wide v2, p0, Lb1/c1;->f:J

    .line 13
    .line 14
    invoke-direct {v0, v2, v3, v1, p2}, Lb1/c1;-><init>(JLay0/n;Lkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v0, Lb1/c1;->g:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    new-instance v4, Lb1/c1;

    .line 21
    .line 22
    iget-object v0, p0, Lb1/c1;->h:Ljava/lang/Object;

    .line 23
    .line 24
    move-object v5, v0

    .line 25
    check-cast v5, Lny/f0;

    .line 26
    .line 27
    iget-wide v6, p0, Lb1/c1;->f:J

    .line 28
    .line 29
    const/4 v9, 0x2

    .line 30
    move-object v8, p2

    .line 31
    invoke-direct/range {v4 .. v9}, Lb1/c1;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    iput-object p1, v4, Lb1/c1;->g:Ljava/lang/Object;

    .line 35
    .line 36
    return-object v4

    .line 37
    :pswitch_1
    move-object v8, p2

    .line 38
    new-instance v5, Lb1/c1;

    .line 39
    .line 40
    iget-object p2, p0, Lb1/c1;->h:Ljava/lang/Object;

    .line 41
    .line 42
    move-object v6, p2

    .line 43
    check-cast v6, Lbo0/k;

    .line 44
    .line 45
    move-object v9, v8

    .line 46
    iget-wide v7, p0, Lb1/c1;->f:J

    .line 47
    .line 48
    const/4 v10, 0x1

    .line 49
    invoke-direct/range {v5 .. v10}, Lb1/c1;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    iput-object p1, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 53
    .line 54
    return-object v5

    .line 55
    :pswitch_2
    move-object v8, p2

    .line 56
    new-instance v5, Lb1/c1;

    .line 57
    .line 58
    iget-object p1, p0, Lb1/c1;->g:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v6, p1

    .line 61
    check-cast v6, Lb1/b1;

    .line 62
    .line 63
    iget-object p1, p0, Lb1/c1;->h:Ljava/lang/Object;

    .line 64
    .line 65
    move-object v9, p1

    .line 66
    check-cast v9, Lb1/e1;

    .line 67
    .line 68
    iget-wide p0, p0, Lb1/c1;->f:J

    .line 69
    .line 70
    move-object v10, v8

    .line 71
    move-wide v7, p0

    .line 72
    invoke-direct/range {v5 .. v10}, Lb1/c1;-><init>(Lb1/b1;JLb1/e1;Lkotlin/coroutines/Continuation;)V

    .line 73
    .line 74
    .line 75
    return-object v5

    .line 76
    nop

    .line 77
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
    iget v0, p0, Lb1/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lb1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lb1/c1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lb1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lyy0/j;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lb1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lb1/c1;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lb1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lb1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lb1/c1;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lb1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lb1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lb1/c1;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lb1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, Lb1/c1;->d:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x2

    .line 7
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    iget-object v3, v5, Lb1/c1;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iget-wide v8, v5, Lb1/c1;->f:J

    .line 12
    .line 13
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 14
    .line 15
    const/4 v6, 0x1

    .line 16
    packed-switch v0, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    iget-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lvy0/b0;

    .line 22
    .line 23
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    iget v11, v5, Lb1/c1;->e:I

    .line 26
    .line 27
    if-eqz v11, :cond_2

    .line 28
    .line 29
    if-eq v11, v6, :cond_1

    .line 30
    .line 31
    if-ne v11, v2, :cond_0

    .line 32
    .line 33
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw v0

    .line 43
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    iput-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 51
    .line 52
    iput v6, v5, Lb1/c1;->e:I

    .line 53
    .line 54
    invoke-static {v8, v9, v5}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    if-ne v4, v10, :cond_3

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    :goto_0
    check-cast v3, Lrx0/i;

    .line 62
    .line 63
    iput-object v1, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 64
    .line 65
    iput v2, v5, Lb1/c1;->e:I

    .line 66
    .line 67
    invoke-interface {v3, v0, v5}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    if-ne v0, v10, :cond_4

    .line 72
    .line 73
    :goto_1
    move-object v7, v10

    .line 74
    :cond_4
    :goto_2
    return-object v7

    .line 75
    :pswitch_0
    iget-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v0, Lyy0/j;

    .line 78
    .line 79
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 80
    .line 81
    iget v10, v5, Lb1/c1;->e:I

    .line 82
    .line 83
    const/4 v11, 0x3

    .line 84
    if-eqz v10, :cond_7

    .line 85
    .line 86
    if-eq v10, v6, :cond_7

    .line 87
    .line 88
    if-eq v10, v2, :cond_6

    .line 89
    .line 90
    if-ne v10, v11, :cond_5

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw v0

    .line 99
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_7
    :goto_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :cond_8
    invoke-interface {v5}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    invoke-static {v4}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    if-eqz v4, :cond_a

    .line 115
    .line 116
    move-object v4, v3

    .line 117
    check-cast v4, Lny/f0;

    .line 118
    .line 119
    iput-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 120
    .line 121
    iput v2, v5, Lb1/c1;->e:I

    .line 122
    .line 123
    invoke-virtual {v4, v0, v5}, Lny/f0;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v4

    .line 127
    if-ne v4, v1, :cond_9

    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_9
    :goto_4
    iput-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 131
    .line 132
    iput v11, v5, Lb1/c1;->e:I

    .line 133
    .line 134
    invoke-static {v8, v9, v5}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    if-ne v4, v1, :cond_8

    .line 139
    .line 140
    :goto_5
    move-object v7, v1

    .line 141
    :cond_a
    return-object v7

    .line 142
    :pswitch_1
    check-cast v3, Lbo0/k;

    .line 143
    .line 144
    iget-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v0, Lvy0/b0;

    .line 147
    .line 148
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 149
    .line 150
    iget v10, v5, Lb1/c1;->e:I

    .line 151
    .line 152
    if-eqz v10, :cond_c

    .line 153
    .line 154
    if-ne v10, v6, :cond_b

    .line 155
    .line 156
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    move-object/from16 v0, p1

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 163
    .line 164
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw v0

    .line 168
    :cond_c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    new-instance v4, Lbo0/j;

    .line 172
    .line 173
    const/4 v10, 0x0

    .line 174
    invoke-direct {v4, v8, v9, v10}, Lbo0/j;-><init>(JI)V

    .line 175
    .line 176
    .line 177
    invoke-static {v0, v4}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 178
    .line 179
    .line 180
    iget-object v0, v3, Lbo0/k;->i:Lyn0/r;

    .line 181
    .line 182
    iget-object v4, v3, Lbo0/k;->o:Ljava/util/List;

    .line 183
    .line 184
    check-cast v4, Ljava/lang/Iterable;

    .line 185
    .line 186
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 187
    .line 188
    .line 189
    move-result-object v4

    .line 190
    :cond_d
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    const-string v11, "Collection contains no element matching the predicate."

    .line 195
    .line 196
    if-eqz v10, :cond_14

    .line 197
    .line 198
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v10

    .line 202
    move-object v13, v10

    .line 203
    check-cast v13, Lao0/c;

    .line 204
    .line 205
    iget-wide v14, v13, Lao0/c;->a:J

    .line 206
    .line 207
    cmp-long v10, v14, v8

    .line 208
    .line 209
    if-nez v10, :cond_d

    .line 210
    .line 211
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    check-cast v4, Lbo0/i;

    .line 216
    .line 217
    iget-object v4, v4, Lbo0/i;->a:Ljava/util/List;

    .line 218
    .line 219
    check-cast v4, Ljava/lang/Iterable;

    .line 220
    .line 221
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 222
    .line 223
    .line 224
    move-result-object v4

    .line 225
    :cond_e
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 226
    .line 227
    .line 228
    move-result v10

    .line 229
    if-eqz v10, :cond_13

    .line 230
    .line 231
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v10

    .line 235
    check-cast v10, Lbo0/h;

    .line 236
    .line 237
    iget-wide v14, v10, Lbo0/h;->a:J

    .line 238
    .line 239
    cmp-long v12, v14, v8

    .line 240
    .line 241
    if-nez v12, :cond_e

    .line 242
    .line 243
    iget-object v14, v10, Lbo0/h;->b:Ljava/lang/String;

    .line 244
    .line 245
    new-instance v12, Lao0/e;

    .line 246
    .line 247
    const/4 v15, 0x0

    .line 248
    const/16 v16, 0x0

    .line 249
    .line 250
    const/16 v17, 0x20

    .line 251
    .line 252
    invoke-direct/range {v12 .. v17}, Lao0/e;-><init>(Lao0/c;Ljava/lang/String;ZZI)V

    .line 253
    .line 254
    .line 255
    iput-object v1, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 256
    .line 257
    iput v6, v5, Lb1/c1;->e:I

    .line 258
    .line 259
    invoke-virtual {v0, v12, v5}, Lyn0/r;->b(Lao0/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    if-ne v0, v2, :cond_f

    .line 264
    .line 265
    move-object v7, v2

    .line 266
    goto :goto_8

    .line 267
    :cond_f
    :goto_6
    check-cast v0, Lao0/c;

    .line 268
    .line 269
    if-eqz v0, :cond_12

    .line 270
    .line 271
    iget-object v1, v3, Lbo0/k;->o:Ljava/util/List;

    .line 272
    .line 273
    check-cast v1, Ljava/lang/Iterable;

    .line 274
    .line 275
    new-instance v2, Ljava/util/ArrayList;

    .line 276
    .line 277
    const/16 v4, 0xa

    .line 278
    .line 279
    invoke-static {v1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 280
    .line 281
    .line 282
    move-result v4

    .line 283
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 284
    .line 285
    .line 286
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 287
    .line 288
    .line 289
    move-result-object v1

    .line 290
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 291
    .line 292
    .line 293
    move-result v4

    .line 294
    if-eqz v4, :cond_11

    .line 295
    .line 296
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v4

    .line 300
    check-cast v4, Lao0/c;

    .line 301
    .line 302
    iget-wide v5, v4, Lao0/c;->a:J

    .line 303
    .line 304
    cmp-long v5, v5, v8

    .line 305
    .line 306
    if-nez v5, :cond_10

    .line 307
    .line 308
    move-object v4, v0

    .line 309
    :cond_10
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 310
    .line 311
    .line 312
    goto :goto_7

    .line 313
    :cond_11
    iput-object v2, v3, Lbo0/k;->o:Ljava/util/List;

    .line 314
    .line 315
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    check-cast v0, Lbo0/i;

    .line 320
    .line 321
    iget-object v1, v3, Lbo0/k;->n:Ljava/util/List;

    .line 322
    .line 323
    iget-object v2, v3, Lbo0/k;->o:Ljava/util/List;

    .line 324
    .line 325
    iget-object v4, v3, Lbo0/k;->l:Lij0/a;

    .line 326
    .line 327
    iget-boolean v5, v3, Lbo0/k;->p:Z

    .line 328
    .line 329
    invoke-static {v0, v1, v2, v4, v5}, Ljp/ya;->b(Lbo0/i;Ljava/util/List;Ljava/util/List;Lij0/a;Z)Lbo0/i;

    .line 330
    .line 331
    .line 332
    move-result-object v0

    .line 333
    invoke-virtual {v3, v0}, Lql0/j;->g(Lql0/h;)V

    .line 334
    .line 335
    .line 336
    :cond_12
    :goto_8
    return-object v7

    .line 337
    :cond_13
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 338
    .line 339
    invoke-direct {v0, v11}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 340
    .line 341
    .line 342
    throw v0

    .line 343
    :cond_14
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 344
    .line 345
    invoke-direct {v0, v11}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 346
    .line 347
    .line 348
    throw v0

    .line 349
    :pswitch_2
    check-cast v3, Lb1/e1;

    .line 350
    .line 351
    iget-object v0, v5, Lb1/c1;->g:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast v0, Lb1/b1;

    .line 354
    .line 355
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 356
    .line 357
    iget v1, v5, Lb1/c1;->e:I

    .line 358
    .line 359
    if-eqz v1, :cond_16

    .line 360
    .line 361
    if-ne v1, v6, :cond_15

    .line 362
    .line 363
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 364
    .line 365
    .line 366
    move-object/from16 v0, p1

    .line 367
    .line 368
    goto :goto_9

    .line 369
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 370
    .line 371
    invoke-direct {v0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 372
    .line 373
    .line 374
    throw v0

    .line 375
    :cond_16
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    iget-object v0, v0, Lb1/b1;->a:Lc1/c;

    .line 379
    .line 380
    new-instance v1, Lt4/l;

    .line 381
    .line 382
    invoke-direct {v1, v8, v9}, Lt4/l;-><init>(J)V

    .line 383
    .line 384
    .line 385
    iget-object v2, v3, Lb1/e1;->s:Lc1/j;

    .line 386
    .line 387
    iput v6, v5, Lb1/c1;->e:I

    .line 388
    .line 389
    const/4 v3, 0x0

    .line 390
    const/4 v4, 0x0

    .line 391
    const/16 v6, 0xc

    .line 392
    .line 393
    invoke-static/range {v0 .. v6}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    if-ne v0, v10, :cond_17

    .line 398
    .line 399
    move-object v7, v10

    .line 400
    goto :goto_a

    .line 401
    :cond_17
    :goto_9
    check-cast v0, Lc1/h;

    .line 402
    .line 403
    iget-object v0, v0, Lc1/h;->b:Lc1/g;

    .line 404
    .line 405
    sget-object v0, Lc1/g;->d:Lc1/g;

    .line 406
    .line 407
    :goto_a
    return-object v7

    .line 408
    nop

    .line 409
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
