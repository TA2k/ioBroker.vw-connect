.class public final Lg1/l1;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:Ljava/lang/Object;

.field public g:I

.field public h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lg1/l1;->e:I

    iput-object p2, p0, Lg1/l1;->h:Ljava/lang/Object;

    iput-object p3, p0, Lg1/l1;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 2
    iput p3, p0, Lg1/l1;->e:I

    iput-object p1, p0, Lg1/l1;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lg1/l1;->e:I

    .line 3
    iput-object p1, p0, Lg1/l1;->h:Ljava/lang/Object;

    check-cast p2, Lrx0/h;

    iput-object p2, p0, Lg1/l1;->i:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lg1/l1;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/l1;

    .line 7
    .line 8
    iget-object p0, p0, Lg1/l1;->i:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lt1/w0;

    .line 11
    .line 12
    const/4 v1, 0x4

    .line 13
    invoke-direct {v0, p0, p2, v1}, Lg1/l1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lg1/l1;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lg1/l1;

    .line 20
    .line 21
    iget-object v1, p0, Lg1/l1;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v1, Ll2/b1;

    .line 24
    .line 25
    iget-object p0, p0, Lg1/l1;->i:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p0, Li91/l1;

    .line 28
    .line 29
    const/4 v2, 0x3

    .line 30
    invoke-direct {v0, v2, v1, p0, p2}, Lg1/l1;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    iput-object p1, v0, Lg1/l1;->f:Ljava/lang/Object;

    .line 34
    .line 35
    return-object v0

    .line 36
    :pswitch_1
    new-instance v0, Lg1/l1;

    .line 37
    .line 38
    iget-object v1, p0, Lg1/l1;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lp3/l;

    .line 41
    .line 42
    iget-object p0, p0, Lg1/l1;->i:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 45
    .line 46
    const/4 v2, 0x2

    .line 47
    invoke-direct {v0, v2, v1, p0, p2}, Lg1/l1;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 48
    .line 49
    .line 50
    iput-object p1, v0, Lg1/l1;->f:Ljava/lang/Object;

    .line 51
    .line 52
    return-object v0

    .line 53
    :pswitch_2
    new-instance v0, Lg1/l1;

    .line 54
    .line 55
    iget-object p0, p0, Lg1/l1;->i:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Ld2/g;

    .line 58
    .line 59
    const/4 v1, 0x1

    .line 60
    invoke-direct {v0, p0, p2, v1}, Lg1/l1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    iput-object p1, v0, Lg1/l1;->h:Ljava/lang/Object;

    .line 64
    .line 65
    return-object v0

    .line 66
    :pswitch_3
    new-instance v0, Lg1/l1;

    .line 67
    .line 68
    iget-object v1, p0, Lg1/l1;->h:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v1, Lpx0/g;

    .line 71
    .line 72
    iget-object p0, p0, Lg1/l1;->i:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Lrx0/h;

    .line 75
    .line 76
    invoke-direct {v0, v1, p0, p2}, Lg1/l1;-><init>(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    iput-object p1, v0, Lg1/l1;->f:Ljava/lang/Object;

    .line 80
    .line 81
    return-object v0

    .line 82
    nop

    .line 83
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
    iget v0, p0, Lg1/l1;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lp3/i0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg1/l1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/l1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/l1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lp3/i0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lg1/l1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg1/l1;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lg1/l1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lp3/i0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lg1/l1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lg1/l1;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lg1/l1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lky0/k;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Lg1/l1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lg1/l1;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lg1/l1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Lp3/i0;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lg1/l1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lg1/l1;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lg1/l1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lg1/l1;->e:I

    .line 4
    .line 5
    const/4 v3, 0x2

    .line 6
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    const/4 v6, 0x1

    .line 11
    iget-object v7, v1, Lg1/l1;->i:Ljava/lang/Object;

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    check-cast v7, Lt1/w0;

    .line 17
    .line 18
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 19
    .line 20
    iget v8, v1, Lg1/l1;->g:I

    .line 21
    .line 22
    if-eqz v8, :cond_2

    .line 23
    .line 24
    if-eq v8, v6, :cond_1

    .line 25
    .line 26
    if-ne v8, v3, :cond_0

    .line 27
    .line 28
    iget-object v5, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v5, Lp3/t;

    .line 31
    .line 32
    iget-object v6, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v6, Lp3/i0;

    .line 35
    .line 36
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    move-object/from16 v8, p1

    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v0

    .line 48
    :cond_1
    iget-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v5, Lp3/i0;

    .line 51
    .line 52
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    move-object/from16 v6, p1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v5, Lp3/i0;

    .line 64
    .line 65
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 66
    .line 67
    iput v6, v1, Lg1/l1;->g:I

    .line 68
    .line 69
    invoke-static {v5, v1, v3}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    if-ne v6, v0, :cond_3

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_3
    :goto_0
    check-cast v6, Lp3/t;

    .line 77
    .line 78
    iget-wide v8, v6, Lp3/t;->c:J

    .line 79
    .line 80
    invoke-interface {v7}, Lt1/w0;->a()V

    .line 81
    .line 82
    .line 83
    move-object/from16 v16, v6

    .line 84
    .line 85
    move-object v6, v5

    .line 86
    move-object/from16 v5, v16

    .line 87
    .line 88
    :goto_1
    iput-object v6, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 89
    .line 90
    iput-object v5, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 91
    .line 92
    iput v3, v1, Lg1/l1;->g:I

    .line 93
    .line 94
    sget-object v8, Lp3/l;->e:Lp3/l;

    .line 95
    .line 96
    invoke-virtual {v6, v8, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    if-ne v8, v0, :cond_4

    .line 101
    .line 102
    :goto_2
    move-object v4, v0

    .line 103
    goto :goto_5

    .line 104
    :cond_4
    :goto_3
    check-cast v8, Lp3/k;

    .line 105
    .line 106
    iget-object v8, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 107
    .line 108
    move-object v9, v8

    .line 109
    check-cast v9, Ljava/util/Collection;

    .line 110
    .line 111
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 112
    .line 113
    .line 114
    move-result v9

    .line 115
    const/4 v10, 0x0

    .line 116
    :goto_4
    if-ge v10, v9, :cond_6

    .line 117
    .line 118
    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v11

    .line 122
    check-cast v11, Lp3/t;

    .line 123
    .line 124
    iget-wide v12, v11, Lp3/t;->a:J

    .line 125
    .line 126
    iget-wide v14, v5, Lp3/t;->a:J

    .line 127
    .line 128
    invoke-static {v12, v13, v14, v15}, Lp3/s;->e(JJ)Z

    .line 129
    .line 130
    .line 131
    move-result v12

    .line 132
    if-eqz v12, :cond_5

    .line 133
    .line 134
    iget-boolean v11, v11, Lp3/t;->d:Z

    .line 135
    .line 136
    if-eqz v11, :cond_5

    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_5
    add-int/lit8 v10, v10, 0x1

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_6
    invoke-interface {v7}, Lt1/w0;->d()V

    .line 143
    .line 144
    .line 145
    :goto_5
    return-object v4

    .line 146
    :pswitch_0
    iget-object v0, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, Ll2/b1;

    .line 149
    .line 150
    iget-object v2, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v2, Lp3/i0;

    .line 153
    .line 154
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 155
    .line 156
    iget v9, v1, Lg1/l1;->g:I

    .line 157
    .line 158
    if-eqz v9, :cond_9

    .line 159
    .line 160
    if-eq v9, v6, :cond_8

    .line 161
    .line 162
    if-ne v9, v3, :cond_7

    .line 163
    .line 164
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    move-object/from16 v5, p1

    .line 168
    .line 169
    goto :goto_8

    .line 170
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 171
    .line 172
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    throw v0

    .line 176
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    iput-object v2, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 184
    .line 185
    iput v6, v1, Lg1/l1;->g:I

    .line 186
    .line 187
    invoke-static {v2, v1, v3}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v5

    .line 191
    if-ne v5, v8, :cond_a

    .line 192
    .line 193
    goto :goto_7

    .line 194
    :cond_a
    :goto_6
    sget-object v5, Lp3/l;->f:Lp3/l;

    .line 195
    .line 196
    iput-object v2, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 197
    .line 198
    iput v3, v1, Lg1/l1;->g:I

    .line 199
    .line 200
    invoke-virtual {v2, v5, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v5

    .line 204
    if-ne v5, v8, :cond_b

    .line 205
    .line 206
    :goto_7
    move-object v4, v8

    .line 207
    goto :goto_a

    .line 208
    :cond_b
    :goto_8
    check-cast v5, Lp3/k;

    .line 209
    .line 210
    iget-object v5, v5, Lp3/k;->a:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v5, Ljava/lang/Iterable;

    .line 213
    .line 214
    instance-of v6, v5, Ljava/util/Collection;

    .line 215
    .line 216
    if-eqz v6, :cond_c

    .line 217
    .line 218
    move-object v6, v5

    .line 219
    check-cast v6, Ljava/util/Collection;

    .line 220
    .line 221
    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    if-eqz v6, :cond_c

    .line 226
    .line 227
    goto :goto_9

    .line 228
    :cond_c
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 229
    .line 230
    .line 231
    move-result-object v5

    .line 232
    :cond_d
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 233
    .line 234
    .line 235
    move-result v6

    .line 236
    if-eqz v6, :cond_e

    .line 237
    .line 238
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v6

    .line 242
    check-cast v6, Lp3/t;

    .line 243
    .line 244
    iget-boolean v6, v6, Lp3/t;->d:Z

    .line 245
    .line 246
    if-eqz v6, :cond_d

    .line 247
    .line 248
    goto :goto_6

    .line 249
    :cond_e
    :goto_9
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    move-result-object v1

    .line 253
    check-cast v1, Ljava/lang/Boolean;

    .line 254
    .line 255
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 256
    .line 257
    .line 258
    move-result v1

    .line 259
    if-eqz v1, :cond_f

    .line 260
    .line 261
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 262
    .line 263
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    check-cast v7, Li91/l1;

    .line 267
    .line 268
    invoke-virtual {v7}, Li91/l1;->e()V

    .line 269
    .line 270
    .line 271
    :cond_f
    :goto_a
    return-object v4

    .line 272
    :pswitch_1
    check-cast v7, Lkotlin/jvm/internal/f0;

    .line 273
    .line 274
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 275
    .line 276
    iget v8, v1, Lg1/l1;->g:I

    .line 277
    .line 278
    sget-object v9, Lg1/m1;->a:Lg1/m1;

    .line 279
    .line 280
    if-eqz v8, :cond_12

    .line 281
    .line 282
    if-eq v8, v6, :cond_11

    .line 283
    .line 284
    if-ne v8, v3, :cond_10

    .line 285
    .line 286
    iget-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v5, Lp3/i0;

    .line 289
    .line 290
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 291
    .line 292
    .line 293
    move-object/from16 v2, p1

    .line 294
    .line 295
    goto/16 :goto_11

    .line 296
    .line 297
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 298
    .line 299
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    throw v0

    .line 303
    :cond_11
    iget-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast v5, Lp3/i0;

    .line 306
    .line 307
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    move-object/from16 v8, p1

    .line 311
    .line 312
    goto :goto_c

    .line 313
    :cond_12
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iget-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v5, Lp3/i0;

    .line 319
    .line 320
    :goto_b
    iget-object v8, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 321
    .line 322
    check-cast v8, Lp3/l;

    .line 323
    .line 324
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 325
    .line 326
    iput v6, v1, Lg1/l1;->g:I

    .line 327
    .line 328
    invoke-virtual {v5, v8, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v8

    .line 332
    if-ne v8, v0, :cond_13

    .line 333
    .line 334
    goto :goto_10

    .line 335
    :cond_13
    :goto_c
    check-cast v8, Lp3/k;

    .line 336
    .line 337
    iget-object v10, v8, Lp3/k;->a:Ljava/lang/Object;

    .line 338
    .line 339
    move-object v11, v10

    .line 340
    check-cast v11, Ljava/util/Collection;

    .line 341
    .line 342
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 343
    .line 344
    .line 345
    move-result v11

    .line 346
    const/4 v12, 0x0

    .line 347
    :goto_d
    if-ge v12, v11, :cond_1c

    .line 348
    .line 349
    invoke-interface {v10, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v13

    .line 353
    check-cast v13, Lp3/t;

    .line 354
    .line 355
    invoke-static {v13}, Lp3/s;->c(Lp3/t;)Z

    .line 356
    .line 357
    .line 358
    move-result v13

    .line 359
    if-nez v13, :cond_1b

    .line 360
    .line 361
    iget v8, v8, Lp3/k;->c:I

    .line 362
    .line 363
    if-ne v8, v3, :cond_14

    .line 364
    .line 365
    sget-object v0, Lg1/o1;->a:Lg1/o1;

    .line 366
    .line 367
    iput-object v0, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 368
    .line 369
    goto/16 :goto_13

    .line 370
    .line 371
    :cond_14
    move-object v8, v10

    .line 372
    check-cast v8, Ljava/util/Collection;

    .line 373
    .line 374
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 375
    .line 376
    .line 377
    move-result v8

    .line 378
    const/4 v11, 0x0

    .line 379
    :goto_e
    if-ge v11, v8, :cond_17

    .line 380
    .line 381
    invoke-interface {v10, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v12

    .line 385
    check-cast v12, Lp3/t;

    .line 386
    .line 387
    invoke-virtual {v12}, Lp3/t;->b()Z

    .line 388
    .line 389
    .line 390
    move-result v13

    .line 391
    if-nez v13, :cond_16

    .line 392
    .line 393
    iget-object v13, v5, Lp3/i0;->i:Lp3/j0;

    .line 394
    .line 395
    iget-wide v13, v13, Lp3/j0;->B:J

    .line 396
    .line 397
    invoke-virtual {v5}, Lp3/i0;->d()J

    .line 398
    .line 399
    .line 400
    move-result-wide v2

    .line 401
    invoke-static {v12, v13, v14, v2, v3}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 402
    .line 403
    .line 404
    move-result v2

    .line 405
    if-eqz v2, :cond_15

    .line 406
    .line 407
    goto :goto_f

    .line 408
    :cond_15
    add-int/lit8 v11, v11, 0x1

    .line 409
    .line 410
    const/4 v3, 0x2

    .line 411
    goto :goto_e

    .line 412
    :cond_16
    :goto_f
    iput-object v9, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 413
    .line 414
    goto :goto_13

    .line 415
    :cond_17
    sget-object v2, Lp3/l;->f:Lp3/l;

    .line 416
    .line 417
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 418
    .line 419
    const/4 v3, 0x2

    .line 420
    iput v3, v1, Lg1/l1;->g:I

    .line 421
    .line 422
    invoke-virtual {v5, v2, v1}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v2

    .line 426
    if-ne v2, v0, :cond_18

    .line 427
    .line 428
    :goto_10
    move-object v4, v0

    .line 429
    goto :goto_13

    .line 430
    :cond_18
    :goto_11
    check-cast v2, Lp3/k;

    .line 431
    .line 432
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 433
    .line 434
    move-object v3, v2

    .line 435
    check-cast v3, Ljava/util/Collection;

    .line 436
    .line 437
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 438
    .line 439
    .line 440
    move-result v3

    .line 441
    const/4 v8, 0x0

    .line 442
    :goto_12
    if-ge v8, v3, :cond_1a

    .line 443
    .line 444
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v10

    .line 448
    check-cast v10, Lp3/t;

    .line 449
    .line 450
    invoke-virtual {v10}, Lp3/t;->b()Z

    .line 451
    .line 452
    .line 453
    move-result v10

    .line 454
    if-eqz v10, :cond_19

    .line 455
    .line 456
    iput-object v9, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 457
    .line 458
    goto :goto_13

    .line 459
    :cond_19
    add-int/lit8 v8, v8, 0x1

    .line 460
    .line 461
    goto :goto_12

    .line 462
    :cond_1a
    const/4 v3, 0x2

    .line 463
    goto/16 :goto_b

    .line 464
    .line 465
    :cond_1b
    add-int/lit8 v12, v12, 0x1

    .line 466
    .line 467
    const/4 v3, 0x2

    .line 468
    goto :goto_d

    .line 469
    :cond_1c
    new-instance v0, Lg1/n1;

    .line 470
    .line 471
    const/4 v15, 0x0

    .line 472
    invoke-interface {v10, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v1

    .line 476
    check-cast v1, Lp3/t;

    .line 477
    .line 478
    invoke-direct {v0, v1}, Lg1/n1;-><init>(Lp3/t;)V

    .line 479
    .line 480
    .line 481
    iput-object v0, v7, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 482
    .line 483
    :goto_13
    return-object v4

    .line 484
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 485
    .line 486
    iget v2, v1, Lg1/l1;->g:I

    .line 487
    .line 488
    if-eqz v2, :cond_1e

    .line 489
    .line 490
    if-ne v2, v6, :cond_1d

    .line 491
    .line 492
    iget-object v2, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 493
    .line 494
    iget-object v3, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 495
    .line 496
    check-cast v3, Lky0/k;

    .line 497
    .line 498
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    goto :goto_14

    .line 502
    :cond_1d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 503
    .line 504
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    throw v0

    .line 508
    :cond_1e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    iget-object v2, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 512
    .line 513
    check-cast v2, Lky0/k;

    .line 514
    .line 515
    move-object v3, v2

    .line 516
    :cond_1f
    move-object v2, v7

    .line 517
    check-cast v2, Ld2/g;

    .line 518
    .line 519
    invoke-virtual {v2}, Ld2/g;->invoke()Ljava/lang/Object;

    .line 520
    .line 521
    .line 522
    move-result-object v2

    .line 523
    if-eqz v2, :cond_20

    .line 524
    .line 525
    iput-object v3, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 526
    .line 527
    iput-object v2, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 528
    .line 529
    iput v6, v1, Lg1/l1;->g:I

    .line 530
    .line 531
    invoke-virtual {v3, v2, v1}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 532
    .line 533
    .line 534
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 535
    .line 536
    move-object v4, v0

    .line 537
    goto :goto_15

    .line 538
    :cond_20
    const/4 v2, 0x0

    .line 539
    :goto_14
    if-nez v2, :cond_1f

    .line 540
    .line 541
    :goto_15
    return-object v4

    .line 542
    :pswitch_3
    iget-object v0, v1, Lg1/l1;->h:Ljava/lang/Object;

    .line 543
    .line 544
    move-object v2, v0

    .line 545
    check-cast v2, Lpx0/g;

    .line 546
    .line 547
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 548
    .line 549
    iget v0, v1, Lg1/l1;->g:I

    .line 550
    .line 551
    const/4 v8, 0x3

    .line 552
    if-eqz v0, :cond_24

    .line 553
    .line 554
    if-eq v0, v6, :cond_23

    .line 555
    .line 556
    const/4 v9, 0x2

    .line 557
    if-eq v0, v9, :cond_22

    .line 558
    .line 559
    if-ne v0, v8, :cond_21

    .line 560
    .line 561
    iget-object v0, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 562
    .line 563
    check-cast v0, Lp3/i0;

    .line 564
    .line 565
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 566
    .line 567
    .line 568
    move-object v5, v0

    .line 569
    goto :goto_16

    .line 570
    :cond_21
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 571
    .line 572
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    throw v0

    .line 576
    :cond_22
    iget-object v0, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 577
    .line 578
    move-object v5, v0

    .line 579
    check-cast v5, Lp3/i0;

    .line 580
    .line 581
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 582
    .line 583
    .line 584
    :goto_16
    const/4 v9, 0x2

    .line 585
    goto :goto_17

    .line 586
    :catch_0
    move-exception v0

    .line 587
    const/4 v9, 0x2

    .line 588
    goto :goto_19

    .line 589
    :cond_23
    iget-object v0, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 590
    .line 591
    move-object v5, v0

    .line 592
    check-cast v5, Lp3/i0;

    .line 593
    .line 594
    :try_start_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 595
    .line 596
    .line 597
    goto :goto_18

    .line 598
    :cond_24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 599
    .line 600
    .line 601
    iget-object v0, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 602
    .line 603
    check-cast v0, Lp3/i0;

    .line 604
    .line 605
    move-object v5, v0

    .line 606
    :cond_25
    :goto_17
    invoke-static {v2}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 607
    .line 608
    .line 609
    move-result v0

    .line 610
    if-eqz v0, :cond_28

    .line 611
    .line 612
    :try_start_2
    move-object v0, v7

    .line 613
    check-cast v0, Lrx0/h;

    .line 614
    .line 615
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 616
    .line 617
    iput v6, v1, Lg1/l1;->g:I

    .line 618
    .line 619
    invoke-interface {v0, v5, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 620
    .line 621
    .line 622
    move-result-object v0

    .line 623
    if-ne v0, v3, :cond_26

    .line 624
    .line 625
    goto :goto_1a

    .line 626
    :cond_26
    :goto_18
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0

    .line 627
    .line 628
    const/4 v9, 0x2

    .line 629
    :try_start_3
    iput v9, v1, Lg1/l1;->g:I

    .line 630
    .line 631
    sget-object v0, Lp3/l;->f:Lp3/l;

    .line 632
    .line 633
    invoke-static {v5, v0, v1}, Lg1/h3;->b(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object v0
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_1

    .line 637
    if-ne v0, v3, :cond_25

    .line 638
    .line 639
    goto :goto_1a

    .line 640
    :catch_1
    move-exception v0

    .line 641
    :goto_19
    invoke-static {v2}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 642
    .line 643
    .line 644
    move-result v10

    .line 645
    if-eqz v10, :cond_27

    .line 646
    .line 647
    iput-object v5, v1, Lg1/l1;->f:Ljava/lang/Object;

    .line 648
    .line 649
    iput v8, v1, Lg1/l1;->g:I

    .line 650
    .line 651
    sget-object v0, Lp3/l;->f:Lp3/l;

    .line 652
    .line 653
    invoke-static {v5, v0, v1}, Lg1/h3;->b(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v0

    .line 657
    if-ne v0, v3, :cond_25

    .line 658
    .line 659
    :goto_1a
    move-object v4, v3

    .line 660
    goto :goto_1b

    .line 661
    :cond_27
    throw v0

    .line 662
    :cond_28
    :goto_1b
    return-object v4

    .line 663
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
