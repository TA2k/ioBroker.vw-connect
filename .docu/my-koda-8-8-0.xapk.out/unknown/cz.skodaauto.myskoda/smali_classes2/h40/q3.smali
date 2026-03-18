.class public final Lh40/q3;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/x3;


# direct methods
.method public synthetic constructor <init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/q3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/q3;->f:Lh40/x3;

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
    iget p1, p0, Lh40/q3;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/q3;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 9
    .line 10
    const/4 v0, 0x7

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/q3;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 18
    .line 19
    const/4 v0, 0x6

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lh40/q3;

    .line 25
    .line 26
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 27
    .line 28
    const/4 v0, 0x5

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lh40/q3;

    .line 34
    .line 35
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 36
    .line 37
    const/4 v0, 0x4

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lh40/q3;

    .line 43
    .line 44
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 45
    .line 46
    const/4 v0, 0x3

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_4
    new-instance p1, Lh40/q3;

    .line 52
    .line 53
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 54
    .line 55
    const/4 v0, 0x2

    .line 56
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 57
    .line 58
    .line 59
    return-object p1

    .line 60
    :pswitch_5
    new-instance p1, Lh40/q3;

    .line 61
    .line 62
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 63
    .line 64
    const/4 v0, 0x1

    .line 65
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 66
    .line 67
    .line 68
    return-object p1

    .line 69
    :pswitch_6
    new-instance p1, Lh40/q3;

    .line 70
    .line 71
    iget-object p0, p0, Lh40/q3;->f:Lh40/x3;

    .line 72
    .line 73
    const/4 v0, 0x0

    .line 74
    invoke-direct {p1, p0, p2, v0}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    return-object p1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
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
    iget v0, p0, Lh40/q3;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/q3;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/q3;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lh40/q3;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lh40/q3;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lh40/q3;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_4
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Lh40/q3;

    .line 80
    .line 81
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :pswitch_5
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lh40/q3;

    .line 93
    .line 94
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_6
    invoke-virtual {p0, p1, p2}, Lh40/q3;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lh40/q3;

    .line 106
    .line 107
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Lh40/q3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh40/q3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lh40/q3;->e:I

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
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 33
    .line 34
    iget-object v4, v2, Lh40/x3;->F:Lbq0/b;

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
    new-instance v5, Lh40/u3;

    .line 43
    .line 44
    const/4 v6, 0x3

    .line 45
    invoke-direct {v5, v2, v6}, Lh40/u3;-><init>(Lh40/x3;I)V

    .line 46
    .line 47
    .line 48
    iput v3, v0, Lh40/q3;->e:I

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
    iget v2, v0, Lh40/q3;->e:I

    .line 63
    .line 64
    const/4 v3, 0x1

    .line 65
    if-eqz v2, :cond_4

    .line 66
    .line 67
    if-ne v2, v3, :cond_3

    .line 68
    .line 69
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 85
    .line 86
    iget-object v2, v2, Lh40/x3;->M:Lf40/s;

    .line 87
    .line 88
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    check-cast v2, Lyy0/i;

    .line 93
    .line 94
    iput v3, v0, Lh40/q3;->e:I

    .line 95
    .line 96
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    if-ne v0, v1, :cond_5

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    :goto_3
    return-object v1

    .line 106
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 107
    .line 108
    iget v2, v0, Lh40/q3;->e:I

    .line 109
    .line 110
    const/4 v3, 0x1

    .line 111
    if-eqz v2, :cond_7

    .line 112
    .line 113
    if-ne v2, v3, :cond_6

    .line 114
    .line 115
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 122
    .line 123
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw v0

    .line 127
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 131
    .line 132
    iget-object v2, v2, Lh40/x3;->C:Lf40/q;

    .line 133
    .line 134
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    check-cast v2, Lyy0/i;

    .line 139
    .line 140
    iput v3, v0, Lh40/q3;->e:I

    .line 141
    .line 142
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    if-ne v0, v1, :cond_8

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_8
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    :goto_5
    return-object v1

    .line 152
    :pswitch_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 153
    .line 154
    iget v2, v0, Lh40/q3;->e:I

    .line 155
    .line 156
    const/4 v3, 0x1

    .line 157
    iget-object v4, v0, Lh40/q3;->f:Lh40/x3;

    .line 158
    .line 159
    if-eqz v2, :cond_a

    .line 160
    .line 161
    if-ne v2, v3, :cond_9

    .line 162
    .line 163
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto :goto_6

    .line 167
    :cond_9
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 168
    .line 169
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 170
    .line 171
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 172
    .line 173
    .line 174
    throw v0

    .line 175
    :cond_a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    move-object v5, v2

    .line 183
    check-cast v5, Lh40/s3;

    .line 184
    .line 185
    const/16 v29, 0x0

    .line 186
    .line 187
    const v30, 0x1fffffb

    .line 188
    .line 189
    .line 190
    const/4 v6, 0x0

    .line 191
    const/4 v7, 0x0

    .line 192
    const/4 v8, 0x1

    .line 193
    const/4 v9, 0x0

    .line 194
    const/4 v10, 0x0

    .line 195
    const/4 v11, 0x0

    .line 196
    const/4 v12, 0x0

    .line 197
    const/4 v13, 0x0

    .line 198
    const/4 v14, 0x0

    .line 199
    const/4 v15, 0x0

    .line 200
    const/16 v16, 0x0

    .line 201
    .line 202
    const/16 v17, 0x0

    .line 203
    .line 204
    const/16 v18, 0x0

    .line 205
    .line 206
    const/16 v19, 0x0

    .line 207
    .line 208
    const/16 v20, 0x0

    .line 209
    .line 210
    const/16 v21, 0x0

    .line 211
    .line 212
    const/16 v22, 0x0

    .line 213
    .line 214
    const/16 v23, 0x0

    .line 215
    .line 216
    const/16 v24, 0x0

    .line 217
    .line 218
    const/16 v25, 0x0

    .line 219
    .line 220
    const/16 v26, 0x0

    .line 221
    .line 222
    const/16 v27, 0x0

    .line 223
    .line 224
    const/16 v28, 0x0

    .line 225
    .line 226
    invoke-static/range {v5 .. v30}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 227
    .line 228
    .line 229
    move-result-object v2

    .line 230
    invoke-virtual {v4, v2}, Lql0/j;->g(Lql0/h;)V

    .line 231
    .line 232
    .line 233
    iget-object v2, v4, Lh40/x3;->o:Lf40/v;

    .line 234
    .line 235
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v2

    .line 239
    check-cast v2, Lyy0/i;

    .line 240
    .line 241
    iput v3, v0, Lh40/q3;->e:I

    .line 242
    .line 243
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    if-ne v0, v1, :cond_b

    .line 248
    .line 249
    goto :goto_7

    .line 250
    :cond_b
    :goto_6
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    move-object v5, v0

    .line 255
    check-cast v5, Lh40/s3;

    .line 256
    .line 257
    const/16 v29, 0x0

    .line 258
    .line 259
    const v30, 0x1fffffb

    .line 260
    .line 261
    .line 262
    const/4 v6, 0x0

    .line 263
    const/4 v7, 0x0

    .line 264
    const/4 v8, 0x0

    .line 265
    const/4 v9, 0x0

    .line 266
    const/4 v10, 0x0

    .line 267
    const/4 v11, 0x0

    .line 268
    const/4 v12, 0x0

    .line 269
    const/4 v13, 0x0

    .line 270
    const/4 v14, 0x0

    .line 271
    const/4 v15, 0x0

    .line 272
    const/16 v16, 0x0

    .line 273
    .line 274
    const/16 v17, 0x0

    .line 275
    .line 276
    const/16 v18, 0x0

    .line 277
    .line 278
    const/16 v19, 0x0

    .line 279
    .line 280
    const/16 v20, 0x0

    .line 281
    .line 282
    const/16 v21, 0x0

    .line 283
    .line 284
    const/16 v22, 0x0

    .line 285
    .line 286
    const/16 v23, 0x0

    .line 287
    .line 288
    const/16 v24, 0x0

    .line 289
    .line 290
    const/16 v25, 0x0

    .line 291
    .line 292
    const/16 v26, 0x0

    .line 293
    .line 294
    const/16 v27, 0x0

    .line 295
    .line 296
    const/16 v28, 0x0

    .line 297
    .line 298
    invoke-static/range {v5 .. v30}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 303
    .line 304
    .line 305
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 306
    .line 307
    :goto_7
    return-object v1

    .line 308
    :pswitch_3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 309
    .line 310
    iget v2, v0, Lh40/q3;->e:I

    .line 311
    .line 312
    const/4 v3, 0x1

    .line 313
    if-eqz v2, :cond_d

    .line 314
    .line 315
    if-ne v2, v3, :cond_c

    .line 316
    .line 317
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 318
    .line 319
    .line 320
    goto :goto_8

    .line 321
    :cond_c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 322
    .line 323
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 324
    .line 325
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    throw v0

    .line 329
    :cond_d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 330
    .line 331
    .line 332
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 333
    .line 334
    iget-object v4, v2, Lh40/x3;->z:Lf40/t;

    .line 335
    .line 336
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    check-cast v4, Lyy0/i;

    .line 341
    .line 342
    new-instance v5, Lh40/u3;

    .line 343
    .line 344
    const/4 v6, 0x2

    .line 345
    invoke-direct {v5, v2, v6}, Lh40/u3;-><init>(Lh40/x3;I)V

    .line 346
    .line 347
    .line 348
    iput v3, v0, Lh40/q3;->e:I

    .line 349
    .line 350
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    if-ne v0, v1, :cond_e

    .line 355
    .line 356
    goto :goto_9

    .line 357
    :cond_e
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 358
    .line 359
    :goto_9
    return-object v1

    .line 360
    :pswitch_4
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 361
    .line 362
    iget v2, v0, Lh40/q3;->e:I

    .line 363
    .line 364
    const/4 v3, 0x1

    .line 365
    if-eqz v2, :cond_10

    .line 366
    .line 367
    if-ne v2, v3, :cond_f

    .line 368
    .line 369
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 370
    .line 371
    .line 372
    goto :goto_a

    .line 373
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 374
    .line 375
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 376
    .line 377
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    throw v0

    .line 381
    :cond_10
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 382
    .line 383
    .line 384
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 385
    .line 386
    iget-object v4, v2, Lh40/x3;->m:Lf40/h;

    .line 387
    .line 388
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v4

    .line 392
    check-cast v4, Lyy0/i;

    .line 393
    .line 394
    new-instance v5, Lh40/u3;

    .line 395
    .line 396
    const/4 v6, 0x0

    .line 397
    invoke-direct {v5, v2, v6}, Lh40/u3;-><init>(Lh40/x3;I)V

    .line 398
    .line 399
    .line 400
    iput v3, v0, Lh40/q3;->e:I

    .line 401
    .line 402
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    if-ne v0, v1, :cond_11

    .line 407
    .line 408
    goto :goto_b

    .line 409
    :cond_11
    :goto_a
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 410
    .line 411
    :goto_b
    return-object v1

    .line 412
    :pswitch_5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 413
    .line 414
    iget v2, v0, Lh40/q3;->e:I

    .line 415
    .line 416
    const/4 v3, 0x1

    .line 417
    if-eqz v2, :cond_13

    .line 418
    .line 419
    if-ne v2, v3, :cond_12

    .line 420
    .line 421
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 422
    .line 423
    .line 424
    goto :goto_c

    .line 425
    :cond_12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 426
    .line 427
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 428
    .line 429
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 430
    .line 431
    .line 432
    throw v0

    .line 433
    :cond_13
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 434
    .line 435
    .line 436
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 437
    .line 438
    iget-object v4, v2, Lh40/x3;->L:Lwr0/i;

    .line 439
    .line 440
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v4

    .line 444
    check-cast v4, Lyy0/i;

    .line 445
    .line 446
    new-instance v5, Le30/p;

    .line 447
    .line 448
    const/4 v6, 0x0

    .line 449
    const/16 v7, 0x18

    .line 450
    .line 451
    invoke-direct {v5, v2, v6, v7}, Le30/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 452
    .line 453
    .line 454
    iput v3, v0, Lh40/q3;->e:I

    .line 455
    .line 456
    invoke-static {v5, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 457
    .line 458
    .line 459
    move-result-object v0

    .line 460
    if-ne v0, v1, :cond_14

    .line 461
    .line 462
    goto :goto_d

    .line 463
    :cond_14
    :goto_c
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 464
    .line 465
    :goto_d
    return-object v1

    .line 466
    :pswitch_6
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 467
    .line 468
    iget v2, v0, Lh40/q3;->e:I

    .line 469
    .line 470
    const/4 v3, 0x1

    .line 471
    if-eqz v2, :cond_16

    .line 472
    .line 473
    if-ne v2, v3, :cond_15

    .line 474
    .line 475
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 476
    .line 477
    .line 478
    goto :goto_e

    .line 479
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 480
    .line 481
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 482
    .line 483
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    throw v0

    .line 487
    :cond_16
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 488
    .line 489
    .line 490
    iget-object v2, v0, Lh40/q3;->f:Lh40/x3;

    .line 491
    .line 492
    iget-object v4, v2, Lh40/x3;->n:Lf40/l1;

    .line 493
    .line 494
    invoke-static {v4}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v4

    .line 498
    check-cast v4, Lyy0/i;

    .line 499
    .line 500
    new-instance v5, La60/b;

    .line 501
    .line 502
    const/16 v6, 0x1b

    .line 503
    .line 504
    invoke-direct {v5, v2, v6}, La60/b;-><init>(Lql0/j;I)V

    .line 505
    .line 506
    .line 507
    iput v3, v0, Lh40/q3;->e:I

    .line 508
    .line 509
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v0

    .line 513
    if-ne v0, v1, :cond_17

    .line 514
    .line 515
    goto :goto_f

    .line 516
    :cond_17
    :goto_e
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 517
    .line 518
    :goto_f
    return-object v1

    .line 519
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
