.class public final Ll60/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ll60/e;


# direct methods
.method public synthetic constructor <init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ll60/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ll60/a;->f:Ll60/e;

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
    iget p1, p0, Ll60/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ll60/a;

    .line 7
    .line 8
    iget-object p0, p0, Ll60/a;->f:Ll60/e;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ll60/a;

    .line 16
    .line 17
    iget-object p0, p0, Ll60/a;->f:Ll60/e;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ll60/a;

    .line 25
    .line 26
    iget-object p0, p0, Ll60/a;->f:Ll60/e;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ll60/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Ll60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ll60/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ll60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ll60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ll60/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ll60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ll60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ll60/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ll60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ll60/a;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object v4, v0, Ll60/a;->f:Ll60/e;

    .line 9
    .line 10
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v2, v0, Ll60/a;->e:I

    .line 19
    .line 20
    if-eqz v2, :cond_1

    .line 21
    .line 22
    if-ne v2, v6, :cond_0

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object v2, v4, Ll60/e;->i:Lzo0/d;

    .line 38
    .line 39
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lyy0/i;

    .line 44
    .line 45
    iput v6, v0, Ll60/a;->e:I

    .line 46
    .line 47
    invoke-static {v2, v0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    if-ne v0, v1, :cond_2

    .line 52
    .line 53
    move-object v3, v1

    .line 54
    :cond_2
    :goto_0
    return-object v3

    .line 55
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    iget v7, v0, Ll60/a;->e:I

    .line 58
    .line 59
    if-eqz v7, :cond_4

    .line 60
    .line 61
    if-ne v7, v6, :cond_3

    .line 62
    .line 63
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    move-object v7, v5

    .line 81
    check-cast v7, Ll60/c;

    .line 82
    .line 83
    const/4 v14, 0x1

    .line 84
    const/16 v15, 0x1f

    .line 85
    .line 86
    const/4 v8, 0x0

    .line 87
    const/4 v9, 0x0

    .line 88
    const/4 v10, 0x0

    .line 89
    const/4 v11, 0x0

    .line 90
    const/4 v12, 0x0

    .line 91
    const/4 v13, 0x0

    .line 92
    invoke-static/range {v7 .. v15}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    invoke-virtual {v4, v5}, Lql0/j;->g(Lql0/h;)V

    .line 97
    .line 98
    .line 99
    iget-object v4, v4, Ll60/e;->m:Lbh0/k;

    .line 100
    .line 101
    iput v6, v0, Ll60/a;->e:I

    .line 102
    .line 103
    iget-object v4, v4, Lbh0/k;->a:Lbh0/a;

    .line 104
    .line 105
    check-cast v4, Lzg0/a;

    .line 106
    .line 107
    new-instance v5, Lzg0/g;

    .line 108
    .line 109
    invoke-direct {v5, v2}, Lzg0/g;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v4, v5}, Lzg0/a;->a(Lzg0/h;)Lyy0/m1;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-static {v2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    if-ne v0, v1, :cond_5

    .line 121
    .line 122
    move-object v3, v1

    .line 123
    :cond_5
    :goto_1
    return-object v3

    .line 124
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 125
    .line 126
    iget v7, v0, Ll60/a;->e:I

    .line 127
    .line 128
    if-eqz v7, :cond_7

    .line 129
    .line 130
    if-ne v7, v6, :cond_6

    .line 131
    .line 132
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 137
    .line 138
    invoke-direct {v0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    throw v0

    .line 142
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    iget-object v5, v4, Ll60/e;->h:Lk60/a;

    .line 146
    .line 147
    invoke-static {v5}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v5

    .line 151
    check-cast v5, Lyy0/i;

    .line 152
    .line 153
    iget-object v7, v4, Ll60/e;->p:Ltn0/d;

    .line 154
    .line 155
    sget-object v8, Lun0/a;->g:Lun0/a;

    .line 156
    .line 157
    invoke-virtual {v7, v8}, Ltn0/d;->a(Lun0/a;)Lyy0/i;

    .line 158
    .line 159
    .line 160
    move-result-object v7

    .line 161
    new-instance v8, Lhk0/a;

    .line 162
    .line 163
    const/4 v9, 0x3

    .line 164
    invoke-direct {v8, v4, v2, v9}, Lhk0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 165
    .line 166
    .line 167
    iput v6, v0, Ll60/a;->e:I

    .line 168
    .line 169
    const/4 v4, 0x2

    .line 170
    new-array v4, v4, [Lyy0/i;

    .line 171
    .line 172
    const/4 v9, 0x0

    .line 173
    aput-object v5, v4, v9

    .line 174
    .line 175
    aput-object v7, v4, v6

    .line 176
    .line 177
    new-instance v5, Lyy0/g1;

    .line 178
    .line 179
    invoke-direct {v5, v8, v2}, Lyy0/g1;-><init>(Lay0/o;Lkotlin/coroutines/Continuation;)V

    .line 180
    .line 181
    .line 182
    sget-object v2, Lyy0/h1;->d:Lyy0/h1;

    .line 183
    .line 184
    sget-object v6, Lzy0/q;->d:Lzy0/q;

    .line 185
    .line 186
    invoke-static {v2, v5, v0, v6, v4}, Lzy0/c;->a(Lay0/a;Lay0/o;Lkotlin/coroutines/Continuation;Lyy0/j;[Lyy0/i;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 191
    .line 192
    if-ne v0, v2, :cond_8

    .line 193
    .line 194
    goto :goto_2

    .line 195
    :cond_8
    move-object v0, v3

    .line 196
    :goto_2
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 197
    .line 198
    if-ne v0, v2, :cond_9

    .line 199
    .line 200
    goto :goto_3

    .line 201
    :cond_9
    move-object v0, v3

    .line 202
    :goto_3
    if-ne v0, v1, :cond_a

    .line 203
    .line 204
    move-object v3, v1

    .line 205
    :cond_a
    :goto_4
    return-object v3

    .line 206
    nop

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
