.class public final Lr60/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lr60/g;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lr60/g;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lr60/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/e;->f:Lr60/g;

    .line 4
    .line 5
    iput-object p2, p0, Lr60/e;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lr60/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lr60/e;

    .line 7
    .line 8
    iget-object v0, p0, Lr60/e;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lr60/e;->f:Lr60/g;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lr60/e;-><init>(Lr60/g;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lr60/e;

    .line 18
    .line 19
    iget-object v0, p0, Lr60/e;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lr60/e;->f:Lr60/g;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lr60/e;-><init>(Lr60/g;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lr60/e;->d:I

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
    invoke-virtual {p0, p1, p2}, Lr60/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lr60/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lr60/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lr60/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lr60/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lr60/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lr60/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lr60/e;->e:I

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    iget-object v6, v0, Lr60/e;->f:Lr60/g;

    .line 17
    .line 18
    if-eqz v2, :cond_3

    .line 19
    .line 20
    if-eq v2, v4, :cond_2

    .line 21
    .line 22
    if-ne v2, v3, :cond_1

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    move-object v1, v5

    .line 28
    goto :goto_3

    .line 29
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    move-object/from16 v2, p1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    move-object v7, v2

    .line 51
    check-cast v7, Lr60/b;

    .line 52
    .line 53
    const/16 v17, 0x0

    .line 54
    .line 55
    const/16 v18, 0x1ff

    .line 56
    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v10, 0x0

    .line 60
    const/4 v11, 0x0

    .line 61
    const/4 v12, 0x0

    .line 62
    const/4 v13, 0x0

    .line 63
    const/4 v14, 0x0

    .line 64
    const/4 v15, 0x0

    .line 65
    const/16 v16, 0x0

    .line 66
    .line 67
    invoke-static/range {v7 .. v18}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-virtual {v6, v2}, Lql0/j;->g(Lql0/h;)V

    .line 72
    .line 73
    .line 74
    iget-object v2, v6, Lr60/g;->j:Lp60/i0;

    .line 75
    .line 76
    iget-object v7, v0, Lr60/e;->g:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v7}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 79
    .line 80
    .line 81
    move-result-wide v7

    .line 82
    iput v4, v0, Lr60/e;->e:I

    .line 83
    .line 84
    iget-object v2, v2, Lp60/i0;->a:Lln0/l;

    .line 85
    .line 86
    iget-object v4, v2, Lln0/l;->a:Lxl0/f;

    .line 87
    .line 88
    new-instance v9, Lln0/k;

    .line 89
    .line 90
    invoke-direct {v9, v2, v7, v8, v10}, Lln0/k;-><init>(Lln0/l;JLkotlin/coroutines/Continuation;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4, v9}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    if-ne v2, v1, :cond_4

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_4
    :goto_0
    check-cast v2, Lyy0/i;

    .line 101
    .line 102
    iput v3, v0, Lr60/e;->e:I

    .line 103
    .line 104
    new-instance v3, Lqg/l;

    .line 105
    .line 106
    const/4 v4, 0x4

    .line 107
    sget-object v7, Lzy0/q;->d:Lzy0/q;

    .line 108
    .line 109
    invoke-direct {v3, v4, v7, v6}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-interface {v2, v3, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    if-ne v0, v1, :cond_5

    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_5
    move-object v0, v5

    .line 120
    :goto_1
    if-ne v0, v1, :cond_6

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_6
    move-object v0, v5

    .line 124
    :goto_2
    if-ne v0, v1, :cond_0

    .line 125
    .line 126
    :goto_3
    return-object v1

    .line 127
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 128
    .line 129
    iget v2, v0, Lr60/e;->e:I

    .line 130
    .line 131
    iget-object v3, v0, Lr60/e;->g:Ljava/lang/String;

    .line 132
    .line 133
    iget-object v4, v0, Lr60/e;->f:Lr60/g;

    .line 134
    .line 135
    const/4 v5, 0x2

    .line 136
    const/4 v6, 0x1

    .line 137
    if-eqz v2, :cond_9

    .line 138
    .line 139
    if-eq v2, v6, :cond_8

    .line 140
    .line 141
    if-ne v2, v5, :cond_7

    .line 142
    .line 143
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 148
    .line 149
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 150
    .line 151
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    throw v0

    .line 155
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    move-object/from16 v2, p1

    .line 159
    .line 160
    goto :goto_4

    .line 161
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    iget-object v2, v4, Lr60/g;->w:Lp60/g0;

    .line 165
    .line 166
    iput v6, v0, Lr60/e;->e:I

    .line 167
    .line 168
    iget-object v2, v2, Lp60/g0;->a:Lln0/l;

    .line 169
    .line 170
    const-string v6, "cardId"

    .line 171
    .line 172
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    iget-object v6, v2, Lln0/l;->a:Lxl0/f;

    .line 176
    .line 177
    new-instance v7, La2/c;

    .line 178
    .line 179
    const/4 v8, 0x0

    .line 180
    const/16 v9, 0x1c

    .line 181
    .line 182
    invoke-direct {v7, v9, v2, v3, v8}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {v6, v7}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    if-ne v2, v1, :cond_a

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_a
    :goto_4
    check-cast v2, Lyy0/i;

    .line 193
    .line 194
    new-instance v6, Lqg/l;

    .line 195
    .line 196
    const/4 v7, 0x3

    .line 197
    invoke-direct {v6, v7, v4, v3}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    iput v5, v0, Lr60/e;->e:I

    .line 201
    .line 202
    invoke-interface {v2, v6, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    if-ne v0, v1, :cond_b

    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_b
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    :goto_6
    return-object v1

    .line 212
    nop

    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
