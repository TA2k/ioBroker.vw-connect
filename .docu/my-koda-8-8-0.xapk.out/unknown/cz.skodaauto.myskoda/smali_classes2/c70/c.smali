.class public final Lc70/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lc70/e;


# direct methods
.method public synthetic constructor <init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lc70/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc70/c;->f:Lc70/e;

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
    iget p1, p0, Lc70/c;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lc70/c;

    .line 7
    .line 8
    iget-object p0, p0, Lc70/c;->f:Lc70/e;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lc70/c;

    .line 16
    .line 17
    iget-object p0, p0, Lc70/c;->f:Lc70/e;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lc70/c;

    .line 25
    .line 26
    iget-object p0, p0, Lc70/c;->f:Lc70/e;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lc70/c;-><init>(Lc70/e;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lc70/c;->d:I

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
    invoke-virtual {p0, p1, p2}, Lc70/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lc70/c;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lc70/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lc70/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lc70/c;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lc70/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lc70/c;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lc70/c;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lc70/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc70/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lc70/c;->e:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    iget-object v6, v0, Lc70/c;->f:Lc70/e;

    .line 17
    .line 18
    if-eqz v2, :cond_3

    .line 19
    .line 20
    if-eq v2, v5, :cond_2

    .line 21
    .line 22
    if-ne v2, v4, :cond_1

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    move-object v1, v3

    .line 28
    goto :goto_1

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
    iget-object v2, v6, Lc70/e;->o:Lcf0/e;

    .line 47
    .line 48
    iput v5, v0, Lc70/c;->e:I

    .line 49
    .line 50
    invoke-virtual {v2, v3, v0}, Lcf0/e;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    if-ne v2, v1, :cond_4

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_4
    :goto_0
    check-cast v2, Ljava/lang/Boolean;

    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 60
    .line 61
    .line 62
    move-result v14

    .line 63
    invoke-virtual {v6}, Lql0/j;->a()Lql0/h;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    move-object v7, v2

    .line 68
    check-cast v7, Lc70/d;

    .line 69
    .line 70
    const/16 v22, 0x0

    .line 71
    .line 72
    const/16 v23, 0x7fbf

    .line 73
    .line 74
    const/4 v8, 0x0

    .line 75
    const/4 v9, 0x0

    .line 76
    const/4 v10, 0x0

    .line 77
    const/4 v11, 0x0

    .line 78
    const/4 v12, 0x0

    .line 79
    const/4 v13, 0x0

    .line 80
    const/4 v15, 0x0

    .line 81
    const/16 v16, 0x0

    .line 82
    .line 83
    const/16 v17, 0x0

    .line 84
    .line 85
    const/16 v18, 0x0

    .line 86
    .line 87
    const/16 v19, 0x0

    .line 88
    .line 89
    const/16 v20, 0x0

    .line 90
    .line 91
    const/16 v21, 0x0

    .line 92
    .line 93
    invoke-static/range {v7 .. v23}, Lc70/d;->a(Lc70/d;Llf0/i;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZLvf0/k;Lvf0/k;FLjava/lang/Float;Lvf0/l;Lvf0/l;I)Lc70/d;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-virtual {v6, v2}, Lql0/j;->g(Lql0/h;)V

    .line 98
    .line 99
    .line 100
    if-eqz v14, :cond_0

    .line 101
    .line 102
    iget-object v2, v6, Lc70/e;->n:Lep0/b;

    .line 103
    .line 104
    invoke-static {v2}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lyy0/i;

    .line 109
    .line 110
    new-instance v5, Lc70/b;

    .line 111
    .line 112
    const/4 v7, 0x2

    .line 113
    invoke-direct {v5, v6, v7}, Lc70/b;-><init>(Lc70/e;I)V

    .line 114
    .line 115
    .line 116
    iput v4, v0, Lc70/c;->e:I

    .line 117
    .line 118
    invoke-interface {v2, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    if-ne v0, v1, :cond_0

    .line 123
    .line 124
    :goto_1
    return-object v1

    .line 125
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 126
    .line 127
    iget v2, v0, Lc70/c;->e:I

    .line 128
    .line 129
    const/4 v3, 0x1

    .line 130
    if-eqz v2, :cond_6

    .line 131
    .line 132
    if-ne v2, v3, :cond_5

    .line 133
    .line 134
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 139
    .line 140
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 141
    .line 142
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw v0

    .line 146
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    iget-object v2, v0, Lc70/c;->f:Lc70/e;

    .line 150
    .line 151
    iget-object v4, v2, Lc70/e;->i:Lkf0/b0;

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
    new-instance v5, Lc70/b;

    .line 160
    .line 161
    const/4 v6, 0x1

    .line 162
    invoke-direct {v5, v2, v6}, Lc70/b;-><init>(Lc70/e;I)V

    .line 163
    .line 164
    .line 165
    iput v3, v0, Lc70/c;->e:I

    .line 166
    .line 167
    invoke-interface {v4, v5, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    if-ne v0, v1, :cond_7

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_7
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 175
    .line 176
    :goto_3
    return-object v1

    .line 177
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    iget v2, v0, Lc70/c;->e:I

    .line 180
    .line 181
    const/4 v3, 0x1

    .line 182
    if-eqz v2, :cond_9

    .line 183
    .line 184
    if-ne v2, v3, :cond_8

    .line 185
    .line 186
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    goto :goto_4

    .line 190
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 193
    .line 194
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw v0

    .line 198
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    iget-object v2, v0, Lc70/c;->f:Lc70/e;

    .line 202
    .line 203
    iget-object v4, v2, Lc70/e;->h:Lkf0/e0;

    .line 204
    .line 205
    sget-object v5, Lss0/e;->N:Lss0/e;

    .line 206
    .line 207
    invoke-virtual {v4, v5}, Lkf0/e0;->a(Lss0/e;)Lne0/k;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    new-instance v5, La50/c;

    .line 212
    .line 213
    const/4 v6, 0x0

    .line 214
    const/16 v7, 0x1b

    .line 215
    .line 216
    invoke-direct {v5, v2, v6, v7}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 217
    .line 218
    .line 219
    iput v3, v0, Lc70/c;->e:I

    .line 220
    .line 221
    invoke-static {v5, v0, v4}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    if-ne v0, v1, :cond_a

    .line 226
    .line 227
    goto :goto_5

    .line 228
    :cond_a
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    :goto_5
    return-object v1

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
