.class public final La50/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:La50/j;


# direct methods
.method public synthetic constructor <init>(La50/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, La50/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La50/e;->f:La50/j;

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
    iget p1, p0, La50/e;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, La50/e;

    .line 7
    .line 8
    iget-object p0, p0, La50/e;->f:La50/j;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, La50/e;

    .line 16
    .line 17
    iget-object p0, p0, La50/e;->f:La50/j;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, La50/e;

    .line 25
    .line 26
    iget-object p0, p0, La50/e;->f:La50/j;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, La50/e;-><init>(La50/j;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, La50/e;->d:I

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
    invoke-virtual {p0, p1, p2}, La50/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, La50/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, La50/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, La50/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, La50/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, La50/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, La50/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, La50/e;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, La50/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, La50/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, La50/e;->e:I

    .line 9
    .line 10
    iget-object v2, p0, La50/e;->f:La50/j;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, La50/j;->h:Lal0/o1;

    .line 33
    .line 34
    iput v3, p0, La50/e;->e:I

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-virtual {p1, v1, p0}, Lal0/o1;->b(Lbl0/h0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-ne p0, v0, :cond_2

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    :goto_0
    iget-object p0, v2, La50/j;->k:Ltr0/b;

    .line 45
    .line 46
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    :goto_1
    return-object v0

    .line 52
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    iget v1, p0, La50/e;->e:I

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    if-eqz v1, :cond_4

    .line 58
    .line 59
    if-ne v1, v2, :cond_3

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object v5, p0, La50/e;->f:La50/j;

    .line 77
    .line 78
    iget-object p1, v5, La50/j;->j:Lwj0/r;

    .line 79
    .line 80
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    check-cast p1, Lyy0/i;

    .line 85
    .line 86
    new-instance v1, La50/h;

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    invoke-direct {v1, p1, v3}, La50/h;-><init>(Lyy0/i;I)V

    .line 90
    .line 91
    .line 92
    new-instance v3, La50/d;

    .line 93
    .line 94
    const/4 v9, 0x4

    .line 95
    const/4 v10, 0x1

    .line 96
    const/4 v4, 0x2

    .line 97
    const-class v6, La50/j;

    .line 98
    .line 99
    const-string v7, "onSelectedPin"

    .line 100
    .line 101
    const-string v8, "onSelectedPin(Z)V"

    .line 102
    .line 103
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 104
    .line 105
    .line 106
    iput v2, p0, La50/e;->e:I

    .line 107
    .line 108
    invoke-static {v3, p0, v1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    if-ne p0, v0, :cond_5

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    :goto_3
    return-object v0

    .line 118
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v1, p0, La50/e;->e:I

    .line 121
    .line 122
    iget-object v4, p0, La50/e;->f:La50/j;

    .line 123
    .line 124
    const/4 v10, 0x2

    .line 125
    const/4 v2, 0x1

    .line 126
    if-eqz v1, :cond_8

    .line 127
    .line 128
    if-eq v1, v2, :cond_7

    .line 129
    .line 130
    if-ne v1, v10, :cond_6

    .line 131
    .line 132
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 133
    .line 134
    .line 135
    goto :goto_5

    .line 136
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 137
    .line 138
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 139
    .line 140
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw p0

    .line 144
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    iget-object p1, v4, La50/j;->i:Luk0/a0;

    .line 152
    .line 153
    iput v2, p0, La50/e;->e:I

    .line 154
    .line 155
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 156
    .line 157
    .line 158
    iget-object v1, p1, Luk0/a0;->a:Lal0/s0;

    .line 159
    .line 160
    invoke-virtual {v1}, Lal0/s0;->invoke()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    check-cast v1, Lyy0/i;

    .line 165
    .line 166
    iget-object v2, p1, Luk0/a0;->b:Lal0/p0;

    .line 167
    .line 168
    invoke-virtual {v2}, Lal0/p0;->invoke()Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    check-cast v2, Lyy0/i;

    .line 173
    .line 174
    iget-object v3, p1, Luk0/a0;->c:Lwj0/r;

    .line 175
    .line 176
    invoke-virtual {v3}, Lwj0/r;->invoke()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v3

    .line 180
    check-cast v3, Lyy0/i;

    .line 181
    .line 182
    new-instance v5, Li50/y;

    .line 183
    .line 184
    const/4 v6, 0x2

    .line 185
    const/4 v7, 0x0

    .line 186
    invoke-direct {v5, p1, v7, v6}, Li50/y;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 187
    .line 188
    .line 189
    invoke-static {v1, v2, v3, v5}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    new-instance v2, Ltr0/e;

    .line 198
    .line 199
    const/16 v3, 0xe

    .line 200
    .line 201
    invoke-direct {v2, v1, v7, p1, v3}, Ltr0/e;-><init>(Lyy0/i;Lkotlin/coroutines/Continuation;Ltr0/c;I)V

    .line 202
    .line 203
    .line 204
    new-instance p1, Lyy0/m1;

    .line 205
    .line 206
    invoke-direct {p1, v2}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 207
    .line 208
    .line 209
    if-ne p1, v0, :cond_9

    .line 210
    .line 211
    goto :goto_6

    .line 212
    :cond_9
    :goto_4
    check-cast p1, Lyy0/i;

    .line 213
    .line 214
    new-instance v2, La50/d;

    .line 215
    .line 216
    const/4 v8, 0x4

    .line 217
    const/4 v9, 0x0

    .line 218
    const/4 v3, 0x2

    .line 219
    const-class v5, La50/j;

    .line 220
    .line 221
    const-string v6, "onSelectedPoi"

    .line 222
    .line 223
    const-string v7, "onSelectedPoi(Lcz/skodaauto/myskoda/library/mapplaces/model/Poi;)V"

    .line 224
    .line 225
    invoke-direct/range {v2 .. v9}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 226
    .line 227
    .line 228
    iput v10, p0, La50/e;->e:I

    .line 229
    .line 230
    invoke-static {v2, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    if-ne p0, v0, :cond_a

    .line 235
    .line 236
    goto :goto_6

    .line 237
    :cond_a
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 238
    .line 239
    :goto_6
    return-object v0

    .line 240
    nop

    .line 241
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
