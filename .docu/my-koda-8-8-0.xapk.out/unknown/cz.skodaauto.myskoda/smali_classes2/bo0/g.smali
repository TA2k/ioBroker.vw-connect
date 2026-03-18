.class public final Lbo0/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Object;

.field public final synthetic g:Lbo0/k;


# direct methods
.method public synthetic constructor <init>(Lbo0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbo0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbo0/g;->g:Lbo0/k;

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
    .locals 2

    .line 1
    iget v0, p0, Lbo0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lbo0/g;

    .line 7
    .line 8
    iget-object p0, p0, Lbo0/g;->g:Lbo0/k;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lbo0/g;-><init>(Lbo0/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lbo0/g;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance p1, Lbo0/g;

    .line 18
    .line 19
    iget-object p0, p0, Lbo0/g;->g:Lbo0/k;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-direct {p1, p0, p2, v0}, Lbo0/g;-><init>(Lbo0/k;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lbo0/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lbo0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lbo0/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lbo0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lbo0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lbo0/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lbo0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Lbo0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lbo0/g;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    iget-object v4, p0, Lbo0/g;->g:Lbo0/k;

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    if-ne v2, v3, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Lbo0/f;

    .line 37
    .line 38
    const/4 v2, 0x2

    .line 39
    invoke-direct {p1, v4, v2}, Lbo0/f;-><init>(Lbo0/k;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, v4, Lbo0/k;->k:Lyn0/n;

    .line 46
    .line 47
    new-instance v0, Lne0/e;

    .line 48
    .line 49
    iget-object v2, v4, Lbo0/k;->o:Ljava/util/List;

    .line 50
    .line 51
    invoke-direct {v0, v2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    iput-object v2, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 56
    .line 57
    iput v3, p0, Lbo0/g;->e:I

    .line 58
    .line 59
    invoke-virtual {p1, v0, p0}, Lyn0/n;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    if-ne p0, v1, :cond_2

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    :goto_0
    iget-object p0, v4, Lbo0/k;->h:Ltr0/b;

    .line 67
    .line 68
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    :goto_1
    return-object v1

    .line 74
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v1, p0, Lbo0/g;->e:I

    .line 77
    .line 78
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    const/4 v3, 0x4

    .line 81
    const/4 v4, 0x3

    .line 82
    const/4 v5, 0x2

    .line 83
    const/4 v6, 0x1

    .line 84
    const/4 v7, 0x0

    .line 85
    iget-object v8, p0, Lbo0/g;->g:Lbo0/k;

    .line 86
    .line 87
    if-eqz v1, :cond_8

    .line 88
    .line 89
    if-eq v1, v6, :cond_7

    .line 90
    .line 91
    if-eq v1, v5, :cond_6

    .line 92
    .line 93
    if-eq v1, v4, :cond_4

    .line 94
    .line 95
    if-eq v1, v3, :cond_3

    .line 96
    .line 97
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_3
    iget-object p0, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 106
    .line 107
    check-cast p0, Ljava/lang/Throwable;

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto/16 :goto_6

    .line 113
    .line 114
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    :cond_5
    move-object v0, v2

    .line 118
    goto :goto_5

    .line 119
    :cond_6
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 120
    .line 121
    .line 122
    goto :goto_3

    .line 123
    :catchall_0
    move-exception p1

    .line 124
    goto :goto_4

    .line 125
    :cond_7
    iget-object v1, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v1, Lbo0/k;

    .line 128
    .line 129
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-object p1, v8, Lbo0/k;->m:Lqf0/g;

    .line 137
    .line 138
    iput-object v8, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 139
    .line 140
    iput v6, p0, Lbo0/g;->e:I

    .line 141
    .line 142
    invoke-virtual {p1, v2, p0}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    if-ne p1, v0, :cond_9

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_9
    move-object v1, v8

    .line 150
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 151
    .line 152
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    iput-boolean p1, v1, Lbo0/k;->p:Z

    .line 157
    .line 158
    :try_start_1
    iget-object p1, v8, Lbo0/k;->j:Lyn0/d;

    .line 159
    .line 160
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    check-cast p1, Lyy0/i;

    .line 165
    .line 166
    new-instance v1, La60/b;

    .line 167
    .line 168
    const/4 v6, 0x3

    .line 169
    invoke-direct {v1, v8, v6}, La60/b;-><init>(Lql0/j;I)V

    .line 170
    .line 171
    .line 172
    iput-object v7, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 173
    .line 174
    iput v5, p0, Lbo0/g;->e:I

    .line 175
    .line 176
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 180
    if-ne p1, v0, :cond_a

    .line 181
    .line 182
    goto :goto_5

    .line 183
    :cond_a
    :goto_3
    sget-object p1, Lvy0/t1;->d:Lvy0/t1;

    .line 184
    .line 185
    new-instance v1, La50/a;

    .line 186
    .line 187
    const/16 v3, 0xb

    .line 188
    .line 189
    invoke-direct {v1, v8, v7, v3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 190
    .line 191
    .line 192
    iput v4, p0, Lbo0/g;->e:I

    .line 193
    .line 194
    invoke-static {p1, v1, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-ne p0, v0, :cond_5

    .line 199
    .line 200
    goto :goto_5

    .line 201
    :goto_4
    sget-object v1, Lvy0/t1;->d:Lvy0/t1;

    .line 202
    .line 203
    new-instance v2, La50/a;

    .line 204
    .line 205
    const/16 v4, 0xb

    .line 206
    .line 207
    invoke-direct {v2, v8, v7, v4}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 208
    .line 209
    .line 210
    iput-object p1, p0, Lbo0/g;->f:Ljava/lang/Object;

    .line 211
    .line 212
    iput v3, p0, Lbo0/g;->e:I

    .line 213
    .line 214
    invoke-static {v1, v2, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    if-ne p0, v0, :cond_b

    .line 219
    .line 220
    :goto_5
    return-object v0

    .line 221
    :cond_b
    move-object p0, p1

    .line 222
    :goto_6
    throw p0

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
