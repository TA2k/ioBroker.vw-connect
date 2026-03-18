.class public final Ltz/t1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ltz/y1;


# direct methods
.method public synthetic constructor <init>(Ltz/y1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/t1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/t1;->f:Ltz/y1;

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
    iget p1, p0, Ltz/t1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ltz/t1;

    .line 7
    .line 8
    iget-object p0, p0, Ltz/t1;->f:Ltz/y1;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ltz/t1;-><init>(Ltz/y1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ltz/t1;

    .line 16
    .line 17
    iget-object p0, p0, Ltz/t1;->f:Ltz/y1;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ltz/t1;-><init>(Ltz/y1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ltz/t1;

    .line 25
    .line 26
    iget-object p0, p0, Ltz/t1;->f:Ltz/y1;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ltz/t1;-><init>(Ltz/y1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Ltz/t1;->d:I

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
    invoke-virtual {p0, p1, p2}, Ltz/t1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ltz/t1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ltz/t1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ltz/t1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ltz/t1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ltz/t1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ltz/t1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ltz/t1;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ltz/t1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 9

    .line 1
    iget v0, p0, Ltz/t1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ltz/t1;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Ltz/t1;->f:Ltz/y1;

    .line 31
    .line 32
    iget-object v1, p1, Ltz/y1;->s:Lrd0/r;

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    iget-object v3, p1, Ltz/y1;->m:Lqd0/o1;

    .line 37
    .line 38
    invoke-virtual {v3, v1}, Lqd0/o1;->a(Lrd0/r;)Lyy0/m1;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    new-instance v3, Ltz/x1;

    .line 43
    .line 44
    const/4 v4, 0x1

    .line 45
    invoke-direct {v3, p1, v4}, Ltz/x1;-><init>(Ltz/y1;I)V

    .line 46
    .line 47
    .line 48
    iput v2, p0, Ltz/t1;->e:I

    .line 49
    .line 50
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    if-ne p0, v0, :cond_2

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    :goto_1
    return-object v0

    .line 60
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    iget v1, p0, Ltz/t1;->e:I

    .line 63
    .line 64
    const/4 v2, 0x1

    .line 65
    if-eqz v1, :cond_4

    .line 66
    .line 67
    if-ne v1, v2, :cond_3

    .line 68
    .line 69
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-object p1, p0, Ltz/t1;->f:Ltz/y1;

    .line 85
    .line 86
    iget-object v1, p1, Ltz/y1;->s:Lrd0/r;

    .line 87
    .line 88
    if-eqz v1, :cond_5

    .line 89
    .line 90
    iget-object v3, p1, Ltz/y1;->l:Lqd0/f;

    .line 91
    .line 92
    new-instance v4, Lqd0/d;

    .line 93
    .line 94
    iget-wide v5, v1, Lrd0/r;->a:J

    .line 95
    .line 96
    iget-object v1, p1, Ltz/y1;->p:Lij0/a;

    .line 97
    .line 98
    const/4 v7, 0x0

    .line 99
    new-array v7, v7, [Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Ljj0/f;

    .line 102
    .line 103
    const v8, 0x7f120f90

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-direct {v4, v5, v6, v1}, Lqd0/d;-><init>(JLjava/lang/String;)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v3, v4}, Lqd0/f;->a(Lqd0/d;)Lyy0/m1;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    new-instance v3, Ltz/x1;

    .line 118
    .line 119
    const/4 v4, 0x0

    .line 120
    invoke-direct {v3, p1, v4}, Ltz/x1;-><init>(Ltz/y1;I)V

    .line 121
    .line 122
    .line 123
    iput v2, p0, Ltz/t1;->e:I

    .line 124
    .line 125
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-ne p0, v0, :cond_5

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    :goto_3
    return-object v0

    .line 135
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 136
    .line 137
    iget v1, p0, Ltz/t1;->e:I

    .line 138
    .line 139
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    const/4 v3, 0x1

    .line 142
    if-eqz v1, :cond_8

    .line 143
    .line 144
    if-ne v1, v3, :cond_7

    .line 145
    .line 146
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_6
    move-object v0, v2

    .line 150
    goto :goto_5

    .line 151
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 152
    .line 153
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 154
    .line 155
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p0

    .line 159
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object p1, p0, Ltz/t1;->f:Ltz/y1;

    .line 163
    .line 164
    iget-object v1, p1, Ltz/y1;->h:Lqd0/r0;

    .line 165
    .line 166
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    check-cast v1, Lyy0/i;

    .line 171
    .line 172
    new-instance v4, Ls90/a;

    .line 173
    .line 174
    const/4 v5, 0x5

    .line 175
    invoke-direct {v4, p1, v5}, Ls90/a;-><init>(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    iput v3, p0, Ltz/t1;->e:I

    .line 179
    .line 180
    new-instance p1, Lwk0/o0;

    .line 181
    .line 182
    const/16 v3, 0x11

    .line 183
    .line 184
    invoke-direct {p1, v4, v3}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 185
    .line 186
    .line 187
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    if-ne p0, v0, :cond_9

    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_9
    move-object p0, v2

    .line 195
    :goto_4
    if-ne p0, v0, :cond_6

    .line 196
    .line 197
    :goto_5
    return-object v0

    .line 198
    nop

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
