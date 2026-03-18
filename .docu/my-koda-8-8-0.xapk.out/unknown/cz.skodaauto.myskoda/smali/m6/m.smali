.class public final Lm6/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lm6/w;


# direct methods
.method public synthetic constructor <init>(Lm6/w;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lm6/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm6/m;->f:Lm6/w;

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
    iget p1, p0, Lm6/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lm6/m;

    .line 7
    .line 8
    iget-object p0, p0, Lm6/m;->f:Lm6/w;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lm6/m;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lm6/m;

    .line 16
    .line 17
    iget-object p0, p0, Lm6/m;->f:Lm6/w;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lm6/m;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lm6/m;

    .line 25
    .line 26
    iget-object p0, p0, Lm6/m;->f:Lm6/w;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lm6/m;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lm6/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lm6/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm6/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm6/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lm6/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lm6/m;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lm6/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lyy0/j;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lm6/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lm6/m;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lm6/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lm6/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lm6/m;->f:Lm6/w;

    .line 7
    .line 8
    iget-object v1, v0, Lm6/w;->h:Lm6/x;

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Lm6/m;->e:I

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    const/4 v5, 0x1

    .line 16
    if-eqz v3, :cond_2

    .line 17
    .line 18
    if-eq v3, v5, :cond_1

    .line 19
    .line 20
    if-ne v3, v4, :cond_0

    .line 21
    .line 22
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v1}, Lm6/x;->a()Lm6/z0;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    instance-of p1, p1, Lm6/h0;

    .line 46
    .line 47
    if-eqz p1, :cond_3

    .line 48
    .line 49
    invoke-virtual {v1}, Lm6/x;->a()Lm6/z0;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    goto :goto_2

    .line 54
    :cond_3
    :try_start_1
    iput v5, p0, Lm6/m;->e:I

    .line 55
    .line 56
    invoke-virtual {v0, p0}, Lm6/w;->h(Lrx0/c;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 60
    if-ne p1, v2, :cond_4

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_4
    :goto_0
    iput v4, p0, Lm6/m;->e:I

    .line 64
    .line 65
    const/4 p1, 0x0

    .line 66
    invoke-static {v0, p1, p0}, Lm6/w;->e(Lm6/w;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v2, :cond_5

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_5
    :goto_1
    move-object v2, p1

    .line 74
    check-cast v2, Lm6/z0;

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    new-instance v2, Lm6/s0;

    .line 79
    .line 80
    const/4 p1, -0x1

    .line 81
    invoke-direct {v2, p0, p1}, Lm6/s0;-><init>(Ljava/lang/Throwable;I)V

    .line 82
    .line 83
    .line 84
    :goto_2
    return-object v2

    .line 85
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 86
    .line 87
    iget v1, p0, Lm6/m;->e:I

    .line 88
    .line 89
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    const/4 v3, 0x2

    .line 92
    const/4 v4, 0x1

    .line 93
    iget-object v5, p0, Lm6/m;->f:Lm6/w;

    .line 94
    .line 95
    if-eqz v1, :cond_9

    .line 96
    .line 97
    if-eq v1, v4, :cond_8

    .line 98
    .line 99
    if-ne v1, v3, :cond_7

    .line 100
    .line 101
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_6
    move-object v0, v2

    .line 105
    goto :goto_5

    .line 106
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 107
    .line 108
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 109
    .line 110
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    throw p0

    .line 114
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iget-object p1, v5, Lm6/w;->i:Lcom/google/firebase/messaging/w;

    .line 122
    .line 123
    iput v4, p0, Lm6/m;->e:I

    .line 124
    .line 125
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p1, Lvy0/r;

    .line 128
    .line 129
    invoke-virtual {p1, p0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    if-ne p1, v0, :cond_a

    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_a
    move-object p1, v2

    .line 137
    :goto_3
    if-ne p1, v0, :cond_b

    .line 138
    .line 139
    goto :goto_5

    .line 140
    :cond_b
    :goto_4
    invoke-virtual {v5}, Lm6/w;->g()Lm6/i0;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-interface {p1}, Lm6/i0;->b()Lyy0/i;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    const/4 v1, -0x1

    .line 149
    invoke-static {p1, v1}, Lyy0/u;->g(Lyy0/i;I)Lyy0/i;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    new-instance v1, Lgt0/c;

    .line 154
    .line 155
    const/16 v4, 0x1b

    .line 156
    .line 157
    invoke-direct {v1, v5, v4}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 158
    .line 159
    .line 160
    iput v3, p0, Lm6/m;->e:I

    .line 161
    .line 162
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    if-ne p0, v0, :cond_6

    .line 167
    .line 168
    :goto_5
    return-object v0

    .line 169
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 170
    .line 171
    iget v1, p0, Lm6/m;->e:I

    .line 172
    .line 173
    const/4 v2, 0x1

    .line 174
    if-eqz v1, :cond_d

    .line 175
    .line 176
    if-ne v1, v2, :cond_c

    .line 177
    .line 178
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 183
    .line 184
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 185
    .line 186
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    throw p0

    .line 190
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    iput v2, p0, Lm6/m;->e:I

    .line 194
    .line 195
    iget-object p1, p0, Lm6/m;->f:Lm6/w;

    .line 196
    .line 197
    invoke-static {p1, p0}, Lm6/w;->d(Lm6/w;Lrx0/c;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    if-ne p0, v0, :cond_e

    .line 202
    .line 203
    goto :goto_7

    .line 204
    :cond_e
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    :goto_7
    return-object v0

    .line 207
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
