.class public final Lk20/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lk20/m;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lk20/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lk20/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk20/k;->f:Lk20/m;

    .line 4
    .line 5
    iput-object p2, p0, Lk20/k;->g:Ljava/lang/String;

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
    iget p1, p0, Lk20/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lk20/k;

    .line 7
    .line 8
    iget-object v0, p0, Lk20/k;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lk20/k;->f:Lk20/m;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lk20/k;-><init>(Lk20/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lk20/k;

    .line 18
    .line 19
    iget-object v0, p0, Lk20/k;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lk20/k;->f:Lk20/m;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lk20/k;-><init>(Lk20/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lk20/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lk20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lk20/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lk20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lk20/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lk20/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lk20/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lk20/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lk20/k;->e:I

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
    goto :goto_4

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
    iget-object p1, p0, Lk20/k;->f:Lk20/m;

    .line 31
    .line 32
    iget-object v1, p1, Lk20/m;->m:Lbd0/c;

    .line 33
    .line 34
    const/16 v3, 0x1e

    .line 35
    .line 36
    and-int/lit8 v4, v3, 0x2

    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    if-eqz v4, :cond_2

    .line 40
    .line 41
    move v8, v2

    .line 42
    goto :goto_0

    .line 43
    :cond_2
    move v8, v5

    .line 44
    :goto_0
    and-int/lit8 v4, v3, 0x4

    .line 45
    .line 46
    if-eqz v4, :cond_3

    .line 47
    .line 48
    move v9, v2

    .line 49
    goto :goto_1

    .line 50
    :cond_3
    move v9, v5

    .line 51
    :goto_1
    and-int/lit8 v4, v3, 0x8

    .line 52
    .line 53
    if-eqz v4, :cond_4

    .line 54
    .line 55
    move v10, v5

    .line 56
    goto :goto_2

    .line 57
    :cond_4
    move v10, v2

    .line 58
    :goto_2
    and-int/lit8 v3, v3, 0x10

    .line 59
    .line 60
    if-eqz v3, :cond_5

    .line 61
    .line 62
    move v11, v5

    .line 63
    goto :goto_3

    .line 64
    :cond_5
    move v11, v2

    .line 65
    :goto_3
    const-string v3, "url"

    .line 66
    .line 67
    iget-object v4, p0, Lk20/k;->g:Ljava/lang/String;

    .line 68
    .line 69
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v1, v1, Lbd0/c;->a:Lbd0/a;

    .line 73
    .line 74
    new-instance v7, Ljava/net/URL;

    .line 75
    .line 76
    invoke-direct {v7, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    move-object v6, v1

    .line 80
    check-cast v6, Lzc0/b;

    .line 81
    .line 82
    invoke-virtual/range {v6 .. v11}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    new-instance v3, Lk20/j;

    .line 87
    .line 88
    const/4 v4, 0x2

    .line 89
    invoke-direct {v3, p1, v4}, Lk20/j;-><init>(Lk20/m;I)V

    .line 90
    .line 91
    .line 92
    iput v2, p0, Lk20/k;->e:I

    .line 93
    .line 94
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v0, :cond_6

    .line 99
    .line 100
    goto :goto_5

    .line 101
    :cond_6
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    :goto_5
    return-object v0

    .line 104
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v1, p0, Lk20/k;->e:I

    .line 107
    .line 108
    const/4 v2, 0x1

    .line 109
    if-eqz v1, :cond_8

    .line 110
    .line 111
    if-ne v1, v2, :cond_7

    .line 112
    .line 113
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    goto :goto_a

    .line 117
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 118
    .line 119
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 120
    .line 121
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Lk20/k;->f:Lk20/m;

    .line 129
    .line 130
    iget-object v1, p1, Lk20/m;->m:Lbd0/c;

    .line 131
    .line 132
    const/16 v3, 0x1e

    .line 133
    .line 134
    and-int/lit8 v4, v3, 0x2

    .line 135
    .line 136
    const/4 v5, 0x0

    .line 137
    if-eqz v4, :cond_9

    .line 138
    .line 139
    move v8, v2

    .line 140
    goto :goto_6

    .line 141
    :cond_9
    move v8, v5

    .line 142
    :goto_6
    and-int/lit8 v4, v3, 0x4

    .line 143
    .line 144
    if-eqz v4, :cond_a

    .line 145
    .line 146
    move v9, v2

    .line 147
    goto :goto_7

    .line 148
    :cond_a
    move v9, v5

    .line 149
    :goto_7
    and-int/lit8 v4, v3, 0x8

    .line 150
    .line 151
    if-eqz v4, :cond_b

    .line 152
    .line 153
    move v10, v5

    .line 154
    goto :goto_8

    .line 155
    :cond_b
    move v10, v2

    .line 156
    :goto_8
    and-int/lit8 v3, v3, 0x10

    .line 157
    .line 158
    if-eqz v3, :cond_c

    .line 159
    .line 160
    move v11, v5

    .line 161
    goto :goto_9

    .line 162
    :cond_c
    move v11, v2

    .line 163
    :goto_9
    const-string v3, "url"

    .line 164
    .line 165
    iget-object v4, p0, Lk20/k;->g:Ljava/lang/String;

    .line 166
    .line 167
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    iget-object v1, v1, Lbd0/c;->a:Lbd0/a;

    .line 171
    .line 172
    new-instance v7, Ljava/net/URL;

    .line 173
    .line 174
    invoke-direct {v7, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    move-object v6, v1

    .line 178
    check-cast v6, Lzc0/b;

    .line 179
    .line 180
    invoke-virtual/range {v6 .. v11}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    new-instance v3, Lk20/j;

    .line 185
    .line 186
    const/4 v4, 0x0

    .line 187
    invoke-direct {v3, p1, v4}, Lk20/j;-><init>(Lk20/m;I)V

    .line 188
    .line 189
    .line 190
    iput v2, p0, Lk20/k;->e:I

    .line 191
    .line 192
    invoke-virtual {v1, v3, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    if-ne p0, v0, :cond_d

    .line 197
    .line 198
    goto :goto_b

    .line 199
    :cond_d
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    :goto_b
    return-object v0

    .line 202
    nop

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
