.class public final Lh50/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh50/h;


# direct methods
.method public synthetic constructor <init>(Lh50/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh50/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh50/f;->f:Lh50/h;

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
    iget p1, p0, Lh50/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh50/f;

    .line 7
    .line 8
    iget-object p0, p0, Lh50/f;->f:Lh50/h;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh50/f;-><init>(Lh50/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh50/f;

    .line 16
    .line 17
    iget-object p0, p0, Lh50/f;->f:Lh50/h;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh50/f;-><init>(Lh50/h;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh50/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh50/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh50/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh50/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh50/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh50/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh50/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lh50/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh50/f;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    iget-object v4, p0, Lh50/f;->f:Lh50/h;

    .line 13
    .line 14
    if-eqz v1, :cond_2

    .line 15
    .line 16
    if-eq v1, v3, :cond_1

    .line 17
    .line 18
    if-ne v1, v2, :cond_0

    .line 19
    .line 20
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget-object p1, v4, Lh50/h;->j:Lpp0/s;

    .line 40
    .line 41
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    check-cast p1, Ljava/lang/String;

    .line 46
    .line 47
    iget-object v1, v4, Lh50/h;->k:Lpp0/e;

    .line 48
    .line 49
    new-instance v5, Lpp0/c;

    .line 50
    .line 51
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    check-cast v6, Lh50/e;

    .line 56
    .line 57
    iget-object v6, v6, Lh50/e;->c:Ljava/lang/String;

    .line 58
    .line 59
    invoke-direct {v5, v6, p1}, Lpp0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    iput v3, p0, Lh50/f;->e:I

    .line 63
    .line 64
    invoke-virtual {v1, v5, p0}, Lpp0/e;->b(Lpp0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v0, :cond_3

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_3
    :goto_0
    check-cast p1, Lyy0/i;

    .line 72
    .line 73
    new-instance v1, Lgt0/c;

    .line 74
    .line 75
    const/4 v3, 0x7

    .line 76
    invoke-direct {v1, v4, v3}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    iput v2, p0, Lh50/f;->e:I

    .line 80
    .line 81
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v0, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    :goto_2
    return-object v0

    .line 91
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 92
    .line 93
    iget v1, p0, Lh50/f;->e:I

    .line 94
    .line 95
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    const/4 v3, 0x1

    .line 98
    iget-object v4, p0, Lh50/f;->f:Lh50/h;

    .line 99
    .line 100
    if-eqz v1, :cond_6

    .line 101
    .line 102
    if-ne v1, v3, :cond_5

    .line 103
    .line 104
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iput v3, p0, Lh50/f;->e:I

    .line 120
    .line 121
    iget-object p1, v4, Lql0/j;->g:Lyy0/l1;

    .line 122
    .line 123
    new-instance v1, La50/h;

    .line 124
    .line 125
    const/16 v3, 0x1b

    .line 126
    .line 127
    invoke-direct {v1, p1, v3}, La50/h;-><init>(Lyy0/i;I)V

    .line 128
    .line 129
    .line 130
    invoke-static {v1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v0, :cond_7

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_7
    move-object p0, v2

    .line 138
    :goto_3
    if-ne p0, v0, :cond_8

    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_8
    :goto_4
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    move-object v5, p0

    .line 146
    check-cast v5, Lh50/e;

    .line 147
    .line 148
    iget-object p0, v4, Lh50/h;->h:Lij0/a;

    .line 149
    .line 150
    new-instance v9, Lyj0/a;

    .line 151
    .line 152
    const/4 p1, 0x0

    .line 153
    new-array v0, p1, [Ljava/lang/Object;

    .line 154
    .line 155
    check-cast p0, Ljj0/f;

    .line 156
    .line 157
    const v1, 0x7f120665

    .line 158
    .line 159
    .line 160
    invoke-virtual {p0, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    const v1, 0x7f120666

    .line 165
    .line 166
    .line 167
    new-array v3, p1, [Ljava/lang/Object;

    .line 168
    .line 169
    invoke-virtual {p0, v1, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    const v3, 0x7f120668

    .line 174
    .line 175
    .line 176
    new-array p1, p1, [Ljava/lang/Object;

    .line 177
    .line 178
    invoke-virtual {p0, v3, p1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-direct {v9, v0, v1, p0}, Lyj0/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    const/4 v10, 0x6

    .line 186
    const/4 v6, 0x0

    .line 187
    const/4 v7, 0x0

    .line 188
    const/4 v8, 0x0

    .line 189
    invoke-static/range {v5 .. v10}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 190
    .line 191
    .line 192
    move-result-object p0

    .line 193
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 194
    .line 195
    .line 196
    move-object v0, v2

    .line 197
    :goto_5
    return-object v0

    .line 198
    nop

    .line 199
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
