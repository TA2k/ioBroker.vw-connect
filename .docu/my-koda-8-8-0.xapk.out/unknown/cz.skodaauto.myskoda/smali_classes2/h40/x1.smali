.class public final Lh40/x1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/z1;


# direct methods
.method public synthetic constructor <init>(Lh40/z1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/x1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/x1;->f:Lh40/z1;

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
    iget p1, p0, Lh40/x1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/x1;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/x1;->f:Lh40/z1;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/x1;-><init>(Lh40/z1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/x1;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/x1;->f:Lh40/z1;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/x1;-><init>(Lh40/z1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lh40/x1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lh40/x1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/x1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/x1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/x1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/x1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/x1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lh40/x1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh40/x1;->e:I

    .line 9
    .line 10
    const/4 v2, 0x3

    .line 11
    const/4 v3, 0x2

    .line 12
    iget-object v4, p0, Lh40/x1;->f:Lh40/z1;

    .line 13
    .line 14
    const/4 v5, 0x1

    .line 15
    if-eqz v1, :cond_3

    .line 16
    .line 17
    if-eq v1, v5, :cond_2

    .line 18
    .line 19
    if-eq v1, v3, :cond_1

    .line 20
    .line 21
    if-ne v1, v2, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_2

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget-object p1, v4, Lh40/z1;->v:Lcr0/e;

    .line 47
    .line 48
    new-instance v1, Lcr0/c;

    .line 49
    .line 50
    invoke-direct {v1, v5}, Lcr0/c;-><init>(Z)V

    .line 51
    .line 52
    .line 53
    iput v5, p0, Lh40/x1;->e:I

    .line 54
    .line 55
    invoke-virtual {p1, v1, p0}, Lcr0/e;->b(Lcr0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v0, :cond_4

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_4
    :goto_0
    check-cast p1, Ljava/lang/String;

    .line 63
    .line 64
    iget-object v1, v4, Lh40/z1;->w:Lkc0/h0;

    .line 65
    .line 66
    new-instance v5, Ldd0/a;

    .line 67
    .line 68
    const/16 v6, 0x1e

    .line 69
    .line 70
    invoke-direct {v5, p1, v6}, Ldd0/a;-><init>(Ljava/lang/String;I)V

    .line 71
    .line 72
    .line 73
    iput v3, p0, Lh40/x1;->e:I

    .line 74
    .line 75
    invoke-virtual {v1, v5, p0}, Lkc0/h0;->b(Ldd0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    if-ne p1, v0, :cond_5

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_5
    :goto_1
    check-cast p1, Lyy0/i;

    .line 83
    .line 84
    new-instance v1, Lh40/y1;

    .line 85
    .line 86
    const/4 v3, 0x1

    .line 87
    invoke-direct {v1, v4, v3}, Lh40/y1;-><init>(Lh40/z1;I)V

    .line 88
    .line 89
    .line 90
    iput v2, p0, Lh40/x1;->e:I

    .line 91
    .line 92
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v0, :cond_6

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_6
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    :goto_3
    return-object v0

    .line 102
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    iget v1, p0, Lh40/x1;->e:I

    .line 105
    .line 106
    const/4 v2, 0x2

    .line 107
    const/4 v3, 0x1

    .line 108
    if-eqz v1, :cond_9

    .line 109
    .line 110
    if-eq v1, v3, :cond_7

    .line 111
    .line 112
    if-ne v1, v2, :cond_8

    .line 113
    .line 114
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 119
    .line 120
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 121
    .line 122
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p0

    .line 126
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iget-object p1, p0, Lh40/x1;->f:Lh40/z1;

    .line 130
    .line 131
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    check-cast v1, Lh40/u1;

    .line 136
    .line 137
    iget-object v1, v1, Lh40/u1;->a:Lh40/z;

    .line 138
    .line 139
    if-eqz v1, :cond_c

    .line 140
    .line 141
    iget-object v4, v1, Lh40/z;->f:Lg40/c0;

    .line 142
    .line 143
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 144
    .line 145
    .line 146
    move-result v4

    .line 147
    if-eqz v4, :cond_b

    .line 148
    .line 149
    if-ne v4, v3, :cond_a

    .line 150
    .line 151
    iget-object v1, p1, Lh40/z1;->p:Lf40/b;

    .line 152
    .line 153
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v1

    .line 157
    check-cast v1, Lyy0/i;

    .line 158
    .line 159
    new-instance v3, Lh40/w1;

    .line 160
    .line 161
    const/4 v4, 0x1

    .line 162
    invoke-direct {v3, p1, v4}, Lh40/w1;-><init>(Lh40/z1;I)V

    .line 163
    .line 164
    .line 165
    iput v2, p0, Lh40/x1;->e:I

    .line 166
    .line 167
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    if-ne p0, v0, :cond_c

    .line 172
    .line 173
    goto :goto_5

    .line 174
    :cond_a
    new-instance p0, La8/r0;

    .line 175
    .line 176
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_b
    iget-object v2, p1, Lh40/z1;->u:Lf40/d;

    .line 181
    .line 182
    new-instance v4, Lf40/c;

    .line 183
    .line 184
    iget-object v1, v1, Lh40/z;->j:Ljava/lang/String;

    .line 185
    .line 186
    invoke-direct {v4, v1}, Lf40/c;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v2, v4}, Lf40/d;->a(Lf40/c;)Lyy0/m1;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    new-instance v2, Lh40/w1;

    .line 194
    .line 195
    const/4 v4, 0x0

    .line 196
    invoke-direct {v2, p1, v4}, Lh40/w1;-><init>(Lh40/z1;I)V

    .line 197
    .line 198
    .line 199
    iput v3, p0, Lh40/x1;->e:I

    .line 200
    .line 201
    invoke-virtual {v1, v2, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    if-ne p0, v0, :cond_c

    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_c
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    :goto_5
    return-object v0

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
