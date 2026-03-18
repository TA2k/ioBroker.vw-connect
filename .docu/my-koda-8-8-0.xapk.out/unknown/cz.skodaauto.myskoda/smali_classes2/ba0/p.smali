.class public final Lba0/p;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lba0/q;

.field public final synthetic h:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lba0/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lba0/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lba0/p;->g:Lba0/q;

    .line 4
    .line 5
    iput-object p2, p0, Lba0/p;->h:Ljava/lang/String;

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
    .locals 3

    .line 1
    iget v0, p0, Lba0/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lba0/p;

    .line 7
    .line 8
    iget-object v1, p0, Lba0/p;->h:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lba0/p;->g:Lba0/q;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lba0/p;-><init>(Lba0/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lba0/p;->f:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lba0/p;

    .line 20
    .line 21
    iget-object v1, p0, Lba0/p;->h:Ljava/lang/String;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lba0/p;->g:Lba0/q;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lba0/p;-><init>(Lba0/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lba0/p;->f:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lba0/p;->d:I

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
    invoke-virtual {p0, p1, p2}, Lba0/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lba0/p;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lba0/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lba0/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lba0/p;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lba0/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 14

    .line 1
    iget v0, p0, Lba0/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lba0/p;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lba0/p;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    if-eqz v2, :cond_1

    .line 16
    .line 17
    if-ne v2, v3, :cond_0

    .line 18
    .line 19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lba0/i;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    iget-object v4, p0, Lba0/p;->g:Lba0/q;

    .line 38
    .line 39
    invoke-direct {p1, v4, v2}, Lba0/i;-><init>(Lba0/q;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, v4, Lba0/q;->j:Lz90/b;

    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    const-string v0, "input"

    .line 51
    .line 52
    iget-object v2, p0, Lba0/p;->h:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, p1, Lz90/b;->a:Lx90/b;

    .line 58
    .line 59
    iget-object v0, p1, Lx90/b;->a:Lxl0/f;

    .line 60
    .line 61
    new-instance v5, Llo0/b;

    .line 62
    .line 63
    const/16 v6, 0x1d

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    invoke-direct {v5, v6, p1, v2, v7}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, v5}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    new-instance v0, Lba0/o;

    .line 74
    .line 75
    const/4 v2, 0x1

    .line 76
    invoke-direct {v0, v4, v2}, Lba0/o;-><init>(Lba0/q;I)V

    .line 77
    .line 78
    .line 79
    iput-object v7, p0, Lba0/p;->f:Ljava/lang/Object;

    .line 80
    .line 81
    iput v3, p0, Lba0/p;->e:I

    .line 82
    .line 83
    invoke-virtual {p1, v0, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-ne p0, v1, :cond_2

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_2
    :goto_0
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    :goto_1
    return-object v1

    .line 93
    :pswitch_0
    iget-object v0, p0, Lba0/p;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Lvy0/b0;

    .line 96
    .line 97
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v2, p0, Lba0/p;->e:I

    .line 100
    .line 101
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    const/4 v4, 0x1

    .line 104
    if-eqz v2, :cond_5

    .line 105
    .line 106
    if-ne v2, v4, :cond_4

    .line 107
    .line 108
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_3
    move-object v1, v3

    .line 112
    goto :goto_3

    .line 113
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 116
    .line 117
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw p0

    .line 121
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    new-instance p1, Lba0/i;

    .line 125
    .line 126
    const/4 v2, 0x3

    .line 127
    iget-object v5, p0, Lba0/p;->g:Lba0/q;

    .line 128
    .line 129
    invoke-direct {p1, v5, v2}, Lba0/i;-><init>(Lba0/q;I)V

    .line 130
    .line 131
    .line 132
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    move-object v6, p1

    .line 140
    check-cast v6, Lba0/l;

    .line 141
    .line 142
    const/4 v12, 0x0

    .line 143
    const/16 v13, 0x3b

    .line 144
    .line 145
    const/4 v7, 0x0

    .line 146
    const/4 v8, 0x0

    .line 147
    const/4 v9, 0x0

    .line 148
    const/4 v10, 0x0

    .line 149
    const/4 v11, 0x0

    .line 150
    invoke-static/range {v6 .. v13}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {v5, p1}, Lql0/j;->g(Lql0/h;)V

    .line 155
    .line 156
    .line 157
    iget-object p1, v5, Lba0/q;->p:Lz90/x;

    .line 158
    .line 159
    new-instance v0, Laa0/c;

    .line 160
    .line 161
    iget-object v2, p0, Lba0/p;->h:Ljava/lang/String;

    .line 162
    .line 163
    invoke-direct {v0, v2}, Laa0/c;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    iget-object p1, p1, Lz90/x;->a:Lz90/p;

    .line 167
    .line 168
    check-cast p1, Lx90/a;

    .line 169
    .line 170
    iget-object p1, p1, Lx90/a;->d:Lyy0/c2;

    .line 171
    .line 172
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    const/4 p1, 0x0

    .line 176
    iput-object p1, p0, Lba0/p;->f:Ljava/lang/Object;

    .line 177
    .line 178
    iput v4, p0, Lba0/p;->e:I

    .line 179
    .line 180
    iget-object p1, v5, Lba0/q;->i:Lz90/a;

    .line 181
    .line 182
    invoke-virtual {p1, v2}, Lz90/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    new-instance v0, Lba0/o;

    .line 187
    .line 188
    const/4 v2, 0x0

    .line 189
    invoke-direct {v0, v5, v2}, Lba0/o;-><init>(Lba0/q;I)V

    .line 190
    .line 191
    .line 192
    check-cast p1, Lzy0/f;

    .line 193
    .line 194
    invoke-virtual {p1, v0, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-ne p0, v1, :cond_6

    .line 199
    .line 200
    goto :goto_2

    .line 201
    :cond_6
    move-object p0, v3

    .line 202
    :goto_2
    if-ne p0, v1, :cond_3

    .line 203
    .line 204
    :goto_3
    return-object v1

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
