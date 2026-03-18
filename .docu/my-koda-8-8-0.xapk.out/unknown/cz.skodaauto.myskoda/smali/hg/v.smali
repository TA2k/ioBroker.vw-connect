.class public final Lhg/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lhg/x;


# direct methods
.method public synthetic constructor <init>(Lhg/x;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhg/v;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhg/v;->f:Lhg/x;

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
    iget p1, p0, Lhg/v;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lhg/v;

    .line 7
    .line 8
    iget-object p0, p0, Lhg/v;->f:Lhg/x;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lhg/v;-><init>(Lhg/x;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lhg/v;

    .line 16
    .line 17
    iget-object p0, p0, Lhg/v;->f:Lhg/x;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lhg/v;-><init>(Lhg/x;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lhg/v;->d:I

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
    invoke-virtual {p0, p1, p2}, Lhg/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhg/v;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhg/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lhg/v;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhg/v;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lhg/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lhg/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lhg/v;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lhg/v;->f:Lhg/x;

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
    iget-object p1, v2, Lhg/x;->f:Lh40/w3;

    .line 33
    .line 34
    iget-object v1, v2, Lhg/x;->j:Ljava/lang/String;

    .line 35
    .line 36
    iput v3, p0, Lhg/v;->e:I

    .line 37
    .line 38
    invoke-virtual {p1, v1, p0}, Lh40/w3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-ne p1, v0, :cond_2

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 46
    .line 47
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 48
    .line 49
    instance-of p1, p0, Llx0/n;

    .line 50
    .line 51
    if-nez p1, :cond_5

    .line 52
    .line 53
    move-object p1, p0

    .line 54
    check-cast p1, Leg/u;

    .line 55
    .line 56
    iget-object p1, p1, Leg/u;->b:Lzi/g;

    .line 57
    .line 58
    if-nez p1, :cond_3

    .line 59
    .line 60
    iget-object p1, v2, Lhg/x;->g:Lh90/d;

    .line 61
    .line 62
    invoke-virtual {p1}, Lh90/d;->invoke()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    iget-object v0, p1, Lzi/g;->b:Ljava/util/List;

    .line 67
    .line 68
    check-cast v0, Ljava/lang/Iterable;

    .line 69
    .line 70
    new-instance v5, Ljava/util/ArrayList;

    .line 71
    .line 72
    const/16 v1, 0xa

    .line 73
    .line 74
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 75
    .line 76
    .line 77
    move-result v1

    .line 78
    invoke-direct {v5, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 86
    .line 87
    .line 88
    move-result v1

    .line 89
    if-eqz v1, :cond_4

    .line 90
    .line 91
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    check-cast v1, Lzi/d;

    .line 96
    .line 97
    new-instance v4, Leg/i;

    .line 98
    .line 99
    iget-object v6, v1, Lzi/d;->a:Ljava/lang/String;

    .line 100
    .line 101
    iget-object v1, v1, Lzi/d;->b:Ljava/lang/String;

    .line 102
    .line 103
    invoke-direct {v4, v6, v1}, Leg/i;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_4
    iget-object v6, p1, Lzi/g;->c:Lgz0/p;

    .line 111
    .line 112
    iget-object v7, p1, Lzi/g;->d:Ljava/lang/String;

    .line 113
    .line 114
    iget-object v8, p1, Lzi/g;->e:Ljava/lang/String;

    .line 115
    .line 116
    iget-boolean v9, p1, Lzi/g;->f:Z

    .line 117
    .line 118
    new-instance v4, Leg/o;

    .line 119
    .line 120
    invoke-direct/range {v4 .. v9}, Leg/o;-><init>(Ljava/util/ArrayList;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 121
    .line 122
    .line 123
    invoke-static {v2, v4, v3}, Lhg/x;->a(Lhg/x;Leg/o;Z)V

    .line 124
    .line 125
    .line 126
    :cond_5
    :goto_2
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    if-eqz p0, :cond_6

    .line 131
    .line 132
    iget-object p1, v2, Lhg/x;->k:Lyy0/c2;

    .line 133
    .line 134
    sget-object v0, Lhg/h;->a:Lhg/h;

    .line 135
    .line 136
    invoke-static {p1, p0, v0}, Lhg/x;->g(Lyy0/c2;Ljava/lang/Throwable;Lhg/j;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    :goto_3
    return-object v0

    .line 142
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 143
    .line 144
    iget v1, p0, Lhg/v;->e:I

    .line 145
    .line 146
    const/4 v2, 0x2

    .line 147
    const/4 v3, 0x1

    .line 148
    iget-object v4, p0, Lhg/v;->f:Lhg/x;

    .line 149
    .line 150
    if-eqz v1, :cond_9

    .line 151
    .line 152
    if-eq v1, v3, :cond_8

    .line 153
    .line 154
    if-ne v1, v2, :cond_7

    .line 155
    .line 156
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    goto :goto_5

    .line 160
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 161
    .line 162
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 163
    .line 164
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw p0

    .line 168
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    iget-object p1, v4, Lhg/x;->e:Lbq0/i;

    .line 176
    .line 177
    iput v3, p0, Lhg/v;->e:I

    .line 178
    .line 179
    invoke-virtual {p1, p0}, Lbq0/i;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    if-ne p1, v0, :cond_a

    .line 184
    .line 185
    goto :goto_6

    .line 186
    :cond_a
    :goto_4
    check-cast p1, Lyy0/i;

    .line 187
    .line 188
    new-instance v1, Lhg/q;

    .line 189
    .line 190
    const/4 v3, 0x0

    .line 191
    invoke-direct {v1, p1, v3}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 192
    .line 193
    .line 194
    new-instance p1, Lam0/i;

    .line 195
    .line 196
    const/4 v3, 0x4

    .line 197
    invoke-direct {p1, v1, v3}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 198
    .line 199
    .line 200
    new-instance v1, Lac/l;

    .line 201
    .line 202
    const/16 v3, 0xc

    .line 203
    .line 204
    invoke-direct {v1, v3, p1, v4}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    new-instance v1, Lc/m;

    .line 212
    .line 213
    const/4 v3, 0x0

    .line 214
    const/4 v5, 0x4

    .line 215
    invoke-direct {v1, v4, v3, v5}, Lc/m;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 216
    .line 217
    .line 218
    iput v2, p0, Lhg/v;->e:I

    .line 219
    .line 220
    invoke-static {v1, p0, p1}, Lyy0/u;->k(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    if-ne p0, v0, :cond_b

    .line 225
    .line 226
    goto :goto_6

    .line 227
    :cond_b
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 228
    .line 229
    :goto_6
    return-object v0

    .line 230
    nop

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
