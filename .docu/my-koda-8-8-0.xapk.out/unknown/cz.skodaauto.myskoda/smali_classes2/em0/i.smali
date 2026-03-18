.class public final Lem0/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;IILkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lem0/i;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lem0/i;->h:Ljava/lang/Object;

    .line 4
    .line 5
    iput p2, p0, Lem0/i;->f:I

    .line 6
    .line 7
    iput p3, p0, Lem0/i;->g:I

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    iget p1, p0, Lem0/i;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lem0/i;

    .line 7
    .line 8
    iget-object p1, p0, Lem0/i;->h:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v1, p1

    .line 11
    check-cast v1, Lc1/c;

    .line 12
    .line 13
    iget v3, p0, Lem0/i;->g:I

    .line 14
    .line 15
    const/4 v5, 0x1

    .line 16
    iget v2, p0, Lem0/i;->f:I

    .line 17
    .line 18
    move-object v4, p2

    .line 19
    invoke-direct/range {v0 .. v5}, Lem0/i;-><init>(Ljava/lang/Object;IILkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_0
    move-object v4, p2

    .line 24
    new-instance v1, Lem0/i;

    .line 25
    .line 26
    iget-object p1, p0, Lem0/i;->h:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v2, p1

    .line 29
    check-cast v2, Lem0/m;

    .line 30
    .line 31
    move-object v5, v4

    .line 32
    iget v4, p0, Lem0/i;->g:I

    .line 33
    .line 34
    const/4 v6, 0x0

    .line 35
    iget v3, p0, Lem0/i;->f:I

    .line 36
    .line 37
    invoke-direct/range {v1 .. v6}, Lem0/i;-><init>(Ljava/lang/Object;IILkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    return-object v1

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lem0/i;->d:I

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
    invoke-virtual {p0, p1, p2}, Lem0/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lem0/i;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lem0/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lem0/i;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lem0/i;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lem0/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lem0/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lem0/i;->e:I

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
    iget-object p1, p0, Lem0/i;->h:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v3, p1

    .line 33
    check-cast v3, Lc1/c;

    .line 34
    .line 35
    new-instance v4, Ljava/lang/Float;

    .line 36
    .line 37
    const/high16 p1, 0x3f800000    # 1.0f

    .line 38
    .line 39
    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    .line 40
    .line 41
    .line 42
    iget p1, p0, Lem0/i;->g:I

    .line 43
    .line 44
    add-int/2addr p1, v2

    .line 45
    mul-int/lit16 p1, p1, 0x15e

    .line 46
    .line 47
    iget v1, p0, Lem0/i;->f:I

    .line 48
    .line 49
    add-int/2addr p1, v1

    .line 50
    sget-object v1, Lc1/x;->a:Lc1/s;

    .line 51
    .line 52
    new-instance v5, Lc1/a2;

    .line 53
    .line 54
    const/16 v6, 0x96

    .line 55
    .line 56
    invoke-direct {v5, v6, p1, v1}, Lc1/a2;-><init>(IILc1/w;)V

    .line 57
    .line 58
    .line 59
    iput v2, p0, Lem0/i;->e:I

    .line 60
    .line 61
    const/4 v6, 0x0

    .line 62
    const/4 v7, 0x0

    .line 63
    const/16 v9, 0xc

    .line 64
    .line 65
    move-object v8, p0

    .line 66
    invoke-static/range {v3 .. v9}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-ne p0, v0, :cond_2

    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_1
    return-object v0

    .line 76
    :pswitch_0
    move-object v8, p0

    .line 77
    iget-object p0, v8, Lem0/i;->h:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lem0/m;

    .line 80
    .line 81
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    iget v1, v8, Lem0/i;->e:I

    .line 84
    .line 85
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    const/4 v3, 0x3

    .line 88
    const/4 v4, 0x2

    .line 89
    const/4 v5, 0x1

    .line 90
    if-eqz v1, :cond_7

    .line 91
    .line 92
    if-eq v1, v5, :cond_6

    .line 93
    .line 94
    if-eq v1, v4, :cond_5

    .line 95
    .line 96
    if-ne v1, v3, :cond_4

    .line 97
    .line 98
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    :cond_3
    move-object v0, v2

    .line 102
    goto :goto_5

    .line 103
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 104
    .line 105
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0

    .line 111
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iget-object p1, p0, Lem0/m;->a:Lti0/a;

    .line 123
    .line 124
    iput v5, v8, Lem0/i;->e:I

    .line 125
    .line 126
    invoke-interface {p1, v8}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    if-ne p1, v0, :cond_8

    .line 131
    .line 132
    goto :goto_5

    .line 133
    :cond_8
    :goto_2
    check-cast p1, Lem0/f;

    .line 134
    .line 135
    iput v4, v8, Lem0/i;->e:I

    .line 136
    .line 137
    iget-object v1, p1, Lem0/f;->a:Lla/u;

    .line 138
    .line 139
    new-instance v4, Lem0/b;

    .line 140
    .line 141
    iget v6, v8, Lem0/i;->f:I

    .line 142
    .line 143
    iget v7, v8, Lem0/i;->g:I

    .line 144
    .line 145
    invoke-direct {v4, v6, v7, p1}, Lem0/b;-><init>(IILem0/f;)V

    .line 146
    .line 147
    .line 148
    const/4 p1, 0x0

    .line 149
    invoke-static {v8, v1, v5, p1, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-ne p1, v0, :cond_9

    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_9
    :goto_3
    check-cast p1, Ljava/util/List;

    .line 157
    .line 158
    iget-object p0, p0, Lem0/m;->c:Lyy0/c2;

    .line 159
    .line 160
    check-cast p1, Ljava/lang/Iterable;

    .line 161
    .line 162
    new-instance v1, Ljava/util/ArrayList;

    .line 163
    .line 164
    const/16 v4, 0xa

    .line 165
    .line 166
    invoke-static {p1, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 167
    .line 168
    .line 169
    move-result v4

    .line 170
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 171
    .line 172
    .line 173
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    :goto_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-eqz v4, :cond_a

    .line 182
    .line 183
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    check-cast v4, Lem0/g;

    .line 188
    .line 189
    invoke-static {v4}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    goto :goto_4

    .line 197
    :cond_a
    iput v3, v8, Lem0/i;->e:I

    .line 198
    .line 199
    invoke-virtual {p0, v1, v8}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    if-ne v2, v0, :cond_3

    .line 203
    .line 204
    :goto_5
    return-object v0

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
