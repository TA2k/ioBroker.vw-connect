.class public final Lt31/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lt31/n;

.field public final synthetic g:Z


# direct methods
.method public synthetic constructor <init>(Lt31/n;ZLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lt31/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lt31/k;->f:Lt31/n;

    .line 4
    .line 5
    iput-boolean p2, p0, Lt31/k;->g:Z

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
    iget p1, p0, Lt31/k;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lt31/k;

    .line 7
    .line 8
    iget-boolean v0, p0, Lt31/k;->g:Z

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lt31/k;->f:Lt31/n;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lt31/k;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lt31/k;

    .line 18
    .line 19
    iget-boolean v0, p0, Lt31/k;->g:Z

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lt31/k;->f:Lt31/n;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lt31/k;-><init>(Lt31/n;ZLkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lt31/k;->d:I

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
    invoke-virtual {p0, p1, p2}, Lt31/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lt31/k;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lt31/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lt31/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lt31/k;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lt31/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lt31/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lt31/k;->e:I

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
    iget-object p1, p0, Lt31/k;->f:Lt31/n;

    .line 31
    .line 32
    iget-object p1, p1, Lt31/n;->m:Lk31/d0;

    .line 33
    .line 34
    new-instance v1, Lk31/c0;

    .line 35
    .line 36
    iget-boolean v3, p0, Lt31/k;->g:Z

    .line 37
    .line 38
    invoke-direct {v1, v3}, Lk31/c0;-><init>(Z)V

    .line 39
    .line 40
    .line 41
    iput v2, p0, Lt31/k;->e:I

    .line 42
    .line 43
    iget-object v2, p1, Lk31/d0;->b:Lvy0/x;

    .line 44
    .line 45
    new-instance v3, Lk31/t;

    .line 46
    .line 47
    const/4 v4, 0x0

    .line 48
    const/4 v5, 0x2

    .line 49
    invoke-direct {v3, v5, v1, p1, v4}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v2, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    if-ne p1, v0, :cond_2

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    :goto_0
    check-cast p1, Lo41/c;

    .line 60
    .line 61
    invoke-static {p1}, Ljp/nb;->b(Lo41/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Ljava/util/List;

    .line 66
    .line 67
    if-eqz p0, :cond_3

    .line 68
    .line 69
    check-cast p0, Ljava/lang/Iterable;

    .line 70
    .line 71
    new-instance v0, Ljava/util/ArrayList;

    .line 72
    .line 73
    const/16 p1, 0xa

    .line 74
    .line 75
    invoke-static {p0, p1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 80
    .line 81
    .line 82
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    if-eqz p1, :cond_4

    .line 91
    .line 92
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    check-cast p1, Li31/h0;

    .line 97
    .line 98
    new-instance v1, Lp31/h;

    .line 99
    .line 100
    iget-object v2, p1, Li31/h0;->c:Ljava/lang/String;

    .line 101
    .line 102
    invoke-static {v2}, Ljp/mb;->b(Ljava/lang/String;)Le3/f;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    const/4 v3, 0x0

    .line 107
    invoke-direct {v1, p1, v2, v3}, Lp31/h;-><init>(Li31/h0;Le3/f;Z)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 115
    .line 116
    :cond_4
    :goto_2
    return-object v0

    .line 117
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 118
    .line 119
    iget v1, p0, Lt31/k;->e:I

    .line 120
    .line 121
    const/4 v2, 0x1

    .line 122
    if-eqz v1, :cond_6

    .line 123
    .line 124
    if-ne v1, v2, :cond_5

    .line 125
    .line 126
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_3

    .line 130
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 133
    .line 134
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iget-object p1, p0, Lt31/k;->f:Lt31/n;

    .line 142
    .line 143
    iget-object p1, p1, Lt31/n;->n:Lk31/x;

    .line 144
    .line 145
    new-instance v1, Lk31/w;

    .line 146
    .line 147
    iget-boolean v3, p0, Lt31/k;->g:Z

    .line 148
    .line 149
    invoke-direct {v1, v3}, Lk31/w;-><init>(Z)V

    .line 150
    .line 151
    .line 152
    iput v2, p0, Lt31/k;->e:I

    .line 153
    .line 154
    iget-object v2, p1, Lk31/x;->b:Lvy0/x;

    .line 155
    .line 156
    new-instance v3, Lk31/t;

    .line 157
    .line 158
    const/4 v4, 0x0

    .line 159
    const/4 v5, 0x1

    .line 160
    invoke-direct {v3, v5, v1, p1, v4}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 161
    .line 162
    .line 163
    invoke-static {v2, v3, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    if-ne p1, v0, :cond_7

    .line 168
    .line 169
    goto :goto_5

    .line 170
    :cond_7
    :goto_3
    check-cast p1, Lo41/c;

    .line 171
    .line 172
    invoke-static {p1}, Ljp/nb;->b(Lo41/c;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    check-cast p0, Ljava/util/List;

    .line 177
    .line 178
    if-eqz p0, :cond_8

    .line 179
    .line 180
    check-cast p0, Ljava/lang/Iterable;

    .line 181
    .line 182
    new-instance v0, Ljava/util/ArrayList;

    .line 183
    .line 184
    const/16 p1, 0xa

    .line 185
    .line 186
    invoke-static {p0, p1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 187
    .line 188
    .line 189
    move-result p1

    .line 190
    invoke-direct {v0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 191
    .line 192
    .line 193
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result p1

    .line 201
    if-eqz p1, :cond_9

    .line 202
    .line 203
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    check-cast p1, Li31/y;

    .line 208
    .line 209
    new-instance v1, Lp31/e;

    .line 210
    .line 211
    const/4 v2, 0x0

    .line 212
    invoke-direct {v1, p1, v2}, Lp31/e;-><init>(Li31/y;Z)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_8
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 220
    .line 221
    :cond_9
    :goto_5
    return-object v0

    .line 222
    nop

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
