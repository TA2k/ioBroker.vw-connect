.class public final Lg1/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lkotlin/jvm/internal/f0;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Lay0/n;


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;Lvy0/b0;Lay0/n;I)V
    .locals 0

    .line 1
    iput p4, p0, Lg1/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg1/h;->e:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    iput-object p2, p0, Lg1/h;->f:Lvy0/b0;

    .line 6
    .line 7
    iput-object p3, p0, Lg1/h;->g:Lay0/n;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lg1/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Li2/j;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Li2/j;

    .line 12
    .line 13
    iget v1, v0, Li2/j;->g:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Li2/j;->g:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Li2/j;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Li2/j;-><init>(Lg1/h;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Li2/j;->e:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Li2/j;->g:I

    .line 35
    .line 36
    iget-object v3, p0, Lg1/h;->e:Lkotlin/jvm/internal/f0;

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    if-ne v2, v4, :cond_1

    .line 42
    .line 43
    iget-object p1, v0, Li2/j;->d:Ljava/lang/Object;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p2, Lvy0/i1;

    .line 63
    .line 64
    if-eqz p2, :cond_3

    .line 65
    .line 66
    new-instance v2, Li2/e;

    .line 67
    .line 68
    invoke-direct {v2}, Li2/e;-><init>()V

    .line 69
    .line 70
    .line 71
    invoke-interface {p2, v2}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 72
    .line 73
    .line 74
    iput-object p1, v0, Li2/j;->d:Ljava/lang/Object;

    .line 75
    .line 76
    iput v4, v0, Li2/j;->g:I

    .line 77
    .line 78
    invoke-interface {p2, v0}, Lvy0/i1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    if-ne p2, v1, :cond_3

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    :goto_1
    move-object v7, p1

    .line 86
    sget-object p1, Lvy0/c0;->g:Lvy0/c0;

    .line 87
    .line 88
    new-instance v5, Lg1/f;

    .line 89
    .line 90
    iget-object v6, p0, Lg1/h;->g:Lay0/n;

    .line 91
    .line 92
    const/4 v10, 0x1

    .line 93
    iget-object v8, p0, Lg1/h;->f:Lvy0/b0;

    .line 94
    .line 95
    const/4 v9, 0x0

    .line 96
    invoke-direct/range {v5 .. v10}, Lg1/f;-><init>(Lay0/n;Ljava/lang/Object;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 97
    .line 98
    .line 99
    invoke-static {v8, v9, p1, v5, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    iput-object p0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 104
    .line 105
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    :goto_2
    return-object v1

    .line 108
    :pswitch_0
    instance-of v0, p2, Lg1/g;

    .line 109
    .line 110
    if-eqz v0, :cond_4

    .line 111
    .line 112
    move-object v0, p2

    .line 113
    check-cast v0, Lg1/g;

    .line 114
    .line 115
    iget v1, v0, Lg1/g;->g:I

    .line 116
    .line 117
    const/high16 v2, -0x80000000

    .line 118
    .line 119
    and-int v3, v1, v2

    .line 120
    .line 121
    if-eqz v3, :cond_4

    .line 122
    .line 123
    sub-int/2addr v1, v2

    .line 124
    iput v1, v0, Lg1/g;->g:I

    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_4
    new-instance v0, Lg1/g;

    .line 128
    .line 129
    invoke-direct {v0, p0, p2}, Lg1/g;-><init>(Lg1/h;Lkotlin/coroutines/Continuation;)V

    .line 130
    .line 131
    .line 132
    :goto_3
    iget-object p2, v0, Lg1/g;->e:Ljava/lang/Object;

    .line 133
    .line 134
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    iget v2, v0, Lg1/g;->g:I

    .line 137
    .line 138
    iget-object v3, p0, Lg1/h;->e:Lkotlin/jvm/internal/f0;

    .line 139
    .line 140
    const/4 v4, 0x1

    .line 141
    if-eqz v2, :cond_6

    .line 142
    .line 143
    if-ne v2, v4, :cond_5

    .line 144
    .line 145
    iget-object p1, v0, Lg1/g;->d:Ljava/lang/Object;

    .line 146
    .line 147
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    goto :goto_4

    .line 151
    :cond_5
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
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    iget-object p2, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p2, Lvy0/i1;

    .line 165
    .line 166
    if-eqz p2, :cond_7

    .line 167
    .line 168
    new-instance v2, Lg1/a;

    .line 169
    .line 170
    invoke-direct {v2}, Lg1/a;-><init>()V

    .line 171
    .line 172
    .line 173
    invoke-interface {p2, v2}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 174
    .line 175
    .line 176
    iput-object p1, v0, Lg1/g;->d:Ljava/lang/Object;

    .line 177
    .line 178
    iput v4, v0, Lg1/g;->g:I

    .line 179
    .line 180
    invoke-interface {p2, v0}, Lvy0/i1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p2

    .line 184
    if-ne p2, v1, :cond_7

    .line 185
    .line 186
    goto :goto_5

    .line 187
    :cond_7
    :goto_4
    move-object v7, p1

    .line 188
    sget-object p1, Lvy0/c0;->g:Lvy0/c0;

    .line 189
    .line 190
    new-instance v5, Lg1/f;

    .line 191
    .line 192
    iget-object v6, p0, Lg1/h;->g:Lay0/n;

    .line 193
    .line 194
    const/4 v10, 0x0

    .line 195
    iget-object v8, p0, Lg1/h;->f:Lvy0/b0;

    .line 196
    .line 197
    const/4 v9, 0x0

    .line 198
    invoke-direct/range {v5 .. v10}, Lg1/f;-><init>(Lay0/n;Ljava/lang/Object;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 199
    .line 200
    .line 201
    invoke-static {v8, v9, p1, v5, v4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    iput-object p0, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 206
    .line 207
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    :goto_5
    return-object v1

    .line 210
    nop

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
