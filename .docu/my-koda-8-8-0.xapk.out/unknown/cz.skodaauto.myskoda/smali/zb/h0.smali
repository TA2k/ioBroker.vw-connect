.class public final Lzb/h0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lay0/k;

.field public e:Lzb/f0;

.field public f:I

.field public g:I

.field public h:I

.field public i:I

.field public j:I

.field public synthetic k:Ljava/lang/Object;

.field public final synthetic l:Lzb/f0;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lzb/f0;Lay0/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lzb/h0;->l:Lzb/f0;

    .line 2
    .line 3
    iput-object p2, p0, Lzb/h0;->m:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lzb/h0;

    .line 2
    .line 3
    iget-object v1, p0, Lzb/h0;->l:Lzb/f0;

    .line 4
    .line 5
    iget-object p0, p0, Lzb/h0;->m:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lzb/h0;-><init>(Lzb/f0;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lzb/h0;->k:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lzb/h0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lzb/h0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lzb/h0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget-object v0, p0, Lzb/h0;->k:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lyy0/j;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lzb/h0;->j:I

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x3

    .line 11
    const/4 v5, 0x2

    .line 12
    const/4 v6, 0x1

    .line 13
    if-eqz v2, :cond_5

    .line 14
    .line 15
    if-eq v2, v6, :cond_4

    .line 16
    .line 17
    if-eq v2, v5, :cond_2

    .line 18
    .line 19
    if-ne v2, v4, :cond_1

    .line 20
    .line 21
    iget v2, p0, Lzb/h0;->g:I

    .line 22
    .line 23
    iget v7, p0, Lzb/h0;->f:I

    .line 24
    .line 25
    iget-object v8, p0, Lzb/h0;->e:Lzb/f0;

    .line 26
    .line 27
    iget-object v9, p0, Lzb/h0;->d:Lay0/k;

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    move-object v10, v8

    .line 33
    :cond_0
    move-object v11, v9

    .line 34
    move v9, v7

    .line 35
    goto/16 :goto_4

    .line 36
    .line 37
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_2
    iget v2, p0, Lzb/h0;->i:I

    .line 46
    .line 47
    iget v7, p0, Lzb/h0;->h:I

    .line 48
    .line 49
    iget v8, p0, Lzb/h0;->g:I

    .line 50
    .line 51
    iget v9, p0, Lzb/h0;->f:I

    .line 52
    .line 53
    iget-object v10, p0, Lzb/h0;->e:Lzb/f0;

    .line 54
    .line 55
    iget-object v11, p0, Lzb/h0;->d:Lay0/k;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    :cond_3
    move p1, v2

    .line 61
    move v2, v8

    .line 62
    move v8, v7

    .line 63
    move v7, v9

    .line 64
    move-object v9, v11

    .line 65
    goto :goto_2

    .line 66
    :cond_4
    iget v2, p0, Lzb/h0;->i:I

    .line 67
    .line 68
    iget v7, p0, Lzb/h0;->h:I

    .line 69
    .line 70
    iget v8, p0, Lzb/h0;->g:I

    .line 71
    .line 72
    iget v9, p0, Lzb/h0;->f:I

    .line 73
    .line 74
    iget-object v10, p0, Lzb/h0;->e:Lzb/f0;

    .line 75
    .line 76
    iget-object v11, p0, Lzb/h0;->d:Lay0/k;

    .line 77
    .line 78
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lzb/h0;->l:Lzb/f0;

    .line 86
    .line 87
    iget v2, p1, Lzb/f0;->a:I

    .line 88
    .line 89
    iget-object v7, p0, Lzb/h0;->m:Ljava/lang/Object;

    .line 90
    .line 91
    move-object v10, p1

    .line 92
    move v9, v2

    .line 93
    move v8, v3

    .line 94
    move-object v11, v7

    .line 95
    :goto_0
    if-ge v8, v9, :cond_8

    .line 96
    .line 97
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-static {p1}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-nez p1, :cond_6

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_6
    iput-object v0, p0, Lzb/h0;->k:Ljava/lang/Object;

    .line 109
    .line 110
    move-object p1, v11

    .line 111
    check-cast p1, Lay0/k;

    .line 112
    .line 113
    iput-object p1, p0, Lzb/h0;->d:Lay0/k;

    .line 114
    .line 115
    iput-object v10, p0, Lzb/h0;->e:Lzb/f0;

    .line 116
    .line 117
    iput v9, p0, Lzb/h0;->f:I

    .line 118
    .line 119
    iput v8, p0, Lzb/h0;->g:I

    .line 120
    .line 121
    iput v8, p0, Lzb/h0;->h:I

    .line 122
    .line 123
    iput v3, p0, Lzb/h0;->i:I

    .line 124
    .line 125
    iput v6, p0, Lzb/h0;->j:I

    .line 126
    .line 127
    invoke-interface {v11, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    if-ne p1, v1, :cond_7

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_7
    move v2, v3

    .line 135
    move v7, v8

    .line 136
    :goto_1
    iput-object v0, p0, Lzb/h0;->k:Ljava/lang/Object;

    .line 137
    .line 138
    move-object v12, v11

    .line 139
    check-cast v12, Lay0/k;

    .line 140
    .line 141
    iput-object v12, p0, Lzb/h0;->d:Lay0/k;

    .line 142
    .line 143
    iput-object v10, p0, Lzb/h0;->e:Lzb/f0;

    .line 144
    .line 145
    iput v9, p0, Lzb/h0;->f:I

    .line 146
    .line 147
    iput v8, p0, Lzb/h0;->g:I

    .line 148
    .line 149
    iput v7, p0, Lzb/h0;->h:I

    .line 150
    .line 151
    iput v2, p0, Lzb/h0;->i:I

    .line 152
    .line 153
    iput v5, p0, Lzb/h0;->j:I

    .line 154
    .line 155
    invoke-interface {v0, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    if-ne p1, v1, :cond_3

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :goto_2
    iget-wide v11, v10, Lzb/f0;->b:J

    .line 163
    .line 164
    iput-object v0, p0, Lzb/h0;->k:Ljava/lang/Object;

    .line 165
    .line 166
    move-object v13, v9

    .line 167
    check-cast v13, Lay0/k;

    .line 168
    .line 169
    iput-object v13, p0, Lzb/h0;->d:Lay0/k;

    .line 170
    .line 171
    iput-object v10, p0, Lzb/h0;->e:Lzb/f0;

    .line 172
    .line 173
    iput v7, p0, Lzb/h0;->f:I

    .line 174
    .line 175
    iput v2, p0, Lzb/h0;->g:I

    .line 176
    .line 177
    iput v8, p0, Lzb/h0;->h:I

    .line 178
    .line 179
    iput p1, p0, Lzb/h0;->i:I

    .line 180
    .line 181
    iput v4, p0, Lzb/h0;->j:I

    .line 182
    .line 183
    invoke-static {v11, v12, p0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object p1

    .line 187
    if-ne p1, v1, :cond_0

    .line 188
    .line 189
    :goto_3
    return-object v1

    .line 190
    :goto_4
    add-int/lit8 v8, v2, 0x1

    .line 191
    .line 192
    goto :goto_0

    .line 193
    :cond_8
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 194
    .line 195
    return-object p0
.end method
