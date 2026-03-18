.class public final Llz/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/m;

.field public final b:Lsf0/a;

.field public final c:Ljn0/c;

.field public final d:Lkf0/j0;

.field public final e:Ljz/m;

.field public final f:Ljr0/f;


# direct methods
.method public constructor <init>(Lkf0/m;Lsf0/a;Ljn0/c;Lkf0/j0;Ljz/m;Ljr0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llz/s;->a:Lkf0/m;

    .line 5
    .line 6
    iput-object p2, p0, Llz/s;->b:Lsf0/a;

    .line 7
    .line 8
    iput-object p3, p0, Llz/s;->c:Ljn0/c;

    .line 9
    .line 10
    iput-object p4, p0, Llz/s;->d:Lkf0/j0;

    .line 11
    .line 12
    iput-object p5, p0, Llz/s;->e:Ljz/m;

    .line 13
    .line 14
    iput-object p6, p0, Llz/s;->f:Ljr0/f;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Llz/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Llz/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Llz/r;

    .line 7
    .line 8
    iget v1, v0, Llz/r;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llz/r;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llz/r;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Llz/r;-><init>(Llz/s;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Llz/r;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llz/r;->g:I

    .line 30
    .line 31
    const/4 v3, 0x4

    .line 32
    const/4 v4, 0x3

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x2

    .line 35
    const/4 v7, 0x0

    .line 36
    if-eqz v2, :cond_5

    .line 37
    .line 38
    if-eq v2, v5, :cond_4

    .line 39
    .line 40
    if-eq v2, v6, :cond_3

    .line 41
    .line 42
    if-eq v2, v4, :cond_2

    .line 43
    .line 44
    if-ne v2, v3, :cond_1

    .line 45
    .line 46
    iget-object p0, v0, Llz/r;->d:Lne0/c;

    .line 47
    .line 48
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto/16 :goto_3

    .line 64
    .line 65
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iput v5, v0, Llz/r;->g:I

    .line 77
    .line 78
    iget-object p1, p0, Llz/s;->a:Lkf0/m;

    .line 79
    .line 80
    invoke-virtual {p1, v0}, Lkf0/m;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    if-ne p1, v1, :cond_6

    .line 85
    .line 86
    goto/16 :goto_4

    .line 87
    .line 88
    :cond_6
    :goto_1
    check-cast p1, Lne0/t;

    .line 89
    .line 90
    new-instance v2, Lk31/t;

    .line 91
    .line 92
    const/16 v5, 0x12

    .line 93
    .line 94
    invoke-direct {v2, p0, v7, v5}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 95
    .line 96
    .line 97
    iput v6, v0, Llz/r;->g:I

    .line 98
    .line 99
    invoke-static {p1, v2, v0}, Llp/sf;->b(Lne0/t;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    if-ne p1, v1, :cond_7

    .line 104
    .line 105
    goto :goto_4

    .line 106
    :cond_7
    :goto_2
    check-cast p1, Lne0/t;

    .line 107
    .line 108
    instance-of v2, p1, Lne0/c;

    .line 109
    .line 110
    if-eqz v2, :cond_8

    .line 111
    .line 112
    check-cast p1, Lne0/c;

    .line 113
    .line 114
    return-object p1

    .line 115
    :cond_8
    instance-of v2, p1, Lne0/e;

    .line 116
    .line 117
    if-eqz v2, :cond_b

    .line 118
    .line 119
    check-cast p1, Lne0/e;

    .line 120
    .line 121
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast p1, Lss0/k;

    .line 124
    .line 125
    iget-object p1, p1, Lss0/k;->a:Ljava/lang/String;

    .line 126
    .line 127
    iget-object v2, p0, Llz/s;->e:Ljz/m;

    .line 128
    .line 129
    const-string v5, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 130
    .line 131
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    iget-object v5, v2, Ljz/m;->a:Lxl0/f;

    .line 135
    .line 136
    new-instance v6, Ljz/k;

    .line 137
    .line 138
    const/4 v8, 0x1

    .line 139
    invoke-direct {v6, v2, p1, v7, v8}, Ljz/k;-><init>(Ljz/m;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v5, v6}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    new-instance v2, La10/a;

    .line 147
    .line 148
    const/16 v5, 0x1c

    .line 149
    .line 150
    invoke-direct {v2, p0, v7, v5}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 151
    .line 152
    .line 153
    new-instance v5, Lne0/n;

    .line 154
    .line 155
    invoke-direct {v5, v2, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 156
    .line 157
    .line 158
    new-instance p1, Llb0/q0;

    .line 159
    .line 160
    const/4 v2, 0x7

    .line 161
    invoke-direct {p1, p0, v7, v2}, Llb0/q0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 162
    .line 163
    .line 164
    invoke-static {p1, v5}, Lbb/j0;->e(Lay0/n;Lyy0/i;)Lne0/n;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    iget-object v2, p0, Llz/s;->b:Lsf0/a;

    .line 169
    .line 170
    invoke-static {p1, v2, v7}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 171
    .line 172
    .line 173
    move-result-object p1

    .line 174
    iput v4, v0, Llz/r;->g:I

    .line 175
    .line 176
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    if-ne p1, v1, :cond_9

    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_9
    :goto_3
    check-cast p1, Lne0/t;

    .line 184
    .line 185
    instance-of v2, p1, Lne0/c;

    .line 186
    .line 187
    if-eqz v2, :cond_a

    .line 188
    .line 189
    move-object v2, p1

    .line 190
    check-cast v2, Lne0/c;

    .line 191
    .line 192
    iput-object v2, v0, Llz/r;->d:Lne0/c;

    .line 193
    .line 194
    iput v3, v0, Llz/r;->g:I

    .line 195
    .line 196
    iget-object p0, p0, Llz/s;->c:Ljn0/c;

    .line 197
    .line 198
    invoke-virtual {p0, v2, v0}, Ljn0/c;->c(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    if-ne p0, v1, :cond_a

    .line 203
    .line 204
    :goto_4
    return-object v1

    .line 205
    :cond_a
    return-object p1

    .line 206
    :cond_b
    new-instance p0, La8/r0;

    .line 207
    .line 208
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 209
    .line 210
    .line 211
    throw p0
.end method
