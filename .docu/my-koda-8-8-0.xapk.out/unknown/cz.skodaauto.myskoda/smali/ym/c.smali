.class public final Lym/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Lym/g;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:F

.field public final synthetic i:Lum/a;

.field public final synthetic j:F

.field public final synthetic k:Lym/k;


# direct methods
.method public constructor <init>(Lym/g;IIFLum/a;FLym/k;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lym/c;->e:Lym/g;

    .line 2
    .line 3
    iput p2, p0, Lym/c;->f:I

    .line 4
    .line 5
    iput p3, p0, Lym/c;->g:I

    .line 6
    .line 7
    iput p4, p0, Lym/c;->h:F

    .line 8
    .line 9
    iput-object p5, p0, Lym/c;->i:Lum/a;

    .line 10
    .line 11
    iput p6, p0, Lym/c;->j:F

    .line 12
    .line 13
    iput-object p7, p0, Lym/c;->k:Lym/k;

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    invoke-direct {p0, p1, p8}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    new-instance v0, Lym/c;

    .line 2
    .line 3
    iget v6, p0, Lym/c;->j:F

    .line 4
    .line 5
    iget-object v7, p0, Lym/c;->k:Lym/k;

    .line 6
    .line 7
    iget-object v1, p0, Lym/c;->e:Lym/g;

    .line 8
    .line 9
    iget v2, p0, Lym/c;->f:I

    .line 10
    .line 11
    iget v3, p0, Lym/c;->g:I

    .line 12
    .line 13
    iget v4, p0, Lym/c;->h:F

    .line 14
    .line 15
    iget-object v5, p0, Lym/c;->i:Lum/a;

    .line 16
    .line 17
    move-object v8, p1

    .line 18
    invoke-direct/range {v0 .. v8}, Lym/c;-><init>(Lym/g;IIFLum/a;FLym/k;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lym/c;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lym/c;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lym/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lym/c;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x1

    .line 9
    iget-object v5, p0, Lym/c;->e:Lym/g;

    .line 10
    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v4, :cond_0

    .line 14
    .line 15
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    goto/16 :goto_1

    .line 19
    .line 20
    :catchall_0
    move-exception v0

    .line 21
    move-object p0, v0

    .line 22
    goto/16 :goto_2

    .line 23
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
    iget p1, p0, Lym/c;->f:I

    .line 36
    .line 37
    invoke-virtual {v5, p1}, Lym/g;->e(I)V

    .line 38
    .line 39
    .line 40
    iget-object p1, v5, Lym/g;->d:Ll2/j1;

    .line 41
    .line 42
    iget-object v1, v5, Lym/g;->f:Ll2/j1;

    .line 43
    .line 44
    iget v6, p0, Lym/c;->g:I

    .line 45
    .line 46
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    invoke-virtual {v1, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object v1, v5, Lym/g;->g:Ll2/j1;

    .line 54
    .line 55
    sget-object v7, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 56
    .line 57
    invoke-virtual {v1, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, v5, Lym/g;->i:Ll2/j1;

    .line 61
    .line 62
    iget v8, p0, Lym/c;->h:F

    .line 63
    .line 64
    invoke-static {v8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    invoke-virtual {v1, v9}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    iget-object v9, v5, Lym/g;->h:Ll2/j1;

    .line 73
    .line 74
    invoke-virtual {v9, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object v1, v5, Lym/g;->l:Ll2/j1;

    .line 78
    .line 79
    iget-object v9, p0, Lym/c;->i:Lum/a;

    .line 80
    .line 81
    invoke-virtual {v1, v9}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget v1, p0, Lym/c;->j:F

    .line 85
    .line 86
    invoke-virtual {v5, v1}, Lym/g;->f(F)V

    .line 87
    .line 88
    .line 89
    iget-object v1, v5, Lym/g;->j:Ll2/j1;

    .line 90
    .line 91
    invoke-virtual {v1, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    iget-object v1, v5, Lym/g;->o:Ll2/j1;

    .line 95
    .line 96
    const-wide/high16 v10, -0x8000000000000000L

    .line 97
    .line 98
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 99
    .line 100
    .line 101
    move-result-object v10

    .line 102
    invoke-virtual {v1, v10}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    if-nez v9, :cond_2

    .line 106
    .line 107
    invoke-virtual {p1, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    return-object v2

    .line 111
    :cond_2
    invoke-static {v8}, Ljava/lang/Float;->isInfinite(F)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_3

    .line 116
    .line 117
    invoke-virtual {v5}, Lym/g;->c()F

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    invoke-virtual {v5, p0}, Lym/g;->f(F)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v5, v6}, Lym/g;->e(I)V

    .line 128
    .line 129
    .line 130
    return-object v2

    .line 131
    :cond_3
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 132
    .line 133
    invoke-virtual {p1, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    :try_start_1
    iget-object p1, p0, Lym/c;->k:Lym/k;

    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 139
    .line 140
    .line 141
    move-result p1

    .line 142
    if-eqz p1, :cond_5

    .line 143
    .line 144
    if-ne p1, v4, :cond_4

    .line 145
    .line 146
    sget-object p1, Lvy0/t1;->d:Lvy0/t1;

    .line 147
    .line 148
    goto :goto_0

    .line 149
    :cond_4
    new-instance p0, La8/r0;

    .line 150
    .line 151
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 152
    .line 153
    .line 154
    throw p0

    .line 155
    :cond_5
    sget-object p1, Lpx0/h;->d:Lpx0/h;

    .line 156
    .line 157
    :goto_0
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-static {v1}, Lvy0/e0;->w(Lpx0/g;)Lvy0/i1;

    .line 162
    .line 163
    .line 164
    move-result-object v8

    .line 165
    new-instance v6, Lh50/r0;

    .line 166
    .line 167
    iget-object v7, p0, Lym/c;->k:Lym/k;

    .line 168
    .line 169
    iget v9, p0, Lym/c;->g:I

    .line 170
    .line 171
    iget v10, p0, Lym/c;->f:I

    .line 172
    .line 173
    iget-object v11, p0, Lym/c;->e:Lym/g;

    .line 174
    .line 175
    const/4 v12, 0x0

    .line 176
    invoke-direct/range {v6 .. v12}, Lh50/r0;-><init>(Lym/k;Lvy0/i1;IILym/g;Lkotlin/coroutines/Continuation;)V

    .line 177
    .line 178
    .line 179
    iput v4, p0, Lym/c;->d:I

    .line 180
    .line 181
    invoke-static {p1, v6, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    if-ne p1, v0, :cond_6

    .line 186
    .line 187
    return-object v0

    .line 188
    :cond_6
    :goto_1
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    invoke-static {p0}, Lvy0/e0;->r(Lpx0/g;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 193
    .line 194
    .line 195
    invoke-static {v5, v3}, Lym/g;->b(Lym/g;Z)V

    .line 196
    .line 197
    .line 198
    return-object v2

    .line 199
    :goto_2
    invoke-static {v5, v3}, Lym/g;->b(Lym/g;Z)V

    .line 200
    .line 201
    .line 202
    throw p0
.end method
