.class public final Lg1/z1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt4/c;

.field public f:Z

.field public g:Z

.field public final h:Lez0/c;


# direct methods
.method public constructor <init>(Lp3/x;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lg1/z1;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lg1/z1;->e:Lt4/c;

    .line 2
    new-instance p1, Lez0/c;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Lez0/c;-><init>(Z)V

    .line 3
    iput-object p1, p0, Lg1/z1;->h:Lez0/c;

    return-void
.end method

.method public constructor <init>(Lt4/c;I)V
    .locals 0

    iput p2, p0, Lg1/z1;->d:I

    packed-switch p2, :pswitch_data_0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lg1/z1;->e:Lt4/c;

    .line 5
    new-instance p1, Lez0/c;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Lez0/c;-><init>(Z)V

    .line 6
    iput-object p1, p0, Lg1/z1;->h:Lez0/c;

    return-void

    .line 7
    :pswitch_0
    const-string p2, "density"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Lg1/z1;->e:Lt4/c;

    .line 10
    new-instance p1, Lez0/c;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Lez0/c;-><init>(Z)V

    .line 11
    iput-object p1, p0, Lg1/z1;->h:Lez0/c;

    return-void

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final G0(J)J
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final Q(F)I
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final V(J)F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final a()F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0}, Lt4/c;->a()F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0}, Lt4/c;->a()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0}, Lt4/c;->a()F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lg1/z1;->g:Z

    .line 3
    .line 4
    iget-object p0, p0, Lg1/z1;->h:Lez0/c;

    .line 5
    .line 6
    invoke-virtual {p0}, Lez0/c;->b()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v0}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public c()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lg1/z1;->f:Z

    .line 3
    .line 4
    iget-object p0, p0, Lg1/z1;->h:Lez0/c;

    .line 5
    .line 6
    invoke-virtual {p0}, Lez0/c;->b()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    invoke-virtual {p0, v0}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method

.method public d(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lg1/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lg1/x1;

    .line 7
    .line 8
    iget v1, v0, Lg1/x1;->f:I

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
    iput v1, v0, Lg1/x1;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/x1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lg1/x1;-><init>(Lg1/z1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lg1/x1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/x1;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lg1/x1;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lg1/z1;->h:Lez0/c;

    .line 54
    .line 55
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    const/4 p1, 0x0

    .line 63
    iput-boolean p1, p0, Lg1/z1;->f:Z

    .line 64
    .line 65
    iput-boolean p1, p0, Lg1/z1;->g:Z

    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0
.end method

.method public final f(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyv/f;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p1

    .line 11
    check-cast v0, Lyv/f;

    .line 12
    .line 13
    iget v1, v0, Lyv/f;->g:I

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
    iput v1, v0, Lyv/f;->g:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyv/f;

    .line 26
    .line 27
    invoke-direct {v0, p0, p1}, Lyv/f;-><init>(Lg1/z1;Lrx0/c;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p1, v0, Lyv/f;->e:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyv/f;->g:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Lyv/f;->d:Lg1/z1;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iget-boolean p1, p0, Lg1/z1;->f:Z

    .line 59
    .line 60
    if-nez p1, :cond_3

    .line 61
    .line 62
    iget-boolean p1, p0, Lg1/z1;->g:Z

    .line 63
    .line 64
    if-nez p1, :cond_3

    .line 65
    .line 66
    iput-object p0, v0, Lyv/f;->d:Lg1/z1;

    .line 67
    .line 68
    iput v3, v0, Lyv/f;->g:I

    .line 69
    .line 70
    iget-object p1, p0, Lg1/z1;->h:Lez0/c;

    .line 71
    .line 72
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-ne p1, v1, :cond_3

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_3
    :goto_1
    iget-boolean p0, p0, Lg1/z1;->f:Z

    .line 80
    .line 81
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    :goto_2
    return-object v1

    .line 86
    :pswitch_0
    instance-of v0, p1, Lxf0/t2;

    .line 87
    .line 88
    if-eqz v0, :cond_4

    .line 89
    .line 90
    move-object v0, p1

    .line 91
    check-cast v0, Lxf0/t2;

    .line 92
    .line 93
    iget v1, v0, Lxf0/t2;->f:I

    .line 94
    .line 95
    const/high16 v2, -0x80000000

    .line 96
    .line 97
    and-int v3, v1, v2

    .line 98
    .line 99
    if-eqz v3, :cond_4

    .line 100
    .line 101
    sub-int/2addr v1, v2

    .line 102
    iput v1, v0, Lxf0/t2;->f:I

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_4
    new-instance v0, Lxf0/t2;

    .line 106
    .line 107
    invoke-direct {v0, p0, p1}, Lxf0/t2;-><init>(Lg1/z1;Lrx0/c;)V

    .line 108
    .line 109
    .line 110
    :goto_3
    iget-object p1, v0, Lxf0/t2;->d:Ljava/lang/Object;

    .line 111
    .line 112
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    iget v2, v0, Lxf0/t2;->f:I

    .line 115
    .line 116
    const/4 v3, 0x1

    .line 117
    if-eqz v2, :cond_6

    .line 118
    .line 119
    if-ne v2, v3, :cond_5

    .line 120
    .line 121
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 128
    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0

    .line 133
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    iget-boolean p1, p0, Lg1/z1;->f:Z

    .line 137
    .line 138
    if-nez p1, :cond_7

    .line 139
    .line 140
    iget-boolean p1, p0, Lg1/z1;->g:Z

    .line 141
    .line 142
    if-nez p1, :cond_7

    .line 143
    .line 144
    iput v3, v0, Lxf0/t2;->f:I

    .line 145
    .line 146
    iget-object p1, p0, Lg1/z1;->h:Lez0/c;

    .line 147
    .line 148
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    if-ne p1, v1, :cond_7

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_7
    :goto_4
    iget-boolean p0, p0, Lg1/z1;->f:Z

    .line 156
    .line 157
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    :goto_5
    return-object v1

    .line 162
    :pswitch_1
    instance-of v0, p1, Lg1/y1;

    .line 163
    .line 164
    if-eqz v0, :cond_8

    .line 165
    .line 166
    move-object v0, p1

    .line 167
    check-cast v0, Lg1/y1;

    .line 168
    .line 169
    iget v1, v0, Lg1/y1;->f:I

    .line 170
    .line 171
    const/high16 v2, -0x80000000

    .line 172
    .line 173
    and-int v3, v1, v2

    .line 174
    .line 175
    if-eqz v3, :cond_8

    .line 176
    .line 177
    sub-int/2addr v1, v2

    .line 178
    iput v1, v0, Lg1/y1;->f:I

    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_8
    new-instance v0, Lg1/y1;

    .line 182
    .line 183
    invoke-direct {v0, p0, p1}, Lg1/y1;-><init>(Lg1/z1;Lrx0/c;)V

    .line 184
    .line 185
    .line 186
    :goto_6
    iget-object p1, v0, Lg1/y1;->d:Ljava/lang/Object;

    .line 187
    .line 188
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 189
    .line 190
    iget v2, v0, Lg1/y1;->f:I

    .line 191
    .line 192
    iget-object v3, p0, Lg1/z1;->h:Lez0/c;

    .line 193
    .line 194
    const/4 v4, 0x1

    .line 195
    if-eqz v2, :cond_a

    .line 196
    .line 197
    if-ne v2, v4, :cond_9

    .line 198
    .line 199
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    goto :goto_7

    .line 203
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 204
    .line 205
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 206
    .line 207
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw p0

    .line 211
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    iget-boolean p1, p0, Lg1/z1;->f:Z

    .line 215
    .line 216
    if-nez p1, :cond_c

    .line 217
    .line 218
    iget-boolean p1, p0, Lg1/z1;->g:Z

    .line 219
    .line 220
    if-nez p1, :cond_c

    .line 221
    .line 222
    iput v4, v0, Lg1/y1;->f:I

    .line 223
    .line 224
    invoke-virtual {v3, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    if-ne p1, v1, :cond_b

    .line 229
    .line 230
    goto :goto_8

    .line 231
    :cond_b
    :goto_7
    const/4 p1, 0x0

    .line 232
    invoke-virtual {v3, p1}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    :cond_c
    iget-boolean p0, p0, Lg1/z1;->f:Z

    .line 236
    .line 237
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    :goto_8
    return-object v1

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final m(F)J
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final n(J)J
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final n0(I)F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o0(F)F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->o0(F)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->o0(F)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->o0(F)F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final s(J)F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final t0()F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final w0(F)F
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->w0(F)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->w0(F)F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->w0(F)F

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final x(I)J
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final y(F)J
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 9
    .line 10
    .line 11
    move-result-wide p0

    .line 12
    return-wide p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final z0(J)I
    .locals 1

    .line 1
    iget v0, p0, Lg1/z1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 7
    .line 8
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lg1/z1;->e:Lt4/c;

    .line 21
    .line 22
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
