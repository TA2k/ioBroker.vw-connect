.class public final Ll2/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/y0;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/view/Choreographer;Lw3/p0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Ll2/l1;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ll2/l1;->e:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Ll2/l1;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ll2/y0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Ll2/l1;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ll2/l1;->e:Ljava/lang/Object;

    .line 5
    new-instance p1, La8/b;

    const/4 v0, 0x6

    invoke-direct {p1, v0}, La8/b;-><init>(I)V

    iput-object p1, p0, Ll2/l1;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ll2/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p2, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-interface {p2, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final get(Lpx0/f;)Lpx0/e;
    .locals 1

    .line 1
    iget v0, p0, Ll2/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final minusKey(Lpx0/f;)Lpx0/g;
    .locals 1

    .line 1
    iget v0, p0, Ll2/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final plus(Lpx0/g;)Lpx0/g;
    .locals 1

    .line 1
    iget v0, p0, Ll2/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Ll2/l1;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    packed-switch v0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Ll2/l1;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lw3/p0;

    .line 10
    .line 11
    new-instance v2, Lvy0/l;

    .line 12
    .line 13
    invoke-static {p2}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    invoke-direct {v2, v1, p2}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 21
    .line 22
    .line 23
    new-instance p2, Lw3/q0;

    .line 24
    .line 25
    invoke-direct {p2, v2, p0, p1}, Lw3/q0;-><init>(Lvy0/l;Ll2/l1;Lay0/k;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, v0, Lw3/p0;->e:Landroid/view/Choreographer;

    .line 29
    .line 30
    iget-object v3, p0, Ll2/l1;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v3, Landroid/view/Choreographer;

    .line 33
    .line 34
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lw3/p0;->g:Ljava/lang/Object;

    .line 41
    .line 42
    monitor-enter p0

    .line 43
    :try_start_0
    iget-object p1, v0, Lw3/p0;->i:Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    iget-boolean p1, v0, Lw3/p0;->l:Z

    .line 49
    .line 50
    if-nez p1, :cond_0

    .line 51
    .line 52
    iput-boolean v1, v0, Lw3/p0;->l:Z

    .line 53
    .line 54
    iget-object p1, v0, Lw3/p0;->e:Landroid/view/Choreographer;

    .line 55
    .line 56
    iget-object v1, v0, Lw3/p0;->m:Lw3/o0;

    .line 57
    .line 58
    invoke-virtual {p1, v1}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :catchall_0
    move-exception p1

    .line 63
    goto :goto_1

    .line 64
    :cond_0
    :goto_0
    monitor-exit p0

    .line 65
    new-instance p0, Lb1/e;

    .line 66
    .line 67
    const/16 p1, 0x10

    .line 68
    .line 69
    invoke-direct {p0, p1, v0, p2}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2, p0}, Lvy0/l;->s(Lay0/k;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :goto_1
    monitor-exit p0

    .line 77
    throw p1

    .line 78
    :cond_1
    iget-object p1, p0, Ll2/l1;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p1, Landroid/view/Choreographer;

    .line 81
    .line 82
    invoke-virtual {p1, p2}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 83
    .line 84
    .line 85
    new-instance p1, Lb1/e;

    .line 86
    .line 87
    const/16 v0, 0x11

    .line 88
    .line 89
    invoke-direct {p1, v0, p0, p2}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 93
    .line 94
    .line 95
    :goto_2
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_0
    instance-of v0, p2, Ll2/k1;

    .line 103
    .line 104
    if-eqz v0, :cond_2

    .line 105
    .line 106
    move-object v0, p2

    .line 107
    check-cast v0, Ll2/k1;

    .line 108
    .line 109
    iget v2, v0, Ll2/k1;->g:I

    .line 110
    .line 111
    const/high16 v3, -0x80000000

    .line 112
    .line 113
    and-int v4, v2, v3

    .line 114
    .line 115
    if-eqz v4, :cond_2

    .line 116
    .line 117
    sub-int/2addr v2, v3

    .line 118
    iput v2, v0, Ll2/k1;->g:I

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_2
    new-instance v0, Ll2/k1;

    .line 122
    .line 123
    invoke-direct {v0, p0, p2}, Ll2/k1;-><init>(Ll2/l1;Lkotlin/coroutines/Continuation;)V

    .line 124
    .line 125
    .line 126
    :goto_3
    iget-object p2, v0, Ll2/k1;->e:Ljava/lang/Object;

    .line 127
    .line 128
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    iget v3, v0, Ll2/k1;->g:I

    .line 131
    .line 132
    const/4 v4, 0x2

    .line 133
    if-eqz v3, :cond_5

    .line 134
    .line 135
    if-eq v3, v1, :cond_4

    .line 136
    .line 137
    if-ne v3, v4, :cond_3

    .line 138
    .line 139
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    goto :goto_7

    .line 143
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 144
    .line 145
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 146
    .line 147
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :cond_4
    iget-object p1, v0, Ll2/k1;->d:Lay0/k;

    .line 152
    .line 153
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_5

    .line 157
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    iget-object p2, p0, Ll2/l1;->f:Ljava/lang/Object;

    .line 161
    .line 162
    check-cast p2, La8/b;

    .line 163
    .line 164
    iput-object p1, v0, Ll2/k1;->d:Lay0/k;

    .line 165
    .line 166
    iput v1, v0, Ll2/k1;->g:I

    .line 167
    .line 168
    iget-object v3, p2, La8/b;->f:Ljava/lang/Object;

    .line 169
    .line 170
    monitor-enter v3

    .line 171
    :try_start_1
    iget-boolean v5, p2, La8/b;->e:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 172
    .line 173
    monitor-exit v3

    .line 174
    if-eqz v5, :cond_6

    .line 175
    .line 176
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_6
    new-instance v3, Lvy0/l;

    .line 180
    .line 181
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 182
    .line 183
    .line 184
    move-result-object v5

    .line 185
    invoke-direct {v3, v1, v5}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v3}, Lvy0/l;->q()V

    .line 189
    .line 190
    .line 191
    iget-object v1, p2, La8/b;->f:Ljava/lang/Object;

    .line 192
    .line 193
    monitor-enter v1

    .line 194
    :try_start_2
    iget-object v5, p2, La8/b;->g:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast v5, Ljava/util/ArrayList;

    .line 197
    .line 198
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 199
    .line 200
    .line 201
    monitor-exit v1

    .line 202
    new-instance v1, Lc41/g;

    .line 203
    .line 204
    const/16 v5, 0xe

    .line 205
    .line 206
    invoke-direct {v1, v5, p2, v3}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v3, v1}, Lvy0/l;->s(Lay0/k;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v3}, Lvy0/l;->p()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p2

    .line 216
    if-ne p2, v2, :cond_7

    .line 217
    .line 218
    goto :goto_4

    .line 219
    :cond_7
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    :goto_4
    if-ne p2, v2, :cond_8

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :cond_8
    :goto_5
    iget-object p0, p0, Ll2/l1;->e:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast p0, Ll2/y0;

    .line 227
    .line 228
    const/4 p2, 0x0

    .line 229
    iput-object p2, v0, Ll2/k1;->d:Lay0/k;

    .line 230
    .line 231
    iput v4, v0, Ll2/k1;->g:I

    .line 232
    .line 233
    invoke-interface {p0, p1, v0}, Ll2/y0;->q(Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object p2

    .line 237
    if-ne p2, v2, :cond_9

    .line 238
    .line 239
    :goto_6
    move-object p2, v2

    .line 240
    :cond_9
    :goto_7
    return-object p2

    .line 241
    :catchall_1
    move-exception p0

    .line 242
    monitor-exit v1

    .line 243
    throw p0

    .line 244
    :catchall_2
    move-exception p0

    .line 245
    monitor-exit v3

    .line 246
    throw p0

    .line 247
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
