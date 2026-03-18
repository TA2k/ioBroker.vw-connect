.class public abstract La7/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh7/m;

.field public final b:Li7/h;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lh7/n;->a:Lh7/m;

    .line 5
    .line 6
    iput-object v0, p0, La7/m0;->a:Lh7/m;

    .line 7
    .line 8
    sget-object v0, Li7/h;->a:Li7/h;

    .line 9
    .line 10
    iput-object v0, p0, La7/m0;->b:Li7/h;

    .line 11
    .line 12
    return-void
.end method

.method public static c(La7/m0;Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, La7/c2;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->get()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const-string v0, "GlanceAppWidget::update"

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    sget-object v2, La7/d2;->a:La7/d2;

    .line 16
    .line 17
    invoke-virtual {v2, v0, v1}, La7/d2;->a(Ljava/lang/String;I)V

    .line 18
    .line 19
    .line 20
    :cond_0
    new-instance v0, La7/c;

    .line 21
    .line 22
    invoke-direct {v0, p2}, La7/c;-><init>(I)V

    .line 23
    .line 24
    .line 25
    iget-object p2, p0, La7/m0;->a:Lh7/m;

    .line 26
    .line 27
    new-instance v1, La7/r;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-direct {v1, p1, v0, p0, v2}, La7/r;-><init>(Landroid/content/Context;La7/c;La7/m0;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p2, v1, p3}, Lh7/m;->a(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    if-ne p0, p1, :cond_1

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object p0
.end method


# virtual methods
.method public final a(Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p3, La7/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, La7/j0;

    .line 7
    .line 8
    iget v1, v0, La7/j0;->i:I

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
    iput v1, v0, La7/j0;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/j0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, La7/j0;-><init>(La7/m0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, La7/j0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/j0;->i:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x0

    .line 34
    packed-switch v2, :pswitch_data_0

    .line 35
    .line 36
    .line 37
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
    :pswitch_0
    iget-object p0, v0, La7/j0;->d:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ljava/lang/Throwable;

    .line 48
    .line 49
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_4

    .line 53
    .line 54
    :pswitch_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_7

    .line 58
    .line 59
    :pswitch_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-object v3

    .line 63
    :pswitch_3
    iget p0, v0, La7/j0;->f:I

    .line 64
    .line 65
    iget-object p1, v0, La7/j0;->e:Landroid/content/Context;

    .line 66
    .line 67
    iget-object p2, v0, La7/j0;->d:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p2, La7/m0;

    .line 70
    .line 71
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :catchall_0
    move-exception p3

    .line 76
    goto/16 :goto_3

    .line 77
    .line 78
    :pswitch_4
    iget p2, v0, La7/j0;->f:I

    .line 79
    .line 80
    iget-object p1, v0, La7/j0;->e:Landroid/content/Context;

    .line 81
    .line 82
    iget-object p0, v0, La7/j0;->d:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast p0, La7/m0;

    .line 85
    .line 86
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :pswitch_5
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    new-instance p3, La7/c;

    .line 94
    .line 95
    invoke-direct {p3, p2}, La7/c;-><init>(I)V

    .line 96
    .line 97
    .line 98
    new-instance v2, La50/c;

    .line 99
    .line 100
    const/4 v5, 0x2

    .line 101
    invoke-direct {v2, p3, v4, v5}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 102
    .line 103
    .line 104
    iput-object p0, v0, La7/j0;->d:Ljava/lang/Object;

    .line 105
    .line 106
    iput-object p1, v0, La7/j0;->e:Landroid/content/Context;

    .line 107
    .line 108
    iput p2, v0, La7/j0;->f:I

    .line 109
    .line 110
    const/4 p3, 0x1

    .line 111
    iput p3, v0, La7/j0;->i:I

    .line 112
    .line 113
    iget-object p3, p0, La7/m0;->a:Lh7/m;

    .line 114
    .line 115
    invoke-virtual {p3, v2, v0}, Lh7/m;->a(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    if-ne p3, v1, :cond_1

    .line 120
    .line 121
    goto/16 :goto_6

    .line 122
    .line 123
    :cond_1
    :goto_1
    :try_start_1
    iput-object p0, v0, La7/j0;->d:Ljava/lang/Object;

    .line 124
    .line 125
    iput-object p1, v0, La7/j0;->e:Landroid/content/Context;

    .line 126
    .line 127
    iput p2, v0, La7/j0;->f:I

    .line 128
    .line 129
    const/4 p3, 0x2

    .line 130
    iput p3, v0, La7/j0;->i:I

    .line 131
    .line 132
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 133
    .line 134
    .line 135
    if-ne v3, v1, :cond_2

    .line 136
    .line 137
    goto/16 :goto_6

    .line 138
    .line 139
    :cond_2
    move v6, p2

    .line 140
    move-object p2, p0

    .line 141
    move p0, v6

    .line 142
    :goto_2
    iget-object p2, p2, La7/m0;->b:Li7/h;

    .line 143
    .line 144
    if-eqz p2, :cond_5

    .line 145
    .line 146
    sget-object p3, Li7/f;->a:Li7/f;

    .line 147
    .line 148
    invoke-static {p0}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    iput-object v4, v0, La7/j0;->d:Ljava/lang/Object;

    .line 153
    .line 154
    iput-object v4, v0, La7/j0;->e:Landroid/content/Context;

    .line 155
    .line 156
    const/4 v2, 0x3

    .line 157
    iput v2, v0, La7/j0;->i:I

    .line 158
    .line 159
    invoke-virtual {p3, p1, p2, p0, v0}, Li7/f;->a(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    if-ne p0, v1, :cond_5

    .line 164
    .line 165
    goto :goto_6

    .line 166
    :catchall_1
    move-exception p3

    .line 167
    move v6, p2

    .line 168
    move-object p2, p0

    .line 169
    move p0, v6

    .line 170
    goto :goto_3

    .line 171
    :catch_0
    move v6, p2

    .line 172
    move-object p2, p0

    .line 173
    move p0, v6

    .line 174
    goto :goto_5

    .line 175
    :goto_3
    :try_start_2
    const-string v2, "GlanceAppWidget"

    .line 176
    .line 177
    const-string v5, "Error in user-provided deletion callback"

    .line 178
    .line 179
    invoke-static {v2, v5, p3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 180
    .line 181
    .line 182
    iget-object p2, p2, La7/m0;->b:Li7/h;

    .line 183
    .line 184
    if-eqz p2, :cond_5

    .line 185
    .line 186
    sget-object p3, Li7/f;->a:Li7/f;

    .line 187
    .line 188
    invoke-static {p0}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    iput-object v4, v0, La7/j0;->d:Ljava/lang/Object;

    .line 193
    .line 194
    iput-object v4, v0, La7/j0;->e:Landroid/content/Context;

    .line 195
    .line 196
    const/4 v2, 0x5

    .line 197
    iput v2, v0, La7/j0;->i:I

    .line 198
    .line 199
    invoke-virtual {p3, p1, p2, p0, v0}, Li7/f;->a(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    if-ne p0, v1, :cond_5

    .line 204
    .line 205
    goto :goto_6

    .line 206
    :catchall_2
    move-exception p3

    .line 207
    iget-object p2, p2, La7/m0;->b:Li7/h;

    .line 208
    .line 209
    if-eqz p2, :cond_4

    .line 210
    .line 211
    sget-object v2, Li7/f;->a:Li7/f;

    .line 212
    .line 213
    invoke-static {p0}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    iput-object p3, v0, La7/j0;->d:Ljava/lang/Object;

    .line 218
    .line 219
    iput-object v4, v0, La7/j0;->e:Landroid/content/Context;

    .line 220
    .line 221
    const/4 v3, 0x6

    .line 222
    iput v3, v0, La7/j0;->i:I

    .line 223
    .line 224
    invoke-virtual {v2, p1, p2, p0, v0}, Li7/f;->a(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    if-ne p0, v1, :cond_3

    .line 229
    .line 230
    goto :goto_6

    .line 231
    :cond_3
    move-object p0, p3

    .line 232
    :goto_4
    move-object p3, p0

    .line 233
    :cond_4
    throw p3

    .line 234
    :catch_1
    :goto_5
    iget-object p2, p2, La7/m0;->b:Li7/h;

    .line 235
    .line 236
    if-eqz p2, :cond_5

    .line 237
    .line 238
    sget-object p3, Li7/f;->a:Li7/f;

    .line 239
    .line 240
    invoke-static {p0}, Lcy0/a;->f(I)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object p0

    .line 244
    iput-object v4, v0, La7/j0;->d:Ljava/lang/Object;

    .line 245
    .line 246
    iput-object v4, v0, La7/j0;->e:Landroid/content/Context;

    .line 247
    .line 248
    const/4 v2, 0x4

    .line 249
    iput v2, v0, La7/j0;->i:I

    .line 250
    .line 251
    invoke-virtual {p3, p1, p2, p0, v0}, Li7/f;->a(Landroid/content/Context;Li7/g;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    if-ne p0, v1, :cond_5

    .line 256
    .line 257
    :goto_6
    return-object v1

    .line 258
    :cond_5
    :goto_7
    return-object v3

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public abstract b(Lrx0/c;)V
.end method
