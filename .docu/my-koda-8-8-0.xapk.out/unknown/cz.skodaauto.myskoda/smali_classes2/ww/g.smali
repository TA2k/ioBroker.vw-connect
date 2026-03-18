.class public final Lww/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/io/File;

.field public f:Landroidx/lifecycle/c1;

.field public g:Ljava/lang/String;

.field public h:I

.field public final synthetic i:Luw/b;

.field public final synthetic j:Landroidx/lifecycle/c1;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/c1;Luw/b;Ljava/io/File;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lww/g;->d:I

    .line 1
    iput-object p1, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    iput-object p2, p0, Lww/g;->i:Luw/b;

    iput-object p3, p0, Lww/g;->e:Ljava/io/File;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Luw/b;Landroidx/lifecycle/c1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lww/g;->d:I

    .line 2
    iput-object p1, p0, Lww/g;->i:Luw/b;

    iput-object p2, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lww/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lww/g;

    .line 7
    .line 8
    iget-object v0, p0, Lww/g;->i:Luw/b;

    .line 9
    .line 10
    iget-object p0, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    .line 11
    .line 12
    invoke-direct {p1, v0, p0, p2}, Lww/g;-><init>(Luw/b;Landroidx/lifecycle/c1;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_0
    new-instance p1, Lww/g;

    .line 17
    .line 18
    iget-object v0, p0, Lww/g;->i:Luw/b;

    .line 19
    .line 20
    iget-object v1, p0, Lww/g;->e:Ljava/io/File;

    .line 21
    .line 22
    iget-object p0, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, v1, p2}, Lww/g;-><init>(Landroidx/lifecycle/c1;Luw/b;Ljava/io/File;Lkotlin/coroutines/Continuation;)V

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
    iget v0, p0, Lww/g;->d:I

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
    invoke-virtual {p0, p1, p2}, Lww/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lww/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lww/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lww/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lww/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lww/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lww/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lww/g;->h:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    const/4 v3, 0x2

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v2, :cond_1

    .line 15
    .line 16
    if-ne v1, v3, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lww/g;->e:Ljava/io/File;

    .line 19
    .line 20
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    goto/16 :goto_2

    .line 24
    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto/16 :goto_4

    .line 27
    .line 28
    :catch_0
    move-exception p1

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    iget-object v0, p0, Lww/g;->g:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v1, p0, Lww/g;->f:Landroidx/lifecycle/c1;

    .line 41
    .line 42
    iget-object p0, p0, Lww/g;->e:Ljava/io/File;

    .line 43
    .line 44
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p1, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    const-string v1, "Reading cached Translations for: "

    .line 54
    .line 55
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lww/g;->i:Luw/b;

    .line 59
    .line 60
    invoke-static {v1}, Llp/td;->a(Luw/b;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-static {p1}, Let/d;->c(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Luw/b;->b()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    new-instance v4, Ljava/io/File;

    .line 79
    .line 80
    iget-object v5, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    .line 81
    .line 82
    iget-object v6, v5, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v6, Ljava/io/File;

    .line 85
    .line 86
    const-string v7, ".xml"

    .line 87
    .line 88
    invoke-static {p1, v7}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-direct {v4, v6, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :try_start_2
    sget-wide v6, Luw/c;->d:J

    .line 96
    .line 97
    const-wide/16 v8, 0x0

    .line 98
    .line 99
    cmp-long p1, v6, v8

    .line 100
    .line 101
    if-gez p1, :cond_4

    .line 102
    .line 103
    invoke-virtual {v1}, Luw/b;->b()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    iput-object v4, p0, Lww/g;->e:Ljava/io/File;

    .line 108
    .line 109
    iput-object v5, p0, Lww/g;->f:Landroidx/lifecycle/c1;

    .line 110
    .line 111
    iput-object p1, p0, Lww/g;->g:Ljava/lang/String;

    .line 112
    .line 113
    iput v2, p0, Lww/g;->h:I

    .line 114
    .line 115
    invoke-static {v5, v4, p0}, Landroidx/lifecycle/c1;->d(Landroidx/lifecycle/c1;Ljava/io/File;Lrx0/c;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0
    :try_end_2
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 119
    if-ne p0, v0, :cond_3

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_3
    move-object v0, p1

    .line 123
    move-object v1, v5

    .line 124
    move-object p1, p0

    .line 125
    move-object p0, v4

    .line 126
    :goto_0
    :try_start_3
    new-instance v2, Llx0/l;

    .line 127
    .line 128
    invoke-direct {v2, v0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iput-object v2, v1, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;
    :try_end_3
    .catch Ljava/io/FileNotFoundException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :goto_1
    move-object v4, p0

    .line 135
    goto :goto_5

    .line 136
    :catch_1
    move-exception p0

    .line 137
    move-object p1, p0

    .line 138
    goto :goto_5

    .line 139
    :cond_4
    :try_start_4
    new-instance p1, Lww/g;

    .line 140
    .line 141
    const/4 v2, 0x0

    .line 142
    invoke-direct {p1, v5, v1, v4, v2}, Lww/g;-><init>(Landroidx/lifecycle/c1;Luw/b;Ljava/io/File;Lkotlin/coroutines/Continuation;)V

    .line 143
    .line 144
    .line 145
    iput-object v4, p0, Lww/g;->e:Ljava/io/File;

    .line 146
    .line 147
    iput v3, p0, Lww/g;->h:I

    .line 148
    .line 149
    invoke-static {v6, v7, p1, p0}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p0
    :try_end_4
    .catch Ljava/io/FileNotFoundException; {:try_start_4 .. :try_end_4} :catch_1
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 153
    if-ne p0, v0, :cond_5

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    :goto_3
    return-object v0

    .line 159
    :goto_4
    const-string p1, "Reading cached Translation failed"

    .line 160
    .line 161
    invoke-static {v3, p1, p0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 162
    .line 163
    .line 164
    throw p0

    .line 165
    :goto_5
    new-instance p0, Ljava/lang/StringBuilder;

    .line 166
    .line 167
    const-string v0, "Reading cached Translation failed: No cached file "

    .line 168
    .line 169
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v4}, Ljava/io/File;->getAbsoluteFile()Ljava/io/File;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    const-string v0, " present"

    .line 180
    .line 181
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    invoke-static {p0}, Let/d;->d(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    throw p1

    .line 192
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 193
    .line 194
    iget v1, p0, Lww/g;->h:I

    .line 195
    .line 196
    const/4 v2, 0x1

    .line 197
    if-eqz v1, :cond_7

    .line 198
    .line 199
    if-ne v1, v2, :cond_6

    .line 200
    .line 201
    iget-object v0, p0, Lww/g;->g:Ljava/lang/String;

    .line 202
    .line 203
    iget-object p0, p0, Lww/g;->f:Landroidx/lifecycle/c1;

    .line 204
    .line 205
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    goto :goto_6

    .line 209
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 210
    .line 211
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 212
    .line 213
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    throw p0

    .line 217
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    iget-object p1, p0, Lww/g;->i:Luw/b;

    .line 221
    .line 222
    invoke-virtual {p1}, Luw/b;->b()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object p1

    .line 226
    iget-object v1, p0, Lww/g;->e:Ljava/io/File;

    .line 227
    .line 228
    iget-object v3, p0, Lww/g;->j:Landroidx/lifecycle/c1;

    .line 229
    .line 230
    iput-object v3, p0, Lww/g;->f:Landroidx/lifecycle/c1;

    .line 231
    .line 232
    iput-object p1, p0, Lww/g;->g:Ljava/lang/String;

    .line 233
    .line 234
    iput v2, p0, Lww/g;->h:I

    .line 235
    .line 236
    invoke-static {v3, v1, p0}, Landroidx/lifecycle/c1;->d(Landroidx/lifecycle/c1;Ljava/io/File;Lrx0/c;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    if-ne p0, v0, :cond_8

    .line 241
    .line 242
    goto :goto_7

    .line 243
    :cond_8
    move-object v0, p1

    .line 244
    move-object p1, p0

    .line 245
    move-object p0, v3

    .line 246
    :goto_6
    new-instance v1, Llx0/l;

    .line 247
    .line 248
    invoke-direct {v1, v0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    iput-object v1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 252
    .line 253
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 254
    .line 255
    :goto_7
    return-object v0

    .line 256
    nop

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
