.class public final synthetic Ly70/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly70/j1;


# direct methods
.method public synthetic constructor <init>(Ly70/j1;I)V
    .locals 0

    .line 1
    iput p2, p0, Ly70/e1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly70/e1;->e:Ly70/j1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()Llx0/e;
    .locals 10

    .line 1
    iget v0, p0, Ly70/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onEncodedUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Ly70/j1;

    .line 13
    .line 14
    iget-object v5, p0, Ly70/e1;->e:Ly70/j1;

    .line 15
    .line 16
    const-string v6, "onEncodedUrlResult"

    .line 17
    .line 18
    invoke-direct/range {v1 .. v7}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object v1

    .line 22
    :pswitch_0
    new-instance v2, Lkotlin/jvm/internal/a;

    .line 23
    .line 24
    const-string v8, "onCzechRequestBookingUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Ly70/j1;

    .line 29
    .line 30
    iget-object v6, p0, Ly70/e1;->e:Ly70/j1;

    .line 31
    .line 32
    const-string v7, "onCzechRequestBookingUrlResult"

    .line 33
    .line 34
    invoke-direct/range {v2 .. v8}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-object v2

    .line 38
    :pswitch_1
    new-instance v3, Lkotlin/jvm/internal/a;

    .line 39
    .line 40
    const-string v9, "onCzechRequestBookingUrlResult(Lcz/skodaauto/myskoda/library/data/infrastructure/ResultData;)V"

    .line 41
    .line 42
    const/4 v5, 0x4

    .line 43
    const/4 v4, 0x2

    .line 44
    const-class v6, Ly70/j1;

    .line 45
    .line 46
    iget-object v7, p0, Ly70/e1;->e:Ly70/j1;

    .line 47
    .line 48
    const-string v8, "onCzechRequestBookingUrlResult"

    .line 49
    .line 50
    invoke-direct/range {v3 .. v9}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object v3

    .line 54
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ly70/e1;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v0, v0, Ly70/e1;->e:Ly70/j1;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lne0/t;

    .line 15
    .line 16
    instance-of v3, v1, Lne0/c;

    .line 17
    .line 18
    if-eqz v3, :cond_0

    .line 19
    .line 20
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    move-object v4, v3

    .line 25
    check-cast v4, Ly70/a1;

    .line 26
    .line 27
    check-cast v1, Lne0/c;

    .line 28
    .line 29
    iget-object v3, v0, Ly70/j1;->j:Lij0/a;

    .line 30
    .line 31
    invoke-static {v1, v3}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 32
    .line 33
    .line 34
    move-result-object v12

    .line 35
    const/16 v30, 0x0

    .line 36
    .line 37
    const v31, 0x7ffff7f

    .line 38
    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    const/4 v6, 0x0

    .line 42
    const/4 v7, 0x0

    .line 43
    const/4 v8, 0x0

    .line 44
    const/4 v9, 0x0

    .line 45
    const/4 v10, 0x0

    .line 46
    const/4 v11, 0x0

    .line 47
    const/4 v13, 0x0

    .line 48
    const/4 v14, 0x0

    .line 49
    const/4 v15, 0x0

    .line 50
    const/16 v16, 0x0

    .line 51
    .line 52
    const/16 v17, 0x0

    .line 53
    .line 54
    const/16 v18, 0x0

    .line 55
    .line 56
    const/16 v19, 0x0

    .line 57
    .line 58
    const/16 v20, 0x0

    .line 59
    .line 60
    const/16 v21, 0x0

    .line 61
    .line 62
    const/16 v22, 0x0

    .line 63
    .line 64
    const/16 v23, 0x0

    .line 65
    .line 66
    const/16 v24, 0x0

    .line 67
    .line 68
    const/16 v25, 0x0

    .line 69
    .line 70
    const/16 v26, 0x0

    .line 71
    .line 72
    const/16 v27, 0x0

    .line 73
    .line 74
    const/16 v28, 0x0

    .line 75
    .line 76
    const/16 v29, 0x0

    .line 77
    .line 78
    invoke-static/range {v4 .. v31}, Ly70/a1;->a(Ly70/a1;ZZZLlf0/i;Ler0/g;Ler0/g;ZLql0/g;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZLy70/w1;Ly70/y0;ZZLjava/lang/String;Ljava/lang/String;Ly70/z0;ZZZZZZI)Ly70/a1;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 83
    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_0
    instance-of v3, v1, Lne0/e;

    .line 87
    .line 88
    if-eqz v3, :cond_5

    .line 89
    .line 90
    iget-object v0, v0, Ly70/j1;->u:Lbd0/c;

    .line 91
    .line 92
    check-cast v1, Lne0/e;

    .line 93
    .line 94
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v1, Ljava/lang/String;

    .line 97
    .line 98
    const/16 v3, 0x1e

    .line 99
    .line 100
    and-int/lit8 v4, v3, 0x2

    .line 101
    .line 102
    const/4 v5, 0x0

    .line 103
    const/4 v6, 0x1

    .line 104
    if-eqz v4, :cond_1

    .line 105
    .line 106
    move v9, v6

    .line 107
    goto :goto_0

    .line 108
    :cond_1
    move v9, v5

    .line 109
    :goto_0
    and-int/lit8 v4, v3, 0x4

    .line 110
    .line 111
    if-eqz v4, :cond_2

    .line 112
    .line 113
    move v10, v6

    .line 114
    goto :goto_1

    .line 115
    :cond_2
    move v10, v5

    .line 116
    :goto_1
    and-int/lit8 v4, v3, 0x8

    .line 117
    .line 118
    if-eqz v4, :cond_3

    .line 119
    .line 120
    move v11, v5

    .line 121
    goto :goto_2

    .line 122
    :cond_3
    move v11, v6

    .line 123
    :goto_2
    and-int/lit8 v3, v3, 0x10

    .line 124
    .line 125
    if-eqz v3, :cond_4

    .line 126
    .line 127
    move v12, v5

    .line 128
    goto :goto_3

    .line 129
    :cond_4
    move v12, v6

    .line 130
    :goto_3
    const-string v3, "url"

    .line 131
    .line 132
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 136
    .line 137
    new-instance v8, Ljava/net/URL;

    .line 138
    .line 139
    invoke-direct {v8, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    move-object v7, v0

    .line 143
    check-cast v7, Lzc0/b;

    .line 144
    .line 145
    invoke-virtual/range {v7 .. v12}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 146
    .line 147
    .line 148
    :goto_4
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 149
    .line 150
    return-object v2

    .line 151
    :cond_5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    new-instance v0, La8/r0;

    .line 155
    .line 156
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 157
    .line 158
    .line 159
    throw v0

    .line 160
    :pswitch_0
    move-object/from16 v1, p1

    .line 161
    .line 162
    check-cast v1, Lne0/t;

    .line 163
    .line 164
    invoke-virtual {v0, v1}, Ly70/j1;->H(Lne0/t;)V

    .line 165
    .line 166
    .line 167
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 168
    .line 169
    return-object v2

    .line 170
    :pswitch_1
    move-object/from16 v1, p1

    .line 171
    .line 172
    check-cast v1, Lne0/t;

    .line 173
    .line 174
    invoke-virtual {v0, v1}, Ly70/j1;->H(Lne0/t;)V

    .line 175
    .line 176
    .line 177
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 178
    .line 179
    return-object v2

    .line 180
    nop

    .line 181
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Ly70/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lyy0/j;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 20
    .line 21
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    :cond_0
    return v1

    .line 30
    :pswitch_0
    instance-of v0, p1, Lyy0/j;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 44
    .line 45
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    :cond_1
    return v1

    .line 54
    :pswitch_1
    instance-of v0, p1, Lyy0/j;

    .line 55
    .line 56
    const/4 v1, 0x0

    .line 57
    if-eqz v0, :cond_2

    .line 58
    .line 59
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 60
    .line 61
    if-eqz v0, :cond_2

    .line 62
    .line 63
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 68
    .line 69
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    :cond_2
    return v1

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Ly70/e1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
