.class public final synthetic Lr80/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr80/f;


# direct methods
.method public synthetic constructor <init>(Lr80/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lr80/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr80/d;->e:Lr80/f;

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
    iget v0, p0, Lr80/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onCareAndInsuranceResult(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Lr80/f;

    .line 13
    .line 14
    iget-object v5, p0, Lr80/d;->e:Lr80/f;

    .line 15
    .line 16
    const-string v6, "onCareAndInsuranceResult"

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
    const-string v8, "onSkodaServicesResult(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Lr80/f;

    .line 29
    .line 30
    iget-object v6, p0, Lr80/d;->e:Lr80/f;

    .line 31
    .line 32
    const-string v7, "onSkodaServicesResult"

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
    const-string v9, "onPowerpassSubscription(Lcz/skodaauto/myskoda/library/data/infrastructure/LoadableData;)V"

    .line 41
    .line 42
    const/4 v5, 0x4

    .line 43
    const/4 v4, 0x2

    .line 44
    const-class v6, Lr80/f;

    .line 45
    .line 46
    iget-object v7, p0, Lr80/d;->e:Lr80/f;

    .line 47
    .line 48
    const-string v8, "onPowerpassSubscription"

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
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lr80/d;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    iget-object v0, v0, Lr80/d;->e:Lr80/f;

    .line 9
    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    move-object/from16 v1, p1

    .line 14
    .line 15
    check-cast v1, Lne0/s;

    .line 16
    .line 17
    instance-of v2, v1, Lne0/e;

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    move-object v4, v1

    .line 26
    check-cast v4, Lr80/e;

    .line 27
    .line 28
    const/16 v17, 0x0

    .line 29
    .line 30
    const/16 v18, 0x1bbf

    .line 31
    .line 32
    const/4 v5, 0x0

    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x0

    .line 35
    const/4 v8, 0x0

    .line 36
    const/4 v9, 0x0

    .line 37
    const/4 v10, 0x0

    .line 38
    const/4 v11, 0x0

    .line 39
    const/4 v12, 0x0

    .line 40
    const/4 v13, 0x0

    .line 41
    const/4 v14, 0x0

    .line 42
    const/4 v15, 0x0

    .line 43
    const/16 v16, 0x0

    .line 44
    .line 45
    invoke-static/range {v4 .. v18}, Lr80/e;->a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    instance-of v2, v1, Lne0/c;

    .line 51
    .line 52
    if-eqz v2, :cond_1

    .line 53
    .line 54
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    move-object v4, v2

    .line 59
    check-cast v4, Lr80/e;

    .line 60
    .line 61
    check-cast v1, Lne0/c;

    .line 62
    .line 63
    iget-object v2, v0, Lr80/f;->i:Lij0/a;

    .line 64
    .line 65
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 66
    .line 67
    .line 68
    move-result-object v5

    .line 69
    const/16 v17, 0x0

    .line 70
    .line 71
    const/16 v18, 0x1bbe

    .line 72
    .line 73
    const/4 v6, 0x0

    .line 74
    const/4 v7, 0x0

    .line 75
    const/4 v8, 0x0

    .line 76
    const/4 v9, 0x0

    .line 77
    const/4 v10, 0x0

    .line 78
    const/4 v11, 0x0

    .line 79
    const/4 v12, 0x0

    .line 80
    const/4 v13, 0x0

    .line 81
    const/4 v14, 0x0

    .line 82
    const/4 v15, 0x1

    .line 83
    const/16 v16, 0x0

    .line 84
    .line 85
    invoke-static/range {v4 .. v18}, Lr80/e;->a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;

    .line 86
    .line 87
    .line 88
    move-result-object v1

    .line 89
    goto :goto_0

    .line 90
    :cond_1
    sget-object v2, Lne0/d;->a:Lne0/d;

    .line 91
    .line 92
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v1

    .line 96
    if-eqz v1, :cond_2

    .line 97
    .line 98
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    move-object v4, v1

    .line 103
    check-cast v4, Lr80/e;

    .line 104
    .line 105
    const/16 v17, 0x0

    .line 106
    .line 107
    const/16 v18, 0x1fbf

    .line 108
    .line 109
    const/4 v5, 0x0

    .line 110
    const/4 v6, 0x0

    .line 111
    const/4 v7, 0x0

    .line 112
    const/4 v8, 0x0

    .line 113
    const/4 v9, 0x0

    .line 114
    const/4 v10, 0x0

    .line 115
    const/4 v11, 0x1

    .line 116
    const/4 v12, 0x0

    .line 117
    const/4 v13, 0x0

    .line 118
    const/4 v14, 0x0

    .line 119
    const/4 v15, 0x0

    .line 120
    const/16 v16, 0x0

    .line 121
    .line 122
    invoke-static/range {v4 .. v18}, Lr80/e;->a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    :goto_0
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 127
    .line 128
    .line 129
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 130
    .line 131
    return-object v3

    .line 132
    :cond_2
    new-instance v0, La8/r0;

    .line 133
    .line 134
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 135
    .line 136
    .line 137
    throw v0

    .line 138
    :pswitch_0
    move-object/from16 v1, p1

    .line 139
    .line 140
    check-cast v1, Lne0/s;

    .line 141
    .line 142
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    new-instance v5, Lr60/t;

    .line 147
    .line 148
    const/4 v6, 0x2

    .line 149
    invoke-direct {v5, v6, v0, v1, v2}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 150
    .line 151
    .line 152
    const/4 v0, 0x3

    .line 153
    invoke-static {v4, v2, v2, v5, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 154
    .line 155
    .line 156
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 157
    .line 158
    return-object v3

    .line 159
    :pswitch_1
    move-object/from16 v1, p1

    .line 160
    .line 161
    check-cast v1, Lne0/s;

    .line 162
    .line 163
    instance-of v4, v1, Lne0/e;

    .line 164
    .line 165
    if-eqz v4, :cond_3

    .line 166
    .line 167
    move-object v2, v1

    .line 168
    check-cast v2, Lne0/e;

    .line 169
    .line 170
    :cond_3
    sget-object v4, Lto0/r;->a:Lto0/r;

    .line 171
    .line 172
    if-eqz v2, :cond_4

    .line 173
    .line 174
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v2, Lto0/s;

    .line 177
    .line 178
    if-eqz v2, :cond_4

    .line 179
    .line 180
    iget-object v2, v2, Lto0/s;->a:Lla/w;

    .line 181
    .line 182
    goto :goto_1

    .line 183
    :cond_4
    move-object v2, v4

    .line 184
    :goto_1
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 185
    .line 186
    .line 187
    move-result-object v5

    .line 188
    move-object v6, v5

    .line 189
    check-cast v6, Lr80/e;

    .line 190
    .line 191
    instance-of v14, v1, Lne0/d;

    .line 192
    .line 193
    invoke-virtual {v2, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v15

    .line 197
    const/16 v19, 0x0

    .line 198
    .line 199
    const/16 v20, 0x1e7f

    .line 200
    .line 201
    const/4 v7, 0x0

    .line 202
    const/4 v8, 0x0

    .line 203
    const/4 v9, 0x0

    .line 204
    const/4 v10, 0x0

    .line 205
    const/4 v11, 0x0

    .line 206
    const/4 v12, 0x0

    .line 207
    const/4 v13, 0x0

    .line 208
    const/16 v16, 0x0

    .line 209
    .line 210
    const/16 v17, 0x0

    .line 211
    .line 212
    const/16 v18, 0x0

    .line 213
    .line 214
    invoke-static/range {v6 .. v20}, Lr80/e;->a(Lr80/e;Lql0/g;ZZZZZZZZZZZLjava/lang/String;I)Lr80/e;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 219
    .line 220
    .line 221
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 222
    .line 223
    return-object v3

    .line 224
    nop

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lr80/d;->d:I

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
    iget v0, p0, Lr80/d;->d:I

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
