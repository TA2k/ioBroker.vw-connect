.class public final synthetic Lyj0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;
.implements Lkotlin/jvm/internal/h;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyj0/f;


# direct methods
.method public synthetic constructor <init>(Lyj0/f;I)V
    .locals 0

    .line 1
    iput p2, p0, Lyj0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyj0/b;->e:Lyj0/f;

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
    .locals 14

    .line 1
    iget v0, p0, Lyj0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lkotlin/jvm/internal/a;

    .line 7
    .line 8
    const-string v7, "onRoutePreview(Lcz/skodaauto/myskoda/library/map/model/RoutePreview;)V"

    .line 9
    .line 10
    const/4 v3, 0x4

    .line 11
    const/4 v2, 0x2

    .line 12
    const-class v4, Lyj0/f;

    .line 13
    .line 14
    iget-object v5, p0, Lyj0/b;->e:Lyj0/f;

    .line 15
    .line 16
    const-string v6, "onRoutePreview"

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
    const-string v8, "onZoom(Lcz/skodaauto/myskoda/library/map/model/Zoom;)V"

    .line 25
    .line 26
    const/4 v4, 0x4

    .line 27
    const/4 v3, 0x2

    .line 28
    const-class v5, Lyj0/f;

    .line 29
    .line 30
    iget-object v6, p0, Lyj0/b;->e:Lyj0/f;

    .line 31
    .line 32
    const-string v7, "onZoom"

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
    const-string v9, "onTileType(Lcz/skodaauto/myskoda/library/map/model/MapTileType;)V"

    .line 41
    .line 42
    const/4 v5, 0x4

    .line 43
    const/4 v4, 0x2

    .line 44
    const-class v6, Lyj0/f;

    .line 45
    .line 46
    iget-object v7, p0, Lyj0/b;->e:Lyj0/f;

    .line 47
    .line 48
    const-string v8, "onTileType"

    .line 49
    .line 50
    invoke-direct/range {v3 .. v9}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    return-object v3

    .line 54
    :pswitch_2
    new-instance v4, Lkotlin/jvm/internal/a;

    .line 55
    .line 56
    const-string v10, "onPolylines(Ljava/util/List;)V"

    .line 57
    .line 58
    const/4 v6, 0x4

    .line 59
    const/4 v5, 0x2

    .line 60
    const-class v7, Lyj0/f;

    .line 61
    .line 62
    iget-object v8, p0, Lyj0/b;->e:Lyj0/f;

    .line 63
    .line 64
    const-string v9, "onPolylines"

    .line 65
    .line 66
    invoke-direct/range {v4 .. v10}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-object v4

    .line 70
    :pswitch_3
    new-instance v5, Lkotlin/jvm/internal/a;

    .line 71
    .line 72
    const-string v11, "onPolygons(Ljava/util/List;)V"

    .line 73
    .line 74
    const/4 v7, 0x4

    .line 75
    const/4 v6, 0x2

    .line 76
    const-class v8, Lyj0/f;

    .line 77
    .line 78
    iget-object v9, p0, Lyj0/b;->e:Lyj0/f;

    .line 79
    .line 80
    const-string v10, "onPolygons"

    .line 81
    .line 82
    invoke-direct/range {v5 .. v11}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    return-object v5

    .line 86
    :pswitch_4
    new-instance v6, Lkotlin/jvm/internal/k;

    .line 87
    .line 88
    const-string v12, "onPins(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 89
    .line 90
    const/4 v8, 0x0

    .line 91
    const/4 v7, 0x2

    .line 92
    const-class v9, Lyj0/f;

    .line 93
    .line 94
    iget-object v10, p0, Lyj0/b;->e:Lyj0/f;

    .line 95
    .line 96
    const-string v11, "onPins"

    .line 97
    .line 98
    invoke-direct/range {v6 .. v12}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    return-object v6

    .line 102
    :pswitch_5
    new-instance v7, Lkotlin/jvm/internal/a;

    .line 103
    .line 104
    const-string v13, "onDevicePosition(Lcz/skodaauto/myskoda/library/map/model/DevicePosition;)V"

    .line 105
    .line 106
    const/4 v9, 0x4

    .line 107
    const/4 v8, 0x2

    .line 108
    const-class v10, Lyj0/f;

    .line 109
    .line 110
    iget-object v11, p0, Lyj0/b;->e:Lyj0/f;

    .line 111
    .line 112
    const-string v12, "onDevicePosition"

    .line 113
    .line 114
    invoke-direct/range {v7 .. v13}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    return-object v7

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lyj0/b;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    iget-object p0, p0, Lyj0/b;->e:Lyj0/f;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    move-object v0, p1

    .line 12
    check-cast v0, Lxj0/u;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v3, p0, Lyj0/f;->p:Lwj0/a0;

    .line 17
    .line 18
    iget-object v4, v0, Lxj0/u;->a:Ljava/util/List;

    .line 19
    .line 20
    invoke-virtual {v3, v4}, Lwj0/a0;->a(Ljava/util/List;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p0, Lyj0/f;->q:Lwj0/c0;

    .line 24
    .line 25
    iget-object v0, v0, Lxj0/u;->b:Ljava/util/List;

    .line 26
    .line 27
    iget-object p0, p0, Lwj0/c0;->a:Luj0/i;

    .line 28
    .line 29
    iget-object p0, p0, Luj0/i;->a:Lyy0/c2;

    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :cond_0
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    return-object v2

    .line 40
    :pswitch_0
    move-object v10, p1

    .line 41
    check-cast v10, Lxj0/y;

    .line 42
    .line 43
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    move-object v3, v0

    .line 48
    check-cast v3, Lyj0/d;

    .line 49
    .line 50
    const/4 v12, 0x0

    .line 51
    const/16 v13, 0x1bf

    .line 52
    .line 53
    const/4 v4, 0x0

    .line 54
    const/4 v5, 0x0

    .line 55
    const/4 v6, 0x0

    .line 56
    const/4 v7, 0x0

    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    const/4 v11, 0x0

    .line 60
    invoke-static/range {v3 .. v13}, Lyj0/d;->a(Lyj0/d;Lxj0/e;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lxj0/y;Lxj0/b;Lxj0/j;I)Lyj0/d;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 65
    .line 66
    .line 67
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 68
    .line 69
    return-object v2

    .line 70
    :pswitch_1
    move-object v12, p1

    .line 71
    check-cast v12, Lxj0/j;

    .line 72
    .line 73
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    move-object v3, v0

    .line 78
    check-cast v3, Lyj0/d;

    .line 79
    .line 80
    const/4 v11, 0x0

    .line 81
    const/16 v13, 0xff

    .line 82
    .line 83
    const/4 v4, 0x0

    .line 84
    const/4 v5, 0x0

    .line 85
    const/4 v6, 0x0

    .line 86
    const/4 v7, 0x0

    .line 87
    const/4 v8, 0x0

    .line 88
    const/4 v9, 0x0

    .line 89
    const/4 v10, 0x0

    .line 90
    invoke-static/range {v3 .. v13}, Lyj0/d;->a(Lyj0/d;Lxj0/e;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lxj0/y;Lxj0/b;Lxj0/j;I)Lyj0/d;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 95
    .line 96
    .line 97
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    return-object v2

    .line 100
    :pswitch_2
    move-object v9, p1

    .line 101
    check-cast v9, Ljava/util/List;

    .line 102
    .line 103
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    move-object v3, v0

    .line 108
    check-cast v3, Lyj0/d;

    .line 109
    .line 110
    const/4 v12, 0x0

    .line 111
    const/16 v13, 0x1df

    .line 112
    .line 113
    const/4 v4, 0x0

    .line 114
    const/4 v5, 0x0

    .line 115
    const/4 v6, 0x0

    .line 116
    const/4 v7, 0x0

    .line 117
    const/4 v8, 0x0

    .line 118
    const/4 v10, 0x0

    .line 119
    const/4 v11, 0x0

    .line 120
    invoke-static/range {v3 .. v13}, Lyj0/d;->a(Lyj0/d;Lxj0/e;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lxj0/y;Lxj0/b;Lxj0/j;I)Lyj0/d;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 125
    .line 126
    .line 127
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 128
    .line 129
    return-object v2

    .line 130
    :pswitch_3
    move-object v8, p1

    .line 131
    check-cast v8, Ljava/util/List;

    .line 132
    .line 133
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    move-object v3, v0

    .line 138
    check-cast v3, Lyj0/d;

    .line 139
    .line 140
    const/4 v12, 0x0

    .line 141
    const/16 v13, 0x1ef

    .line 142
    .line 143
    const/4 v4, 0x0

    .line 144
    const/4 v5, 0x0

    .line 145
    const/4 v6, 0x0

    .line 146
    const/4 v7, 0x0

    .line 147
    const/4 v9, 0x0

    .line 148
    const/4 v10, 0x0

    .line 149
    const/4 v11, 0x0

    .line 150
    invoke-static/range {v3 .. v13}, Lyj0/d;->a(Lyj0/d;Lxj0/e;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lxj0/y;Lxj0/b;Lxj0/j;I)Lyj0/d;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 155
    .line 156
    .line 157
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 158
    .line 159
    return-object v2

    .line 160
    :pswitch_4
    move-object v0, p1

    .line 161
    check-cast v0, Ljava/util/List;

    .line 162
    .line 163
    sget-object v3, Lge0/b;->a:Lcz0/e;

    .line 164
    .line 165
    new-instance v4, Lwa0/c;

    .line 166
    .line 167
    const/16 v5, 0xc

    .line 168
    .line 169
    invoke-direct {v4, v5, p0, v0, v1}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 170
    .line 171
    .line 172
    move-object/from16 p0, p2

    .line 173
    .line 174
    invoke-static {v3, v4, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 179
    .line 180
    if-ne p0, v0, :cond_1

    .line 181
    .line 182
    goto :goto_0

    .line 183
    :cond_1
    move-object p0, v2

    .line 184
    :goto_0
    if-ne p0, v0, :cond_2

    .line 185
    .line 186
    move-object v2, p0

    .line 187
    :cond_2
    return-object v2

    .line 188
    :pswitch_5
    move-object v4, p1

    .line 189
    check-cast v4, Lxj0/e;

    .line 190
    .line 191
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    move-object v3, v0

    .line 196
    check-cast v3, Lyj0/d;

    .line 197
    .line 198
    const/4 v12, 0x0

    .line 199
    const/16 v13, 0x1fe

    .line 200
    .line 201
    const/4 v5, 0x0

    .line 202
    const/4 v6, 0x0

    .line 203
    const/4 v7, 0x0

    .line 204
    const/4 v8, 0x0

    .line 205
    const/4 v9, 0x0

    .line 206
    const/4 v10, 0x0

    .line 207
    const/4 v11, 0x0

    .line 208
    invoke-static/range {v3 .. v13}, Lyj0/d;->a(Lyj0/d;Lxj0/e;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Lxj0/y;Lxj0/b;Lxj0/j;I)Lyj0/d;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 213
    .line 214
    .line 215
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 216
    .line 217
    return-object v2

    .line 218
    nop

    .line 219
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    iget v0, p0, Lyj0/b;->d:I

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
    :pswitch_2
    instance-of v0, p1, Lyy0/j;

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    if-eqz v0, :cond_3

    .line 82
    .line 83
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 84
    .line 85
    if-eqz v0, :cond_3

    .line 86
    .line 87
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 92
    .line 93
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    :cond_3
    return v1

    .line 102
    :pswitch_3
    instance-of v0, p1, Lyy0/j;

    .line 103
    .line 104
    const/4 v1, 0x0

    .line 105
    if-eqz v0, :cond_4

    .line 106
    .line 107
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 108
    .line 109
    if-eqz v0, :cond_4

    .line 110
    .line 111
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 116
    .line 117
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v1

    .line 125
    :cond_4
    return v1

    .line 126
    :pswitch_4
    instance-of v0, p1, Lyy0/j;

    .line 127
    .line 128
    const/4 v1, 0x0

    .line 129
    if-eqz v0, :cond_5

    .line 130
    .line 131
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 132
    .line 133
    if-eqz v0, :cond_5

    .line 134
    .line 135
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 140
    .line 141
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 142
    .line 143
    .line 144
    move-result-object p1

    .line 145
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    :cond_5
    return v1

    .line 150
    :pswitch_5
    instance-of v0, p1, Lyy0/j;

    .line 151
    .line 152
    const/4 v1, 0x0

    .line 153
    if-eqz v0, :cond_6

    .line 154
    .line 155
    instance-of v0, p1, Lkotlin/jvm/internal/h;

    .line 156
    .line 157
    if-eqz v0, :cond_6

    .line 158
    .line 159
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    check-cast p1, Lkotlin/jvm/internal/h;

    .line 164
    .line 165
    invoke-interface {p1}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v1

    .line 173
    :cond_6
    return v1

    .line 174
    nop

    .line 175
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lyj0/b;->d:I

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
    :pswitch_2
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result p0

    .line 41
    return p0

    .line 42
    :pswitch_3
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    return p0

    .line 51
    :pswitch_4
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    return p0

    .line 60
    :pswitch_5
    invoke-interface {p0}, Lkotlin/jvm/internal/h;->b()Llx0/e;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    return p0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
