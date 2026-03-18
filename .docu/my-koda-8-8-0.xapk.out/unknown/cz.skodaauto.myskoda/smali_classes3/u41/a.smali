.class public final synthetic Lu41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# instance fields
.field public final synthetic a:Lqz0/a;

.field private final descriptor:Lsz0/g;


# direct methods
.method public constructor <init>(Lqz0/a;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Luz0/d1;

    .line 5
    .line 6
    const-string v1, "technology.cariad.cat.capabilities.Capability"

    .line 7
    .line 8
    const/4 v2, 0x7

    .line 9
    invoke-direct {v0, v1, p0, v2}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 10
    .line 11
    .line 12
    const-string v1, "id"

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 16
    .line 17
    .line 18
    const-string v1, "expirationDate"

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    invoke-virtual {v0, v1, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 22
    .line 23
    .line 24
    const-string v1, "userDisablingAllowed"

    .line 25
    .line 26
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 27
    .line 28
    .line 29
    const-string v1, "operations"

    .line 30
    .line 31
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 32
    .line 33
    .line 34
    const-string v1, "isEnabled"

    .line 35
    .line 36
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 37
    .line 38
    .line 39
    const-string v1, "status"

    .line 40
    .line 41
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 42
    .line 43
    .line 44
    const-string v1, "parameters"

    .line 45
    .line 46
    invoke-virtual {v0, v1, v3}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lu41/a;->descriptor:Lsz0/g;

    .line 50
    .line 51
    iput-object p1, p0, Lu41/a;->a:Lqz0/a;

    .line 52
    .line 53
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 5

    .line 1
    sget-object v0, Lu41/f;->h:[Llx0/i;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    new-array v1, v1, [Lqz0/a;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    iget-object p0, p0, Lu41/a;->a:Lqz0/a;

    .line 8
    .line 9
    aput-object p0, v1, v2

    .line 10
    .line 11
    sget-object v2, Lw41/a;->a:Lw41/a;

    .line 12
    .line 13
    invoke-static {v2}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    const/4 v3, 0x1

    .line 18
    aput-object v2, v1, v3

    .line 19
    .line 20
    sget-object v2, Luz0/g;->a:Luz0/g;

    .line 21
    .line 22
    const/4 v3, 0x2

    .line 23
    aput-object v2, v1, v3

    .line 24
    .line 25
    const/4 v3, 0x3

    .line 26
    aget-object v4, v0, v3

    .line 27
    .line 28
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    aput-object v4, v1, v3

    .line 33
    .line 34
    const/4 v3, 0x4

    .line 35
    aput-object v2, v1, v3

    .line 36
    .line 37
    const/4 v2, 0x5

    .line 38
    aget-object v0, v0, v2

    .line 39
    .line 40
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    aput-object v0, v1, v2

    .line 45
    .line 46
    sget-object v0, Lu41/o;->Companion:Lu41/n;

    .line 47
    .line 48
    invoke-virtual {v0, p0}, Lu41/n;->serializer(Lqz0/a;)Lqz0/a;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const/4 v0, 0x6

    .line 53
    aput-object p0, v1, v0

    .line 54
    .line 55
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lu41/a;->descriptor:Lsz0/g;

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    invoke-interface {v2, v1}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    sget-object v3, Lu41/f;->h:[Llx0/i;

    .line 12
    .line 13
    const/4 v4, 0x1

    .line 14
    move v7, v4

    .line 15
    const/4 v8, 0x0

    .line 16
    const/4 v9, 0x0

    .line 17
    const/4 v10, 0x0

    .line 18
    const/4 v11, 0x0

    .line 19
    const/4 v12, 0x0

    .line 20
    const/4 v13, 0x0

    .line 21
    const/4 v14, 0x0

    .line 22
    const/4 v15, 0x0

    .line 23
    :goto_0
    if-eqz v7, :cond_2

    .line 24
    .line 25
    invoke-interface {v2, v1}, Ltz0/a;->E(Lsz0/g;)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    iget-object v5, v0, Lu41/a;->a:Lqz0/a;

    .line 30
    .line 31
    packed-switch v6, :pswitch_data_0

    .line 32
    .line 33
    .line 34
    new-instance v0, Lqz0/k;

    .line 35
    .line 36
    invoke-direct {v0, v6}, Lqz0/k;-><init>(I)V

    .line 37
    .line 38
    .line 39
    throw v0

    .line 40
    :pswitch_0
    sget-object v6, Lu41/o;->Companion:Lu41/n;

    .line 41
    .line 42
    invoke-virtual {v6, v5}, Lu41/n;->serializer(Lqz0/a;)Lqz0/a;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    check-cast v5, Lqz0/a;

    .line 47
    .line 48
    if-eqz v8, :cond_0

    .line 49
    .line 50
    new-instance v6, Lu41/o;

    .line 51
    .line 52
    invoke-direct {v6, v8}, Lu41/o;-><init>(Ljava/util/Map;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_0
    const/4 v6, 0x0

    .line 57
    :goto_1
    const/4 v8, 0x6

    .line 58
    invoke-interface {v2, v1, v8, v5, v6}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    check-cast v5, Lu41/o;

    .line 63
    .line 64
    if-eqz v5, :cond_1

    .line 65
    .line 66
    iget-object v5, v5, Lu41/o;->a:Ljava/util/Map;

    .line 67
    .line 68
    move-object v8, v5

    .line 69
    goto :goto_2

    .line 70
    :cond_1
    const/4 v8, 0x0

    .line 71
    :goto_2
    or-int/lit8 v9, v9, 0x40

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_1
    const/4 v5, 0x5

    .line 75
    aget-object v6, v3, v5

    .line 76
    .line 77
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    check-cast v6, Lqz0/a;

    .line 82
    .line 83
    invoke-interface {v2, v1, v5, v6, v15}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    move-object v15, v5

    .line 88
    check-cast v15, Ljava/util/List;

    .line 89
    .line 90
    or-int/lit8 v9, v9, 0x20

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :pswitch_2
    const/4 v5, 0x4

    .line 94
    invoke-interface {v2, v1, v5}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 95
    .line 96
    .line 97
    move-result v14

    .line 98
    or-int/lit8 v9, v9, 0x10

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :pswitch_3
    const/4 v5, 0x3

    .line 102
    aget-object v6, v3, v5

    .line 103
    .line 104
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    check-cast v6, Lqz0/a;

    .line 109
    .line 110
    invoke-interface {v2, v1, v5, v6, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    move-object v13, v5

    .line 115
    check-cast v13, Ljava/util/Map;

    .line 116
    .line 117
    or-int/lit8 v9, v9, 0x8

    .line 118
    .line 119
    goto :goto_0

    .line 120
    :pswitch_4
    const/4 v5, 0x2

    .line 121
    invoke-interface {v2, v1, v5}, Ltz0/a;->w(Lsz0/g;I)Z

    .line 122
    .line 123
    .line 124
    move-result v12

    .line 125
    or-int/lit8 v9, v9, 0x4

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :pswitch_5
    sget-object v5, Lw41/a;->a:Lw41/a;

    .line 129
    .line 130
    invoke-interface {v2, v1, v4, v5, v11}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    move-object v11, v5

    .line 135
    check-cast v11, Ljava/time/OffsetDateTime;

    .line 136
    .line 137
    or-int/lit8 v9, v9, 0x2

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :pswitch_6
    check-cast v5, Lqz0/a;

    .line 141
    .line 142
    const/4 v6, 0x0

    .line 143
    invoke-interface {v2, v1, v6, v5, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    move-object v10, v5

    .line 148
    check-cast v10, Lu41/d;

    .line 149
    .line 150
    or-int/lit8 v9, v9, 0x1

    .line 151
    .line 152
    goto/16 :goto_0

    .line 153
    .line 154
    :pswitch_7
    const/4 v6, 0x0

    .line 155
    move v7, v6

    .line 156
    goto/16 :goto_0

    .line 157
    .line 158
    :cond_2
    invoke-interface {v2, v1}, Ltz0/a;->b(Lsz0/g;)V

    .line 159
    .line 160
    .line 161
    move-object/from16 v16, v8

    .line 162
    .line 163
    new-instance v8, Lu41/f;

    .line 164
    .line 165
    invoke-direct/range {v8 .. v16}, Lu41/f;-><init>(ILu41/d;Ljava/time/OffsetDateTime;ZLjava/util/Map;ZLjava/util/List;Ljava/util/Map;)V

    .line 166
    .line 167
    .line 168
    return-object v8

    .line 169
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lu41/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 7

    .line 1
    check-cast p2, Lu41/f;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lu41/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, v0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v1, Lu41/f;->h:[Llx0/i;

    .line 15
    .line 16
    iget-object p0, p0, Lu41/a;->a:Lqz0/a;

    .line 17
    .line 18
    move-object v2, p0

    .line 19
    check-cast v2, Lqz0/a;

    .line 20
    .line 21
    iget-object v3, p2, Lu41/f;->a:Lu41/d;

    .line 22
    .line 23
    iget-object v4, p2, Lu41/f;->g:Ljava/util/Map;

    .line 24
    .line 25
    iget-object v5, p2, Lu41/f;->b:Ljava/time/OffsetDateTime;

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    invoke-interface {p1, v0, v6, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    invoke-interface {p1, v0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    if-eqz v5, :cond_1

    .line 39
    .line 40
    :goto_0
    sget-object v2, Lw41/a;->a:Lw41/a;

    .line 41
    .line 42
    const/4 v3, 0x1

    .line 43
    invoke-interface {p1, v0, v3, v2, v5}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_1
    const/4 v2, 0x2

    .line 47
    iget-boolean v3, p2, Lu41/f;->c:Z

    .line 48
    .line 49
    invoke-interface {p1, v0, v2, v3}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 50
    .line 51
    .line 52
    const/4 v2, 0x3

    .line 53
    aget-object v3, v1, v2

    .line 54
    .line 55
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Lqz0/a;

    .line 60
    .line 61
    iget-object v5, p2, Lu41/f;->d:Ljava/util/Map;

    .line 62
    .line 63
    invoke-interface {p1, v0, v2, v3, v5}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    const/4 v2, 0x4

    .line 67
    iget-boolean v3, p2, Lu41/f;->e:Z

    .line 68
    .line 69
    invoke-interface {p1, v0, v2, v3}, Ltz0/b;->y(Lsz0/g;IZ)V

    .line 70
    .line 71
    .line 72
    const/4 v2, 0x5

    .line 73
    aget-object v1, v1, v2

    .line 74
    .line 75
    invoke-interface {v1}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    check-cast v1, Lqz0/a;

    .line 80
    .line 81
    iget-object p2, p2, Lu41/f;->f:Ljava/util/List;

    .line 82
    .line 83
    invoke-interface {p1, v0, v2, v1, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-interface {p1, v0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_2

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_2
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 94
    .line 95
    invoke-static {v4, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    if-nez p2, :cond_3

    .line 100
    .line 101
    :goto_1
    sget-object p2, Lu41/o;->Companion:Lu41/n;

    .line 102
    .line 103
    invoke-virtual {p2, p0}, Lu41/n;->serializer(Lqz0/a;)Lqz0/a;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    check-cast p0, Lqz0/a;

    .line 108
    .line 109
    new-instance p2, Lu41/o;

    .line 110
    .line 111
    invoke-direct {p2, v4}, Lu41/o;-><init>(Ljava/util/Map;)V

    .line 112
    .line 113
    .line 114
    const/4 v1, 0x6

    .line 115
    invoke-interface {p1, v0, v1, p0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    :cond_3
    invoke-interface {p1, v0}, Ltz0/b;->b(Lsz0/g;)V

    .line 119
    .line 120
    .line 121
    return-void
.end method

.method public final typeParametersSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v0, v0, [Lqz0/a;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    iget-object p0, p0, Lu41/a;->a:Lqz0/a;

    .line 6
    .line 7
    aput-object p0, v0, v1

    .line 8
    .line 9
    return-object v0
.end method
