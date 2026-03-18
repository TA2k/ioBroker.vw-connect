.class public final synthetic Lc91/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lc91/a;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc91/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/a;->a:Lc91/a;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.telemetry.serialization.AttributesSerializer.InternalSerializableAttributes"

    .line 11
    .line 12
    const/16 v3, 0x8

    .line 13
    .line 14
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 15
    .line 16
    .line 17
    const-string v0, "strings"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 21
    .line 22
    .line 23
    const-string v0, "booleans"

    .line 24
    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "longs"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "doubles"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    const-string v0, "stringArrays"

    .line 39
    .line 40
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 41
    .line 42
    .line 43
    const-string v0, "booleanArrays"

    .line 44
    .line 45
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    const-string v0, "longArrays"

    .line 49
    .line 50
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 51
    .line 52
    .line 53
    const-string v0, "doubleArrays"

    .line 54
    .line 55
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Lc91/a;->descriptor:Lsz0/g;

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lc91/c;->i:[Llx0/i;

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    new-array v0, v0, [Lqz0/a;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    aget-object v2, p0, v1

    .line 9
    .line 10
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    aput-object v2, v0, v1

    .line 15
    .line 16
    const/4 v1, 0x1

    .line 17
    aget-object v2, p0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    aput-object v2, v0, v1

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    aget-object v2, p0, v1

    .line 27
    .line 28
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    aput-object v2, v0, v1

    .line 33
    .line 34
    const/4 v1, 0x3

    .line 35
    aget-object v2, p0, v1

    .line 36
    .line 37
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    aput-object v2, v0, v1

    .line 42
    .line 43
    const/4 v1, 0x4

    .line 44
    aget-object v2, p0, v1

    .line 45
    .line 46
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    aput-object v2, v0, v1

    .line 51
    .line 52
    const/4 v1, 0x5

    .line 53
    aget-object v2, p0, v1

    .line 54
    .line 55
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    aput-object v2, v0, v1

    .line 60
    .line 61
    const/4 v1, 0x6

    .line 62
    aget-object v2, p0, v1

    .line 63
    .line 64
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    aput-object v2, v0, v1

    .line 69
    .line 70
    const/4 v1, 0x7

    .line 71
    aget-object p0, p0, v1

    .line 72
    .line 73
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    aput-object p0, v0, v1

    .line 78
    .line 79
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    sget-object v0, Lc91/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-interface {v1, v0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    sget-object v2, Lc91/c;->i:[Llx0/i;

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v5, 0x0

    .line 13
    move-object v8, v5

    .line 14
    move-object v9, v8

    .line 15
    move-object v10, v9

    .line 16
    move-object v11, v10

    .line 17
    move-object v12, v11

    .line 18
    move-object v13, v12

    .line 19
    move-object v14, v13

    .line 20
    move-object v15, v14

    .line 21
    const/4 v7, 0x0

    .line 22
    move v5, v3

    .line 23
    :goto_0
    if-eqz v5, :cond_0

    .line 24
    .line 25
    invoke-interface {v1, v0}, Ltz0/a;->E(Lsz0/g;)I

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    packed-switch v6, :pswitch_data_0

    .line 30
    .line 31
    .line 32
    new-instance v0, Lqz0/k;

    .line 33
    .line 34
    invoke-direct {v0, v6}, Lqz0/k;-><init>(I)V

    .line 35
    .line 36
    .line 37
    throw v0

    .line 38
    :pswitch_0
    const/4 v6, 0x7

    .line 39
    aget-object v16, v2, v6

    .line 40
    .line 41
    invoke-interface/range {v16 .. v16}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v16

    .line 45
    const/16 p0, 0x0

    .line 46
    .line 47
    move-object/from16 v4, v16

    .line 48
    .line 49
    check-cast v4, Lqz0/a;

    .line 50
    .line 51
    invoke-interface {v1, v0, v6, v4, v15}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    move-object v15, v4

    .line 56
    check-cast v15, Ljava/util/Map;

    .line 57
    .line 58
    or-int/lit16 v7, v7, 0x80

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :pswitch_1
    const/16 p0, 0x0

    .line 62
    .line 63
    const/4 v4, 0x6

    .line 64
    aget-object v6, v2, v4

    .line 65
    .line 66
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v6

    .line 70
    check-cast v6, Lqz0/a;

    .line 71
    .line 72
    invoke-interface {v1, v0, v4, v6, v14}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    move-object v14, v4

    .line 77
    check-cast v14, Ljava/util/Map;

    .line 78
    .line 79
    or-int/lit8 v7, v7, 0x40

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :pswitch_2
    const/16 p0, 0x0

    .line 83
    .line 84
    const/4 v4, 0x5

    .line 85
    aget-object v6, v2, v4

    .line 86
    .line 87
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    check-cast v6, Lqz0/a;

    .line 92
    .line 93
    invoke-interface {v1, v0, v4, v6, v13}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    move-object v13, v4

    .line 98
    check-cast v13, Ljava/util/Map;

    .line 99
    .line 100
    or-int/lit8 v7, v7, 0x20

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :pswitch_3
    const/16 p0, 0x0

    .line 104
    .line 105
    const/4 v4, 0x4

    .line 106
    aget-object v6, v2, v4

    .line 107
    .line 108
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v6

    .line 112
    check-cast v6, Lqz0/a;

    .line 113
    .line 114
    invoke-interface {v1, v0, v4, v6, v12}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    move-object v12, v4

    .line 119
    check-cast v12, Ljava/util/Map;

    .line 120
    .line 121
    or-int/lit8 v7, v7, 0x10

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :pswitch_4
    const/16 p0, 0x0

    .line 125
    .line 126
    const/4 v4, 0x3

    .line 127
    aget-object v6, v2, v4

    .line 128
    .line 129
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    check-cast v6, Lqz0/a;

    .line 134
    .line 135
    invoke-interface {v1, v0, v4, v6, v11}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    move-object v11, v4

    .line 140
    check-cast v11, Ljava/util/Map;

    .line 141
    .line 142
    or-int/lit8 v7, v7, 0x8

    .line 143
    .line 144
    goto :goto_0

    .line 145
    :pswitch_5
    const/16 p0, 0x0

    .line 146
    .line 147
    const/4 v4, 0x2

    .line 148
    aget-object v6, v2, v4

    .line 149
    .line 150
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v6

    .line 154
    check-cast v6, Lqz0/a;

    .line 155
    .line 156
    invoke-interface {v1, v0, v4, v6, v10}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    move-object v10, v4

    .line 161
    check-cast v10, Ljava/util/Map;

    .line 162
    .line 163
    or-int/lit8 v7, v7, 0x4

    .line 164
    .line 165
    goto/16 :goto_0

    .line 166
    .line 167
    :pswitch_6
    const/16 p0, 0x0

    .line 168
    .line 169
    aget-object v4, v2, v3

    .line 170
    .line 171
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    check-cast v4, Lqz0/a;

    .line 176
    .line 177
    invoke-interface {v1, v0, v3, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v4

    .line 181
    move-object v9, v4

    .line 182
    check-cast v9, Ljava/util/Map;

    .line 183
    .line 184
    or-int/lit8 v7, v7, 0x2

    .line 185
    .line 186
    goto/16 :goto_0

    .line 187
    .line 188
    :pswitch_7
    const/16 p0, 0x0

    .line 189
    .line 190
    aget-object v4, v2, p0

    .line 191
    .line 192
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v4

    .line 196
    check-cast v4, Lqz0/a;

    .line 197
    .line 198
    move/from16 v6, p0

    .line 199
    .line 200
    invoke-interface {v1, v0, v6, v4, v8}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    move-object v8, v4

    .line 205
    check-cast v8, Ljava/util/Map;

    .line 206
    .line 207
    or-int/lit8 v7, v7, 0x1

    .line 208
    .line 209
    goto/16 :goto_0

    .line 210
    .line 211
    :pswitch_8
    const/4 v6, 0x0

    .line 212
    move v5, v6

    .line 213
    goto/16 :goto_0

    .line 214
    .line 215
    :cond_0
    invoke-interface {v1, v0}, Ltz0/a;->b(Lsz0/g;)V

    .line 216
    .line 217
    .line 218
    new-instance v6, Lc91/c;

    .line 219
    .line 220
    invoke-direct/range {v6 .. v15}, Lc91/c;-><init>(ILjava/util/Map;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;Ljava/util/Map;)V

    .line 221
    .line 222
    .line 223
    return-object v6

    .line 224
    nop

    .line 225
    :pswitch_data_0
    .packed-switch -0x1
        :pswitch_8
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
    sget-object p0, Lc91/a;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lc91/c;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc91/a;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lc91/c;->i:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    iget-object v3, p2, Lc91/c;->a:Ljava/util/Map;

    .line 26
    .line 27
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    aget-object v2, v0, v1

    .line 32
    .line 33
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Lqz0/a;

    .line 38
    .line 39
    iget-object v3, p2, Lc91/c;->b:Ljava/util/Map;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    const/4 v1, 0x2

    .line 45
    aget-object v2, v0, v1

    .line 46
    .line 47
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v2, Lqz0/a;

    .line 52
    .line 53
    iget-object v3, p2, Lc91/c;->c:Ljava/util/Map;

    .line 54
    .line 55
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    const/4 v1, 0x3

    .line 59
    aget-object v2, v0, v1

    .line 60
    .line 61
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    check-cast v2, Lqz0/a;

    .line 66
    .line 67
    iget-object v3, p2, Lc91/c;->d:Ljava/util/Map;

    .line 68
    .line 69
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    const/4 v1, 0x4

    .line 73
    aget-object v2, v0, v1

    .line 74
    .line 75
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lqz0/a;

    .line 80
    .line 81
    iget-object v3, p2, Lc91/c;->e:Ljava/util/Map;

    .line 82
    .line 83
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    const/4 v1, 0x5

    .line 87
    aget-object v2, v0, v1

    .line 88
    .line 89
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    check-cast v2, Lqz0/a;

    .line 94
    .line 95
    iget-object v3, p2, Lc91/c;->f:Ljava/util/Map;

    .line 96
    .line 97
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    const/4 v1, 0x6

    .line 101
    aget-object v2, v0, v1

    .line 102
    .line 103
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    check-cast v2, Lqz0/a;

    .line 108
    .line 109
    iget-object v3, p2, Lc91/c;->g:Ljava/util/Map;

    .line 110
    .line 111
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    const/4 v1, 0x7

    .line 115
    aget-object v0, v0, v1

    .line 116
    .line 117
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    check-cast v0, Lqz0/a;

    .line 122
    .line 123
    iget-object p2, p2, Lc91/c;->h:Ljava/util/Map;

    .line 124
    .line 125
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 129
    .line 130
    .line 131
    return-void
.end method
