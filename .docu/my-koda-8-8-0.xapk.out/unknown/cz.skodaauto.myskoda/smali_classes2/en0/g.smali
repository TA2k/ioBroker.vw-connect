.class public final Len0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;

.field public final b:Las0/h;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Len0/g;->a:Lla/u;

    .line 5
    .line 6
    new-instance p1, Las0/h;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-direct {p1, p0, v0}, Las0/h;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Len0/g;->b:Las0/h;

    .line 13
    .line 14
    return-void
.end method

.method public static a(Ljava/lang/String;)Lss0/a;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "Unknown"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lss0/a;->g:Lss0/a;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "CanNotBeActivated"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lss0/a;->e:Lss0/a;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "InProgress"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lss0/a;->f:Lss0/a;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "CanBeActivated"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lss0/a;->d:Lss0/a;

    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 54
    .line 55
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :sswitch_data_0
    .sparse-switch
        0x1296eafe -> :sswitch_3
        0x26881a92 -> :sswitch_2
        0x3174a3cb -> :sswitch_1
        0x523e442a -> :sswitch_0
    .end sparse-switch
.end method

.method public static b(Ljava/lang/String;)Lss0/t;
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :sswitch_0
    const-string v0, "ToHandover"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lss0/t;->m:Lss0/t;

    .line 18
    .line 19
    return-object p0

    .line 20
    :sswitch_1
    const-string v0, "Unknown"

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    sget-object p0, Lss0/t;->n:Lss0/t;

    .line 29
    .line 30
    return-object p0

    .line 31
    :sswitch_2
    const-string v0, "Ordered"

    .line 32
    .line 33
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-object p0, Lss0/t;->j:Lss0/t;

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_3
    const-string v0, "InProduction"

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object p0, Lss0/t;->k:Lss0/t;

    .line 51
    .line 52
    return-object p0

    .line 53
    :sswitch_4
    const-string v0, "InDelivery"

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_0

    .line 60
    .line 61
    sget-object p0, Lss0/t;->l:Lss0/t;

    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_0
    :goto_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 65
    .line 66
    const-string v1, "Can\'t convert value to enum, unknown value: "

    .line 67
    .line 68
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw v0

    .line 76
    nop

    .line 77
    :sswitch_data_0
    .sparse-switch
        -0x6cb78ba7 -> :sswitch_4
        0xb3bc3de -> :sswitch_3
        0x1b45904d -> :sswitch_2
        0x523e442a -> :sswitch_1
        0x75c0d17e -> :sswitch_0
    .end sparse-switch
.end method


# virtual methods
.method public final c(Lua/a;Landroidx/collection/f;)V
    .locals 11

    .line 1
    invoke-virtual {p2}, Landroidx/collection/f;->keySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    invoke-virtual {p2}, Landroidx/collection/a1;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/16 v2, 0x3e7

    .line 17
    .line 18
    if-le v1, v2, :cond_1

    .line 19
    .line 20
    new-instance v0, Laa/z;

    .line 21
    .line 22
    const/16 v1, 0x1d

    .line 23
    .line 24
    invoke-direct {v0, v1, p0, p1}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p2, v0}, Ljp/ye;->b(Landroidx/collection/f;Lay0/k;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    const-string p0, "SELECT `id`,`orderStatus`,`date`,`startEstimatedDate`,`endEstimatedDate`,`commissionId` FROM `order_checkpoint` WHERE `commissionId` IN ("

    .line 32
    .line 33
    invoke-static {p0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    invoke-static {v1, p0}, Ljp/cf;->d(ILjava/lang/StringBuilder;)V

    .line 42
    .line 43
    .line 44
    const-string v1, ")"

    .line 45
    .line 46
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    const-string v1, "toString(...)"

    .line 54
    .line 55
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p1, p0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    const/4 v0, 0x1

    .line 67
    move v1, v0

    .line 68
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_2

    .line 73
    .line 74
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Ljava/lang/String;

    .line 79
    .line 80
    invoke-interface {p0, v1, v2}, Lua/c;->w(ILjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    add-int/2addr v1, v0

    .line 84
    goto :goto_0

    .line 85
    :cond_2
    :try_start_0
    const-string p1, "commissionId"

    .line 86
    .line 87
    invoke-static {p0, p1}, Ljp/af;->c(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 91
    const/4 v1, -0x1

    .line 92
    if-ne p1, v1, :cond_3

    .line 93
    .line 94
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 95
    .line 96
    .line 97
    return-void

    .line 98
    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    if-eqz v1, :cond_7

    .line 103
    .line 104
    invoke-interface {p0, p1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    invoke-virtual {p2, v1}, Landroidx/collection/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    check-cast v1, Ljava/util/List;

    .line 113
    .line 114
    if-eqz v1, :cond_3

    .line 115
    .line 116
    const/4 v2, 0x0

    .line 117
    invoke-interface {p0, v2}, Lua/c;->getLong(I)J

    .line 118
    .line 119
    .line 120
    move-result-wide v2

    .line 121
    long-to-int v5, v2

    .line 122
    invoke-interface {p0, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-static {v2}, Len0/g;->b(Ljava/lang/String;)Lss0/t;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    const/4 v2, 0x2

    .line 131
    invoke-interface {p0, v2}, Lua/c;->isNull(I)Z

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    const/4 v4, 0x0

    .line 136
    if-eqz v3, :cond_4

    .line 137
    .line 138
    move-object v2, v4

    .line 139
    goto :goto_2

    .line 140
    :cond_4
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    :goto_2
    invoke-static {v2}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 145
    .line 146
    .line 147
    move-result-object v7

    .line 148
    const/4 v2, 0x3

    .line 149
    invoke-interface {p0, v2}, Lua/c;->isNull(I)Z

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    if-eqz v3, :cond_5

    .line 154
    .line 155
    move-object v2, v4

    .line 156
    goto :goto_3

    .line 157
    :cond_5
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v2

    .line 161
    :goto_3
    invoke-static {v2}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 162
    .line 163
    .line 164
    move-result-object v8

    .line 165
    const/4 v2, 0x4

    .line 166
    invoke-interface {p0, v2}, Lua/c;->isNull(I)Z

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    if-eqz v3, :cond_6

    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_6
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v4

    .line 177
    :goto_4
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 178
    .line 179
    .line 180
    move-result-object v9

    .line 181
    const/4 v2, 0x5

    .line 182
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    new-instance v4, Len0/d;

    .line 187
    .line 188
    invoke-direct/range {v4 .. v10}, Len0/d;-><init>(ILss0/t;Ljava/time/LocalDate;Ljava/time/LocalDate;Ljava/time/LocalDate;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    invoke-interface {v1, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 192
    .line 193
    .line 194
    goto :goto_1

    .line 195
    :catchall_0
    move-exception v0

    .line 196
    move-object p1, v0

    .line 197
    goto :goto_5

    .line 198
    :cond_7
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :goto_5
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 203
    .line 204
    .line 205
    throw p1
.end method
