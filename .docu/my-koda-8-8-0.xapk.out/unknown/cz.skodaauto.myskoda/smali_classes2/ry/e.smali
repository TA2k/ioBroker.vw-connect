.class public final Lry/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/u;


# direct methods
.method public constructor <init>(Lla/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lry/e;->a:Lla/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lua/a;Landroidx/collection/f;)V
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
    new-instance v0, Lod0/n;

    .line 21
    .line 22
    const/16 v1, 0x11

    .line 23
    .line 24
    invoke-direct {v0, v1, p0, p1}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

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
    const-string p0, "SELECT `id`,`vin`,`enabled`,`time`,`type`,`days` FROM `active_ventilation_timers` WHERE `vin` IN ("

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
    const-string p1, "vin"

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
    move-result-wide v4

    .line 121
    invoke-interface {p0, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v6

    .line 125
    const/4 v3, 0x2

    .line 126
    invoke-interface {p0, v3}, Lua/c;->getLong(I)J

    .line 127
    .line 128
    .line 129
    move-result-wide v7

    .line 130
    long-to-int v3, v7

    .line 131
    if-eqz v3, :cond_4

    .line 132
    .line 133
    move v7, v0

    .line 134
    goto :goto_2

    .line 135
    :cond_4
    move v7, v2

    .line 136
    :goto_2
    const/4 v2, 0x3

    .line 137
    invoke-interface {p0, v2}, Lua/c;->isNull(I)Z

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    if-eqz v3, :cond_5

    .line 142
    .line 143
    const/4 v2, 0x0

    .line 144
    goto :goto_3

    .line 145
    :cond_5
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    :goto_3
    invoke-static {v2}, Lwq/f;->m(Ljava/lang/String;)Ljava/time/LocalTime;

    .line 150
    .line 151
    .line 152
    move-result-object v8

    .line 153
    if-eqz v8, :cond_6

    .line 154
    .line 155
    const/4 v2, 0x4

    .line 156
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v9

    .line 160
    const/4 v2, 0x5

    .line 161
    invoke-interface {p0, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v10

    .line 165
    new-instance v3, Lry/g;

    .line 166
    .line 167
    invoke-direct/range {v3 .. v10}, Lry/g;-><init>(JLjava/lang/String;ZLjava/time/LocalTime;Ljava/lang/String;Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    invoke-interface {v1, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    goto :goto_1

    .line 174
    :catchall_0
    move-exception v0

    .line 175
    move-object p1, v0

    .line 176
    goto :goto_4

    .line 177
    :cond_6
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 178
    .line 179
    const-string p2, "Expected NON-NULL \'java.time.LocalTime\', but it was NULL."

    .line 180
    .line 181
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 185
    :cond_7
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 186
    .line 187
    .line 188
    return-void

    .line 189
    :goto_4
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 190
    .line 191
    .line 192
    throw p1
.end method
