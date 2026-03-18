.class public final synthetic Lcp0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lcp0/s;->d:I

    iput-object p1, p0, Lcp0/s;->e:Ljava/lang/String;

    iput-object p2, p0, Lcp0/s;->f:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Ljava/lang/String;Lcp0/t;)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Lcp0/s;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcp0/s;->e:Ljava/lang/String;

    iput-object p2, p0, Lcp0/s;->f:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lcp0/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ld4/l;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-static {p1, v0}, Ld4/x;->e(Ld4/l;I)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcp0/s;->e:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", "

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lcp0/s;->f:Ljava/lang/String;

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_0
    check-cast p1, Ld4/l;

    .line 43
    .line 44
    new-instance v0, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Lcp0/s;->e:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", "

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lcp0/s;->f:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :pswitch_1
    check-cast p1, Ld4/l;

    .line 73
    .line 74
    new-instance v0, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lcp0/s;->e:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", "

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object p0, p0, Lcp0/s;->f:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :pswitch_2
    check-cast p1, Ld4/l;

    .line 103
    .line 104
    new-instance v0, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 107
    .line 108
    .line 109
    iget-object v1, p0, Lcp0/s;->e:Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v1, ", "

    .line 115
    .line 116
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    iget-object p0, p0, Lcp0/s;->f:Ljava/lang/String;

    .line 120
    .line 121
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-static {p1, p0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    goto :goto_0

    .line 132
    :pswitch_3
    iget-object v0, p0, Lcp0/s;->e:Ljava/lang/String;

    .line 133
    .line 134
    iget-object p0, p0, Lcp0/s;->f:Ljava/lang/String;

    .line 135
    .line 136
    check-cast p1, Lua/a;

    .line 137
    .line 138
    const-string v1, "_connection"

    .line 139
    .line 140
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    const-string v1, "SELECT * FROM vehicle_fuel_level WHERE vin = ? AND fuel_type = ?"

    .line 144
    .line 145
    invoke-interface {p1, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    const/4 v1, 0x1

    .line 150
    :try_start_0
    invoke-interface {p1, v1, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 151
    .line 152
    .line 153
    const/4 v0, 0x2

    .line 154
    invoke-interface {p1, v0, p0}, Lua/c;->w(ILjava/lang/String;)V

    .line 155
    .line 156
    .line 157
    const-string p0, "vin"

    .line 158
    .line 159
    invoke-static {p1, p0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    const-string v0, "fuel_type"

    .line 164
    .line 165
    invoke-static {p1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    const-string v1, "fuel_level_pct"

    .line 170
    .line 171
    invoke-static {p1, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    const-string v2, "last_notification_date"

    .line 176
    .line 177
    invoke-static {p1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 178
    .line 179
    .line 180
    move-result v2

    .line 181
    invoke-interface {p1}, Lua/c;->s0()Z

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    const/4 v4, 0x0

    .line 186
    if-eqz v3, :cond_1

    .line 187
    .line 188
    invoke-interface {p1, p0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    invoke-interface {p1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-interface {p1, v1}, Lua/c;->getLong(I)J

    .line 197
    .line 198
    .line 199
    move-result-wide v5

    .line 200
    long-to-int v1, v5

    .line 201
    invoke-interface {p1, v2}, Lua/c;->isNull(I)Z

    .line 202
    .line 203
    .line 204
    move-result v3

    .line 205
    if-eqz v3, :cond_0

    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_0
    invoke-interface {p1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v4

    .line 212
    :goto_1
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    new-instance v4, Lcp0/u;

    .line 217
    .line 218
    invoke-direct {v4, p0, v0, v1, v2}, Lcp0/u;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/time/LocalDate;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 219
    .line 220
    .line 221
    goto :goto_2

    .line 222
    :catchall_0
    move-exception p0

    .line 223
    goto :goto_3

    .line 224
    :cond_1
    :goto_2
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 225
    .line 226
    .line 227
    return-object v4

    .line 228
    :goto_3
    invoke-interface {p1}, Ljava/lang/AutoCloseable;->close()V

    .line 229
    .line 230
    .line 231
    throw p0

    .line 232
    nop

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
