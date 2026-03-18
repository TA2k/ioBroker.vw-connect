.class public final Landroidx/datastore/preferences/protobuf/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic c:I


# instance fields
.field public final a:Landroidx/datastore/preferences/protobuf/c1;

.field public b:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroidx/datastore/preferences/protobuf/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Landroidx/datastore/preferences/protobuf/r;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c1;->f()Landroidx/datastore/preferences/protobuf/c1;

    move-result-object v0

    iput-object v0, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 0

    .line 3
    invoke-static {}, Landroidx/datastore/preferences/protobuf/c1;->f()Landroidx/datastore/preferences/protobuf/c1;

    move-result-object p1

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 6
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/r;->a()V

    .line 7
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/r;->a()V

    return-void
.end method

.method public static b(Landroidx/datastore/preferences/protobuf/l;Landroidx/datastore/preferences/protobuf/v1;ILjava/lang/Object;)V
    .locals 2

    .line 1
    sget-object v0, Landroidx/datastore/preferences/protobuf/v1;->g:Landroidx/datastore/preferences/protobuf/s1;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    check-cast p3, Landroidx/datastore/preferences/protobuf/a;

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-virtual {p0, p2, p1}, Landroidx/datastore/preferences/protobuf/l;->I(II)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p3, p0}, Landroidx/datastore/preferences/protobuf/a;->b(Landroidx/datastore/preferences/protobuf/l;)V

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x4

    .line 15
    invoke-virtual {p0, p2, p1}, Landroidx/datastore/preferences/protobuf/l;->I(II)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget v0, p1, Landroidx/datastore/preferences/protobuf/v1;->e:I

    .line 20
    .line 21
    invoke-virtual {p0, p2, v0}, Landroidx/datastore/preferences/protobuf/l;->I(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    packed-switch p1, :pswitch_data_0

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_0
    check-cast p3, Ljava/lang/Long;

    .line 33
    .line 34
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 35
    .line 36
    .line 37
    move-result-wide p1

    .line 38
    const/4 p3, 0x1

    .line 39
    shl-long v0, p1, p3

    .line 40
    .line 41
    const/16 p3, 0x3f

    .line 42
    .line 43
    shr-long/2addr p1, p3

    .line 44
    xor-long/2addr p1, v0

    .line 45
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->M(J)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_1
    check-cast p3, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    shl-int/lit8 p2, p1, 0x1

    .line 56
    .line 57
    shr-int/lit8 p1, p1, 0x1f

    .line 58
    .line 59
    xor-int/2addr p1, p2

    .line 60
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->K(I)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_2
    check-cast p3, Ljava/lang/Long;

    .line 65
    .line 66
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 67
    .line 68
    .line 69
    move-result-wide p1

    .line 70
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->C(J)V

    .line 71
    .line 72
    .line 73
    return-void

    .line 74
    :pswitch_3
    check-cast p3, Ljava/lang/Integer;

    .line 75
    .line 76
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->A(I)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :pswitch_4
    check-cast p3, Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result p1

    .line 90
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->E(I)V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :pswitch_5
    check-cast p3, Ljava/lang/Integer;

    .line 95
    .line 96
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->K(I)V

    .line 101
    .line 102
    .line 103
    return-void

    .line 104
    :pswitch_6
    instance-of p1, p3, Landroidx/datastore/preferences/protobuf/h;

    .line 105
    .line 106
    if-eqz p1, :cond_1

    .line 107
    .line 108
    check-cast p3, Landroidx/datastore/preferences/protobuf/h;

    .line 109
    .line 110
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/l;->y(Landroidx/datastore/preferences/protobuf/h;)V

    .line 111
    .line 112
    .line 113
    return-void

    .line 114
    :cond_1
    check-cast p3, [B

    .line 115
    .line 116
    array-length p1, p3

    .line 117
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->K(I)V

    .line 118
    .line 119
    .line 120
    const/4 p2, 0x0

    .line 121
    invoke-virtual {p0, p3, p2, p1}, Landroidx/datastore/preferences/protobuf/l;->v([BII)V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :pswitch_7
    check-cast p3, Landroidx/datastore/preferences/protobuf/a;

    .line 126
    .line 127
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    move-object p1, p3

    .line 131
    check-cast p1, Landroidx/datastore/preferences/protobuf/x;

    .line 132
    .line 133
    const/4 p2, 0x0

    .line 134
    invoke-virtual {p1, p2}, Landroidx/datastore/preferences/protobuf/x;->a(Landroidx/datastore/preferences/protobuf/a1;)I

    .line 135
    .line 136
    .line 137
    move-result p1

    .line 138
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->K(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {p3, p0}, Landroidx/datastore/preferences/protobuf/a;->b(Landroidx/datastore/preferences/protobuf/l;)V

    .line 142
    .line 143
    .line 144
    return-void

    .line 145
    :pswitch_8
    check-cast p3, Landroidx/datastore/preferences/protobuf/a;

    .line 146
    .line 147
    invoke-virtual {p3, p0}, Landroidx/datastore/preferences/protobuf/a;->b(Landroidx/datastore/preferences/protobuf/l;)V

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :pswitch_9
    instance-of p1, p3, Landroidx/datastore/preferences/protobuf/h;

    .line 152
    .line 153
    if-eqz p1, :cond_2

    .line 154
    .line 155
    check-cast p3, Landroidx/datastore/preferences/protobuf/h;

    .line 156
    .line 157
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/l;->y(Landroidx/datastore/preferences/protobuf/h;)V

    .line 158
    .line 159
    .line 160
    return-void

    .line 161
    :cond_2
    check-cast p3, Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {p0, p3}, Landroidx/datastore/preferences/protobuf/l;->H(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    return-void

    .line 167
    :pswitch_a
    check-cast p3, Ljava/lang/Boolean;

    .line 168
    .line 169
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result p1

    .line 173
    int-to-byte p1, p1

    .line 174
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->u(B)V

    .line 175
    .line 176
    .line 177
    return-void

    .line 178
    :pswitch_b
    check-cast p3, Ljava/lang/Integer;

    .line 179
    .line 180
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 181
    .line 182
    .line 183
    move-result p1

    .line 184
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->A(I)V

    .line 185
    .line 186
    .line 187
    return-void

    .line 188
    :pswitch_c
    check-cast p3, Ljava/lang/Long;

    .line 189
    .line 190
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 191
    .line 192
    .line 193
    move-result-wide p1

    .line 194
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->C(J)V

    .line 195
    .line 196
    .line 197
    return-void

    .line 198
    :pswitch_d
    check-cast p3, Ljava/lang/Integer;

    .line 199
    .line 200
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 201
    .line 202
    .line 203
    move-result p1

    .line 204
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->E(I)V

    .line 205
    .line 206
    .line 207
    return-void

    .line 208
    :pswitch_e
    check-cast p3, Ljava/lang/Long;

    .line 209
    .line 210
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 211
    .line 212
    .line 213
    move-result-wide p1

    .line 214
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->M(J)V

    .line 215
    .line 216
    .line 217
    return-void

    .line 218
    :pswitch_f
    check-cast p3, Ljava/lang/Long;

    .line 219
    .line 220
    invoke-virtual {p3}, Ljava/lang/Long;->longValue()J

    .line 221
    .line 222
    .line 223
    move-result-wide p1

    .line 224
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->M(J)V

    .line 225
    .line 226
    .line 227
    return-void

    .line 228
    :pswitch_10
    check-cast p3, Ljava/lang/Float;

    .line 229
    .line 230
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 231
    .line 232
    .line 233
    move-result p1

    .line 234
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 235
    .line 236
    .line 237
    move-result p1

    .line 238
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/l;->A(I)V

    .line 239
    .line 240
    .line 241
    return-void

    .line 242
    :pswitch_11
    check-cast p3, Ljava/lang/Double;

    .line 243
    .line 244
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    .line 245
    .line 246
    .line 247
    move-result-wide p1

    .line 248
    invoke-static {p1, p2}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 249
    .line 250
    .line 251
    move-result-wide p1

    .line 252
    invoke-virtual {p0, p1, p2}, Landroidx/datastore/preferences/protobuf/l;->C(J)V

    .line 253
    .line 254
    .line 255
    return-void

    .line 256
    nop

    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
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


# virtual methods
.method public final a()V
    .locals 7

    .line 1
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/r;->b:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 7
    .line 8
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    move v3, v2

    .line 16
    :goto_0
    if-ge v3, v1, :cond_2

    .line 17
    .line 18
    invoke-virtual {v0, v3}, Landroidx/datastore/preferences/protobuf/c1;->c(I)Ljava/util/Map$Entry;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    instance-of v5, v5, Landroidx/datastore/preferences/protobuf/x;

    .line 27
    .line 28
    if-eqz v5, :cond_1

    .line 29
    .line 30
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    check-cast v4, Landroidx/datastore/preferences/protobuf/x;

    .line 35
    .line 36
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    sget-object v5, Landroidx/datastore/preferences/protobuf/x0;->c:Landroidx/datastore/preferences/protobuf/x0;

    .line 40
    .line 41
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    invoke-virtual {v5, v6}, Landroidx/datastore/preferences/protobuf/x0;->a(Ljava/lang/Class;)Landroidx/datastore/preferences/protobuf/a1;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    invoke-interface {v5, v4}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v4}, Landroidx/datastore/preferences/protobuf/x;->h()V

    .line 56
    .line 57
    .line 58
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-boolean v1, v0, Landroidx/datastore/preferences/protobuf/c1;->f:Z

    .line 62
    .line 63
    if-nez v1, :cond_5

    .line 64
    .line 65
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 66
    .line 67
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-gtz v1, :cond_4

    .line 72
    .line 73
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/c1;->d()Ljava/util/Set;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    if-nez v2, :cond_3

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Ljava/util/Map$Entry;

    .line 93
    .line 94
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    new-instance p0, Ljava/lang/ClassCastException;

    .line 102
    .line 103
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 104
    .line 105
    .line 106
    throw p0

    .line 107
    :cond_4
    invoke-virtual {v0, v2}, Landroidx/datastore/preferences/protobuf/c1;->c(I)Ljava/util/Map$Entry;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    new-instance p0, Ljava/lang/ClassCastException;

    .line 119
    .line 120
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 121
    .line 122
    .line 123
    throw p0

    .line 124
    :cond_5
    :goto_1
    iget-boolean v1, v0, Landroidx/datastore/preferences/protobuf/c1;->f:Z

    .line 125
    .line 126
    const/4 v2, 0x1

    .line 127
    if-nez v1, :cond_8

    .line 128
    .line 129
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->e:Ljava/util/Map;

    .line 130
    .line 131
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_6

    .line 136
    .line 137
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 138
    .line 139
    goto :goto_2

    .line 140
    :cond_6
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->e:Ljava/util/Map;

    .line 141
    .line 142
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    :goto_2
    iput-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->e:Ljava/util/Map;

    .line 147
    .line 148
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->h:Ljava/util/Map;

    .line 149
    .line 150
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-eqz v1, :cond_7

    .line 155
    .line 156
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_7
    iget-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->h:Ljava/util/Map;

    .line 160
    .line 161
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    :goto_3
    iput-object v1, v0, Landroidx/datastore/preferences/protobuf/c1;->h:Ljava/util/Map;

    .line 166
    .line 167
    iput-boolean v2, v0, Landroidx/datastore/preferences/protobuf/c1;->f:Z

    .line 168
    .line 169
    :cond_8
    iput-boolean v2, p0, Landroidx/datastore/preferences/protobuf/r;->b:Z

    .line 170
    .line 171
    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Landroidx/datastore/preferences/protobuf/r;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/datastore/preferences/protobuf/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 7
    .line 8
    iget-object v1, p0, Landroidx/datastore/preferences/protobuf/c1;->d:Ljava/util/List;

    .line 9
    .line 10
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-gtz v1, :cond_2

    .line 16
    .line 17
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/c1;->d()Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/util/Map$Entry;

    .line 37
    .line 38
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    if-nez v0, :cond_1

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    throw v2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/ClassCastException;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    const/4 v0, 0x0

    .line 55
    invoke-virtual {p0, v0}, Landroidx/datastore/preferences/protobuf/c1;->c(I)Ljava/util/Map$Entry;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    throw v2

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    .line 70
    .line 71
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Landroidx/datastore/preferences/protobuf/r;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Landroidx/datastore/preferences/protobuf/r;

    .line 12
    .line 13
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 14
    .line 15
    iget-object p1, p1, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Landroidx/datastore/preferences/protobuf/c1;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/r;->a:Landroidx/datastore/preferences/protobuf/c1;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroidx/datastore/preferences/protobuf/c1;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
