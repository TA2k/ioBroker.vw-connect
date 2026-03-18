.class public final Lu2/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu2/c;


# static fields
.field public static final h:Lu2/l;


# instance fields
.field public final d:Ljava/util/Map;

.field public final e:Landroidx/collection/q0;

.field public f:Lu2/g;

.field public final g:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltf0/a;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ltf0/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lu2/d;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v1, v2}, Lu2/d;-><init>(I)V

    .line 12
    .line 13
    .line 14
    new-instance v2, Lu2/l;

    .line 15
    .line 16
    invoke-direct {v2, v0, v1}, Lu2/l;-><init>(Lay0/n;Lay0/k;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lu2/e;->h:Lu2/l;

    .line 20
    .line 21
    return-void
.end method

.method public constructor <init>(Ljava/util/Map;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu2/e;->d:Ljava/util/Map;

    .line 5
    .line 6
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 7
    .line 8
    new-instance p1, Landroidx/collection/q0;

    .line 9
    .line 10
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lu2/e;->e:Landroidx/collection/q0;

    .line 14
    .line 15
    new-instance p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 16
    .line 17
    const/4 v0, 0x7

    .line 18
    invoke-direct {p1, p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lu2/e;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Object;Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x1fcd8740

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p4

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p4

    .line 25
    :goto_1
    and-int/lit8 v1, p4, 0x30

    .line 26
    .line 27
    if-nez v1, :cond_3

    .line 28
    .line 29
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    const/16 v1, 0x20

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    const/16 v1, 0x10

    .line 39
    .line 40
    :goto_2
    or-int/2addr v0, v1

    .line 41
    :cond_3
    and-int/lit16 v1, p4, 0x180

    .line 42
    .line 43
    if-nez v1, :cond_5

    .line 44
    .line 45
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    const/16 v1, 0x100

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_4
    const/16 v1, 0x80

    .line 55
    .line 56
    :goto_3
    or-int/2addr v0, v1

    .line 57
    :cond_5
    and-int/lit16 v1, v0, 0x93

    .line 58
    .line 59
    const/16 v2, 0x92

    .line 60
    .line 61
    const/4 v3, 0x0

    .line 62
    if-eq v1, v2, :cond_6

    .line 63
    .line 64
    const/4 v1, 0x1

    .line 65
    goto :goto_4

    .line 66
    :cond_6
    move v1, v3

    .line 67
    :goto_4
    and-int/lit8 v2, v0, 0x1

    .line 68
    .line 69
    invoke-virtual {p3, v2, v1}, Ll2/t;->O(IZ)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    if-eqz v1, :cond_c

    .line 74
    .line 75
    invoke-virtual {p3, p1}, Ll2/t;->b0(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 83
    .line 84
    if-ne v1, v2, :cond_8

    .line 85
    .line 86
    iget-object v1, p0, Lu2/e;->g:Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 87
    .line 88
    invoke-virtual {v1, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    check-cast v4, Ljava/lang/Boolean;

    .line 93
    .line 94
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    if-eqz v4, :cond_7

    .line 99
    .line 100
    new-instance v4, Lu2/j;

    .line 101
    .line 102
    iget-object v5, p0, Lu2/e;->d:Ljava/util/Map;

    .line 103
    .line 104
    invoke-interface {v5, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    check-cast v5, Ljava/util/Map;

    .line 109
    .line 110
    sget-object v6, Lu2/i;->a:Ll2/u2;

    .line 111
    .line 112
    new-instance v6, Lu2/h;

    .line 113
    .line 114
    invoke-direct {v6, v5, v1}, Lu2/h;-><init>(Ljava/util/Map;Lay0/k;)V

    .line 115
    .line 116
    .line 117
    invoke-direct {v4, v6}, Lu2/j;-><init>(Lu2/h;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    move-object v1, v4

    .line 124
    goto :goto_5

    .line 125
    :cond_7
    const-string p0, "Type of the key "

    .line 126
    .line 127
    const-string p2, " is not supported. On Android you can only use types which can be stored inside the Bundle."

    .line 128
    .line 129
    invoke-static {p1, p0, p2}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 134
    .line 135
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p1

    .line 143
    :cond_8
    :goto_5
    check-cast v1, Lu2/j;

    .line 144
    .line 145
    sget-object v4, Lu2/i;->a:Ll2/u2;

    .line 146
    .line 147
    invoke-virtual {v4, v1}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 148
    .line 149
    .line 150
    move-result-object v4

    .line 151
    sget-object v5, Lsa/a;->a:Ll2/s1;

    .line 152
    .line 153
    invoke-virtual {v5, v1}, Ll2/s1;->a(Ljava/lang/Object;)Ll2/t1;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    filled-new-array {v4, v5}, [Ll2/t1;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    and-int/lit8 v0, v0, 0x70

    .line 162
    .line 163
    const/16 v5, 0x8

    .line 164
    .line 165
    or-int/2addr v0, v5

    .line 166
    invoke-static {v4, p2, p3, v0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    invoke-virtual {p3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    or-int/2addr v0, v4

    .line 178
    invoke-virtual {p3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v4

    .line 182
    or-int/2addr v0, v4

    .line 183
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    if-nez v0, :cond_9

    .line 188
    .line 189
    if-ne v4, v2, :cond_a

    .line 190
    .line 191
    :cond_9
    new-instance v4, Lkv0/e;

    .line 192
    .line 193
    const/16 v0, 0x16

    .line 194
    .line 195
    invoke-direct {v4, p0, p1, v1, v0}, Lkv0/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p3, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    :cond_a
    check-cast v4, Lay0/k;

    .line 202
    .line 203
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    invoke-static {v0, v4, p3}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 206
    .line 207
    .line 208
    iget-boolean v0, p3, Ll2/t;->y:Z

    .line 209
    .line 210
    if-eqz v0, :cond_b

    .line 211
    .line 212
    iget-object v0, p3, Ll2/t;->G:Ll2/e2;

    .line 213
    .line 214
    iget v0, v0, Ll2/e2;->i:I

    .line 215
    .line 216
    iget v1, p3, Ll2/t;->z:I

    .line 217
    .line 218
    if-ne v0, v1, :cond_b

    .line 219
    .line 220
    const/4 v0, -0x1

    .line 221
    iput v0, p3, Ll2/t;->z:I

    .line 222
    .line 223
    iput-boolean v3, p3, Ll2/t;->y:Z

    .line 224
    .line 225
    :cond_b
    invoke-virtual {p3, v3}, Ll2/t;->q(Z)V

    .line 226
    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_c
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 230
    .line 231
    .line 232
    :goto_6
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 233
    .line 234
    .line 235
    move-result-object p3

    .line 236
    if-eqz p3, :cond_d

    .line 237
    .line 238
    new-instance v0, Lph/a;

    .line 239
    .line 240
    const/16 v2, 0xc

    .line 241
    .line 242
    move-object v3, p0

    .line 243
    move-object v4, p1

    .line 244
    move-object v5, p2

    .line 245
    move v1, p4

    .line 246
    invoke-direct/range {v0 .. v5}, Lph/a;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 250
    .line 251
    :cond_d
    return-void
.end method

.method public final c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lu2/e;->e:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lu2/e;->d:Ljava/util/Map;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method
