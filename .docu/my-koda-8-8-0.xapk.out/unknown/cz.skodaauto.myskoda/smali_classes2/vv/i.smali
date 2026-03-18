.class public final Lvv/i;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic f:Lx2/s;

.field public final synthetic g:F

.field public final synthetic h:Lg4/p0;

.field public final synthetic i:Lt2/b;


# direct methods
.method public constructor <init>(Lx2/s;FLg4/p0;Lt2/b;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lvv/i;->f:Lx2/s;

    .line 2
    .line 3
    iput p2, p0, Lvv/i;->g:F

    .line 4
    .line 5
    iput-object p3, p0, Lvv/i;->h:Lg4/p0;

    .line 6
    .line 7
    iput-object p4, p0, Lvv/i;->i:Lt2/b;

    .line 8
    .line 9
    const/4 p1, 0x4

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lvv/m0;

    .line 2
    .line 3
    check-cast p2, Lx2/s;

    .line 4
    .line 5
    check-cast p3, Ll2/o;

    .line 6
    .line 7
    check-cast p4, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    const-string v0, "$this$CodeBlockLayout"

    .line 14
    .line 15
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v0, "layoutModifier"

    .line 19
    .line 20
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    and-int/lit8 v0, p4, 0xe

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    move-object v0, p3

    .line 28
    check-cast v0, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    const/4 v0, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v0, 0x2

    .line 39
    :goto_0
    or-int/2addr v0, p4

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v0, p4

    .line 42
    :goto_1
    and-int/lit8 p4, p4, 0x70

    .line 43
    .line 44
    if-nez p4, :cond_3

    .line 45
    .line 46
    move-object p4, p3

    .line 47
    check-cast p4, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result p4

    .line 53
    if-eqz p4, :cond_2

    .line 54
    .line 55
    const/16 p4, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 p4, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v0, p4

    .line 61
    :cond_3
    and-int/lit16 p4, v0, 0x2db

    .line 62
    .line 63
    const/16 v0, 0x92

    .line 64
    .line 65
    if-ne p4, v0, :cond_5

    .line 66
    .line 67
    move-object p4, p3

    .line 68
    check-cast p4, Ll2/t;

    .line 69
    .line 70
    invoke-virtual {p4}, Ll2/t;->A()Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-nez v0, :cond_4

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_4
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 78
    .line 79
    .line 80
    goto/16 :goto_5

    .line 81
    .line 82
    :cond_5
    :goto_3
    iget-object p4, p0, Lvv/i;->f:Lx2/s;

    .line 83
    .line 84
    invoke-interface {p2, p4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    iget p4, p0, Lvv/i;->g:F

    .line 89
    .line 90
    invoke-static {p2, p4}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    check-cast p3, Ll2/t;

    .line 95
    .line 96
    const p4, 0x2bb5b5d7

    .line 97
    .line 98
    .line 99
    invoke-virtual {p3, p4}, Ll2/t;->Z(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {p3}, Lk1/n;->e(Ll2/o;)Lk1/p;

    .line 103
    .line 104
    .line 105
    move-result-object p4

    .line 106
    const v0, -0x4ee9b9da

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3, v0}, Ll2/t;->Z(I)V

    .line 110
    .line 111
    .line 112
    iget-wide v0, p3, Ll2/t;->T:J

    .line 113
    .line 114
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    invoke-virtual {p3}, Ll2/t;->m()Ll2/p1;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    sget-object v2, Lv3/k;->m1:Lv3/j;

    .line 123
    .line 124
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    sget-object v2, Lv3/j;->b:Lv3/i;

    .line 128
    .line 129
    invoke-static {p2}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    invoke-virtual {p3}, Ll2/t;->c0()V

    .line 134
    .line 135
    .line 136
    iget-boolean v3, p3, Ll2/t;->S:Z

    .line 137
    .line 138
    if-eqz v3, :cond_6

    .line 139
    .line 140
    invoke-virtual {p3, v2}, Ll2/t;->l(Lay0/a;)V

    .line 141
    .line 142
    .line 143
    goto :goto_4

    .line 144
    :cond_6
    invoke-virtual {p3}, Ll2/t;->m0()V

    .line 145
    .line 146
    .line 147
    :goto_4
    sget-object v2, Lv3/j;->g:Lv3/h;

    .line 148
    .line 149
    invoke-static {v2, p4, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    sget-object p4, Lv3/j;->f:Lv3/h;

    .line 153
    .line 154
    invoke-static {p4, v1, p3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 155
    .line 156
    .line 157
    sget-object p4, Lv3/j;->j:Lv3/h;

    .line 158
    .line 159
    iget-boolean v1, p3, Ll2/t;->S:Z

    .line 160
    .line 161
    if-nez v1, :cond_7

    .line 162
    .line 163
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-nez v1, :cond_8

    .line 176
    .line 177
    :cond_7
    invoke-static {v0, p3, v0, p4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 178
    .line 179
    .line 180
    :cond_8
    new-instance p4, Ll2/d2;

    .line 181
    .line 182
    invoke-direct {p4, p3}, Ll2/d2;-><init>(Ll2/o;)V

    .line 183
    .line 184
    .line 185
    const/4 v0, 0x0

    .line 186
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    invoke-virtual {p2, p4, p3, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    const p2, 0x7ab4aae9

    .line 194
    .line 195
    .line 196
    invoke-virtual {p3, p2}, Ll2/t;->Z(I)V

    .line 197
    .line 198
    .line 199
    invoke-static {p1, p3}, Lvv/q0;->a(Lvv/m0;Ll2/o;)Lay0/p;

    .line 200
    .line 201
    .line 202
    move-result-object p2

    .line 203
    new-instance p4, Lvv/h;

    .line 204
    .line 205
    const/4 v1, 0x0

    .line 206
    iget-object v2, p0, Lvv/i;->i:Lt2/b;

    .line 207
    .line 208
    invoke-direct {p4, v2, p1, v1}, Lvv/h;-><init>(Lt2/b;Lvv/m0;I)V

    .line 209
    .line 210
    .line 211
    const p1, 0xc49e1fc

    .line 212
    .line 213
    .line 214
    invoke-static {p1, p3, p4}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    const/16 p4, 0x30

    .line 219
    .line 220
    invoke-static {p4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 221
    .line 222
    .line 223
    move-result-object p4

    .line 224
    iget-object p0, p0, Lvv/i;->h:Lg4/p0;

    .line 225
    .line 226
    invoke-interface {p2, p0, p1, p3, p4}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 230
    .line 231
    .line 232
    const/4 p0, 0x1

    .line 233
    invoke-virtual {p3, p0}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {p3, v0}, Ll2/t;->q(Z)V

    .line 240
    .line 241
    .line 242
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    return-object p0
.end method
