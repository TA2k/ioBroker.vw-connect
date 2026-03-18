.class public final synthetic Ll61/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Z

.field public final synthetic f:Z


# direct methods
.method public synthetic constructor <init>(FZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Ll61/d;->d:F

    .line 5
    .line 6
    iput-boolean p2, p0, Ll61/d;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Ll61/d;->f:Z

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    const-string p1, "$this$Canvas"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    int-to-float p1, p1

    .line 11
    invoke-interface {v0, p1}, Lt4/c;->w0(F)F

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const p1, 0x3f333333    # 0.7f

    .line 16
    .line 17
    .line 18
    iget v1, p0, Ll61/d;->d:F

    .line 19
    .line 20
    mul-float/2addr v1, p1

    .line 21
    iget-boolean p1, p0, Ll61/d;->e:Z

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    invoke-static {v0, v1}, Llp/bf;->h(Lg3/d;F)Le3/i;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    :goto_0
    move-object v8, v3

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    invoke-static {v0, v1}, Llp/bf;->i(Lg3/d;F)Le3/i;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    goto :goto_0

    .line 36
    :goto_1
    const/4 v9, 0x0

    .line 37
    const-wide v3, 0xffffffffL

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    const/16 v5, 0x20

    .line 43
    .line 44
    if-eqz p1, :cond_1

    .line 45
    .line 46
    invoke-static {v0, v1}, Llp/bf;->h(Lg3/d;F)Le3/i;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-interface {v0}, Lg3/d;->e()J

    .line 51
    .line 52
    .line 53
    move-result-wide v6

    .line 54
    shr-long v5, v6, v5

    .line 55
    .line 56
    long-to-int v5, v5

    .line 57
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    invoke-interface {v0}, Lg3/d;->e()J

    .line 62
    .line 63
    .line 64
    move-result-wide v6

    .line 65
    and-long/2addr v6, v3

    .line 66
    long-to-int v6, v6

    .line 67
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    invoke-virtual {v1, v5, v6}, Le3/i;->g(FF)V

    .line 72
    .line 73
    .line 74
    invoke-interface {v0}, Lg3/d;->e()J

    .line 75
    .line 76
    .line 77
    move-result-wide v5

    .line 78
    and-long/2addr v3, v5

    .line 79
    long-to-int v3, v3

    .line 80
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    invoke-virtual {v1, v9, v3}, Le3/i;->g(FF)V

    .line 85
    .line 86
    .line 87
    :goto_2
    move-object v10, v1

    .line 88
    goto :goto_3

    .line 89
    :cond_1
    invoke-static {v0, v1}, Llp/bf;->i(Lg3/d;F)Le3/i;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-interface {v0}, Lg3/d;->e()J

    .line 94
    .line 95
    .line 96
    move-result-wide v6

    .line 97
    shr-long/2addr v6, v5

    .line 98
    long-to-int v6, v6

    .line 99
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    invoke-interface {v0}, Lg3/d;->e()J

    .line 104
    .line 105
    .line 106
    move-result-wide v10

    .line 107
    and-long/2addr v3, v10

    .line 108
    long-to-int v3, v3

    .line 109
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    invoke-virtual {v1, v6, v3}, Le3/i;->g(FF)V

    .line 114
    .line 115
    .line 116
    invoke-interface {v0}, Lg3/d;->e()J

    .line 117
    .line 118
    .line 119
    move-result-wide v3

    .line 120
    shr-long/2addr v3, v5

    .line 121
    long-to-int v3, v3

    .line 122
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    invoke-virtual {v1, v3, v9}, Le3/i;->g(FF)V

    .line 127
    .line 128
    .line 129
    goto :goto_2

    .line 130
    :goto_3
    invoke-virtual {v10}, Le3/i;->e()V

    .line 131
    .line 132
    .line 133
    new-instance v1, Lg3/h;

    .line 134
    .line 135
    const/4 v6, 0x0

    .line 136
    const/16 v7, 0x1e

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    const/4 v4, 0x0

    .line 140
    const/4 v5, 0x0

    .line 141
    invoke-direct/range {v1 .. v7}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 142
    .line 143
    .line 144
    sget-wide v2, Ln61/a;->b:J

    .line 145
    .line 146
    const/high16 v4, 0x3f000000    # 0.5f

    .line 147
    .line 148
    const/16 v6, 0x30

    .line 149
    .line 150
    move-object v5, v1

    .line 151
    move-object v1, v8

    .line 152
    invoke-static/range {v0 .. v6}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 153
    .line 154
    .line 155
    new-instance v1, Le3/s;

    .line 156
    .line 157
    invoke-direct {v1, v2, v3}, Le3/s;-><init>(J)V

    .line 158
    .line 159
    .line 160
    sget-wide v2, Ln61/a;->a:J

    .line 161
    .line 162
    new-instance v4, Le3/s;

    .line 163
    .line 164
    invoke-direct {v4, v2, v3}, Le3/s;-><init>(J)V

    .line 165
    .line 166
    .line 167
    filled-new-array {v1, v4}, [Le3/s;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    if-nez p1, :cond_2

    .line 176
    .line 177
    iget-boolean p0, p0, Ll61/d;->f:Z

    .line 178
    .line 179
    if-eqz p0, :cond_2

    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_2
    check-cast v1, Ljava/lang/Iterable;

    .line 183
    .line 184
    invoke-static {v1}, Lmx0/q;->g0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    :goto_4
    const/16 p0, 0xe

    .line 189
    .line 190
    invoke-static {v1, v9, v9, p0}, Lpy/a;->t(Ljava/util/List;FFI)Le3/b0;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    const/4 v4, 0x0

    .line 195
    const/16 v5, 0x38

    .line 196
    .line 197
    const v3, 0x3d4ccccd    # 0.05f

    .line 198
    .line 199
    .line 200
    move-object v1, v10

    .line 201
    invoke-static/range {v0 .. v5}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 202
    .line 203
    .line 204
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    return-object p0
.end method
