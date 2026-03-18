.class public final Lg1/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:F

.field public final synthetic d:Lg1/q;


# direct methods
.method public constructor <init>(Lg1/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg1/p;->d:Lg1/q;

    .line 5
    .line 6
    const/high16 p1, 0x7fc00000    # Float.NaN

    .line 7
    .line 8
    iput p1, p0, Lg1/p;->c:F

    .line 9
    .line 10
    return-void
.end method

.method public static synthetic b(Lg1/p;F)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, v0}, Lg1/p;->a(FF)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public final a(FF)V
    .locals 6

    .line 1
    iget-object v0, p0, Lg1/p;->d:Lg1/q;

    .line 2
    .line 3
    iget-object v1, v0, Lg1/q;->i:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ll2/f1;

    .line 6
    .line 7
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {v1, p1}, Ll2/f1;->p(F)V

    .line 12
    .line 13
    .line 14
    iget-object v3, v0, Lg1/q;->j:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v3, Ll2/f1;

    .line 17
    .line 18
    invoke-virtual {v3, p2}, Ll2/f1;->p(F)V

    .line 19
    .line 20
    .line 21
    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    goto/16 :goto_4

    .line 28
    .line 29
    :cond_0
    cmpl-float p1, p1, v2

    .line 30
    .line 31
    const/4 p2, 0x0

    .line 32
    const/4 v2, 0x1

    .line 33
    if-ltz p1, :cond_1

    .line 34
    .line 35
    move p1, v2

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    move p1, p2

    .line 38
    :goto_0
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    iget-object v4, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v4, Ll2/j1;

    .line 45
    .line 46
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    invoke-virtual {v3, v5}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    cmpg-float v3, v5, v3

    .line 59
    .line 60
    if-nez v3, :cond_5

    .line 61
    .line 62
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    if-eqz p1, :cond_2

    .line 67
    .line 68
    const/high16 v2, 0x3f800000    # 1.0f

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    const/high16 v2, -0x40800000    # -1.0f

    .line 72
    .line 73
    :goto_1
    add-float/2addr p2, v2

    .line 74
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    invoke-virtual {v2, p2, p1}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    if-nez p2, :cond_3

    .line 83
    .line 84
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    :cond_3
    if-eqz p1, :cond_4

    .line 89
    .line 90
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    iput-object v2, p0, Lg1/p;->a:Ljava/lang/Object;

    .line 95
    .line 96
    iput-object p2, p0, Lg1/p;->b:Ljava/lang/Object;

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_4
    iput-object p2, p0, Lg1/p;->a:Ljava/lang/Object;

    .line 100
    .line 101
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p2

    .line 105
    iput-object p2, p0, Lg1/p;->b:Ljava/lang/Object;

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_5
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    invoke-virtual {v3, v5, p2}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p2

    .line 120
    if-nez p2, :cond_6

    .line 121
    .line 122
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    :cond_6
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    invoke-virtual {v3, v5, v2}, Lg1/z;->b(FZ)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    if-nez v2, :cond_7

    .line 139
    .line 140
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    :cond_7
    iput-object p2, p0, Lg1/p;->a:Ljava/lang/Object;

    .line 145
    .line 146
    iput-object v2, p0, Lg1/p;->b:Ljava/lang/Object;

    .line 147
    .line 148
    :goto_2
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    iget-object v2, p0, Lg1/p;->a:Ljava/lang/Object;

    .line 153
    .line 154
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p2, v2}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 158
    .line 159
    .line 160
    move-result p2

    .line 161
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 162
    .line 163
    .line 164
    move-result-object v2

    .line 165
    iget-object v3, p0, Lg1/p;->b:Ljava/lang/Object;

    .line 166
    .line 167
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v2, v3}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    sub-float/2addr p2, v2

    .line 175
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 176
    .line 177
    .line 178
    move-result p2

    .line 179
    iput p2, p0, Lg1/p;->c:F

    .line 180
    .line 181
    invoke-virtual {v1}, Ll2/f1;->o()F

    .line 182
    .line 183
    .line 184
    move-result p2

    .line 185
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    invoke-virtual {v1, v2}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    sub-float/2addr p2, v1

    .line 198
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    iget v1, p0, Lg1/p;->c:F

    .line 203
    .line 204
    const/high16 v2, 0x40000000    # 2.0f

    .line 205
    .line 206
    div-float/2addr v1, v2

    .line 207
    cmpl-float p2, p2, v1

    .line 208
    .line 209
    if-ltz p2, :cond_a

    .line 210
    .line 211
    if-eqz p1, :cond_8

    .line 212
    .line 213
    iget-object p0, p0, Lg1/p;->b:Ljava/lang/Object;

    .line 214
    .line 215
    goto :goto_3

    .line 216
    :cond_8
    iget-object p0, p0, Lg1/p;->a:Ljava/lang/Object;

    .line 217
    .line 218
    :goto_3
    if-nez p0, :cond_9

    .line 219
    .line 220
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    :cond_9
    iget-object p1, v0, Lg1/q;->b:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast p1, Lay0/k;

    .line 227
    .line 228
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object p1

    .line 232
    check-cast p1, Ljava/lang/Boolean;

    .line 233
    .line 234
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 235
    .line 236
    .line 237
    move-result p1

    .line 238
    if-eqz p1, :cond_a

    .line 239
    .line 240
    invoke-virtual {v0, p0}, Lg1/q;->m(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    :cond_a
    :goto_4
    return-void
.end method
