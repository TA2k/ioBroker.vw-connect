.class public final synthetic Lzb/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:F


# direct methods
.method public synthetic constructor <init>(FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lzb/m0;->d:F

    .line 5
    .line 6
    iput p2, p0, Lzb/m0;->e:F

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    check-cast p1, Lx2/s;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$composed"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    check-cast p2, Ll2/t;

    .line 16
    .line 17
    const p3, -0x4d5049cf

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 21
    .line 22
    .line 23
    sget-object p3, Lzb/o0;->a:Ll2/u2;

    .line 24
    .line 25
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p3

    .line 29
    check-cast p3, Ll2/t2;

    .line 30
    .line 31
    sget-object v0, Lzb/o0;->b:Ll2/u2;

    .line 32
    .line 33
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    move-object v2, v0

    .line 38
    check-cast v2, Ljava/util/List;

    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    if-eqz p3, :cond_3

    .line 42
    .line 43
    if-nez v2, :cond_0

    .line 44
    .line 45
    goto/16 :goto_0

    .line 46
    .line 47
    :cond_0
    const v1, -0x123a92c4

    .line 48
    .line 49
    .line 50
    invoke-virtual {p2, v1}, Ll2/t;->Y(I)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    check-cast v1, Ljava/lang/Number;

    .line 58
    .line 59
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    const/high16 v3, 0x43510000    # 209.0f

    .line 64
    .line 65
    add-float/2addr v1, v3

    .line 66
    invoke-interface {p3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p3

    .line 70
    check-cast p3, Ljava/lang/Number;

    .line 71
    .line 72
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 73
    .line 74
    .line 75
    move-result p3

    .line 76
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    int-to-long v3, v1

    .line 81
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 82
    .line 83
    .line 84
    move-result p3

    .line 85
    int-to-long v5, p3

    .line 86
    const/16 p3, 0x20

    .line 87
    .line 88
    shl-long/2addr v3, p3

    .line 89
    const-wide v7, 0xffffffffL

    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    and-long/2addr v5, v7

    .line 95
    or-long v6, v3, v5

    .line 96
    .line 97
    new-instance v1, Le3/b0;

    .line 98
    .line 99
    const/4 v3, 0x0

    .line 100
    const-wide/16 v4, 0x0

    .line 101
    .line 102
    const/4 v8, 0x0

    .line 103
    invoke-direct/range {v1 .. v8}, Le3/b0;-><init>(Ljava/util/List;Ljava/util/ArrayList;JJI)V

    .line 104
    .line 105
    .line 106
    sget-object p3, Lw3/h1;->h:Ll2/u2;

    .line 107
    .line 108
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p3

    .line 112
    check-cast p3, Lt4/c;

    .line 113
    .line 114
    const/4 v2, 0x4

    .line 115
    int-to-float v2, v2

    .line 116
    invoke-interface {p3, v2}, Lt4/c;->w0(F)F

    .line 117
    .line 118
    .line 119
    move-result v2

    .line 120
    iget v3, p0, Lzb/m0;->d:F

    .line 121
    .line 122
    invoke-interface {p3, v3}, Lt4/c;->w0(F)F

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    iget p0, p0, Lzb/m0;->e:F

    .line 127
    .line 128
    invoke-interface {p3, p0}, Lt4/c;->w0(F)F

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-virtual {p2, v3}, Ll2/t;->d(F)Z

    .line 133
    .line 134
    .line 135
    move-result p3

    .line 136
    invoke-virtual {p2, p0}, Ll2/t;->d(F)Z

    .line 137
    .line 138
    .line 139
    move-result v4

    .line 140
    or-int/2addr p3, v4

    .line 141
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    or-int/2addr p3, v4

    .line 146
    invoke-virtual {p2, v2}, Ll2/t;->d(F)Z

    .line 147
    .line 148
    .line 149
    move-result v4

    .line 150
    or-int/2addr p3, v4

    .line 151
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    if-nez p3, :cond_1

    .line 156
    .line 157
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 158
    .line 159
    if-ne v4, p3, :cond_2

    .line 160
    .line 161
    :cond_1
    new-instance v4, Lzb/n0;

    .line 162
    .line 163
    invoke-direct {v4, v3, p0, v1, v2}, Lzb/n0;-><init>(FFLe3/b0;F)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    :cond_2
    check-cast v4, Lay0/k;

    .line 170
    .line 171
    invoke-static {p1, v4}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 176
    .line 177
    .line 178
    goto :goto_1

    .line 179
    :cond_3
    :goto_0
    const p0, -0x123b35a3

    .line 180
    .line 181
    .line 182
    invoke-virtual {p2, p0}, Ll2/t;->Y(I)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 186
    .line 187
    .line 188
    :goto_1
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    return-object p1
.end method
