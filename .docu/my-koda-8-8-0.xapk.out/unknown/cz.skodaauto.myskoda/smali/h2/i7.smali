.class public final synthetic Lh2/i7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Ll2/t2;

.field public final synthetic e:I

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Ll2/t2;

.field public final synthetic i:Ll2/t2;

.field public final synthetic j:J

.field public final synthetic k:Lg3/h;

.field public final synthetic l:J


# direct methods
.method public synthetic constructor <init>(Lc1/g0;IFFLc1/g0;Lc1/g0;JLg3/h;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/i7;->d:Ll2/t2;

    .line 5
    .line 6
    iput p2, p0, Lh2/i7;->e:I

    .line 7
    .line 8
    iput p3, p0, Lh2/i7;->f:F

    .line 9
    .line 10
    iput p4, p0, Lh2/i7;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lh2/i7;->h:Ll2/t2;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/i7;->i:Ll2/t2;

    .line 15
    .line 16
    iput-wide p7, p0, Lh2/i7;->j:J

    .line 17
    .line 18
    iput-object p9, p0, Lh2/i7;->k:Lg3/h;

    .line 19
    .line 20
    iput-wide p10, p0, Lh2/i7;->l:J

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget-wide v3, p0, Lh2/i7;->j:J

    .line 2
    .line 3
    iget-object v5, p0, Lh2/i7;->k:Lg3/h;

    .line 4
    .line 5
    iget-wide v8, p0, Lh2/i7;->l:J

    .line 6
    .line 7
    move-object v0, p1

    .line 8
    check-cast v0, Lg3/d;

    .line 9
    .line 10
    iget-object p1, p0, Lh2/i7;->d:Ll2/t2;

    .line 11
    .line 12
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p1, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    const/high16 v1, 0x43b40000    # 360.0f

    .line 23
    .line 24
    mul-float v7, p1, v1

    .line 25
    .line 26
    iget p1, p0, Lh2/i7;->e:I

    .line 27
    .line 28
    iget v2, p0, Lh2/i7;->f:F

    .line 29
    .line 30
    const/16 v6, 0x20

    .line 31
    .line 32
    if-nez p1, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-interface {v0}, Lg3/d;->e()J

    .line 36
    .line 37
    .line 38
    move-result-wide v10

    .line 39
    const-wide v12, 0xffffffffL

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    and-long/2addr v10, v12

    .line 45
    long-to-int p1, v10

    .line 46
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-interface {v0}, Lg3/d;->e()J

    .line 51
    .line 52
    .line 53
    move-result-wide v10

    .line 54
    shr-long/2addr v10, v6

    .line 55
    long-to-int v10, v10

    .line 56
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v10

    .line 60
    cmpl-float p1, p1, v10

    .line 61
    .line 62
    if-lez p1, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    iget p1, p0, Lh2/i7;->g:F

    .line 66
    .line 67
    add-float/2addr v2, p1

    .line 68
    :goto_0
    invoke-interface {v0}, Lg3/d;->e()J

    .line 69
    .line 70
    .line 71
    move-result-wide v10

    .line 72
    shr-long/2addr v10, v6

    .line 73
    long-to-int p1, v10

    .line 74
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    invoke-interface {v0, p1}, Lt4/c;->o0(F)F

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    float-to-double v10, p1

    .line 83
    const-wide v12, 0x400921fb54442d18L    # Math.PI

    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    mul-double/2addr v10, v12

    .line 89
    double-to-float p1, v10

    .line 90
    div-float/2addr v2, p1

    .line 91
    mul-float/2addr v2, v1

    .line 92
    iget-object p1, p0, Lh2/i7;->h:Ll2/t2;

    .line 93
    .line 94
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    check-cast p1, Ljava/lang/Number;

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    iget-object p0, p0, Lh2/i7;->i:Ll2/t2;

    .line 105
    .line 106
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Ljava/lang/Number;

    .line 111
    .line 112
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    add-float/2addr p0, p1

    .line 117
    invoke-interface {v0}, Lg3/d;->D0()J

    .line 118
    .line 119
    .line 120
    move-result-wide v10

    .line 121
    invoke-interface {v0}, Lg3/d;->x0()Lgw0/c;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {p1}, Lgw0/c;->o()J

    .line 126
    .line 127
    .line 128
    move-result-wide v12

    .line 129
    invoke-virtual {p1}, Lgw0/c;->h()Le3/r;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    invoke-interface {v6}, Le3/r;->o()V

    .line 134
    .line 135
    .line 136
    :try_start_0
    iget-object v6, p1, Lgw0/c;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v6, Lbu/c;

    .line 139
    .line 140
    invoke-virtual {v6, v10, v11, p0}, Lbu/c;->z(JF)V

    .line 141
    .line 142
    .line 143
    invoke-static {v7, v2}, Ljava/lang/Math;->min(FF)F

    .line 144
    .line 145
    .line 146
    move-result p0

    .line 147
    add-float/2addr p0, v7

    .line 148
    sub-float/2addr v1, v7

    .line 149
    invoke-static {v7, v2}, Ljava/lang/Math;->min(FF)F

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    const/4 v6, 0x2

    .line 154
    int-to-float v6, v6

    .line 155
    mul-float/2addr v2, v6

    .line 156
    sub-float v2, v1, v2

    .line 157
    .line 158
    move v1, p0

    .line 159
    invoke-static/range {v0 .. v5}, Lh2/n7;->e(Lg3/d;FFJLg3/h;)V

    .line 160
    .line 161
    .line 162
    const/4 v6, 0x0

    .line 163
    move-object v10, v5

    .line 164
    move-object v5, v0

    .line 165
    invoke-static/range {v5 .. v10}, Lh2/n7;->e(Lg3/d;FFJLg3/h;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 166
    .line 167
    .line 168
    invoke-static {p1, v12, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 169
    .line 170
    .line 171
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 172
    .line 173
    return-object p0

    .line 174
    :catchall_0
    move-exception v0

    .line 175
    move-object p0, v0

    .line 176
    invoke-static {p1, v12, v13}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 177
    .line 178
    .line 179
    throw p0
.end method
