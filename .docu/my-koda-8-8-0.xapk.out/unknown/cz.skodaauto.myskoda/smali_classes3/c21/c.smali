.class public abstract Lc21/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lum/a;ZILl2/o;I)Lym/g;
    .locals 10

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    const v0, 0x28bfd0f4

    .line 4
    .line 5
    .line 6
    invoke-virtual {p3, v0}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p4, 0x2

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    move v3, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v3, p1

    .line 17
    :goto_0
    and-int/lit8 p1, p4, 0x40

    .line 18
    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    move v6, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move v6, p2

    .line 24
    :goto_1
    sget-object p1, Lym/k;->d:Lym/k;

    .line 25
    .line 26
    if-lez v6, :cond_5

    .line 27
    .line 28
    const/high16 p1, 0x3f800000    # 1.0f

    .line 29
    .line 30
    invoke-static {p1}, Ljava/lang/Float;->isInfinite(F)Z

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    if-nez p2, :cond_4

    .line 35
    .line 36
    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    if-nez p2, :cond_4

    .line 41
    .line 42
    const p2, 0x78ab5fda

    .line 43
    .line 44
    .line 45
    invoke-virtual {p3, p2}, Ll2/t;->Z(I)V

    .line 46
    .line 47
    .line 48
    const p2, -0x245f086a

    .line 49
    .line 50
    .line 51
    invoke-virtual {p3, p2}, Ll2/t;->Z(I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p2

    .line 58
    sget-object p4, Ll2/n;->a:Ll2/x0;

    .line 59
    .line 60
    if-ne p2, p4, :cond_2

    .line 61
    .line 62
    new-instance p2, Lym/g;

    .line 63
    .line 64
    invoke-direct {p2}, Lym/g;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p3, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :cond_2
    move-object v4, p2

    .line 71
    check-cast v4, Lym/g;

    .line 72
    .line 73
    const/4 p2, 0x0

    .line 74
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 78
    .line 79
    .line 80
    const v0, -0xac3d7f4

    .line 81
    .line 82
    .line 83
    invoke-virtual {p3, v0}, Ll2/t;->Z(I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    if-ne v0, p4, :cond_3

    .line 91
    .line 92
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 93
    .line 94
    .line 95
    move-result-object p4

    .line 96
    invoke-static {p4}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    invoke-virtual {p3, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_3
    move-object v8, v0

    .line 104
    check-cast v8, Ll2/b1;

    .line 105
    .line 106
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    const p4, -0xac3d772

    .line 110
    .line 111
    .line 112
    invoke-virtual {p3, p4}, Ll2/t;->Z(I)V

    .line 113
    .line 114
    .line 115
    sget-object p4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 116
    .line 117
    invoke-virtual {p3, p4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p4

    .line 121
    check-cast p4, Landroid/content/Context;

    .line 122
    .line 123
    sget-object v0, Lgn/h;->a:Landroid/graphics/Matrix;

    .line 124
    .line 125
    invoke-virtual {p4}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 126
    .line 127
    .line 128
    move-result-object p4

    .line 129
    const-string v0, "animator_duration_scale"

    .line 130
    .line 131
    invoke-static {p4, v0, p1}, Landroid/provider/Settings$Global;->getFloat(Landroid/content/ContentResolver;Ljava/lang/String;F)F

    .line 132
    .line 133
    .line 134
    move-result p4

    .line 135
    div-float v7, p1, p4

    .line 136
    .line 137
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 138
    .line 139
    .line 140
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 145
    .line 146
    .line 147
    move-result-object p4

    .line 148
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    const/4 v1, 0x0

    .line 153
    filled-new-array {p0, p1, v1, p4, v0}, [Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    new-instance v2, Lym/a;

    .line 158
    .line 159
    const/4 v9, 0x0

    .line 160
    move-object v5, p0

    .line 161
    invoke-direct/range {v2 .. v9}, Lym/a;-><init>(ZLym/g;Lum/a;IFLl2/b1;Lkotlin/coroutines/Continuation;)V

    .line 162
    .line 163
    .line 164
    invoke-static {p1, v2, p3}, Ll2/l0;->f([Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 168
    .line 169
    .line 170
    return-object v4

    .line 171
    :cond_4
    new-instance p0, Ljava/lang/StringBuilder;

    .line 172
    .line 173
    const-string p2, "Speed must be a finite number. It is "

    .line 174
    .line 175
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    const-string p1, "."

    .line 182
    .line 183
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 191
    .line 192
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object p0

    .line 196
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw p1

    .line 200
    :cond_5
    const-string p0, "Iterations must be a positive number ("

    .line 201
    .line 202
    const-string p1, ")."

    .line 203
    .line 204
    invoke-static {p0, v6, p1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 209
    .line 210
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    throw p1
.end method

.method public static final b(Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;)Ld20/a;
    .locals 8

    .line 1
    new-instance v0, Ld20/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getMain()Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getBraking()Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getSpeeding()Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getAcceleration()Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getEnergyLevel()Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getFavorableConditions()Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDto;->getExcessiveTrip()Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    invoke-direct/range {v0 .. v7}, Ld20/a;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final c(Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;)Ld20/b;
    .locals 8

    .line 1
    new-instance v0, Ld20/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getMain()Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getBraking()Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getSpeeding()Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getAcceleration()Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v4

    .line 19
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getEnergyLevel()Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v5

    .line 23
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getFavorableConditions()Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    invoke-virtual {p0}, Lcz/myskoda/api/bff_vehicle_status/v2/DrivingScoreDifferenceDto;->getExcessiveTrip()Ljava/lang/Integer;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    invoke-direct/range {v0 .. v7}, Ld20/b;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final d(Lm1/l;)I
    .locals 5

    .line 1
    iget-object v0, p0, Lm1/l;->k:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    const/4 v2, 0x0

    .line 11
    move v3, v2

    .line 12
    :goto_0
    if-ge v2, v1, :cond_0

    .line 13
    .line 14
    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    check-cast v4, Lm1/m;

    .line 19
    .line 20
    iget v4, v4, Lm1/m;->p:I

    .line 21
    .line 22
    add-int/2addr v3, v4

    .line 23
    add-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    div-int/2addr v3, v0

    .line 31
    iget p0, p0, Lm1/l;->q:I

    .line 32
    .line 33
    add-int/2addr v3, p0

    .line 34
    return v3
.end method
