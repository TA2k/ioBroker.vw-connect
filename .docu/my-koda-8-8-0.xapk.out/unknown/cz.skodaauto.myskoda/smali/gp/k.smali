.class public final Lgp/k;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpp/a;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lgp/k;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:J

.field public final f:S

.field public final g:D

.field public final h:D

.field public final i:F

.field public final j:I

.field public final k:I

.field public final l:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgl/c;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgl/c;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lgp/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ISDDFJII)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_4

    .line 5
    .line 6
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/16 v1, 0x64

    .line 11
    .line 12
    if-gt v0, v1, :cond_4

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    cmpg-float v0, p8, v0

    .line 16
    .line 17
    if-lez v0, :cond_3

    .line 18
    .line 19
    const-wide v0, 0x4056800000000000L    # 90.0

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    cmpl-double v0, p4, v0

    .line 25
    .line 26
    if-gtz v0, :cond_2

    .line 27
    .line 28
    const-wide v0, -0x3fa9800000000000L    # -90.0

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmpg-double v0, p4, v0

    .line 34
    .line 35
    if-ltz v0, :cond_2

    .line 36
    .line 37
    const-wide v0, 0x4066800000000000L    # 180.0

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    cmpl-double v0, p6, v0

    .line 43
    .line 44
    if-gtz v0, :cond_1

    .line 45
    .line 46
    const-wide v0, -0x3f99800000000000L    # -180.0

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    cmpg-double v0, p6, v0

    .line 52
    .line 53
    if-ltz v0, :cond_1

    .line 54
    .line 55
    and-int/lit8 v0, p2, 0x7

    .line 56
    .line 57
    if-eqz v0, :cond_0

    .line 58
    .line 59
    iput-short p3, p0, Lgp/k;->f:S

    .line 60
    .line 61
    iput-object p1, p0, Lgp/k;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput-wide p4, p0, Lgp/k;->g:D

    .line 64
    .line 65
    iput-wide p6, p0, Lgp/k;->h:D

    .line 66
    .line 67
    iput p8, p0, Lgp/k;->i:F

    .line 68
    .line 69
    iput-wide p9, p0, Lgp/k;->e:J

    .line 70
    .line 71
    iput v0, p0, Lgp/k;->j:I

    .line 72
    .line 73
    iput p11, p0, Lgp/k;->k:I

    .line 74
    .line 75
    iput p12, p0, Lgp/k;->l:I

    .line 76
    .line 77
    return-void

    .line 78
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 79
    .line 80
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    new-instance p3, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    add-int/lit8 p1, p1, 0x23

    .line 91
    .line 92
    invoke-direct {p3, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 93
    .line 94
    .line 95
    const-string p1, "No supported transition specified: "

    .line 96
    .line 97
    invoke-static {p2, p1, p3}, Lvj/b;->h(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 106
    .line 107
    invoke-static {p6, p7}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    new-instance p2, Ljava/lang/StringBuilder;

    .line 116
    .line 117
    add-int/lit8 p1, p1, 0x13

    .line 118
    .line 119
    invoke-direct {p2, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 120
    .line 121
    .line 122
    const-string p1, "invalid longitude: "

    .line 123
    .line 124
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {p2, p6, p7}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 139
    .line 140
    invoke-static {p4, p5}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 145
    .line 146
    .line 147
    move-result p1

    .line 148
    new-instance p2, Ljava/lang/StringBuilder;

    .line 149
    .line 150
    add-int/lit8 p1, p1, 0x12

    .line 151
    .line 152
    invoke-direct {p2, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 153
    .line 154
    .line 155
    const-string p1, "invalid latitude: "

    .line 156
    .line 157
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {p2, p4, p5}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p0

    .line 171
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 172
    .line 173
    invoke-static {p8}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 178
    .line 179
    .line 180
    move-result p1

    .line 181
    new-instance p2, Ljava/lang/StringBuilder;

    .line 182
    .line 183
    add-int/lit8 p1, p1, 0x10

    .line 184
    .line 185
    invoke-direct {p2, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 186
    .line 187
    .line 188
    const-string p1, "invalid radius: "

    .line 189
    .line 190
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {p2, p8}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0

    .line 204
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 205
    .line 206
    const-string p2, "requestId is null or too long: "

    .line 207
    .line 208
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lgp/k;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lgp/k;

    .line 11
    .line 12
    iget v1, p0, Lgp/k;->i:F

    .line 13
    .line 14
    iget v3, p1, Lgp/k;->i:F

    .line 15
    .line 16
    cmpl-float v1, v1, v3

    .line 17
    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    iget-wide v3, p0, Lgp/k;->g:D

    .line 21
    .line 22
    iget-wide v5, p1, Lgp/k;->g:D

    .line 23
    .line 24
    cmpl-double v1, v3, v5

    .line 25
    .line 26
    if-nez v1, :cond_1

    .line 27
    .line 28
    iget-wide v3, p0, Lgp/k;->h:D

    .line 29
    .line 30
    iget-wide v5, p1, Lgp/k;->h:D

    .line 31
    .line 32
    cmpl-double v1, v3, v5

    .line 33
    .line 34
    if-nez v1, :cond_1

    .line 35
    .line 36
    iget-short v1, p0, Lgp/k;->f:S

    .line 37
    .line 38
    iget-short v3, p1, Lgp/k;->f:S

    .line 39
    .line 40
    if-ne v1, v3, :cond_1

    .line 41
    .line 42
    iget p0, p0, Lgp/k;->j:I

    .line 43
    .line 44
    iget p1, p1, Lgp/k;->j:I

    .line 45
    .line 46
    if-ne p0, p1, :cond_1

    .line 47
    .line 48
    return v0

    .line 49
    :cond_1
    return v2
.end method

.method public final hashCode()I
    .locals 7

    .line 1
    iget-wide v0, p0, Lgp/k;->g:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const/16 v2, 0x20

    .line 8
    .line 9
    ushr-long v3, v0, v2

    .line 10
    .line 11
    xor-long/2addr v0, v3

    .line 12
    iget-wide v3, p0, Lgp/k;->h:D

    .line 13
    .line 14
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToLongBits(D)J

    .line 15
    .line 16
    .line 17
    move-result-wide v3

    .line 18
    ushr-long v5, v3, v2

    .line 19
    .line 20
    xor-long v2, v3, v5

    .line 21
    .line 22
    long-to-int v0, v0

    .line 23
    add-int/lit8 v0, v0, 0x1f

    .line 24
    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    long-to-int v1, v2

    .line 28
    add-int/2addr v0, v1

    .line 29
    mul-int/lit8 v0, v0, 0x1f

    .line 30
    .line 31
    iget v1, p0, Lgp/k;->i:F

    .line 32
    .line 33
    invoke-static {v1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    add-int/2addr v1, v0

    .line 38
    mul-int/lit8 v1, v1, 0x1f

    .line 39
    .line 40
    iget-short v0, p0, Lgp/k;->f:S

    .line 41
    .line 42
    add-int/2addr v1, v0

    .line 43
    mul-int/lit8 v1, v1, 0x1f

    .line 44
    .line 45
    iget p0, p0, Lgp/k;->j:I

    .line 46
    .line 47
    add-int/2addr v1, p0

    .line 48
    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 12

    .line 1
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    iget-short v2, p0, Lgp/k;->f:S

    .line 5
    .line 6
    if-eq v2, v1, :cond_1

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eq v2, v1, :cond_0

    .line 10
    .line 11
    const-string v1, "UNKNOWN"

    .line 12
    .line 13
    :goto_0
    move-object v2, v1

    .line 14
    goto :goto_1

    .line 15
    :cond_0
    const-string v1, "CIRCLE"

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    const-string v1, "INVALID"

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :goto_1
    const-string v1, "\\p{C}"

    .line 22
    .line 23
    const-string v3, "?"

    .line 24
    .line 25
    iget-object v4, p0, Lgp/k;->d:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v4, v1, v3}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget v1, p0, Lgp/k;->j:I

    .line 32
    .line 33
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-wide v5, p0, Lgp/k;->g:D

    .line 38
    .line 39
    invoke-static {v5, v6}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    iget-wide v6, p0, Lgp/k;->h:D

    .line 44
    .line 45
    invoke-static {v6, v7}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 46
    .line 47
    .line 48
    move-result-object v6

    .line 49
    iget v1, p0, Lgp/k;->i:F

    .line 50
    .line 51
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    iget v1, p0, Lgp/k;->k:I

    .line 56
    .line 57
    div-int/lit16 v1, v1, 0x3e8

    .line 58
    .line 59
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 60
    .line 61
    .line 62
    move-result-object v8

    .line 63
    iget v1, p0, Lgp/k;->l:I

    .line 64
    .line 65
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    iget-wide v10, p0, Lgp/k;->e:J

    .line 70
    .line 71
    invoke-static {v10, v11}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 72
    .line 73
    .line 74
    move-result-object v10

    .line 75
    filled-new-array/range {v2 .. v10}, [Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    const-string v1, "Geofence[%s id:%s transitions:%d %.6f, %.6f %.0fm, resp=%ds, dwell=%dms, @%d]"

    .line 80
    .line 81
    invoke-static {v0, v1, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 5

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x1

    .line 8
    iget-object v1, p0, Lgp/k;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    const/16 v1, 0x8

    .line 15
    .line 16
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 17
    .line 18
    .line 19
    iget-wide v2, p0, Lgp/k;->e:J

    .line 20
    .line 21
    invoke-virtual {p1, v2, v3}, Landroid/os/Parcel;->writeLong(J)V

    .line 22
    .line 23
    .line 24
    const/4 v0, 0x3

    .line 25
    const/4 v2, 0x4

    .line 26
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 27
    .line 28
    .line 29
    iget-short v0, p0, Lgp/k;->f:S

    .line 30
    .line 31
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {p1, v2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 35
    .line 36
    .line 37
    iget-wide v3, p0, Lgp/k;->g:D

    .line 38
    .line 39
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeDouble(D)V

    .line 40
    .line 41
    .line 42
    const/4 v0, 0x5

    .line 43
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 44
    .line 45
    .line 46
    iget-wide v3, p0, Lgp/k;->h:D

    .line 47
    .line 48
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeDouble(D)V

    .line 49
    .line 50
    .line 51
    const/4 v0, 0x6

    .line 52
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 53
    .line 54
    .line 55
    iget v0, p0, Lgp/k;->i:F

    .line 56
    .line 57
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeFloat(F)V

    .line 58
    .line 59
    .line 60
    const/4 v0, 0x7

    .line 61
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 62
    .line 63
    .line 64
    iget v0, p0, Lgp/k;->j:I

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 67
    .line 68
    .line 69
    invoke-static {p1, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 70
    .line 71
    .line 72
    iget v0, p0, Lgp/k;->k:I

    .line 73
    .line 74
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 75
    .line 76
    .line 77
    const/16 v0, 0x9

    .line 78
    .line 79
    invoke-static {p1, v0, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 80
    .line 81
    .line 82
    iget p0, p0, Lgp/k;->l:I

    .line 83
    .line 84
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 85
    .line 86
    .line 87
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 88
    .line 89
    .line 90
    return-void
.end method
