.class public abstract Lh0/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lb0/r;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lh0/e1;

    .line 7
    .line 8
    const/4 v2, 0x2

    .line 9
    invoke-direct {v1, v2}, Lh0/e1;-><init>(I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    new-instance v1, Lb0/r;

    .line 16
    .line 17
    invoke-direct {v1, v0}, Lb0/r;-><init>(Ljava/util/LinkedHashSet;)V

    .line 18
    .line 19
    .line 20
    sput-object v1, Lh0/n0;->a:Lb0/r;

    .line 21
    .line 22
    return-void
.end method

.method public static a(Landroid/content/Context;Lh0/i0;Lb0/r;)V
    .locals 7

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    const-string v2, "CameraValidator"

    .line 6
    .line 7
    if-lt v0, v1, :cond_0

    .line 8
    .line 9
    invoke-static {p0}, Lb/a;->f(Landroid/content/Context;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    new-instance p2, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v0, "Virtual device with ID: "

    .line 22
    .line 23
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p0}, Lb/a;->f(Landroid/content/Context;)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, " has "

    .line 34
    .line 35
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-interface {p1}, Ljava/util/Set;->size()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string p0, " cameras. Skipping validation."

    .line 46
    .line 47
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-static {v2, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_0
    const/4 v0, 0x0

    .line 59
    if-eqz p2, :cond_1

    .line 60
    .line 61
    :try_start_0
    invoke-virtual {p2}, Lb0/r;->b()Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    if-nez v1, :cond_2

    .line 66
    .line 67
    const-string p0, "No lens facing info in the availableCamerasSelector, don\'t verify the camera lens facing."

    .line 68
    .line 69
    invoke-static {v2, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :catch_0
    move-exception p0

    .line 74
    const-string p1, "Cannot get lens facing from the availableCamerasSelector don\'t verify the camera lens facing."

    .line 75
    .line 76
    invoke-static {v2, p1, p0}, Ljp/v1;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 77
    .line 78
    .line 79
    return-void

    .line 80
    :cond_1
    move-object v1, v0

    .line 81
    :cond_2
    new-instance v3, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v4, "Verifying camera lens facing on "

    .line 84
    .line 85
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    sget-object v4, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 89
    .line 90
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v4, ", lensFacingInteger: "

    .line 94
    .line 95
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-static {v2, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    const/4 v3, 0x0

    .line 113
    :try_start_1
    const-string v4, "android.hardware.camera"

    .line 114
    .line 115
    invoke-virtual {p0, v4}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    if-eqz v4, :cond_4

    .line 120
    .line 121
    const/4 v4, 0x1

    .line 122
    if-eqz p2, :cond_3

    .line 123
    .line 124
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    if-ne v5, v4, :cond_4

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :catch_1
    move-exception v0

    .line 132
    goto :goto_1

    .line 133
    :cond_3
    :goto_0
    sget-object v5, Lb0/r;->c:Lb0/r;

    .line 134
    .line 135
    invoke-virtual {p1}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    invoke-virtual {v5, v6}, Lb0/r;->c(Ljava/util/LinkedHashSet;)Lh0/b0;
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 140
    .line 141
    .line 142
    move v3, v4

    .line 143
    goto :goto_2

    .line 144
    :goto_1
    const-string v4, "Camera LENS_FACING_BACK verification failed"

    .line 145
    .line 146
    invoke-static {v2, v4, v0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 147
    .line 148
    .line 149
    :cond_4
    :goto_2
    :try_start_2
    const-string v4, "android.hardware.camera.front"

    .line 150
    .line 151
    invoke-virtual {p0, v4}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 152
    .line 153
    .line 154
    move-result p0

    .line 155
    if-eqz p0, :cond_6

    .line 156
    .line 157
    if-eqz p2, :cond_5

    .line 158
    .line 159
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    if-nez p0, :cond_6

    .line 164
    .line 165
    goto :goto_3

    .line 166
    :catch_2
    move-exception p0

    .line 167
    move-object v0, p0

    .line 168
    goto :goto_4

    .line 169
    :cond_5
    :goto_3
    sget-object p0, Lb0/r;->b:Lb0/r;

    .line 170
    .line 171
    invoke-virtual {p1}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 172
    .line 173
    .line 174
    move-result-object p2

    .line 175
    invoke-virtual {p0, p2}, Lb0/r;->c(Ljava/util/LinkedHashSet;)Lh0/b0;
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_2

    .line 176
    .line 177
    .line 178
    add-int/lit8 v3, v3, 0x1

    .line 179
    .line 180
    goto :goto_5

    .line 181
    :goto_4
    const-string p0, "Camera LENS_FACING_FRONT verification failed"

    .line 182
    .line 183
    invoke-static {v2, p0, v0}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 184
    .line 185
    .line 186
    :cond_6
    :goto_5
    :try_start_3
    sget-object p0, Lh0/n0;->a:Lb0/r;

    .line 187
    .line 188
    invoke-virtual {p1}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 189
    .line 190
    .line 191
    move-result-object p2

    .line 192
    invoke-virtual {p0, p2}, Lb0/r;->c(Ljava/util/LinkedHashSet;)Lh0/b0;

    .line 193
    .line 194
    .line 195
    const-string p0, "Found a LENS_FACING_EXTERNAL camera"

    .line 196
    .line 197
    invoke-static {v2, p0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_3

    .line 198
    .line 199
    .line 200
    add-int/lit8 v3, v3, 0x1

    .line 201
    .line 202
    :catch_3
    if-nez v0, :cond_7

    .line 203
    .line 204
    return-void

    .line 205
    :cond_7
    new-instance p0, Ljava/lang/StringBuilder;

    .line 206
    .line 207
    const-string p2, "Camera LensFacing verification failed, existing cameras: "

    .line 208
    .line 209
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    invoke-virtual {p1}, Lh0/i0;->c()Ljava/util/LinkedHashSet;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object p0

    .line 223
    invoke-static {v2, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    new-instance p0, Lh0/m0;

    .line 227
    .line 228
    invoke-direct {p0, v3, v0}, Lh0/m0;-><init>(ILjava/lang/IllegalArgumentException;)V

    .line 229
    .line 230
    .line 231
    throw p0
.end method
