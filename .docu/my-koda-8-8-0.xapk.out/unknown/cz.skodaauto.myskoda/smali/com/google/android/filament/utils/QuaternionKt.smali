.class public final Lcom/google/android/filament/utils/QuaternionKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000*\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0008\u0014\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0004\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0005\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\n\u001a\u0015\u0010\u0006\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\n\u001a\u0019\u0010\u0007\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0008\u001a\u0019\u0010\u0007\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001H\u0086\u0008\u001a\u0019\u0010\u000b\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0008\u001a\u0019\u0010\u000b\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001H\u0086\u0008\u001a\u0019\u0010\u000c\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0008\u001a\u0019\u0010\u000c\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001H\u0086\u0008\u001a\u0019\u0010\r\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u0008\u001a\u0019\u0010\r\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001H\u0086\u0008\u001a#\u0010\u000e\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0002H\u0086\u0008\u001a#\u0010\u000e\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0002H\u0086\u0008\u001a#\u0010\u0010\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0002H\u0086\u0008\u001a#\u0010\u0010\u001a\u00020\u00082\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0008\u0008\u0002\u0010\u000f\u001a\u00020\u0002H\u0086\u0008\u001a\u0015\u0010\u0011\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0011\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0015\u0010\u0013\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0013\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0015\u0010\u0014\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0014\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0015\u0010\u0015\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0015\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0015\u0010\u0016\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0016\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0015\u0010\u0017\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0002H\u0086\u000c\u001a\u0015\u0010\u0017\u001a\u00020\u0008*\u00020\u00012\u0006\u0010\n\u001a\u00020\u0012H\u0086\u000c\u001a\u0011\u0010\u0018\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\u0008\u001a\u0011\u0010\u0019\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\u0008\u001a\u0011\u0010\u001a\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0001H\u0086\u0008\u001a\u0019\u0010\u001b\u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001H\u0086\u0008\u001a\u000e\u0010\u001c\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001\u001a\u000e\u0010\u001d\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001\u001a\u000e\u0010\u001e\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0001\u001a\u0016\u0010\u001f\u001a\u00020\u00012\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001\u001a\u0016\u0010 \u001a\u00020\u00022\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u0001\u001a(\u0010!\u001a\u00020\u00012\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\"\u001a\u00020\u00022\u0008\u0008\u0002\u0010#\u001a\u00020\u0002\u001a\u001e\u0010$\u001a\u00020\u00012\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\"\u001a\u00020\u0002\u001a\u001e\u0010%\u001a\u00020\u00012\u0006\u0010\t\u001a\u00020\u00012\u0006\u0010\n\u001a\u00020\u00012\u0006\u0010\"\u001a\u00020\u0002\u001a\u0018\u0010&\u001a\u00020\'2\u0006\u0010\u0003\u001a\u00020\u00012\u0008\u0008\u0002\u0010(\u001a\u00020)\u00a8\u0006*"
    }
    d2 = {
        "plus",
        "Lcom/google/android/filament/utils/Quaternion;",
        "",
        "q",
        "minus",
        "times",
        "div",
        "lessThan",
        "Lcom/google/android/filament/utils/Bool4;",
        "a",
        "b",
        "lessThanEqual",
        "greaterThan",
        "greaterThanEqual",
        "equal",
        "delta",
        "notEqual",
        "lt",
        "Lcom/google/android/filament/utils/Float4;",
        "lte",
        "gt",
        "gte",
        "eq",
        "neq",
        "abs",
        "length",
        "length2",
        "dot",
        "normalize",
        "conjugate",
        "inverse",
        "cross",
        "angle",
        "slerp",
        "t",
        "dotThreshold",
        "lerp",
        "nlerp",
        "eulerAngles",
        "Lcom/google/android/filament/utils/Float3;",
        "order",
        "Lcom/google/android/filament/utils/RotationsOrder;",
        "filament-utils-android_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final abs(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 41
    .line 42
    .line 43
    return-object v0
.end method

.method public static final angle(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)F
    .locals 3

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    mul-float/2addr v1, v0

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    mul-float/2addr v2, v0

    .line 29
    add-float/2addr v2, v1

    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    mul-float/2addr v1, v0

    .line 39
    add-float/2addr v1, v2

    .line 40
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    mul-float/2addr p1, p0

    .line 49
    add-float/2addr p1, v1

    .line 50
    const/high16 p0, -0x40800000    # -1.0f

    .line 51
    .line 52
    cmpg-float v0, p1, p0

    .line 53
    .line 54
    if-gez v0, :cond_0

    .line 55
    .line 56
    :goto_0
    move p1, p0

    .line 57
    goto :goto_1

    .line 58
    :cond_0
    const/high16 p0, 0x3f800000    # 1.0f

    .line 59
    .line 60
    cmpl-float v0, p1, p0

    .line 61
    .line 62
    if-lez v0, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    :goto_1
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    float-to-double p0, p0

    .line 70
    invoke-static {p0, p1}, Ljava/lang/Math;->acos(D)D

    .line 71
    .line 72
    .line 73
    move-result-wide p0

    .line 74
    double-to-float p0, p0

    .line 75
    const/high16 p1, 0x40000000    # 2.0f

    .line 76
    .line 77
    mul-float/2addr p0, p1

    .line 78
    return p0
.end method

.method public static final conjugate(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    neg-float v1, v1

    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    neg-float v2, v2

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    neg-float v3, v3

    .line 23
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static final cross(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 7

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 12
    .line 13
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    mul-float/2addr v2, v1

    .line 22
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    mul-float/2addr v3, v1

    .line 31
    add-float/2addr v3, v2

    .line 32
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    mul-float/2addr v2, v1

    .line 41
    add-float/2addr v2, v3

    .line 42
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    mul-float/2addr v3, v1

    .line 51
    sub-float/2addr v2, v3

    .line 52
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    mul-float/2addr v3, v1

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    mul-float/2addr v4, v1

    .line 70
    sub-float/2addr v3, v4

    .line 71
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    mul-float/2addr v4, v1

    .line 80
    add-float/2addr v4, v3

    .line 81
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    mul-float/2addr v3, v1

    .line 90
    add-float/2addr v3, v4

    .line 91
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    mul-float/2addr v4, v1

    .line 100
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 105
    .line 106
    .line 107
    move-result v5

    .line 108
    mul-float/2addr v5, v1

    .line 109
    add-float/2addr v5, v4

    .line 110
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    mul-float/2addr v4, v1

    .line 119
    sub-float/2addr v5, v4

    .line 120
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    mul-float/2addr v4, v1

    .line 129
    add-float/2addr v4, v5

    .line 130
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    mul-float/2addr v5, v1

    .line 139
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 144
    .line 145
    .line 146
    move-result v6

    .line 147
    mul-float/2addr v6, v1

    .line 148
    sub-float/2addr v5, v6

    .line 149
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    mul-float/2addr v6, v1

    .line 158
    sub-float/2addr v5, v6

    .line 159
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    mul-float/2addr p1, p0

    .line 168
    sub-float/2addr v5, p1

    .line 169
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 170
    .line 171
    .line 172
    new-instance p0, Lcom/google/android/filament/utils/Quaternion;

    .line 173
    .line 174
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 175
    .line 176
    .line 177
    move-result p1

    .line 178
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    const/4 v2, 0x0

    .line 187
    invoke-direct {p0, p1, v1, v0, v2}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 188
    .line 189
    .line 190
    return-object p0
.end method

.method public static final div(FLcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    div-float v1, p0, v1

    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    div-float v2, p0, v2

    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    div-float v3, p0, v3

    .line 25
    .line 26
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    div-float/2addr p0, p1

    .line 31
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final dot(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)F
    .locals 3

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    mul-float/2addr v1, v0

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    mul-float/2addr v2, v0

    .line 29
    add-float/2addr v2, v1

    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    mul-float/2addr v1, v0

    .line 39
    add-float/2addr v1, v2

    .line 40
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    mul-float/2addr p1, p0

    .line 49
    add-float/2addr p1, v1

    .line 50
    return p1
.end method

.method public static final eq(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-nez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-nez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-nez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-nez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final eq(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-nez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-nez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-nez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-nez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final equal(Lcom/google/android/filament/utils/Quaternion;FF)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    sub-float/2addr v1, p1

    .line 3
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 4
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    sub-float/2addr v4, p1

    .line 5
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 6
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    sub-float/2addr v5, p1

    .line 7
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 8
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 9
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    .line 10
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final equal(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    sub-float/2addr v1, v2

    .line 13
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 14
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    sub-float/2addr v4, v5

    .line 15
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 16
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    sub-float/2addr v5, v6

    .line 17
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 18
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    sub-float/2addr p0, p1

    .line 19
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    .line 20
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static synthetic equal$default(Lcom/google/android/filament/utils/Quaternion;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 4

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    const-string p3, "a"

    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    sub-float/2addr p4, p1

    .line 3
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    .line 4
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    sub-float/2addr v2, p1

    .line 5
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    .line 6
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    sub-float/2addr v3, p1

    .line 7
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    .line 8
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 9
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    .line 10
    :cond_4
    invoke-direct {p3, p4, v2, v3, v0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method

.method public static synthetic equal$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;FILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 5

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 11
    :cond_0
    const-string p3, "a"

    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "b"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v0

    sub-float/2addr p4, v0

    .line 13
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    .line 14
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    sub-float/2addr v2, v3

    .line 15
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    .line 16
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    sub-float/2addr v3, v4

    .line 17
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    .line 18
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    sub-float/2addr p0, p1

    .line 19
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    .line 20
    :cond_4
    invoke-direct {p3, p4, v2, v3, v0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method

.method public static final eulerAngles(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;
    .locals 1

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "order"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0}, Lcom/google/android/filament/utils/MatrixKt;->rotation(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Mat4;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/MatrixKt;->eulerAngles(Lcom/google/android/filament/utils/Mat4;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static synthetic eulerAngles$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/RotationsOrder;ILjava/lang/Object;)Lcom/google/android/filament/utils/Float3;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x2

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    sget-object p1, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 6
    .line 7
    :cond_0
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/QuaternionKt;->eulerAngles(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/RotationsOrder;)Lcom/google/android/filament/utils/Float3;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public static final greaterThan(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpl-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-lez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 3
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpl-float v4, v4, p1

    if-lez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 4
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpl-float v5, v5, p1

    if-lez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 5
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpl-float p0, p0, p1

    if-lez p0, :cond_3

    move v2, v3

    .line 6
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final greaterThan(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    cmpl-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-lez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 9
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    cmpl-float v4, v4, v5

    if-lez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 10
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    cmpl-float v5, v5, v6

    if-lez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    cmpl-float p0, p0, p1

    if-lez p0, :cond_3

    move v2, v3

    .line 12
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final greaterThanEqual(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpl-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ltz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 3
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpl-float v4, v4, p1

    if-ltz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 4
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpl-float v5, v5, p1

    if-ltz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 5
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpl-float p0, p0, p1

    if-ltz p0, :cond_3

    move v2, v3

    .line 6
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final greaterThanEqual(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    cmpl-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ltz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 9
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    cmpl-float v4, v4, v5

    if-ltz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 10
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    cmpl-float v5, v5, v6

    if-ltz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    cmpl-float p0, p0, p1

    if-ltz p0, :cond_3

    move v2, v3

    .line 12
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final gt(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpl-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-lez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpl-float v4, v4, p1

    if-lez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpl-float v5, v5, p1

    if-lez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpl-float p0, p0, p1

    if-lez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final gt(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpl-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-lez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpl-float v4, v4, v5

    if-lez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpl-float v5, v5, v6

    if-lez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpl-float p0, p0, p1

    if-lez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final gte(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpl-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ltz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpl-float v4, v4, p1

    if-ltz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpl-float v5, v5, p1

    if-ltz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpl-float p0, p0, p1

    if-ltz p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final gte(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpl-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ltz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpl-float v4, v4, v5

    if-ltz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpl-float v5, v5, v6

    if-ltz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpl-float p0, p0, p1

    if-ltz p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final inverse(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    mul-float/2addr v1, v0

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    mul-float/2addr v2, v0

    .line 24
    add-float/2addr v2, v1

    .line 25
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    mul-float/2addr v1, v0

    .line 34
    add-float/2addr v1, v2

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    mul-float/2addr v2, v0

    .line 44
    add-float/2addr v2, v1

    .line 45
    const/high16 v0, 0x3f800000    # 1.0f

    .line 46
    .line 47
    div-float/2addr v0, v2

    .line 48
    new-instance v1, Lcom/google/android/filament/utils/Quaternion;

    .line 49
    .line 50
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    neg-float v2, v2

    .line 55
    mul-float/2addr v2, v0

    .line 56
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    neg-float v3, v3

    .line 61
    mul-float/2addr v3, v0

    .line 62
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    neg-float v4, v4

    .line 67
    mul-float/2addr v4, v0

    .line 68
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    mul-float/2addr p0, v0

    .line 73
    invoke-direct {v1, v2, v3, v4, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 74
    .line 75
    .line 76
    return-object v1
.end method

.method public static final length(Lcom/google/android/filament/utils/Quaternion;)F
    .locals 3

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    mul-float/2addr v1, v0

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    mul-float/2addr v2, v0

    .line 24
    add-float/2addr v2, v1

    .line 25
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    mul-float/2addr v1, v0

    .line 34
    add-float/2addr v1, v2

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    mul-float/2addr p0, v0

    .line 44
    add-float/2addr p0, v1

    .line 45
    float-to-double v0, p0

    .line 46
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    double-to-float p0, v0

    .line 51
    return p0
.end method

.method public static final length2(Lcom/google/android/filament/utils/Quaternion;)F
    .locals 3

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    mul-float/2addr v1, v0

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    mul-float/2addr v2, v0

    .line 24
    add-float/2addr v2, v1

    .line 25
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    mul-float/2addr v1, v0

    .line 34
    add-float/2addr v1, v2

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    mul-float/2addr p0, v0

    .line 44
    add-float/2addr p0, v1

    .line 45
    return p0
.end method

.method public static final lerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/high16 v0, 0x3f800000    # 1.0f

    .line 12
    .line 13
    sub-float/2addr v0, p2

    .line 14
    new-instance v1, Lcom/google/android/filament/utils/Quaternion;

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    mul-float/2addr v2, v0

    .line 21
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    mul-float/2addr v3, v0

    .line 26
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    mul-float/2addr v4, v0

    .line 31
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    mul-float/2addr p0, v0

    .line 36
    invoke-direct {v1, v2, v3, v4, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 37
    .line 38
    .line 39
    new-instance p0, Lcom/google/android/filament/utils/Quaternion;

    .line 40
    .line 41
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    mul-float/2addr v0, p2

    .line 46
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    mul-float/2addr v2, p2

    .line 51
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    mul-float/2addr v3, p2

    .line 56
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    mul-float/2addr p1, p2

    .line 61
    invoke-direct {p0, v0, v2, v3, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 62
    .line 63
    .line 64
    new-instance p1, Lcom/google/android/filament/utils/Quaternion;

    .line 65
    .line 66
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    add-float/2addr v0, p2

    .line 75
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 76
    .line 77
    .line 78
    move-result p2

    .line 79
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    add-float/2addr v2, p2

    .line 84
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    add-float/2addr v3, p2

    .line 93
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 94
    .line 95
    .line 96
    move-result p2

    .line 97
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 98
    .line 99
    .line 100
    move-result p0

    .line 101
    add-float/2addr p0, p2

    .line 102
    invoke-direct {p1, v0, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 103
    .line 104
    .line 105
    return-object p1
.end method

.method public static final lessThan(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 3
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 4
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 5
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    move v2, v3

    .line 6
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lessThan(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 9
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 10
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    move v2, v3

    .line 12
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lessThanEqual(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gtz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 3
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-gtz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 4
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-gtz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 5
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-gtz p0, :cond_3

    move v2, v3

    .line 6
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lessThanEqual(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gtz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    .line 9
    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-gtz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    .line 10
    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-gtz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    .line 11
    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-gtz p0, :cond_3

    move v2, v3

    .line 12
    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lt(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lt(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-gez p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lte(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gtz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-gtz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-gtz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-gtz p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final lte(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gtz v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-gtz v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-gtz v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-gtz p0, :cond_3

    move v2, v3

    :cond_3
    invoke-direct {v0, v1, v4, v5, v2}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final minus(FLcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    sub-float v1, p0, v1

    .line 13
    .line 14
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    sub-float v2, p0, v2

    .line 19
    .line 20
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    sub-float v3, p0, v3

    .line 25
    .line 26
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    sub-float/2addr p0, p1

    .line 31
    invoke-direct {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 32
    .line 33
    .line 34
    return-object v0
.end method

.method public static final neq(Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    cmpg-float v1, v1, p1

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-nez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    xor-int/2addr v1, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    cmpg-float v4, v4, p1

    if-nez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    xor-int/2addr v4, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    cmpg-float v5, v5, p1

    if-nez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    xor-int/2addr v5, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    cmpg-float p0, p0, p1

    if-nez p0, :cond_3

    move v2, v3

    :cond_3
    xor-int/lit8 p0, v2, 0x1

    invoke-direct {v0, v1, v4, v5, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final neq(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Float4;)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getX()F

    move-result v2

    cmpg-float v1, v1, v2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-nez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    xor-int/2addr v1, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getY()F

    move-result v5

    cmpg-float v4, v4, v5

    if-nez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    xor-int/2addr v4, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getZ()F

    move-result v6

    cmpg-float v5, v5, v6

    if-nez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    xor-int/2addr v5, v3

    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Float4;->getW()F

    move-result p1

    cmpg-float p0, p0, p1

    if-nez p0, :cond_3

    move v2, v3

    :cond_3
    xor-int/lit8 p0, v2, 0x1

    invoke-direct {v0, v1, v4, v5, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final nlerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Quaternion;
    .locals 1

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/QuaternionKt;->lerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Quaternion;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lcom/google/android/filament/utils/QuaternionKt;->normalize(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static final normalize(Lcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 5

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    mul-float/2addr v1, v0

    .line 15
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    mul-float/2addr v2, v0

    .line 24
    add-float/2addr v2, v1

    .line 25
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    mul-float/2addr v1, v0

    .line 34
    add-float/2addr v1, v2

    .line 35
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    mul-float/2addr v2, v0

    .line 44
    add-float/2addr v2, v1

    .line 45
    float-to-double v0, v2

    .line 46
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    double-to-float v0, v0

    .line 51
    const/high16 v1, 0x3f800000    # 1.0f

    .line 52
    .line 53
    div-float/2addr v1, v0

    .line 54
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 55
    .line 56
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    mul-float/2addr v2, v1

    .line 61
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    mul-float/2addr v3, v1

    .line 66
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    mul-float/2addr v4, v1

    .line 71
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    mul-float/2addr p0, v1

    .line 76
    invoke-direct {v0, v2, v3, v4, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 77
    .line 78
    .line 79
    return-object v0
.end method

.method public static final notEqual(Lcom/google/android/filament/utils/Quaternion;FF)Lcom/google/android/filament/utils/Bool4;
    .locals 6

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    sub-float/2addr v1, p1

    .line 3
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    xor-int/2addr v1, v3

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    sub-float/2addr v4, p1

    .line 5
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    xor-int/2addr v4, v3

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    sub-float/2addr v5, p1

    .line 7
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    xor-int/2addr v5, v3

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 9
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    :cond_3
    xor-int/lit8 p0, v2, 0x1

    .line 10
    invoke-direct {v0, v1, v4, v5, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static final notEqual(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Bool4;
    .locals 7

    const-string v0, "a"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "b"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    new-instance v0, Lcom/google/android/filament/utils/Bool4;

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v1

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v2

    sub-float/2addr v1, v2

    .line 13
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    cmpg-float v1, v1, p2

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-gez v1, :cond_0

    move v1, v3

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    xor-int/2addr v1, v3

    .line 14
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v5

    sub-float/2addr v4, v5

    .line 15
    invoke-static {v4}, Ljava/lang/Math;->abs(F)F

    move-result v4

    cmpg-float v4, v4, p2

    if-gez v4, :cond_1

    move v4, v3

    goto :goto_1

    :cond_1
    move v4, v2

    :goto_1
    xor-int/2addr v4, v3

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v5

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v6

    sub-float/2addr v5, v6

    .line 17
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    cmpg-float v5, v5, p2

    if-gez v5, :cond_2

    move v5, v3

    goto :goto_2

    :cond_2
    move v5, v2

    :goto_2
    xor-int/2addr v5, v3

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    sub-float/2addr p0, p1

    .line 19
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_3

    move v2, v3

    :cond_3
    xor-int/lit8 p0, v2, 0x1

    .line 20
    invoke-direct {v0, v1, v4, v5, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object v0
.end method

.method public static synthetic notEqual$default(Lcom/google/android/filament/utils/Quaternion;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 4

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 1
    :cond_0
    const-string p3, "a"

    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    sub-float/2addr p4, p1

    .line 3
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    :goto_0
    xor-int/2addr p4, v1

    .line 4
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    sub-float/2addr v2, p1

    .line 5
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    :goto_1
    xor-int/2addr v2, v1

    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    sub-float/2addr v3, p1

    .line 7
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    :goto_2
    xor-int/2addr v3, v1

    .line 8
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    sub-float/2addr p0, p1

    .line 9
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    :cond_4
    xor-int/lit8 p0, v0, 0x1

    .line 10
    invoke-direct {p3, p4, v2, v3, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method

.method public static synthetic notEqual$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;FILjava/lang/Object;)Lcom/google/android/filament/utils/Bool4;
    .locals 5

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 11
    :cond_0
    const-string p3, "a"

    invoke-static {p0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "b"

    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p3, Lcom/google/android/filament/utils/Bool4;

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result p4

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    move-result v0

    sub-float/2addr p4, v0

    .line 13
    invoke-static {p4}, Ljava/lang/Math;->abs(F)F

    move-result p4

    cmpg-float p4, p4, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-gez p4, :cond_1

    move p4, v1

    goto :goto_0

    :cond_1
    move p4, v0

    :goto_0
    xor-int/2addr p4, v1

    .line 14
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v2

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    move-result v3

    sub-float/2addr v2, v3

    .line 15
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    cmpg-float v2, v2, p2

    if-gez v2, :cond_2

    move v2, v1

    goto :goto_1

    :cond_2
    move v2, v0

    :goto_1
    xor-int/2addr v2, v1

    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v3

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    move-result v4

    sub-float/2addr v3, v4

    .line 17
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    cmpg-float v3, v3, p2

    if-gez v3, :cond_3

    move v3, v1

    goto :goto_2

    :cond_3
    move v3, v0

    :goto_2
    xor-int/2addr v3, v1

    .line 18
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p0

    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    move-result p1

    sub-float/2addr p0, p1

    .line 19
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    move-result p0

    cmpg-float p0, p0, p2

    if-gez p0, :cond_4

    move v0, v1

    :cond_4
    xor-int/lit8 p0, v0, 0x1

    .line 20
    invoke-direct {p3, p4, v2, v3, p0}, Lcom/google/android/filament/utils/Bool4;-><init>(ZZZZ)V

    return-object p3
.end method

.method public static final plus(FLcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    add-float/2addr v1, p0

    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    add-float/2addr v2, p0

    .line 18
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    add-float/2addr v3, p0

    .line 23
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    add-float/2addr p1, p0

    .line 28
    invoke-direct {v0, v1, v2, v3, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method

.method public static final slerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;FF)Lcom/google/android/filament/utils/Quaternion;
    .locals 6

    .line 1
    const-string v0, "a"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "b"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    mul-float/2addr v1, v0

    .line 20
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    mul-float/2addr v2, v0

    .line 29
    add-float/2addr v2, v1

    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    mul-float/2addr v1, v0

    .line 39
    add-float/2addr v1, v2

    .line 40
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    mul-float/2addr v2, v0

    .line 49
    add-float/2addr v2, v1

    .line 50
    const/4 v0, 0x0

    .line 51
    cmpg-float v0, v2, v0

    .line 52
    .line 53
    if-gez v0, :cond_0

    .line 54
    .line 55
    neg-float v2, v2

    .line 56
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->unaryMinus()Lcom/google/android/filament/utils/Quaternion;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    :cond_0
    cmpg-float p3, v2, p3

    .line 61
    .line 62
    if-gez p3, :cond_1

    .line 63
    .line 64
    float-to-double v0, v2

    .line 65
    invoke-static {v0, v1}, Ljava/lang/Math;->acos(D)D

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    double-to-float p3, v0

    .line 70
    float-to-double v0, p3

    .line 71
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 72
    .line 73
    .line 74
    move-result-wide v0

    .line 75
    double-to-float v0, v0

    .line 76
    const/high16 v1, 0x3f800000    # 1.0f

    .line 77
    .line 78
    sub-float/2addr v1, p2

    .line 79
    mul-float/2addr v1, p3

    .line 80
    float-to-double v1, v1

    .line 81
    invoke-static {v1, v2}, Ljava/lang/Math;->sin(D)D

    .line 82
    .line 83
    .line 84
    move-result-wide v1

    .line 85
    double-to-float v1, v1

    .line 86
    new-instance v2, Lcom/google/android/filament/utils/Quaternion;

    .line 87
    .line 88
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    mul-float/2addr v3, v1

    .line 93
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 94
    .line 95
    .line 96
    move-result v4

    .line 97
    mul-float/2addr v4, v1

    .line 98
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    mul-float/2addr v5, v1

    .line 103
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    mul-float/2addr p0, v1

    .line 108
    invoke-direct {v2, v3, v4, v5, p0}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 109
    .line 110
    .line 111
    new-instance p0, Lcom/google/android/filament/utils/Quaternion;

    .line 112
    .line 113
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    div-float/2addr v1, v0

    .line 118
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    div-float/2addr v3, v0

    .line 123
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 124
    .line 125
    .line 126
    move-result v4

    .line 127
    div-float/2addr v4, v0

    .line 128
    invoke-virtual {v2}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    div-float/2addr v2, v0

    .line 133
    invoke-direct {p0, v1, v3, v4, v2}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 134
    .line 135
    .line 136
    mul-float/2addr p2, p3

    .line 137
    float-to-double p2, p2

    .line 138
    invoke-static {p2, p3}, Ljava/lang/Math;->sin(D)D

    .line 139
    .line 140
    .line 141
    move-result-wide p2

    .line 142
    double-to-float p2, p2

    .line 143
    new-instance p3, Lcom/google/android/filament/utils/Quaternion;

    .line 144
    .line 145
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    mul-float/2addr v1, p2

    .line 150
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    mul-float/2addr v2, p2

    .line 155
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    mul-float/2addr v3, p2

    .line 160
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 161
    .line 162
    .line 163
    move-result p1

    .line 164
    mul-float/2addr p1, p2

    .line 165
    invoke-direct {p3, v1, v2, v3, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 166
    .line 167
    .line 168
    new-instance p1, Lcom/google/android/filament/utils/Quaternion;

    .line 169
    .line 170
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 171
    .line 172
    .line 173
    move-result p2

    .line 174
    div-float/2addr p2, v0

    .line 175
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    div-float/2addr v1, v0

    .line 180
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    div-float/2addr v2, v0

    .line 185
    invoke-virtual {p3}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 186
    .line 187
    .line 188
    move-result p3

    .line 189
    div-float/2addr p3, v0

    .line 190
    invoke-direct {p1, p2, v1, v2, p3}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 191
    .line 192
    .line 193
    new-instance p2, Lcom/google/android/filament/utils/Quaternion;

    .line 194
    .line 195
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 196
    .line 197
    .line 198
    move-result p3

    .line 199
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 200
    .line 201
    .line 202
    move-result v0

    .line 203
    add-float/2addr v0, p3

    .line 204
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 205
    .line 206
    .line 207
    move-result p3

    .line 208
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 209
    .line 210
    .line 211
    move-result v1

    .line 212
    add-float/2addr v1, p3

    .line 213
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 214
    .line 215
    .line 216
    move-result p3

    .line 217
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 218
    .line 219
    .line 220
    move-result v2

    .line 221
    add-float/2addr v2, p3

    .line 222
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 223
    .line 224
    .line 225
    move-result p0

    .line 226
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 227
    .line 228
    .line 229
    move-result p1

    .line 230
    add-float/2addr p1, p0

    .line 231
    invoke-direct {p2, v0, v1, v2, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 232
    .line 233
    .line 234
    return-object p2

    .line 235
    :cond_1
    invoke-static {p0, p1, p2}, Lcom/google/android/filament/utils/QuaternionKt;->nlerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;F)Lcom/google/android/filament/utils/Quaternion;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    return-object p0
.end method

.method public static synthetic slerp$default(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;FFILjava/lang/Object;)Lcom/google/android/filament/utils/Quaternion;
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x8

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    const p3, 0x3f7fdf3b    # 0.9995f

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/utils/QuaternionKt;->slerp(Lcom/google/android/filament/utils/Quaternion;Lcom/google/android/filament/utils/Quaternion;FF)Lcom/google/android/filament/utils/Quaternion;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public static final times(FLcom/google/android/filament/utils/Quaternion;)Lcom/google/android/filament/utils/Quaternion;
    .locals 4

    .line 1
    const-string v0, "q"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/google/android/filament/utils/Quaternion;

    .line 7
    .line 8
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getX()F

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    mul-float/2addr v1, p0

    .line 13
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getY()F

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    mul-float/2addr v2, p0

    .line 18
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getZ()F

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    mul-float/2addr v3, p0

    .line 23
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Quaternion;->getW()F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    mul-float/2addr p1, p0

    .line 28
    invoke-direct {v0, v1, v2, v3, p1}, Lcom/google/android/filament/utils/Quaternion;-><init>(FFFF)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method
