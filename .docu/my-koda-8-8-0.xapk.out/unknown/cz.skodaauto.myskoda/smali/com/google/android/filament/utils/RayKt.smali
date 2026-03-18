.class public final Lcom/google/android/filament/utils/RayKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0007\n\u0000\u001a\u0016\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005\u00a8\u0006\u0006"
    }
    d2 = {
        "pointAt",
        "Lcom/google/android/filament/utils/Float3;",
        "r",
        "Lcom/google/android/filament/utils/Ray;",
        "t",
        "",
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
.method public static final pointAt(Lcom/google/android/filament/utils/Ray;F)Lcom/google/android/filament/utils/Float3;
    .locals 4

    .line 1
    const-string v0, "r"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Ray;->getOrigin()Lcom/google/android/filament/utils/Float3;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Ray;->getDirection()Lcom/google/android/filament/utils/Float3;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v1, Lcom/google/android/filament/utils/Float3;

    .line 15
    .line 16
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    mul-float/2addr v2, p1

    .line 21
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    mul-float/2addr v3, p1

    .line 26
    invoke-virtual {p0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    mul-float/2addr p0, p1

    .line 31
    invoke-direct {v1, v2, v3, p0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 32
    .line 33
    .line 34
    new-instance p0, Lcom/google/android/filament/utils/Float3;

    .line 35
    .line 36
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getX()F

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    add-float/2addr v2, p1

    .line 45
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getY()F

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    add-float/2addr v3, p1

    .line 54
    invoke-virtual {v0}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    invoke-virtual {v1}, Lcom/google/android/filament/utils/Float3;->getZ()F

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    add-float/2addr v0, p1

    .line 63
    invoke-direct {p0, v2, v3, v0}, Lcom/google/android/filament/utils/Float3;-><init>(FFF)V

    .line 64
    .line 65
    .line 66
    return-object p0
.end method
