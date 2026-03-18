.class public Lcom/google/android/filament/LightManager$ShadowOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/LightManager;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ShadowOptions"
.end annotation


# instance fields
.field public blurWidth:F

.field public cascadeSplitPositions:[F

.field public constantBias:F

.field public elvsm:Z

.field public lispsm:Z

.field public mapSize:I

.field public maxShadowDistance:F

.field public normalBias:F

.field polygonOffsetConstant:F

.field polygonOffsetSlope:F

.field public screenSpaceContactShadows:Z

.field public shadowBulbRadius:F

.field public shadowCascades:I

.field public shadowFar:F

.field public shadowFarHint:F

.field public shadowNearHint:F

.field public stable:Z

.field public stepCount:I

.field public transform:[F


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x400

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->mapSize:I

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowCascades:I

    .line 10
    .line 11
    const/4 v0, 0x3

    .line 12
    new-array v0, v0, [F

    .line 13
    .line 14
    fill-array-data v0, :array_0

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->cascadeSplitPositions:[F

    .line 18
    .line 19
    const v0, 0x3a83126f    # 0.001f

    .line 20
    .line 21
    .line 22
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->constantBias:F

    .line 23
    .line 24
    const/high16 v0, 0x3f800000    # 1.0f

    .line 25
    .line 26
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->normalBias:F

    .line 27
    .line 28
    const/4 v1, 0x0

    .line 29
    iput v1, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowFar:F

    .line 30
    .line 31
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowNearHint:F

    .line 32
    .line 33
    const/high16 v0, 0x42c80000    # 100.0f

    .line 34
    .line 35
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowFarHint:F

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    iput-boolean v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->stable:Z

    .line 39
    .line 40
    iput-boolean v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->lispsm:Z

    .line 41
    .line 42
    const/high16 v2, 0x3f000000    # 0.5f

    .line 43
    .line 44
    iput v2, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->polygonOffsetConstant:F

    .line 45
    .line 46
    const/high16 v2, 0x40000000    # 2.0f

    .line 47
    .line 48
    iput v2, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->polygonOffsetSlope:F

    .line 49
    .line 50
    iput-boolean v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->screenSpaceContactShadows:Z

    .line 51
    .line 52
    const/16 v2, 0x8

    .line 53
    .line 54
    iput v2, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->stepCount:I

    .line 55
    .line 56
    const v2, 0x3e99999a    # 0.3f

    .line 57
    .line 58
    .line 59
    iput v2, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->maxShadowDistance:F

    .line 60
    .line 61
    iput-boolean v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->elvsm:Z

    .line 62
    .line 63
    iput v1, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->blurWidth:F

    .line 64
    .line 65
    const v0, 0x3ca3d70a    # 0.02f

    .line 66
    .line 67
    .line 68
    iput v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->shadowBulbRadius:F

    .line 69
    .line 70
    const/4 v0, 0x4

    .line 71
    new-array v0, v0, [F

    .line 72
    .line 73
    fill-array-data v0, :array_1

    .line 74
    .line 75
    .line 76
    iput-object v0, p0, Lcom/google/android/filament/LightManager$ShadowOptions;->transform:[F

    .line 77
    .line 78
    return-void

    .line 79
    :array_0
    .array-data 4
        0x3e000000    # 0.125f
        0x3e800000    # 0.25f
        0x3f000000    # 0.5f
    .end array-data

    .line 80
    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    :array_1
    .array-data 4
        0x0
        0x0
        0x0
        0x3f800000    # 1.0f
    .end array-data
.end method
