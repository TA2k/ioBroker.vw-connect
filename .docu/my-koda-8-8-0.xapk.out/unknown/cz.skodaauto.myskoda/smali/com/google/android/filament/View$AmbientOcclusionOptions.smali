.class public Lcom/google/android/filament/View$AmbientOcclusionOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "AmbientOcclusionOptions"
.end annotation


# instance fields
.field public bentNormals:Z

.field public bias:F

.field public bilateralThreshold:F

.field public enabled:Z

.field public intensity:F

.field public lowPassFilter:Lcom/google/android/filament/View$QualityLevel;

.field public minHorizonAngleRad:F

.field public power:F

.field public quality:Lcom/google/android/filament/View$QualityLevel;

.field public radius:F

.field public resolution:F

.field public ssctContactDistanceMax:F

.field public ssctDepthBias:F

.field public ssctDepthSlopeBias:F

.field public ssctEnabled:Z

.field public ssctIntensity:F

.field public ssctLightConeRad:F

.field public ssctLightDirection:[F

.field public ssctRayCount:I

.field public ssctSampleCount:I

.field public ssctShadowDistance:F

.field public upsampling:Lcom/google/android/filament/View$QualityLevel;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const v0, 0x3e99999a    # 0.3f

    .line 5
    .line 6
    .line 7
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->radius:F

    .line 8
    .line 9
    const/high16 v1, 0x3f800000    # 1.0f

    .line 10
    .line 11
    iput v1, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->power:F

    .line 12
    .line 13
    const v2, 0x3a03126f    # 5.0E-4f

    .line 14
    .line 15
    .line 16
    iput v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bias:F

    .line 17
    .line 18
    const/high16 v2, 0x3f000000    # 0.5f

    .line 19
    .line 20
    iput v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->resolution:F

    .line 21
    .line 22
    iput v1, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->intensity:F

    .line 23
    .line 24
    const v2, 0x3d4ccccd    # 0.05f

    .line 25
    .line 26
    .line 27
    iput v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bilateralThreshold:F

    .line 28
    .line 29
    sget-object v2, Lcom/google/android/filament/View$QualityLevel;->LOW:Lcom/google/android/filament/View$QualityLevel;

    .line 30
    .line 31
    iput-object v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->quality:Lcom/google/android/filament/View$QualityLevel;

    .line 32
    .line 33
    sget-object v3, Lcom/google/android/filament/View$QualityLevel;->MEDIUM:Lcom/google/android/filament/View$QualityLevel;

    .line 34
    .line 35
    iput-object v3, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->lowPassFilter:Lcom/google/android/filament/View$QualityLevel;

    .line 36
    .line 37
    iput-object v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->upsampling:Lcom/google/android/filament/View$QualityLevel;

    .line 38
    .line 39
    const/4 v2, 0x0

    .line 40
    iput-boolean v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->enabled:Z

    .line 41
    .line 42
    iput-boolean v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->bentNormals:Z

    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    iput v3, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->minHorizonAngleRad:F

    .line 46
    .line 47
    iput v1, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctLightConeRad:F

    .line 48
    .line 49
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctShadowDistance:F

    .line 50
    .line 51
    iput v1, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctContactDistanceMax:F

    .line 52
    .line 53
    const v0, 0x3f4ccccd    # 0.8f

    .line 54
    .line 55
    .line 56
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctIntensity:F

    .line 57
    .line 58
    const/4 v0, 0x3

    .line 59
    new-array v0, v0, [F

    .line 60
    .line 61
    fill-array-data v0, :array_0

    .line 62
    .line 63
    .line 64
    iput-object v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctLightDirection:[F

    .line 65
    .line 66
    const v0, 0x3c23d70a    # 0.01f

    .line 67
    .line 68
    .line 69
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctDepthBias:F

    .line 70
    .line 71
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctDepthSlopeBias:F

    .line 72
    .line 73
    const/4 v0, 0x4

    .line 74
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctSampleCount:I

    .line 75
    .line 76
    const/4 v0, 0x1

    .line 77
    iput v0, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctRayCount:I

    .line 78
    .line 79
    iput-boolean v2, p0, Lcom/google/android/filament/View$AmbientOcclusionOptions;->ssctEnabled:Z

    .line 80
    .line 81
    return-void

    .line 82
    nop

    .line 83
    :array_0
    .array-data 4
        0x0
        -0x40800000    # -1.0f
        0x0
    .end array-data
.end method
