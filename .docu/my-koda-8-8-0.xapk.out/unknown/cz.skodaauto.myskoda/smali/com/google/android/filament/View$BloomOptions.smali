.class public Lcom/google/android/filament/View$BloomOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "BloomOptions"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/View$BloomOptions$BlendMode;
    }
.end annotation


# instance fields
.field public blendMode:Lcom/google/android/filament/View$BloomOptions$BlendMode;

.field public chromaticAberration:F

.field public dirt:Lcom/google/android/filament/Texture;

.field public dirtStrength:F

.field public enabled:Z

.field public ghostCount:I

.field public ghostSpacing:F

.field public ghostThreshold:F

.field public haloRadius:F

.field public haloThickness:F

.field public haloThreshold:F

.field public highlight:F

.field public lensFlare:Z

.field public levels:I

.field public quality:Lcom/google/android/filament/View$QualityLevel;

.field public resolution:I

.field public starburst:Z

.field public strength:F

.field public threshold:Z


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lcom/google/android/filament/View$BloomOptions;->dirt:Lcom/google/android/filament/Texture;

    .line 6
    .line 7
    const v0, 0x3e4ccccd    # 0.2f

    .line 8
    .line 9
    .line 10
    iput v0, p0, Lcom/google/android/filament/View$BloomOptions;->dirtStrength:F

    .line 11
    .line 12
    const v0, 0x3dcccccd    # 0.1f

    .line 13
    .line 14
    .line 15
    iput v0, p0, Lcom/google/android/filament/View$BloomOptions;->strength:F

    .line 16
    .line 17
    const/16 v1, 0x180

    .line 18
    .line 19
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->resolution:I

    .line 20
    .line 21
    const/4 v1, 0x6

    .line 22
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->levels:I

    .line 23
    .line 24
    sget-object v1, Lcom/google/android/filament/View$BloomOptions$BlendMode;->ADD:Lcom/google/android/filament/View$BloomOptions$BlendMode;

    .line 25
    .line 26
    iput-object v1, p0, Lcom/google/android/filament/View$BloomOptions;->blendMode:Lcom/google/android/filament/View$BloomOptions$BlendMode;

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    iput-boolean v1, p0, Lcom/google/android/filament/View$BloomOptions;->threshold:Z

    .line 30
    .line 31
    const/4 v2, 0x0

    .line 32
    iput-boolean v2, p0, Lcom/google/android/filament/View$BloomOptions;->enabled:Z

    .line 33
    .line 34
    const/high16 v3, 0x447a0000    # 1000.0f

    .line 35
    .line 36
    iput v3, p0, Lcom/google/android/filament/View$BloomOptions;->highlight:F

    .line 37
    .line 38
    sget-object v3, Lcom/google/android/filament/View$QualityLevel;->LOW:Lcom/google/android/filament/View$QualityLevel;

    .line 39
    .line 40
    iput-object v3, p0, Lcom/google/android/filament/View$BloomOptions;->quality:Lcom/google/android/filament/View$QualityLevel;

    .line 41
    .line 42
    iput-boolean v2, p0, Lcom/google/android/filament/View$BloomOptions;->lensFlare:Z

    .line 43
    .line 44
    iput-boolean v1, p0, Lcom/google/android/filament/View$BloomOptions;->starburst:Z

    .line 45
    .line 46
    const v1, 0x3ba3d70a    # 0.005f

    .line 47
    .line 48
    .line 49
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->chromaticAberration:F

    .line 50
    .line 51
    const/4 v1, 0x4

    .line 52
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->ghostCount:I

    .line 53
    .line 54
    const v1, 0x3f19999a    # 0.6f

    .line 55
    .line 56
    .line 57
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->ghostSpacing:F

    .line 58
    .line 59
    const/high16 v1, 0x41200000    # 10.0f

    .line 60
    .line 61
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->ghostThreshold:F

    .line 62
    .line 63
    iput v0, p0, Lcom/google/android/filament/View$BloomOptions;->haloThickness:F

    .line 64
    .line 65
    const v0, 0x3ecccccd    # 0.4f

    .line 66
    .line 67
    .line 68
    iput v0, p0, Lcom/google/android/filament/View$BloomOptions;->haloRadius:F

    .line 69
    .line 70
    iput v1, p0, Lcom/google/android/filament/View$BloomOptions;->haloThreshold:F

    .line 71
    .line 72
    return-void
.end method
