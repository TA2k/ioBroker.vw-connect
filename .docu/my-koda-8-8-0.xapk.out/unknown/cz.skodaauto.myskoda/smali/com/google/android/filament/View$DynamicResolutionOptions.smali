.class public Lcom/google/android/filament/View$DynamicResolutionOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "DynamicResolutionOptions"
.end annotation


# instance fields
.field public enabled:Z

.field public homogeneousScaling:Z

.field public maxScale:F

.field public minScale:F

.field public quality:Lcom/google/android/filament/View$QualityLevel;

.field public sharpness:F


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f000000    # 0.5f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->minScale:F

    .line 7
    .line 8
    const/high16 v0, 0x3f800000    # 1.0f

    .line 9
    .line 10
    iput v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->maxScale:F

    .line 11
    .line 12
    const v0, 0x3f666666    # 0.9f

    .line 13
    .line 14
    .line 15
    iput v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->sharpness:F

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->enabled:Z

    .line 19
    .line 20
    iput-boolean v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->homogeneousScaling:Z

    .line 21
    .line 22
    sget-object v0, Lcom/google/android/filament/View$QualityLevel;->LOW:Lcom/google/android/filament/View$QualityLevel;

    .line 23
    .line 24
    iput-object v0, p0, Lcom/google/android/filament/View$DynamicResolutionOptions;->quality:Lcom/google/android/filament/View$QualityLevel;

    .line 25
    .line 26
    return-void
.end method
