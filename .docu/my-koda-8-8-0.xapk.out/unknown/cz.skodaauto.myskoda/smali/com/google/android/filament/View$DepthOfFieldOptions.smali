.class public Lcom/google/android/filament/View$DepthOfFieldOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "DepthOfFieldOptions"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;
    }
.end annotation


# instance fields
.field public backgroundRingCount:I

.field public cocAspectRatio:F

.field public cocScale:F

.field public enabled:Z

.field public fastGatherRingCount:I

.field public filter:Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;

.field public foregroundRingCount:I

.field public maxApertureDiameter:F

.field public maxBackgroundCOC:I

.field public maxForegroundCOC:I

.field public nativeResolution:Z


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->cocScale:F

    .line 7
    .line 8
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->cocAspectRatio:F

    .line 9
    .line 10
    const v0, 0x3c23d70a    # 0.01f

    .line 11
    .line 12
    .line 13
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxApertureDiameter:F

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iput-boolean v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->enabled:Z

    .line 17
    .line 18
    sget-object v1, Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;->MEDIAN:Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;

    .line 19
    .line 20
    iput-object v1, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->filter:Lcom/google/android/filament/View$DepthOfFieldOptions$Filter;

    .line 21
    .line 22
    iput-boolean v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->nativeResolution:Z

    .line 23
    .line 24
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->foregroundRingCount:I

    .line 25
    .line 26
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->backgroundRingCount:I

    .line 27
    .line 28
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->fastGatherRingCount:I

    .line 29
    .line 30
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxForegroundCOC:I

    .line 31
    .line 32
    iput v0, p0, Lcom/google/android/filament/View$DepthOfFieldOptions;->maxBackgroundCOC:I

    .line 33
    .line 34
    return-void
.end method
