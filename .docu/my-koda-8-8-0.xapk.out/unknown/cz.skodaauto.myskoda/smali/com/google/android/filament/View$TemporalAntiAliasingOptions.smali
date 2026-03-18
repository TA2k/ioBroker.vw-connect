.class public Lcom/google/android/filament/View$TemporalAntiAliasingOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "TemporalAntiAliasingOptions"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxType;,
        Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxClipping;,
        Lcom/google/android/filament/View$TemporalAntiAliasingOptions$JitterPattern;
    }
.end annotation


# instance fields
.field public boxClipping:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxClipping;

.field public boxType:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxType;

.field public enabled:Z

.field public feedback:F

.field public filterHistory:Z

.field public filterInput:Z

.field public filterWidth:F

.field public historyReprojection:Z

.field public jitterPattern:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$JitterPattern;

.field public lodBias:F

.field public preventFlickering:Z

.field public sharpness:F

.field public upscaling:Z

.field public useYCoCg:Z

.field public varianceGamma:F


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->filterWidth:F

    .line 7
    .line 8
    const v1, 0x3df5c28f    # 0.12f

    .line 9
    .line 10
    .line 11
    iput v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->feedback:F

    .line 12
    .line 13
    const/high16 v1, -0x40800000    # -1.0f

    .line 14
    .line 15
    iput v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->lodBias:F

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    iput v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->sharpness:F

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    iput-boolean v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->enabled:Z

    .line 22
    .line 23
    iput-boolean v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->upscaling:Z

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    iput-boolean v2, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->filterHistory:Z

    .line 27
    .line 28
    iput-boolean v2, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->filterInput:Z

    .line 29
    .line 30
    iput-boolean v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->useYCoCg:Z

    .line 31
    .line 32
    sget-object v3, Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxType;->AABB:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxType;

    .line 33
    .line 34
    iput-object v3, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->boxType:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxType;

    .line 35
    .line 36
    sget-object v3, Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxClipping;->ACCURATE:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxClipping;

    .line 37
    .line 38
    iput-object v3, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->boxClipping:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$BoxClipping;

    .line 39
    .line 40
    sget-object v3, Lcom/google/android/filament/View$TemporalAntiAliasingOptions$JitterPattern;->HALTON_23_X16:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$JitterPattern;

    .line 41
    .line 42
    iput-object v3, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->jitterPattern:Lcom/google/android/filament/View$TemporalAntiAliasingOptions$JitterPattern;

    .line 43
    .line 44
    iput v0, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->varianceGamma:F

    .line 45
    .line 46
    iput-boolean v1, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->preventFlickering:Z

    .line 47
    .line 48
    iput-boolean v2, p0, Lcom/google/android/filament/View$TemporalAntiAliasingOptions;->historyReprojection:Z

    .line 49
    .line 50
    return-void
.end method
