.class public Lcom/google/android/filament/View$VignetteOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "VignetteOptions"
.end annotation


# instance fields
.field public color:[F

.field public enabled:Z

.field public feather:F

.field public midPoint:F

.field public roundness:F


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
    iput v0, p0, Lcom/google/android/filament/View$VignetteOptions;->midPoint:F

    .line 7
    .line 8
    iput v0, p0, Lcom/google/android/filament/View$VignetteOptions;->roundness:F

    .line 9
    .line 10
    iput v0, p0, Lcom/google/android/filament/View$VignetteOptions;->feather:F

    .line 11
    .line 12
    const/4 v0, 0x4

    .line 13
    new-array v0, v0, [F

    .line 14
    .line 15
    fill-array-data v0, :array_0

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lcom/google/android/filament/View$VignetteOptions;->color:[F

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    iput-boolean v0, p0, Lcom/google/android/filament/View$VignetteOptions;->enabled:Z

    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :array_0
    .array-data 4
        0x0
        0x0
        0x0
        0x3f800000    # 1.0f
    .end array-data
.end method
