.class public Lcom/google/android/filament/View$VsmShadowOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "VsmShadowOptions"
.end annotation


# instance fields
.field public anisotropy:I

.field public highPrecision:Z

.field public lightBleedReduction:F

.field public minVarianceScale:F

.field public mipmapping:Z

.field public msaaSamples:I


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/filament/View$VsmShadowOptions;->anisotropy:I

    .line 6
    .line 7
    iput-boolean v0, p0, Lcom/google/android/filament/View$VsmShadowOptions;->mipmapping:Z

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    iput v1, p0, Lcom/google/android/filament/View$VsmShadowOptions;->msaaSamples:I

    .line 11
    .line 12
    iput-boolean v0, p0, Lcom/google/android/filament/View$VsmShadowOptions;->highPrecision:Z

    .line 13
    .line 14
    const/high16 v0, 0x3f000000    # 0.5f

    .line 15
    .line 16
    iput v0, p0, Lcom/google/android/filament/View$VsmShadowOptions;->minVarianceScale:F

    .line 17
    .line 18
    const v0, 0x3e19999a    # 0.15f

    .line 19
    .line 20
    .line 21
    iput v0, p0, Lcom/google/android/filament/View$VsmShadowOptions;->lightBleedReduction:F

    .line 22
    .line 23
    return-void
.end method
