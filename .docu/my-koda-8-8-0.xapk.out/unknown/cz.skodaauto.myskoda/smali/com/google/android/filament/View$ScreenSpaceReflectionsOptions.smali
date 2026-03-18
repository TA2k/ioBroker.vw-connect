.class public Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ScreenSpaceReflectionsOptions"
.end annotation


# instance fields
.field public bias:F

.field public enabled:Z

.field public maxDistance:F

.field public stride:F

.field public thickness:F


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const v0, 0x3dcccccd    # 0.1f

    .line 5
    .line 6
    .line 7
    iput v0, p0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->thickness:F

    .line 8
    .line 9
    const v0, 0x3c23d70a    # 0.01f

    .line 10
    .line 11
    .line 12
    iput v0, p0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->bias:F

    .line 13
    .line 14
    const/high16 v0, 0x40400000    # 3.0f

    .line 15
    .line 16
    iput v0, p0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->maxDistance:F

    .line 17
    .line 18
    const/high16 v0, 0x40000000    # 2.0f

    .line 19
    .line 20
    iput v0, p0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->stride:F

    .line 21
    .line 22
    const/4 v0, 0x0

    .line 23
    iput-boolean v0, p0, Lcom/google/android/filament/View$ScreenSpaceReflectionsOptions;->enabled:Z

    .line 24
    .line 25
    return-void
.end method
