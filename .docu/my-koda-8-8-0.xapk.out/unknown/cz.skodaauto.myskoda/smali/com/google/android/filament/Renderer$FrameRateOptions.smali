.class public Lcom/google/android/filament/Renderer$FrameRateOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Renderer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "FrameRateOptions"
.end annotation


# instance fields
.field public headRoomRatio:F

.field public history:I

.field public interval:F

.field public scaleRate:F


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/Renderer$FrameRateOptions;->interval:F

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput v0, p0, Lcom/google/android/filament/Renderer$FrameRateOptions;->headRoomRatio:F

    .line 10
    .line 11
    const v0, 0x3d888889

    .line 12
    .line 13
    .line 14
    iput v0, p0, Lcom/google/android/filament/Renderer$FrameRateOptions;->scaleRate:F

    .line 15
    .line 16
    const/16 v0, 0xf

    .line 17
    .line 18
    iput v0, p0, Lcom/google/android/filament/Renderer$FrameRateOptions;->history:I

    .line 19
    .line 20
    return-void
.end method
