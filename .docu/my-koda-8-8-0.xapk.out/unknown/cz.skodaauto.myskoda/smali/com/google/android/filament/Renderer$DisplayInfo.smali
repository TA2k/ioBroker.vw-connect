.class public Lcom/google/android/filament/Renderer$DisplayInfo;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Renderer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "DisplayInfo"
.end annotation


# instance fields
.field public presentationDeadlineNanos:J
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end field

.field public refreshRate:F

.field public vsyncOffsetNanos:J
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x42700000    # 60.0f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/Renderer$DisplayInfo;->refreshRate:F

    .line 7
    .line 8
    const-wide/16 v0, 0x0

    .line 9
    .line 10
    iput-wide v0, p0, Lcom/google/android/filament/Renderer$DisplayInfo;->presentationDeadlineNanos:J

    .line 11
    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/Renderer$DisplayInfo;->vsyncOffsetNanos:J

    .line 13
    .line 14
    return-void
.end method
