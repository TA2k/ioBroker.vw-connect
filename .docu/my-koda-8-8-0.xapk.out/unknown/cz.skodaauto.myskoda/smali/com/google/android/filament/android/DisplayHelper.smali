.class public Lcom/google/android/filament/android/DisplayHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mDisplay:Landroid/view/Display;

.field private mDisplayManager:Landroid/hardware/display/DisplayManager;

.field private mHandler:Landroid/os/Handler;

.field private mListener:Landroid/hardware/display/DisplayManager$DisplayListener;

.field private mRenderer:Lcom/google/android/filament/Renderer;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mHandler:Landroid/os/Handler;

    .line 3
    const-string v0, "display"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/hardware/display/DisplayManager;

    iput-object p1, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplayManager:Landroid/hardware/display/DisplayManager;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Handler;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/DisplayHelper;-><init>(Landroid/content/Context;)V

    .line 5
    iput-object p2, p0, Lcom/google/android/filament/android/DisplayHelper;->mHandler:Landroid/os/Handler;

    return-void
.end method

.method public static bridge synthetic a(Lcom/google/android/filament/android/DisplayHelper;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/android/DisplayHelper;->updateDisplayInfo()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getAppVsyncOffsetNanos(Landroid/view/Display;)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/Display;->getAppVsyncOffsetNanos()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static getDisplayInfo(Landroid/view/Display;Lcom/google/android/filament/Renderer$DisplayInfo;)Lcom/google/android/filament/Renderer$DisplayInfo;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    new-instance p1, Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 4
    .line 5
    invoke-direct {p1}, Lcom/google/android/filament/Renderer$DisplayInfo;-><init>()V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-static {p0}, Lcom/google/android/filament/android/DisplayHelper;->getRefreshRate(Landroid/view/Display;)F

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    iput p0, p1, Lcom/google/android/filament/Renderer$DisplayInfo;->refreshRate:F

    .line 13
    .line 14
    return-object p1
.end method

.method public static getPresentationDeadlineNanos(Landroid/view/Display;)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/Display;->getPresentationDeadlineNanos()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static getRefreshPeriodNanos(Landroid/view/Display;)J
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/Display;->getRefreshRate()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-double v0, p0

    .line 6
    const-wide v2, 0x41cdcd6500000000L    # 1.0E9

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    div-double/2addr v2, v0

    .line 12
    double-to-long v0, v2

    .line 13
    return-wide v0
.end method

.method public static getRefreshRate(Landroid/view/Display;)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Landroid/view/Display;->getRefreshRate()F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private updateDisplayInfo()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mRenderer:Lcom/google/android/filament/Renderer;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplay:Landroid/view/Display;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/google/android/filament/Renderer;->getDisplayInfo()Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {p0, v1}, Lcom/google/android/filament/android/DisplayHelper;->getDisplayInfo(Landroid/view/Display;Lcom/google/android/filament/Renderer$DisplayInfo;)Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {v0, p0}, Lcom/google/android/filament/Renderer;->setDisplayInfo(Lcom/google/android/filament/Renderer$DisplayInfo;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public attach(Lcom/google/android/filament/Renderer;Landroid/view/Display;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mRenderer:Lcom/google/android/filament/Renderer;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplay:Landroid/view/Display;

    .line 6
    .line 7
    if-ne p2, v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iput-object p1, p0, Lcom/google/android/filament/android/DisplayHelper;->mRenderer:Lcom/google/android/filament/Renderer;

    .line 11
    .line 12
    iput-object p2, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplay:Landroid/view/Display;

    .line 13
    .line 14
    new-instance p1, Lcom/google/android/filament/android/DisplayHelper$1;

    .line 15
    .line 16
    invoke-direct {p1, p0, p2}, Lcom/google/android/filament/android/DisplayHelper$1;-><init>(Lcom/google/android/filament/android/DisplayHelper;Landroid/view/Display;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/google/android/filament/android/DisplayHelper;->mListener:Landroid/hardware/display/DisplayManager$DisplayListener;

    .line 20
    .line 21
    iget-object p2, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplayManager:Landroid/hardware/display/DisplayManager;

    .line 22
    .line 23
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mHandler:Landroid/os/Handler;

    .line 24
    .line 25
    invoke-virtual {p2, p1, v0}, Landroid/hardware/display/DisplayManager;->registerDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;Landroid/os/Handler;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lcom/google/android/filament/android/DisplayHelper;->mHandler:Landroid/os/Handler;

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    new-instance p2, Lcom/google/android/filament/android/DisplayHelper$2;

    .line 33
    .line 34
    invoke-direct {p2, p0}, Lcom/google/android/filament/android/DisplayHelper$2;-><init>(Lcom/google/android/filament/android/DisplayHelper;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    invoke-direct {p0}, Lcom/google/android/filament/android/DisplayHelper;->updateDisplayInfo()V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public detach()V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mListener:Landroid/hardware/display/DisplayManager$DisplayListener;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplayManager:Landroid/hardware/display/DisplayManager;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Landroid/hardware/display/DisplayManager;->unregisterDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mListener:Landroid/hardware/display/DisplayManager$DisplayListener;

    .line 12
    .line 13
    iput-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplay:Landroid/view/Display;

    .line 14
    .line 15
    iput-object v0, p0, Lcom/google/android/filament/android/DisplayHelper;->mRenderer:Lcom/google/android/filament/Renderer;

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public finalize()V
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p0}, Lcom/google/android/filament/android/DisplayHelper;->detach()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2
    .line 3
    .line 4
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 5
    .line 6
    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception v0

    .line 9
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 10
    .line 11
    .line 12
    throw v0
.end method

.method public getDisplay()Landroid/view/Display;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/DisplayHelper;->mDisplay:Landroid/view/Display;

    .line 2
    .line 3
    return-object p0
.end method
