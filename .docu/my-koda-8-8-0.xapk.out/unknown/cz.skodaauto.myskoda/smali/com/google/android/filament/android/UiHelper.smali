.class public Lcom/google/android/filament/android/UiHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;,
        Lcom/google/android/filament/android/UiHelper$RendererCallback;,
        Lcom/google/android/filament/android/UiHelper$RenderSurface;,
        Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;,
        Lcom/google/android/filament/android/UiHelper$TextureViewHandler;,
        Lcom/google/android/filament/android/UiHelper$SurfaceHolderHandler;
    }
.end annotation


# static fields
.field private static final LOGGING:Z = false

.field private static final LOG_TAG:Ljava/lang/String; = "UiHelper"


# instance fields
.field private mDesiredHeight:I

.field private mDesiredWidth:I

.field private mHasSwapChain:Z

.field private mNativeWindow:Ljava/lang/Object;

.field private mOpaque:Z

.field private mOverlay:Z

.field private mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

.field private mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;->CHECK:Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;

    invoke-direct {p0, v0}, Lcom/google/android/filament/android/UiHelper;-><init>(Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;)V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/filament/android/UiHelper$ContextErrorPolicy;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x1

    .line 3
    iput-boolean p1, p0, Lcom/google/android/filament/android/UiHelper;->mOpaque:Z

    const/4 p1, 0x0

    .line 4
    iput-boolean p1, p0, Lcom/google/android/filament/android/UiHelper;->mOverlay:Z

    return-void
.end method

.method public static bridge synthetic a(Lcom/google/android/filament/android/UiHelper;)I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredHeight:I

    .line 2
    .line 3
    return p0
.end method

.method private attach(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mNativeWindow:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    if-ne v0, p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-interface {v0}, Lcom/google/android/filament/android/UiHelper$RenderSurface;->detach()V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    .line 18
    .line 19
    :cond_1
    invoke-direct {p0}, Lcom/google/android/filament/android/UiHelper;->destroySwapChain()V

    .line 20
    .line 21
    .line 22
    :cond_2
    iput-object p1, p0, Lcom/google/android/filament/android/UiHelper;->mNativeWindow:Ljava/lang/Object;

    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0
.end method

.method public static bridge synthetic b(Lcom/google/android/filament/android/UiHelper;)I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public static bridge synthetic c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method private createSwapChain(Landroid/view/Surface;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0, p1}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onNativeWindowChanged(Landroid/view/Surface;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 p1, 0x1

    .line 9
    iput-boolean p1, p0, Lcom/google/android/filament/android/UiHelper;->mHasSwapChain:Z

    .line 10
    .line 11
    return-void
.end method

.method public static bridge synthetic d(Lcom/google/android/filament/android/UiHelper;Landroid/view/Surface;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/UiHelper;->createSwapChain(Landroid/view/Surface;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private destroySwapChain()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onDetachedFromSurface()V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    iput-boolean v0, p0, Lcom/google/android/filament/android/UiHelper;->mHasSwapChain:Z

    .line 10
    .line 11
    return-void
.end method

.method public static bridge synthetic e(Lcom/google/android/filament/android/UiHelper;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/android/UiHelper;->destroySwapChain()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public attachTo(Landroid/view/SurfaceHolder;)V
    .locals 1

    .line 11
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/UiHelper;->attach(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isOpaque()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, -0x1

    goto :goto_0

    :cond_0
    const/4 v0, -0x3

    :goto_0
    invoke-interface {p1, v0}, Landroid/view/SurfaceHolder;->setFormat(I)V

    .line 13
    new-instance v0, Lcom/google/android/filament/android/UiHelper$SurfaceHolderHandler;

    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/android/UiHelper$SurfaceHolderHandler;-><init>(Lcom/google/android/filament/android/UiHelper;Landroid/view/SurfaceHolder;)V

    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    :cond_1
    return-void
.end method

.method public attachTo(Landroid/view/SurfaceView;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/UiHelper;->attach(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    .line 2
    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isOpaque()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isMediaOverlay()Z

    move-result v1

    if-eqz v1, :cond_0

    .line 4
    invoke-virtual {p1, v0}, Landroid/view/SurfaceView;->setZOrderMediaOverlay(Z)V

    goto :goto_0

    .line 5
    :cond_0
    invoke-virtual {p1, v0}, Landroid/view/SurfaceView;->setZOrderOnTop(Z)V

    .line 6
    :goto_0
    invoke-virtual {p1}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    move-result-object v0

    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isOpaque()Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 v1, -0x1

    goto :goto_1

    :cond_1
    const/4 v1, -0x3

    :goto_1
    invoke-interface {v0, v1}, Landroid/view/SurfaceHolder;->setFormat(I)V

    .line 7
    new-instance v0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;

    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;-><init>(Lcom/google/android/filament/android/UiHelper;Landroid/view/SurfaceView;)V

    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    :cond_2
    return-void
.end method

.method public attachTo(Landroid/view/TextureView;)V
    .locals 1

    .line 8
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/UiHelper;->attach(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 9
    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isOpaque()Z

    move-result v0

    invoke-virtual {p1, v0}, Landroid/view/TextureView;->setOpaque(Z)V

    .line 10
    new-instance v0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;

    invoke-direct {v0, p0, p1}, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;-><init>(Lcom/google/android/filament/android/UiHelper;Landroid/view/TextureView;)V

    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    :cond_0
    return-void
.end method

.method public detach()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lcom/google/android/filament/android/UiHelper$RenderSurface;->detach()V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-direct {p0}, Lcom/google/android/filament/android/UiHelper;->destroySwapChain()V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mNativeWindow:Ljava/lang/Object;

    .line 13
    .line 14
    iput-object v0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    .line 15
    .line 16
    return-void
.end method

.method public getDesiredHeight()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredHeight:I

    .line 2
    .line 3
    return p0
.end method

.method public getDesiredWidth()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredWidth:I

    .line 2
    .line 3
    return p0
.end method

.method public getRenderCallback()Lcom/google/android/filament/android/UiHelper$RendererCallback;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSwapChainFlags()J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/android/UiHelper;->isOpaque()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const-wide/16 v0, 0x0

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    const-wide/16 v0, 0x1

    .line 11
    .line 12
    return-wide v0
.end method

.method public isMediaOverlay()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/filament/android/UiHelper;->mOverlay:Z

    .line 2
    .line 3
    return p0
.end method

.method public isOpaque()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/filament/android/UiHelper;->mOpaque:Z

    .line 2
    .line 3
    return p0
.end method

.method public isReadyToRender()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/google/android/filament/android/UiHelper;->mHasSwapChain:Z

    .line 2
    .line 3
    return p0
.end method

.method public setDesiredSize(II)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredWidth:I

    .line 2
    .line 3
    iput p2, p0, Lcom/google/android/filament/android/UiHelper;->mDesiredHeight:I

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper;->mRenderSurface:Lcom/google/android/filament/android/UiHelper$RenderSurface;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0, p1, p2}, Lcom/google/android/filament/android/UiHelper$RenderSurface;->resize(II)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public setMediaOverlay(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/filament/android/UiHelper;->mOverlay:Z

    .line 2
    .line 3
    return-void
.end method

.method public setOpaque(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/filament/android/UiHelper;->mOpaque:Z

    .line 2
    .line 3
    return-void
.end method

.method public setRenderCallback(Lcom/google/android/filament/android/UiHelper$RendererCallback;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/android/UiHelper;->mRenderCallback:Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 2
    .line 3
    return-void
.end method
