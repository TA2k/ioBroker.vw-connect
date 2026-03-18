.class Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/filament/android/UiHelper$RenderSurface;
.implements Landroid/view/SurfaceHolder$Callback;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/android/UiHelper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "SurfaceViewHandler"
.end annotation


# instance fields
.field private final mSurfaceView:Landroid/view/SurfaceView;

.field final synthetic this$0:Lcom/google/android/filament/android/UiHelper;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/android/UiHelper;Landroid/view/SurfaceView;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->mSurfaceView:Landroid/view/SurfaceView;

    .line 7
    .line 8
    invoke-virtual {p2}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    invoke-interface {p2, p0}, Landroid/view/SurfaceHolder;->addCallback(Landroid/view/SurfaceHolder$Callback;)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-lez v0, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-lez v0, :cond_0

    .line 26
    .line 27
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    invoke-interface {p2, v0, p1}, Landroid/view/SurfaceHolder;->setFixedSize(II)V

    .line 36
    .line 37
    .line 38
    :cond_0
    invoke-interface {p2}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-eqz p1, :cond_1

    .line 43
    .line 44
    invoke-virtual {p1}, Landroid/view/Surface;->isValid()Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-eqz p1, :cond_1

    .line 49
    .line 50
    invoke-virtual {p0, p2}, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->surfaceCreated(Landroid/view/SurfaceHolder;)V

    .line 51
    .line 52
    .line 53
    invoke-interface {p2}, Landroid/view/SurfaceHolder;->getSurfaceFrame()Landroid/graphics/Rect;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    invoke-interface {p2}, Landroid/view/SurfaceHolder;->getSurfaceFrame()Landroid/graphics/Rect;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-virtual {v0}, Landroid/graphics/Rect;->height()I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    const/4 v1, 0x1

    .line 70
    invoke-virtual {p0, p2, v1, p1, v0}, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->surfaceChanged(Landroid/view/SurfaceHolder;III)V

    .line 71
    .line 72
    .line 73
    :cond_1
    return-void
.end method


# virtual methods
.method public detach()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->mSurfaceView:Landroid/view/SurfaceView;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-interface {v0, p0}, Landroid/view/SurfaceHolder;->removeCallback(Landroid/view/SurfaceHolder$Callback;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public resize(II)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->mSurfaceView:Landroid/view/SurfaceView;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0, p1, p2}, Landroid/view/SurfaceHolder;->setFixedSize(II)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public surfaceChanged(Landroid/view/SurfaceHolder;III)V
    .locals 0

    .line 1
    iget-object p1, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 10
    .line 11
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0, p3, p4}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onResized(II)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public surfaceCreated(Landroid/view/SurfaceHolder;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-interface {p1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p0, p1}, Lcom/google/android/filament/android/UiHelper;->d(Lcom/google/android/filament/android/UiHelper;Landroid/view/Surface;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public surfaceDestroyed(Landroid/view/SurfaceHolder;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$SurfaceViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->e(Lcom/google/android/filament/android/UiHelper;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
