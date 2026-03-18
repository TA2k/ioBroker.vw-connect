.class public final Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/filament/android/UiHelper$RendererCallback;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/ModelViewer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "SurfaceCallback"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u0008\n\u0002\u0008\u0005\u0008\u0086\u0004\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0016\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u000f\u0010\t\u001a\u00020\u0006H\u0016\u00a2\u0006\u0004\u0008\t\u0010\nJ\u001f\u0010\u000e\u001a\u00020\u00062\u0006\u0010\u000c\u001a\u00020\u000b2\u0006\u0010\r\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0010"
    }
    d2 = {
        "Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;",
        "Lcom/google/android/filament/android/UiHelper$RendererCallback;",
        "<init>",
        "(Lcom/google/android/filament/utils/ModelViewer;)V",
        "Landroid/view/Surface;",
        "surface",
        "Llx0/b0;",
        "onNativeWindowChanged",
        "(Landroid/view/Surface;)V",
        "onDetachedFromSurface",
        "()V",
        "",
        "width",
        "height",
        "onResized",
        "(II)V",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field final synthetic this$0:Lcom/google/android/filament/utils/ModelViewer;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/utils/ModelViewer;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public onDetachedFromSurface()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/google/android/filament/utils/ModelViewer;->access$getDisplayHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/DisplayHelper;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    invoke-virtual {v0}, Lcom/google/android/filament/android/DisplayHelper;->detach()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 14
    .line 15
    invoke-static {v0}, Lcom/google/android/filament/utils/ModelViewer;->access$getSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/SwapChain;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 22
    .line 23
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v2, v0}, Lcom/google/android/filament/Engine;->destroySwapChain(Lcom/google/android/filament/SwapChain;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {v0}, Lcom/google/android/filament/Engine;->flushAndWait()V

    .line 35
    .line 36
    .line 37
    invoke-static {p0, v1}, Lcom/google/android/filament/utils/ModelViewer;->access$setSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/SwapChain;)V

    .line 38
    .line 39
    .line 40
    :cond_0
    return-void

    .line 41
    :cond_1
    const-string p0, "displayHelper"

    .line 42
    .line 43
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw v1
.end method

.method public onNativeWindowChanged(Landroid/view/Surface;)V
    .locals 4

    .line 1
    const-string v0, "surface"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 7
    .line 8
    invoke-static {v0}, Lcom/google/android/filament/utils/ModelViewer;->access$getSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/SwapChain;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object v1, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 15
    .line 16
    invoke-virtual {v1}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {v1, v0}, Lcom/google/android/filament/Engine;->destroySwapChain(Lcom/google/android/filament/SwapChain;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 24
    .line 25
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v1, p1}, Lcom/google/android/filament/Engine;->createSwapChain(Ljava/lang/Object;)Lcom/google/android/filament/SwapChain;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-static {v0, p1}, Lcom/google/android/filament/utils/ModelViewer;->access$setSwapChain$p(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/SwapChain;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 37
    .line 38
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getSurfaceView$p(Lcom/google/android/filament/utils/ModelViewer;)Landroid/view/SurfaceView;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    const/4 v0, 0x0

    .line 43
    const-string v1, "displayHelper"

    .line 44
    .line 45
    if-eqz p1, :cond_2

    .line 46
    .line 47
    iget-object v2, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 48
    .line 49
    invoke-static {v2}, Lcom/google/android/filament/utils/ModelViewer;->access$getDisplayHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/DisplayHelper;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    if-eqz v3, :cond_1

    .line 54
    .line 55
    invoke-virtual {v2}, Lcom/google/android/filament/utils/ModelViewer;->getRenderer()Lcom/google/android/filament/Renderer;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {p1}, Landroid/view/View;->getDisplay()Landroid/view/Display;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-virtual {v3, v2, p1}, Lcom/google/android/filament/android/DisplayHelper;->attach(Lcom/google/android/filament/Renderer;Landroid/view/Display;)V

    .line 64
    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw v0

    .line 71
    :cond_2
    :goto_0
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 72
    .line 73
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$getTextureView$p(Lcom/google/android/filament/utils/ModelViewer;)Landroid/view/TextureView;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-eqz p1, :cond_4

    .line 78
    .line 79
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 80
    .line 81
    invoke-static {p0}, Lcom/google/android/filament/utils/ModelViewer;->access$getDisplayHelper$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/android/DisplayHelper;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    if-eqz v2, :cond_3

    .line 86
    .line 87
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->getRenderer()Lcom/google/android/filament/Renderer;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-virtual {p1}, Landroid/view/View;->getDisplay()Landroid/view/Display;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-virtual {v2, p0, p1}, Lcom/google/android/filament/android/DisplayHelper;->attach(Lcom/google/android/filament/Renderer;Landroid/view/Display;)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :cond_3
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw v0

    .line 103
    :cond_4
    return-void
.end method

.method public onResized(II)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/filament/utils/ModelViewer;->getView()Lcom/google/android/filament/View;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/google/android/filament/Viewport;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-direct {v1, v2, v2, p1, p2}, Lcom/google/android/filament/Viewport;-><init>(IIII)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1}, Lcom/google/android/filament/View;->setViewport(Lcom/google/android/filament/Viewport;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 17
    .line 18
    invoke-static {v0}, Lcom/google/android/filament/utils/ModelViewer;->access$getCameraManipulator$p(Lcom/google/android/filament/utils/ModelViewer;)Lcom/google/android/filament/utils/Manipulator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-virtual {v0, p1, p2}, Lcom/google/android/filament/utils/Manipulator;->setViewport(II)V

    .line 25
    .line 26
    .line 27
    iget-object p1, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 28
    .line 29
    invoke-static {p1}, Lcom/google/android/filament/utils/ModelViewer;->access$updateCameraProjection(Lcom/google/android/filament/utils/ModelViewer;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lcom/google/android/filament/utils/ModelViewer$SurfaceCallback;->this$0:Lcom/google/android/filament/utils/ModelViewer;

    .line 33
    .line 34
    invoke-virtual {p0}, Lcom/google/android/filament/utils/ModelViewer;->getEngine()Lcom/google/android/filament/Engine;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/ModelViewer;->access$synchronizePendingFrames(Lcom/google/android/filament/utils/ModelViewer;Lcom/google/android/filament/Engine;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_0
    const-string p0, "cameraManipulator"

    .line 43
    .line 44
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const/4 p0, 0x0

    .line 48
    throw p0
.end method
