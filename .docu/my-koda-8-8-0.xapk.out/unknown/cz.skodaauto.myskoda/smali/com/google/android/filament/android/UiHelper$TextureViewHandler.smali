.class Lcom/google/android/filament/android/UiHelper$TextureViewHandler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/filament/android/UiHelper$RenderSurface;
.implements Landroid/view/TextureView$SurfaceTextureListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/android/UiHelper;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "TextureViewHandler"
.end annotation


# instance fields
.field private mSurface:Landroid/view/Surface;

.field private final mTextureView:Landroid/view/TextureView;

.field final synthetic this$0:Lcom/google/android/filament/android/UiHelper;


# direct methods
.method public constructor <init>(Lcom/google/android/filament/android/UiHelper;Landroid/view/TextureView;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mTextureView:Landroid/view/TextureView;

    .line 7
    .line 8
    invoke-virtual {p2, p0}, Landroid/view/TextureView;->setSurfaceTextureListener(Landroid/view/TextureView$SurfaceTextureListener;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2}, Landroid/view/TextureView;->isAvailable()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    invoke-virtual {p2}, Landroid/view/TextureView;->getSurfaceTexture()Landroid/graphics/SurfaceTexture;

    .line 18
    .line 19
    .line 20
    move-result-object p2

    .line 21
    if-eqz p2, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-virtual {p0, p2, v0, p1}, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->onSurfaceTextureAvailable(Landroid/graphics/SurfaceTexture;II)V

    .line 32
    .line 33
    .line 34
    :cond_0
    return-void
.end method

.method private getSurface()Landroid/view/Surface;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mSurface:Landroid/view/Surface;

    .line 2
    .line 3
    return-object p0
.end method

.method private setSurface(Landroid/view/Surface;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mSurface:Landroid/view/Surface;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/Surface;->release()V

    .line 8
    .line 9
    .line 10
    :cond_0
    iput-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mSurface:Landroid/view/Surface;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public detach()V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mTextureView:Landroid/view/TextureView;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, v0}, Landroid/view/TextureView;->setSurfaceTextureListener(Landroid/view/TextureView$SurfaceTextureListener;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public onSurfaceTextureAvailable(Landroid/graphics/SurfaceTexture;II)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 10
    .line 11
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-lez v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 18
    .line 19
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iget-object v1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 24
    .line 25
    invoke-static {v1}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    invoke-virtual {p1, v0, v1}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 30
    .line 31
    .line 32
    :cond_0
    new-instance v0, Landroid/view/Surface;

    .line 33
    .line 34
    invoke-direct {v0, p1}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 35
    .line 36
    .line 37
    invoke-direct {p0, v0}, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->setSurface(Landroid/view/Surface;)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 41
    .line 42
    invoke-static {p1, v0}, Lcom/google/android/filament/android/UiHelper;->d(Lcom/google/android/filament/android/UiHelper;Landroid/view/Surface;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 46
    .line 47
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    if-eqz p1, :cond_1

    .line 52
    .line 53
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 54
    .line 55
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-interface {p0, p2, p3}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onResized(II)V

    .line 60
    .line 61
    .line 62
    :cond_1
    return-void
.end method

.method public onSurfaceTextureDestroyed(Landroid/graphics/SurfaceTexture;)Z
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-direct {p0, p1}, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->setSurface(Landroid/view/Surface;)V

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 6
    .line 7
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->e(Lcom/google/android/filament/android/UiHelper;)V

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0
.end method

.method public onSurfaceTextureSizeChanged(Landroid/graphics/SurfaceTexture;II)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 2
    .line 3
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 10
    .line 11
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-lez v0, :cond_0

    .line 16
    .line 17
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 18
    .line 19
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-lez v0, :cond_0

    .line 24
    .line 25
    iget-object p2, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 26
    .line 27
    invoke-static {p2}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    iget-object p3, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 32
    .line 33
    invoke-static {p3}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 34
    .line 35
    .line 36
    move-result p3

    .line 37
    invoke-virtual {p1, p2, p3}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 41
    .line 42
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iget-object p2, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 47
    .line 48
    invoke-static {p2}, Lcom/google/android/filament/android/UiHelper;->b(Lcom/google/android/filament/android/UiHelper;)I

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    iget-object p3, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 53
    .line 54
    invoke-static {p3}, Lcom/google/android/filament/android/UiHelper;->a(Lcom/google/android/filament/android/UiHelper;)I

    .line 55
    .line 56
    .line 57
    move-result p3

    .line 58
    invoke-interface {p1, p2, p3}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onResized(II)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    iget-object p1, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 63
    .line 64
    invoke-static {p1}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-interface {p1, p2, p3}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onResized(II)V

    .line 69
    .line 70
    .line 71
    :goto_0
    invoke-direct {p0}, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->getSurface()Landroid/view/Surface;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-eqz p1, :cond_1

    .line 76
    .line 77
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 78
    .line 79
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-interface {p0, p1}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onNativeWindowChanged(Landroid/view/Surface;)V

    .line 84
    .line 85
    .line 86
    :cond_1
    return-void
.end method

.method public onSurfaceTextureUpdated(Landroid/graphics/SurfaceTexture;)V
    .locals 0

    .line 1
    return-void
.end method

.method public resize(II)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->mTextureView:Landroid/view/TextureView;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/TextureView;->getSurfaceTexture()Landroid/graphics/SurfaceTexture;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p1, p2}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 13
    .line 14
    invoke-static {v0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Lcom/google/android/filament/android/UiHelper$TextureViewHandler;->this$0:Lcom/google/android/filament/android/UiHelper;

    .line 21
    .line 22
    invoke-static {p0}, Lcom/google/android/filament/android/UiHelper;->c(Lcom/google/android/filament/android/UiHelper;)Lcom/google/android/filament/android/UiHelper$RendererCallback;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {p0, p1, p2}, Lcom/google/android/filament/android/UiHelper$RendererCallback;->onResized(II)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method
