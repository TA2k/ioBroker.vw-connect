.class public final La8/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/SurfaceHolder$Callback;
.implements Landroid/view/TextureView$SurfaceTextureListener;


# instance fields
.field public final synthetic d:La8/i0;


# direct methods
.method public constructor <init>(La8/i0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La8/f0;->d:La8/i0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final onSurfaceTextureAvailable(Landroid/graphics/SurfaceTexture;II)V
    .locals 1

    .line 1
    new-instance v0, Landroid/view/Surface;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, La8/i0;->Z:Landroid/view/Surface;

    .line 12
    .line 13
    invoke-virtual {p0, p2, p3}, La8/i0;->v0(II)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final onSurfaceTextureDestroyed(Landroid/graphics/SurfaceTexture;)Z
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 3
    .line 4
    invoke-virtual {p0, p1}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-virtual {p0, p1, p1}, La8/i0;->v0(II)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0
.end method

.method public final onSurfaceTextureSizeChanged(Landroid/graphics/SurfaceTexture;II)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 2
    .line 3
    invoke-virtual {p0, p2, p3}, La8/i0;->v0(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final onSurfaceTextureUpdated(Landroid/graphics/SurfaceTexture;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final surfaceChanged(Landroid/view/SurfaceHolder;III)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 2
    .line 3
    invoke-virtual {p0, p3, p4}, La8/i0;->v0(II)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final surfaceCreated(Landroid/view/SurfaceHolder;)V
    .locals 1

    .line 1
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 2
    .line 3
    iget-boolean v0, p0, La8/i0;->c0:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p0, p1}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final surfaceDestroyed(Landroid/view/SurfaceHolder;)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 2
    .line 3
    iget-boolean p1, p0, La8/i0;->c0:Z

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-virtual {p0, p1}, La8/i0;->E0(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    const/4 p1, 0x0

    .line 12
    invoke-virtual {p0, p1, p1}, La8/i0;->v0(II)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
