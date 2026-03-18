.class public final synthetic Lq0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc6/a;


# instance fields
.field public final synthetic a:Lq0/e;

.field public final synthetic b:Landroid/graphics/SurfaceTexture;

.field public final synthetic c:Landroid/view/Surface;


# direct methods
.method public synthetic constructor <init>(Lq0/e;Landroid/graphics/SurfaceTexture;Landroid/view/Surface;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lq0/d;->a:Lq0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lq0/d;->b:Landroid/graphics/SurfaceTexture;

    .line 7
    .line 8
    iput-object p3, p0, Lq0/d;->c:Landroid/view/Surface;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lb0/i;

    .line 2
    .line 3
    iget-object p1, p0, Lq0/d;->a:Lq0/e;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iget-object v1, p0, Lq0/d;->b:Landroid/graphics/SurfaceTexture;

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Landroid/graphics/SurfaceTexture;->setOnFrameAvailableListener(Landroid/graphics/SurfaceTexture$OnFrameAvailableListener;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1}, Landroid/graphics/SurfaceTexture;->release()V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lq0/d;->c:Landroid/view/Surface;

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/Surface;->release()V

    .line 20
    .line 21
    .line 22
    iget p0, p1, Lq0/e;->h:I

    .line 23
    .line 24
    add-int/lit8 p0, p0, -0x1

    .line 25
    .line 26
    iput p0, p1, Lq0/e;->h:I

    .line 27
    .line 28
    invoke-virtual {p1}, Lq0/e;->d()V

    .line 29
    .line 30
    .line 31
    return-void
.end method
