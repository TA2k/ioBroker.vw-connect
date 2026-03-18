.class public final synthetic Lp0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc6/a;


# instance fields
.field public final synthetic a:Lp0/c;

.field public final synthetic b:Lb0/x1;

.field public final synthetic c:Landroid/graphics/SurfaceTexture;

.field public final synthetic d:Landroid/view/Surface;


# direct methods
.method public synthetic constructor <init>(Lp0/c;Lb0/x1;Landroid/graphics/SurfaceTexture;Landroid/view/Surface;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp0/b;->a:Lp0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lp0/b;->b:Lb0/x1;

    .line 7
    .line 8
    iput-object p3, p0, Lp0/b;->c:Landroid/graphics/SurfaceTexture;

    .line 9
    .line 10
    iput-object p4, p0, Lp0/b;->d:Landroid/view/Surface;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lp0/b;->a:Lp0/c;

    .line 2
    .line 3
    iget-object v1, p0, Lp0/b;->b:Lb0/x1;

    .line 4
    .line 5
    iget-object v2, p0, Lp0/b;->c:Landroid/graphics/SurfaceTexture;

    .line 6
    .line 7
    iget-object p0, p0, Lp0/b;->d:Landroid/view/Surface;

    .line 8
    .line 9
    check-cast p1, Lb0/i;

    .line 10
    .line 11
    iget-object p1, v1, Lb0/x1;->a:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter p1

    .line 14
    const/4 v3, 0x0

    .line 15
    :try_start_0
    iput-object v3, v1, Lb0/x1;->m:Lb0/w1;

    .line 16
    .line 17
    iput-object v3, v1, Lb0/x1;->n:Ljava/util/concurrent/Executor;

    .line 18
    .line 19
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    invoke-virtual {v2, v3}, Landroid/graphics/SurfaceTexture;->setOnFrameAvailableListener(Landroid/graphics/SurfaceTexture$OnFrameAvailableListener;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v2}, Landroid/graphics/SurfaceTexture;->release()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Landroid/view/Surface;->release()V

    .line 27
    .line 28
    .line 29
    iget p0, v0, Lp0/c;->l:I

    .line 30
    .line 31
    add-int/lit8 p0, p0, -0x1

    .line 32
    .line 33
    iput p0, v0, Lp0/c;->l:I

    .line 34
    .line 35
    invoke-virtual {v0}, Lp0/c;->d()V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    throw p0
.end method
