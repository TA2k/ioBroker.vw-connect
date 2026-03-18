.class public final Lw0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/view/SurfaceHolder$Callback;


# instance fields
.field public d:Landroid/util/Size;

.field public e:Lb0/x1;

.field public f:Lb0/x1;

.field public g:Lbb/i;

.field public h:Landroid/util/Size;

.field public i:Z

.field public j:Z

.field public final synthetic k:Lw0/p;


# direct methods
.method public constructor <init>(Lw0/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw0/o;->k:Lw0/p;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput-boolean p1, p0, Lw0/o;->i:Z

    .line 8
    .line 9
    iput-boolean p1, p0, Lw0/o;->j:Z

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lw0/o;->e:Lb0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v1, "Request canceled: "

    .line 8
    .line 9
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lw0/o;->e:Lb0/x1;

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-string v1, "SurfaceViewImpl"

    .line 22
    .line 23
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lw0/o;->e:Lb0/x1;

    .line 27
    .line 28
    invoke-virtual {v0}, Lb0/x1;->c()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    iget-object p0, p0, Lw0/o;->g:Lbb/i;

    .line 35
    .line 36
    if-eqz p0, :cond_0

    .line 37
    .line 38
    invoke-virtual {p0}, Lbb/i;->a()V

    .line 39
    .line 40
    .line 41
    :cond_0
    return-void
.end method

.method public final b()Z
    .locals 7

    .line 1
    iget-object v0, p0, Lw0/o;->k:Lw0/p;

    .line 2
    .line 3
    iget-object v1, v0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 4
    .line 5
    invoke-virtual {v1}, Landroid/view/SurfaceView;->getHolder()Landroid/view/SurfaceHolder;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-interface {v1}, Landroid/view/SurfaceHolder;->getSurface()Landroid/view/Surface;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-boolean v2, p0, Lw0/o;->i:Z

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    iget-object v2, p0, Lw0/o;->e:Lb0/x1;

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    iget-object v2, p0, Lw0/o;->d:Landroid/util/Size;

    .line 22
    .line 23
    iget-object v3, p0, Lw0/o;->h:Landroid/util/Size;

    .line 24
    .line 25
    invoke-static {v2, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    const-string v2, "SurfaceViewImpl"

    .line 32
    .line 33
    const-string v3, "Surface set on Preview."

    .line 34
    .line 35
    invoke-static {v2, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v2, p0, Lw0/o;->g:Lbb/i;

    .line 39
    .line 40
    iget-object v3, p0, Lw0/o;->e:Lb0/x1;

    .line 41
    .line 42
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    iget-object v4, v0, Lw0/p;->e:Landroid/view/SurfaceView;

    .line 46
    .line 47
    invoke-virtual {v4}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    invoke-virtual {v4}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    new-instance v5, Lg0/c;

    .line 56
    .line 57
    const/4 v6, 0x2

    .line 58
    invoke-direct {v5, v2, v6}, Lg0/c;-><init>(Ljava/lang/Object;I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v3, v1, v4, v5}, Lb0/x1;->a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V

    .line 62
    .line 63
    .line 64
    const/4 v1, 0x1

    .line 65
    iput-boolean v1, p0, Lw0/o;->i:Z

    .line 66
    .line 67
    iput-boolean v1, v0, Landroidx/core/app/a0;->a:Z

    .line 68
    .line 69
    invoke-virtual {v0}, Landroidx/core/app/a0;->h()V

    .line 70
    .line 71
    .line 72
    return v1

    .line 73
    :cond_0
    const/4 p0, 0x0

    .line 74
    return p0
.end method

.method public final surfaceChanged(Landroid/view/SurfaceHolder;III)V
    .locals 0

    .line 1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string p2, "Surface changed. Size: "

    .line 4
    .line 5
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p2, "x"

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    const-string p2, "SurfaceViewImpl"

    .line 24
    .line 25
    invoke-static {p2, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance p1, Landroid/util/Size;

    .line 29
    .line 30
    invoke-direct {p1, p3, p4}, Landroid/util/Size;-><init>(II)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lw0/o;->h:Landroid/util/Size;

    .line 34
    .line 35
    invoke-virtual {p0}, Lw0/o;->b()Z

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final surfaceCreated(Landroid/view/SurfaceHolder;)V
    .locals 1

    .line 1
    const-string p1, "SurfaceViewImpl"

    .line 2
    .line 3
    const-string v0, "Surface created."

    .line 4
    .line 5
    invoke-static {p1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean p1, p0, Lw0/o;->j:Z

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    iget-object p1, p0, Lw0/o;->f:Lb0/x1;

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p1}, Lb0/x1;->c()Z

    .line 17
    .line 18
    .line 19
    iget-object p1, p1, Lb0/x1;->i:Ly4/h;

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-virtual {p1, v0}, Ly4/h;->b(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lw0/o;->f:Lb0/x1;

    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iput-boolean p1, p0, Lw0/o;->j:Z

    .line 29
    .line 30
    :cond_0
    return-void
.end method

.method public final surfaceDestroyed(Landroid/view/SurfaceHolder;)V
    .locals 2

    .line 1
    const-string p1, "Surface destroyed."

    .line 2
    .line 3
    const-string v0, "SurfaceViewImpl"

    .line 4
    .line 5
    invoke-static {v0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean p1, p0, Lw0/o;->i:Z

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    iget-object p1, p0, Lw0/o;->e:Lb0/x1;

    .line 13
    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    new-instance p1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v1, "Surface closed "

    .line 19
    .line 20
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Lw0/o;->e:Lb0/x1;

    .line 24
    .line 25
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-static {v0, p1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lw0/o;->e:Lb0/x1;

    .line 36
    .line 37
    iget-object p1, p1, Lb0/x1;->k:Lb0/u1;

    .line 38
    .line 39
    invoke-virtual {p1}, Lh0/t0;->a()V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-virtual {p0}, Lw0/o;->a()V

    .line 44
    .line 45
    .line 46
    :cond_1
    :goto_0
    const/4 p1, 0x1

    .line 47
    iput-boolean p1, p0, Lw0/o;->j:Z

    .line 48
    .line 49
    iget-object p1, p0, Lw0/o;->e:Lb0/x1;

    .line 50
    .line 51
    if-eqz p1, :cond_2

    .line 52
    .line 53
    iput-object p1, p0, Lw0/o;->f:Lb0/x1;

    .line 54
    .line 55
    :cond_2
    const/4 p1, 0x0

    .line 56
    iput-boolean p1, p0, Lw0/o;->i:Z

    .line 57
    .line 58
    const/4 p1, 0x0

    .line 59
    iput-object p1, p0, Lw0/o;->e:Lb0/x1;

    .line 60
    .line 61
    iput-object p1, p0, Lw0/o;->g:Lbb/i;

    .line 62
    .line 63
    iput-object p1, p0, Lw0/o;->h:Landroid/util/Size;

    .line 64
    .line 65
    iput-object p1, p0, Lw0/o;->d:Landroid/util/Size;

    .line 66
    .line 67
    return-void
.end method
