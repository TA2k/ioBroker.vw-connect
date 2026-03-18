.class public abstract Landroidx/lifecycle/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:Ljava/lang/Object;


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Lo/f;

.field public c:I

.field public d:Z

.field public volatile e:Ljava/lang/Object;

.field public volatile f:Ljava/lang/Object;

.field public g:I

.field public h:Z

.field public i:Z

.field public final j:Landroidx/lifecycle/c0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/lifecycle/g0;->k:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/g0;->a:Ljava/lang/Object;

    .line 11
    new-instance v0, Lo/f;

    invoke-direct {v0}, Lo/f;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    const/4 v0, 0x0

    .line 12
    iput v0, p0, Landroidx/lifecycle/g0;->c:I

    .line 13
    sget-object v0, Landroidx/lifecycle/g0;->k:Ljava/lang/Object;

    iput-object v0, p0, Landroidx/lifecycle/g0;->f:Ljava/lang/Object;

    .line 14
    new-instance v1, Landroidx/lifecycle/c0;

    invoke-direct {v1, p0}, Landroidx/lifecycle/c0;-><init>(Landroidx/lifecycle/g0;)V

    iput-object v1, p0, Landroidx/lifecycle/g0;->j:Landroidx/lifecycle/c0;

    .line 15
    iput-object v0, p0, Landroidx/lifecycle/g0;->e:Ljava/lang/Object;

    const/4 v0, -0x1

    .line 16
    iput v0, p0, Landroidx/lifecycle/g0;->g:I

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/g0;->a:Ljava/lang/Object;

    .line 3
    new-instance v0, Lo/f;

    invoke-direct {v0}, Lo/f;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    const/4 v0, 0x0

    .line 4
    iput v0, p0, Landroidx/lifecycle/g0;->c:I

    .line 5
    sget-object v1, Landroidx/lifecycle/g0;->k:Ljava/lang/Object;

    iput-object v1, p0, Landroidx/lifecycle/g0;->f:Ljava/lang/Object;

    .line 6
    new-instance v1, Landroidx/lifecycle/c0;

    invoke-direct {v1, p0}, Landroidx/lifecycle/c0;-><init>(Landroidx/lifecycle/g0;)V

    iput-object v1, p0, Landroidx/lifecycle/g0;->j:Landroidx/lifecycle/c0;

    .line 7
    iput-object p1, p0, Landroidx/lifecycle/g0;->e:Ljava/lang/Object;

    .line 8
    iput v0, p0, Landroidx/lifecycle/g0;->g:I

    return-void
.end method

.method public static a(Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Ln/a;->g()Ln/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Ln/a;->a:Ln/b;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    if-ne v0, v1, :cond_0

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string v1, "Cannot invoke "

    .line 28
    .line 29
    const-string v2, " on a background thread"

    .line 30
    .line 31
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0
.end method


# virtual methods
.method public final b(Landroidx/lifecycle/f0;)V
    .locals 2

    .line 1
    iget-boolean v0, p1, Landroidx/lifecycle/f0;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-virtual {p1}, Landroidx/lifecycle/f0;->d()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_1

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    invoke-virtual {p1, p0}, Landroidx/lifecycle/f0;->a(Z)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_1
    iget v0, p1, Landroidx/lifecycle/f0;->f:I

    .line 18
    .line 19
    iget v1, p0, Landroidx/lifecycle/g0;->g:I

    .line 20
    .line 21
    if-lt v0, v1, :cond_2

    .line 22
    .line 23
    :goto_0
    return-void

    .line 24
    :cond_2
    iput v1, p1, Landroidx/lifecycle/f0;->f:I

    .line 25
    .line 26
    iget-object p1, p1, Landroidx/lifecycle/f0;->d:Landroidx/lifecycle/j0;

    .line 27
    .line 28
    iget-object p0, p0, Landroidx/lifecycle/g0;->e:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-interface {p1, p0}, Landroidx/lifecycle/j0;->a(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public final c(Landroidx/lifecycle/f0;)V
    .locals 4

    .line 1
    iget-boolean v0, p0, Landroidx/lifecycle/g0;->h:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Landroidx/lifecycle/g0;->i:Z

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iput-boolean v1, p0, Landroidx/lifecycle/g0;->h:Z

    .line 10
    .line 11
    :cond_1
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Landroidx/lifecycle/g0;->i:Z

    .line 13
    .line 14
    if-eqz p1, :cond_2

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Landroidx/lifecycle/g0;->b(Landroidx/lifecycle/f0;)V

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    goto :goto_0

    .line 21
    :cond_2
    iget-object v1, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    new-instance v2, Lo/d;

    .line 27
    .line 28
    invoke-direct {v2, v1}, Lo/d;-><init>(Lo/f;)V

    .line 29
    .line 30
    .line 31
    iget-object v1, v1, Lo/f;->f:Ljava/util/WeakHashMap;

    .line 32
    .line 33
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 34
    .line 35
    invoke-virtual {v1, v2, v3}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    :cond_3
    invoke-virtual {v2}, Lo/d;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_4

    .line 43
    .line 44
    invoke-virtual {v2}, Lo/d;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/util/Map$Entry;

    .line 49
    .line 50
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Landroidx/lifecycle/f0;

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Landroidx/lifecycle/g0;->b(Landroidx/lifecycle/f0;)V

    .line 57
    .line 58
    .line 59
    iget-boolean v1, p0, Landroidx/lifecycle/g0;->i:Z

    .line 60
    .line 61
    if-eqz v1, :cond_3

    .line 62
    .line 63
    :cond_4
    :goto_0
    iget-boolean v1, p0, Landroidx/lifecycle/g0;->i:Z

    .line 64
    .line 65
    if-nez v1, :cond_1

    .line 66
    .line 67
    iput-boolean v0, p0, Landroidx/lifecycle/g0;->h:Z

    .line 68
    .line 69
    return-void
.end method

.method public d()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/g0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v0, Landroidx/lifecycle/g0;->k:Ljava/lang/Object;

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public final e(Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V
    .locals 2

    .line 1
    const-string v0, "observe"

    .line 2
    .line 3
    invoke-static {v0}, Landroidx/lifecycle/g0;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sget-object v1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 15
    .line 16
    if-ne v0, v1, :cond_0

    .line 17
    .line 18
    goto :goto_3

    .line 19
    :cond_0
    new-instance v0, Landroidx/lifecycle/e0;

    .line 20
    .line 21
    invoke-direct {v0, p0, p1, p2}, Landroidx/lifecycle/e0;-><init>(Landroidx/lifecycle/g0;Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    .line 25
    .line 26
    invoke-virtual {p0, p2}, Lo/f;->c(Ljava/lang/Object;)Lo/c;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    iget-object p0, v1, Lo/c;->e:Ljava/lang/Object;

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    new-instance v1, Lo/c;

    .line 36
    .line 37
    invoke-direct {v1, p2, v0}, Lo/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    iget p2, p0, Lo/f;->g:I

    .line 41
    .line 42
    add-int/lit8 p2, p2, 0x1

    .line 43
    .line 44
    iput p2, p0, Lo/f;->g:I

    .line 45
    .line 46
    iget-object p2, p0, Lo/f;->e:Lo/c;

    .line 47
    .line 48
    if-nez p2, :cond_2

    .line 49
    .line 50
    iput-object v1, p0, Lo/f;->d:Lo/c;

    .line 51
    .line 52
    iput-object v1, p0, Lo/f;->e:Lo/c;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    iput-object v1, p2, Lo/c;->f:Lo/c;

    .line 56
    .line 57
    iput-object p2, v1, Lo/c;->g:Lo/c;

    .line 58
    .line 59
    iput-object v1, p0, Lo/f;->e:Lo/c;

    .line 60
    .line 61
    :goto_0
    const/4 p0, 0x0

    .line 62
    :goto_1
    check-cast p0, Landroidx/lifecycle/f0;

    .line 63
    .line 64
    if-eqz p0, :cond_4

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Landroidx/lifecycle/f0;->c(Landroidx/fragment/app/j0;)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_3

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 74
    .line 75
    const-string p1, "Cannot add the same observer with different lifecycles"

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_4
    :goto_2
    if-eqz p0, :cond_5

    .line 82
    .line 83
    :goto_3
    return-void

    .line 84
    :cond_5
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {p0, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 89
    .line 90
    .line 91
    return-void
.end method

.method public final f(Landroidx/lifecycle/j0;)V
    .locals 3

    .line 1
    const-string v0, "observeForever"

    .line 2
    .line 3
    invoke-static {v0}, Landroidx/lifecycle/g0;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Landroidx/lifecycle/d0;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Landroidx/lifecycle/f0;-><init>(Landroidx/lifecycle/g0;Landroidx/lifecycle/j0;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lo/f;->c(Ljava/lang/Object;)Lo/c;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    iget-object p0, v1, Lo/c;->e:Ljava/lang/Object;

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    new-instance v1, Lo/c;

    .line 24
    .line 25
    invoke-direct {v1, p1, v0}, Lo/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget p1, p0, Lo/f;->g:I

    .line 29
    .line 30
    add-int/2addr p1, v2

    .line 31
    iput p1, p0, Lo/f;->g:I

    .line 32
    .line 33
    iget-object p1, p0, Lo/f;->e:Lo/c;

    .line 34
    .line 35
    if-nez p1, :cond_1

    .line 36
    .line 37
    iput-object v1, p0, Lo/f;->d:Lo/c;

    .line 38
    .line 39
    iput-object v1, p0, Lo/f;->e:Lo/c;

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    iput-object v1, p1, Lo/c;->f:Lo/c;

    .line 43
    .line 44
    iput-object p1, v1, Lo/c;->g:Lo/c;

    .line 45
    .line 46
    iput-object v1, p0, Lo/f;->e:Lo/c;

    .line 47
    .line 48
    :goto_0
    const/4 p0, 0x0

    .line 49
    :goto_1
    check-cast p0, Landroidx/lifecycle/f0;

    .line 50
    .line 51
    instance-of p1, p0, Landroidx/lifecycle/e0;

    .line 52
    .line 53
    if-nez p1, :cond_3

    .line 54
    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    return-void

    .line 58
    :cond_2
    invoke-virtual {v0, v2}, Landroidx/lifecycle/f0;->a(Z)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    const-string p1, "Cannot add the same observer with different lifecycles"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0
.end method

.method public g()V
    .locals 0

    .line 1
    return-void
.end method

.method public h()V
    .locals 0

    .line 1
    return-void
.end method

.method public final i(Landroidx/lifecycle/j0;)V
    .locals 1

    .line 1
    const-string v0, "removeObserver"

    .line 2
    .line 3
    invoke-static {v0}, Landroidx/lifecycle/g0;->a(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/lifecycle/g0;->b:Lo/f;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lo/f;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Landroidx/lifecycle/f0;

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    invoke-virtual {p0}, Landroidx/lifecycle/f0;->b()V

    .line 18
    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    invoke-virtual {p0, p1}, Landroidx/lifecycle/f0;->a(Z)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public abstract j(Ljava/lang/Object;)V
.end method
