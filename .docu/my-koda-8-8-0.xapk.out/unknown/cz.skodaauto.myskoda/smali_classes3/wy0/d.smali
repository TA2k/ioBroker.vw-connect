.class public abstract Lwy0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:I

.field private static volatile choreographer:Landroid/view/Choreographer;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    :try_start_0
    new-instance v0, Lwy0/c;

    .line 2
    .line 3
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {v1}, Lwy0/d;->b(Landroid/os/Looper;)Landroid/os/Handler;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1}, Lwy0/c;-><init>(Landroid/os/Handler;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    .line 13
    .line 14
    goto :goto_0

    .line 15
    :catchall_0
    move-exception v0

    .line 16
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :goto_0
    instance-of v1, v0, Llx0/n;

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    :cond_0
    check-cast v0, Lwy0/c;

    .line 26
    .line 27
    return-void
.end method

.method public static final a(Lvy0/l;)V
    .locals 2

    .line 1
    sget-object v0, Lwy0/d;->choreographer:Landroid/view/Choreographer;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Landroid/view/Choreographer;->getInstance()Landroid/view/Choreographer;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lwy0/d;->choreographer:Landroid/view/Choreographer;

    .line 13
    .line 14
    :cond_0
    new-instance v1, Lia/e;

    .line 15
    .line 16
    invoke-direct {v1, p0}, Lia/e;-><init>(Lvy0/l;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v1}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public static final b(Landroid/os/Looper;)Landroid/os/Handler;
    .locals 3

    .line 1
    const-class v0, Landroid/os/Looper;

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-class v1, Landroid/os/Handler;

    .line 8
    .line 9
    const-string v2, "createAsync"

    .line 10
    .line 11
    invoke-virtual {v1, v2, v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const/4 v1, 0x0

    .line 16
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {v0, v1, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const-string v0, "null cannot be cast to non-null type android.os.Handler"

    .line 25
    .line 26
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    check-cast p0, Landroid/os/Handler;

    .line 30
    .line 31
    return-object p0
.end method

.method public static final c(Lvu/j;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lwy0/d;->choreographer:Landroid/view/Choreographer;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    new-instance v2, Lvy0/l;

    .line 7
    .line 8
    invoke-static {p0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-direct {v2, v1, p0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 16
    .line 17
    .line 18
    new-instance p0, Lia/e;

    .line 19
    .line 20
    invoke-direct {p0, v2}, Lia/e;-><init>(Lvy0/l;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, p0}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_0
    new-instance v0, Lvy0/l;

    .line 34
    .line 35
    invoke-static {p0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {v0, v1, p0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Lvy0/l;->q()V

    .line 43
    .line 44
    .line 45
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    if-ne p0, v1, :cond_1

    .line 54
    .line 55
    invoke-static {v0}, Lwy0/d;->a(Lvy0/l;)V

    .line 56
    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_1
    sget-object p0, Lvy0/p0;->a:Lcz0/e;

    .line 60
    .line 61
    sget-object p0, Laz0/m;->a:Lwy0/c;

    .line 62
    .line 63
    iget-object v1, v0, Lvy0/l;->h:Lpx0/g;

    .line 64
    .line 65
    new-instance v2, Lvp/g4;

    .line 66
    .line 67
    const/4 v3, 0x4

    .line 68
    invoke-direct {v2, v0, v3}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p0, v1, v2}, Lwy0/c;->T(Lpx0/g;Ljava/lang/Runnable;)V

    .line 72
    .line 73
    .line 74
    :goto_0
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 79
    .line 80
    return-object p0
.end method
