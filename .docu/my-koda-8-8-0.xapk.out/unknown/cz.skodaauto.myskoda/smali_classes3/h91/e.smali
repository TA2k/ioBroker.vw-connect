.class public final Lh91/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh91/e;

.field public static final b:Ljava/util/concurrent/CopyOnWriteArrayList;

.field public static final c:Lxy0/j;

.field public static final d:I

.field public static final e:I

.field public static f:Lgw0/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lh91/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh91/e;->a:Lh91/e;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lh91/e;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    const/4 v1, 0x6

    .line 17
    const v2, 0x7fffffff

    .line 18
    .line 19
    .line 20
    invoke-static {v2, v1, v0}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lh91/e;->c:Lxy0/j;

    .line 25
    .line 26
    new-instance v1, Lyy0/d;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v1, v0, v2}, Lyy0/d;-><init>(Lxy0/z;Z)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x5

    .line 33
    sput v0, Lh91/e;->d:I

    .line 34
    .line 35
    const/16 v0, 0x32

    .line 36
    .line 37
    sput v0, Lh91/e;->e:I

    .line 38
    .line 39
    return-void
.end method

.method public static a(Lay0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lh91/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 5
    .line 6
    .line 7
    :try_start_0
    sget-object p0, Lh91/e;->f:Lgw0/c;

    .line 8
    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    new-instance p0, Lgw0/c;

    .line 12
    .line 13
    sget v1, Lh91/e;->d:I

    .line 14
    .line 15
    sget v2, Lh91/e;->e:I

    .line 16
    .line 17
    invoke-direct {p0, v1, v2}, Lgw0/c;-><init>(II)V

    .line 18
    .line 19
    .line 20
    sget-object v1, Lh91/e;->a:Lh91/e;

    .line 21
    .line 22
    iput-object v1, p0, Lgw0/c;->g:Ljava/lang/Object;

    .line 23
    .line 24
    sput-object p0, Lh91/e;->f:Lgw0/c;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catch_0
    move-exception p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    iget-object v1, p0, Lgw0/c;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lh91/b;

    .line 32
    .line 33
    invoke-virtual {v1, v0}, Ljava/util/concurrent/AbstractExecutorService;->submit(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iget-object p0, p0, Lgw0/c;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 40
    .line 41
    invoke-virtual {p0, v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    return-void

    .line 45
    :goto_1
    new-instance v1, Lh50/p;

    .line 46
    .line 47
    const/16 v2, 0x13

    .line 48
    .line 49
    invoke-direct {v1, v2}, Lh50/p;-><init>(I)V

    .line 50
    .line 51
    .line 52
    sget-object v2, Lf91/b;->a:Lw51/b;

    .line 53
    .line 54
    invoke-static {v2, p0, v1}, Lw51/c;->a(Lw51/b;Ljava/lang/Exception;Lay0/a;)V

    .line 55
    .line 56
    .line 57
    sget-object p0, Ld91/a;->a:Landroid/os/Handler;

    .line 58
    .line 59
    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 60
    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Runnable;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    sget-object p0, Lh91/e;->b:Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArrayList;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    new-instance p0, Lh91/d;

    .line 14
    .line 15
    invoke-direct {p0, p1, p2}, Lh91/d;-><init>(Ljava/lang/Runnable;Ljava/lang/Throwable;)V

    .line 16
    .line 17
    .line 18
    sget-object p1, Lh91/e;->c:Lxy0/j;

    .line 19
    .line 20
    invoke-interface {p1, p0}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    throw p0
.end method
