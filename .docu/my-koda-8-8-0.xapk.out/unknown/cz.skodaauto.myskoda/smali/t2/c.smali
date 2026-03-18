.class public abstract Lt2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/Object;

.field public static final b:[Ljava/lang/StackTraceElement;

.field public static final c:Lt2/h;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt2/c;->a:Ljava/lang/Object;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [Ljava/lang/StackTraceElement;

    .line 10
    .line 11
    sput-object v0, Lt2/c;->b:[Ljava/lang/StackTraceElement;

    .line 12
    .line 13
    new-instance v0, Lt2/h;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    new-array v2, v1, [J

    .line 17
    .line 18
    new-array v3, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-direct {v0, v1, v2, v3}, Lt2/h;-><init>(I[J[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lt2/c;->c:Lt2/h;

    .line 24
    .line 25
    return-void
.end method

.method public static final a(II)I
    .locals 0

    .line 1
    rem-int/lit8 p1, p1, 0xa

    .line 2
    .line 3
    mul-int/lit8 p1, p1, 0x3

    .line 4
    .line 5
    add-int/lit8 p1, p1, 0x1

    .line 6
    .line 7
    shl-int/2addr p0, p1

    .line 8
    return p0
.end method

.method public static final b(ILl2/o;Llx0/e;)Lt2/b;
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {p0, v0}, Ljava/lang/Integer;->rotateLeft(II)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    sget-object v2, Lt2/c;->a:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-virtual {p1, v1, v2}, Ll2/t;->V(ILjava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 18
    .line 19
    if-ne v1, v2, :cond_0

    .line 20
    .line 21
    new-instance v1, Lt2/b;

    .line 22
    .line 23
    invoke-direct {v1, p2, v0, p0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const-string p0, "null cannot be cast to non-null type androidx.compose.runtime.internal.ComposableLambdaImpl"

    .line 31
    .line 32
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    check-cast v1, Lt2/b;

    .line 36
    .line 37
    invoke-virtual {v1, p2}, Lt2/b;->g(Llx0/e;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    const/4 p0, 0x0

    .line 41
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 42
    .line 43
    .line 44
    return-object v1
.end method

.method public static final c(ILay0/p;)Lt2/b;
    .locals 2

    .line 1
    new-instance v0, Lt2/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p1, v1, p0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public static final d()J
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Thread;->getId()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public static final e(Ll2/t;Lay0/n;)V
    .locals 1

    .line 1
    const-string v0, "null cannot be cast to non-null type kotlin.Function2<androidx.compose.runtime.Composer, kotlin.Int, kotlin.Unit>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    invoke-static {v0, p1}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-interface {p1, p0, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static final f(ILl2/o;Llx0/e;)Lt2/b;
    .locals 2

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 8
    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    new-instance v0, Lt2/b;

    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    invoke-direct {v0, p2, v1, p0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    check-cast v0, Lt2/b;

    .line 21
    .line 22
    invoke-virtual {v0, p2}, Lt2/b;->g(Llx0/e;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public static final g(Ll2/u1;Ll2/u1;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    instance-of v0, p0, Ll2/u1;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Ll2/u1;->b()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Ll2/u1;->c:Ll2/a;

    .line 20
    .line 21
    iget-object p1, p1, Ll2/u1;->c:Ll2/a;

    .line 22
    .line 23
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 33
    return p0
.end method
