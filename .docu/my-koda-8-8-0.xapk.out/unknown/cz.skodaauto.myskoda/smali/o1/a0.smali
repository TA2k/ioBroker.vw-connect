.class public final Lo1/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lu2/c;

.field public final b:Lio0/f;

.field public final c:Landroidx/collection/q0;


# direct methods
.method public constructor <init>(Lu2/c;Lio0/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/a0;->a:Lu2/c;

    .line 5
    .line 6
    iput-object p2, p0, Lo1/a0;->b:Lio0/f;

    .line 7
    .line 8
    sget-object p1, Landroidx/collection/y0;->a:[J

    .line 9
    .line 10
    new-instance p1, Landroidx/collection/q0;

    .line 11
    .line 12
    invoke-direct {p1}, Landroidx/collection/q0;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lo1/a0;->c:Landroidx/collection/q0;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(ILjava/lang/Object;Ljava/lang/Object;)Lay0/n;
    .locals 5

    .line 1
    iget-object v0, p0, Lo1/a0;->c:Landroidx/collection/q0;

    .line 2
    .line 3
    invoke-virtual {v0, p2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lo1/z;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    const v3, 0x30c58c04

    .line 11
    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    iget v4, v1, Lo1/z;->c:I

    .line 16
    .line 17
    if-ne v4, p1, :cond_1

    .line 18
    .line 19
    iget-object v4, v1, Lo1/z;->b:Ljava/lang/Object;

    .line 20
    .line 21
    invoke-static {v4, p3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-eqz v4, :cond_1

    .line 26
    .line 27
    iget-object p0, v1, Lo1/z;->d:Lt2/b;

    .line 28
    .line 29
    if-nez p0, :cond_0

    .line 30
    .line 31
    new-instance p0, Laa/p;

    .line 32
    .line 33
    iget-object p1, v1, Lo1/z;->e:Lo1/a0;

    .line 34
    .line 35
    const/16 p2, 0x10

    .line 36
    .line 37
    invoke-direct {p0, p2, p1, v1}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    new-instance p1, Lt2/b;

    .line 41
    .line 42
    invoke-direct {p1, p0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 43
    .line 44
    .line 45
    iput-object p1, v1, Lo1/z;->d:Lt2/b;

    .line 46
    .line 47
    return-object p1

    .line 48
    :cond_0
    return-object p0

    .line 49
    :cond_1
    new-instance v1, Lo1/z;

    .line 50
    .line 51
    invoke-direct {v1, p0, p1, p2, p3}, Lo1/z;-><init>(Lo1/a0;ILjava/lang/Object;Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, p2, v1}, Landroidx/collection/q0;->m(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p1, v1, Lo1/z;->d:Lt2/b;

    .line 58
    .line 59
    if-nez p1, :cond_2

    .line 60
    .line 61
    new-instance p1, Laa/p;

    .line 62
    .line 63
    const/16 p2, 0x10

    .line 64
    .line 65
    invoke-direct {p1, p2, p0, v1}, Laa/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance p0, Lt2/b;

    .line 69
    .line 70
    invoke-direct {p0, p1, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 71
    .line 72
    .line 73
    iput-object p0, v1, Lo1/z;->d:Lt2/b;

    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_2
    return-object p1
.end method

.method public final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    iget-object v0, p0, Lo1/a0;->c:Landroidx/collection/q0;

    .line 5
    .line 6
    invoke-virtual {v0, p1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lo1/z;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object p0, v0, Lo1/z;->b:Ljava/lang/Object;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_1
    iget-object p0, p0, Lo1/a0;->b:Lio0/f;

    .line 18
    .line 19
    invoke-virtual {p0}, Lio0/f;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lo1/b0;

    .line 24
    .line 25
    invoke-interface {p0, p1}, Lo1/b0;->c(Ljava/lang/Object;)I

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    const/4 v0, -0x1

    .line 30
    if-eq p1, v0, :cond_2

    .line 31
    .line 32
    invoke-interface {p0, p1}, Lo1/b0;->b(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_2
    :goto_0
    const/4 p0, 0x0

    .line 38
    return-object p0
.end method
