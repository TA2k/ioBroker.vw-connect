.class public final Ly7/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly7/h;


# instance fields
.field public final d:Ly7/h;

.field public e:J

.field public f:Landroid/net/Uri;


# direct methods
.method public constructor <init>(Ly7/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Ly7/y;->d:Ly7/h;

    .line 8
    .line 9
    sget-object p1, Landroid/net/Uri;->EMPTY:Landroid/net/Uri;

    .line 10
    .line 11
    iput-object p1, p0, Ly7/y;->f:Landroid/net/Uri;

    .line 12
    .line 13
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/y;->d:Ly7/h;

    .line 2
    .line 3
    invoke-interface {p0}, Ly7/h;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final d()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/y;->d:Ly7/h;

    .line 2
    .line 3
    invoke-interface {p0}, Ly7/h;->d()Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final g(Ly7/j;)J
    .locals 3

    .line 1
    iget-object v0, p0, Ly7/y;->d:Ly7/h;

    .line 2
    .line 3
    iget-object v1, p1, Ly7/j;->a:Landroid/net/Uri;

    .line 4
    .line 5
    iput-object v1, p0, Ly7/y;->f:Landroid/net/Uri;

    .line 6
    .line 7
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 8
    .line 9
    :try_start_0
    invoke-interface {v0, p1}, Ly7/h;->g(Ly7/j;)J

    .line 10
    .line 11
    .line 12
    move-result-wide v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    invoke-interface {v0}, Ly7/h;->getUri()Landroid/net/Uri;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iput-object p1, p0, Ly7/y;->f:Landroid/net/Uri;

    .line 20
    .line 21
    :cond_0
    invoke-interface {v0}, Ly7/h;->d()Ljava/util/Map;

    .line 22
    .line 23
    .line 24
    return-wide v1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    invoke-interface {v0}, Ly7/h;->getUri()Landroid/net/Uri;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    iput-object v1, p0, Ly7/y;->f:Landroid/net/Uri;

    .line 33
    .line 34
    :cond_1
    invoke-interface {v0}, Ly7/h;->d()Ljava/util/Map;

    .line 35
    .line 36
    .line 37
    throw p1
.end method

.method public final getUri()Landroid/net/Uri;
    .locals 0

    .line 1
    iget-object p0, p0, Ly7/y;->d:Ly7/h;

    .line 2
    .line 3
    invoke-interface {p0}, Ly7/h;->getUri()Landroid/net/Uri;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final l(Ly7/z;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ly7/y;->d:Ly7/h;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ly7/h;->l(Ly7/z;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final read([BII)I
    .locals 2

    .line 1
    iget-object v0, p0, Ly7/y;->d:Ly7/h;

    .line 2
    .line 3
    invoke-interface {v0, p1, p2, p3}, Lt7/g;->read([BII)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 p2, -0x1

    .line 8
    if-eq p1, p2, :cond_0

    .line 9
    .line 10
    iget-wide p2, p0, Ly7/y;->e:J

    .line 11
    .line 12
    int-to-long v0, p1

    .line 13
    add-long/2addr p2, v0

    .line 14
    iput-wide p2, p0, Ly7/y;->e:J

    .line 15
    .line 16
    :cond_0
    return p1
.end method
