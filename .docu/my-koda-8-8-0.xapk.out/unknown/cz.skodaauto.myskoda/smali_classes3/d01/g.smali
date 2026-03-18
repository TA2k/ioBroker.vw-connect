.class public final Ld01/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/io/Flushable;


# instance fields
.field public final d:Lf01/g;


# direct methods
.method public constructor <init>(Ljava/io/File;)V
    .locals 3

    .line 1
    const-string v0, "directory"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lu01/k;->d:Lu01/u;

    .line 7
    .line 8
    sget-object v1, Lu01/y;->e:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1}, Lrb0/a;->b(Ljava/io/File;)Lu01/y;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string v1, "fileSystem"

    .line 15
    .line 16
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    sget-object v1, Lg01/c;->l:Lg01/c;

    .line 20
    .line 21
    const-string v2, "taskRunner"

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v2, Lf01/g;

    .line 30
    .line 31
    invoke-direct {v2, v0, p1, v1}, Lf01/g;-><init>(Lu01/k;Lu01/y;Lg01/c;)V

    .line 32
    .line 33
    .line 34
    iput-object v2, p0, Ld01/g;->d:Lf01/g;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a(Ld01/k0;)V
    .locals 4

    .line 1
    const-string v0, "request"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ld01/g;->d:Lf01/g;

    .line 7
    .line 8
    iget-object p1, p1, Ld01/k0;->a:Ld01/a0;

    .line 9
    .line 10
    invoke-static {p1}, Ljp/pe;->b(Ld01/a0;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    monitor-enter p0

    .line 15
    :try_start_0
    const-string v0, "key"

    .line 16
    .line 17
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lf01/g;->g()V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lf01/g;->a()V

    .line 24
    .line 25
    .line 26
    invoke-static {p1}, Lf01/g;->H(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lf01/g;->l:Ljava/util/LinkedHashMap;

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    check-cast p1, Lf01/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    .line 37
    if-nez p1, :cond_0

    .line 38
    .line 39
    monitor-exit p0

    .line 40
    return-void

    .line 41
    :cond_0
    :try_start_1
    invoke-virtual {p0, p1}, Lf01/g;->B(Lf01/c;)V

    .line 42
    .line 43
    .line 44
    iget-wide v0, p0, Lf01/g;->j:J

    .line 45
    .line 46
    iget-wide v2, p0, Lf01/g;->f:J

    .line 47
    .line 48
    cmp-long p1, v0, v2

    .line 49
    .line 50
    if-gtz p1, :cond_1

    .line 51
    .line 52
    const/4 p1, 0x0

    .line 53
    iput-boolean p1, p0, Lf01/g;->r:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :catchall_0
    move-exception p1

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    :goto_0
    monitor-exit p0

    .line 59
    return-void

    .line 60
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 61
    throw p1
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/g;->d:Lf01/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Lf01/g;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final flush()V
    .locals 0

    .line 1
    iget-object p0, p0, Ld01/g;->d:Lf01/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Lf01/g;->flush()V

    .line 4
    .line 5
    .line 6
    return-void
.end method
