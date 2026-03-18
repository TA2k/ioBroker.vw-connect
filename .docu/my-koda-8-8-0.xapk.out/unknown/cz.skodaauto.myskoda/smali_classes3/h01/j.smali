.class public final Lh01/j;
.super Lg01/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:Lh01/u;

.field public final synthetic f:Lh01/k;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lh01/u;Lh01/k;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lh01/j;->e:Lh01/u;

    .line 2
    .line 3
    iput-object p3, p0, Lh01/j;->f:Lh01/k;

    .line 4
    .line 5
    const/4 p2, 0x1

    .line 6
    invoke-direct {p0, p1, p2}, Lg01/a;-><init>(Ljava/lang/String;Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 5

    .line 1
    iget-object v0, p0, Lh01/j;->e:Lh01/u;

    .line 2
    .line 3
    :try_start_0
    invoke-interface {v0}, Lh01/u;->g()Lh01/t;

    .line 4
    .line 5
    .line 6
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    goto :goto_0

    .line 8
    :catchall_0
    move-exception v1

    .line 9
    new-instance v2, Lh01/t;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    const/4 v4, 0x2

    .line 13
    invoke-direct {v2, v0, v3, v1, v4}, Lh01/t;-><init>(Lh01/u;Lh01/c;Ljava/lang/Throwable;I)V

    .line 14
    .line 15
    .line 16
    move-object v1, v2

    .line 17
    :goto_0
    iget-object p0, p0, Lh01/j;->f:Lh01/k;

    .line 18
    .line 19
    iget-object v2, p0, Lh01/k;->i:Ljava/io/Serializable;

    .line 20
    .line 21
    check-cast v2, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 22
    .line 23
    invoke-virtual {v2, v0}, Ljava/util/concurrent/CopyOnWriteArrayList;->contains(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object p0, p0, Lh01/k;->j:Ljava/lang/Iterable;

    .line 30
    .line 31
    check-cast p0, Ljava/util/concurrent/LinkedBlockingDeque;

    .line 32
    .line 33
    invoke-virtual {p0, v1}, Ljava/util/concurrent/LinkedBlockingDeque;->put(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    const-wide/16 v0, -0x1

    .line 37
    .line 38
    return-wide v0
.end method
