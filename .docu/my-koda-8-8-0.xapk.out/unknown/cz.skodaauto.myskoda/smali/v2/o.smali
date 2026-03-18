.class public final Lv2/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Lv2/t;
.implements Ljava/util/List;
.implements Ljava/util/RandomAccess;
.implements Lby0/c;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lv2/o;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:Lv2/s;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lv2/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lv2/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lv2/o;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 8
    sget-object v0, Lp2/i;->e:Lp2/i;

    invoke-direct {p0, v0}, Lv2/o;-><init>(Lp2/c;)V

    return-void
.end method

.method public constructor <init>(Lp2/c;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v0

    .line 3
    new-instance v1, Lv2/s;

    invoke-virtual {v0}, Lv2/f;->g()J

    move-result-wide v2

    invoke-direct {v1, v2, v3, p1}, Lv2/s;-><init>(JLp2/c;)V

    .line 4
    instance-of v0, v0, Lv2/a;

    if-nez v0, :cond_0

    .line 5
    new-instance v0, Lv2/s;

    const/4 v2, 0x1

    int-to-long v2, v2

    invoke-direct {v0, v2, v3, p1}, Lv2/s;-><init>(JLp2/c;)V

    .line 6
    iput-object v0, v1, Lv2/v;->b:Lv2/v;

    .line 7
    :cond_0
    iput-object v1, p0, Lv2/o;->d:Lv2/s;

    return-void
.end method


# virtual methods
.method public final add(ILjava/lang/Object;)V
    .locals 6

    .line 22
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 23
    monitor-enter v0

    .line 24
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 25
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    .line 27
    iget v2, v1, Lv2/s;->d:I

    .line 28
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 29
    monitor-exit v0

    .line 30
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 31
    invoke-virtual {v1, p1, p2}, Lp2/c;->e(ILjava/lang/Object;)Lp2/c;

    move-result-object v0

    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    .line 33
    :cond_1
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 34
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 36
    monitor-enter v3

    .line 37
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v4

    .line 38
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    const/4 v5, 0x1

    .line 39
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    monitor-exit v3

    .line 41
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    if-eqz v0, :cond_0

    :goto_0
    return-void

    :catchall_0
    move-exception p0

    .line 42
    monitor-exit v3

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v0

    throw p0
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 2
    monitor-enter v0

    .line 3
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 4
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    .line 6
    iget v2, v1, Lv2/s;->d:I

    .line 7
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 8
    monitor-exit v0

    .line 9
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    invoke-virtual {v1, p1}, Lp2/c;->g(Ljava/lang/Object;)Lp2/c;

    move-result-object v0

    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 p0, 0x0

    return p0

    .line 12
    :cond_1
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 13
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 15
    monitor-enter v3

    .line 16
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v4

    .line 17
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    const/4 v5, 0x1

    .line 18
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 19
    monitor-exit v3

    .line 20
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p0

    .line 21
    monitor-exit v3

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v0

    throw p0
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 2

    .line 1
    new-instance v0, Lcz/m;

    const/4 v1, 0x2

    invoke-direct {v0, p1, p2, v1}, Lcz/m;-><init>(ILjava/util/Collection;I)V

    invoke-static {p0, v0}, Lv2/p;->g(Lv2/o;Lay0/k;)Z

    move-result p0

    return p0
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 6

    .line 2
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 5
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    .line 7
    iget v2, v1, Lv2/s;->d:I

    .line 8
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 9
    monitor-exit v0

    .line 10
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    invoke-virtual {v1, p1}, Lp2/c;->i(Ljava/util/Collection;)Lp2/c;

    move-result-object v0

    .line 12
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 p0, 0x0

    return p0

    .line 13
    :cond_1
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 14
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 16
    monitor-enter v3

    .line 17
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v4

    .line 18
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    const/4 v5, 0x1

    .line 19
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    monitor-exit v3

    .line 21
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p0

    .line 22
    monitor-exit v3

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v0

    throw p0
.end method

.method public final c(II)V
    .locals 6

    .line 1
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 5
    .line 6
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    .line 7
    .line 8
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lv2/s;

    .line 16
    .line 17
    iget v2, v1, Lv2/s;->d:I

    .line 18
    .line 19
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Lp2/c;->k()Lp2/f;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v0, p1, p2}, Ljava/util/AbstractList;->subList(II)Ljava/util/List;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-interface {v3}, Ljava/util/List;->clear()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Lp2/f;->g()Lp2/c;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-nez v1, :cond_1

    .line 45
    .line 46
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 47
    .line 48
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 54
    .line 55
    monitor-enter v3

    .line 56
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lv2/s;

    .line 65
    .line 66
    const/4 v5, 0x1

    .line 67
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    .line 68
    .line 69
    .line 70
    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    monitor-exit v3

    .line 72
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 73
    .line 74
    .line 75
    if-eqz v0, :cond_0

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :catchall_0
    move-exception p0

    .line 79
    monitor-exit v3

    .line 80
    throw p0

    .line 81
    :cond_1
    :goto_0
    return-void

    .line 82
    :catchall_1
    move-exception p0

    .line 83
    monitor-exit v0

    .line 84
    throw p0
.end method

.method public final clear()V
    .locals 5

    .line 1
    iget-object v0, p0, Lv2/o;->d:Lv2/s;

    .line 2
    .line 3
    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lv2/l;->c:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v1

    .line 11
    :try_start_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-static {v0, p0, v2}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lv2/s;

    .line 20
    .line 21
    sget-object v3, Lv2/p;->a:Ljava/lang/Object;

    .line 22
    .line 23
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    :try_start_1
    sget-object v4, Lp2/i;->e:Lp2/i;

    .line 25
    .line 26
    iput-object v4, v0, Lv2/s;->c:Lp2/c;

    .line 27
    .line 28
    iget v4, v0, Lv2/s;->d:I

    .line 29
    .line 30
    add-int/lit8 v4, v4, 0x1

    .line 31
    .line 32
    iput v4, v0, Lv2/s;->d:I

    .line 33
    .line 34
    iget v4, v0, Lv2/s;->e:I

    .line 35
    .line 36
    add-int/lit8 v4, v4, 0x1

    .line 37
    .line 38
    iput v4, v0, Lv2/s;->e:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 39
    .line 40
    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 41
    monitor-exit v1

    .line 42
    invoke-static {v2, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_0

    .line 48
    :catchall_1
    move-exception p0

    .line 49
    :try_start_3
    monitor-exit v3

    .line 50
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 51
    :goto_0
    monitor-exit v1

    .line 52
    throw p0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ljava/util/List;->containsAll(Ljava/util/Collection;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/o;->listIterator()Ljava/util/ListIterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final k()Lv2/v;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/o;->d:Lv2/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 2

    .line 1
    new-instance v0, Lnx0/a;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lnx0/a;-><init>(Lv2/o;I)V

    return-object v0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    .line 2
    new-instance v0, Lnx0/a;

    invoke-direct {v0, p0, p1}, Lnx0/a;-><init>(Lv2/o;I)V

    return-object v0
.end method

.method public final n(Lv2/v;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lv2/o;->d:Lv2/s;

    .line 2
    .line 3
    iput-object v0, p1, Lv2/v;->b:Lv2/v;

    .line 4
    .line 5
    check-cast p1, Lv2/s;

    .line 6
    .line 7
    iput-object p1, p0, Lv2/o;->d:Lv2/s;

    .line 8
    .line 9
    return-void
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p0, p1}, Lv2/o;->get(I)Ljava/lang/Object;

    move-result-object v0

    .line 2
    :cond_0
    sget-object v1, Lv2/p;->a:Ljava/lang/Object;

    .line 3
    monitor-enter v1

    .line 4
    :try_start_0
    iget-object v2, p0, Lv2/o;->d:Lv2/s;

    .line 5
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-static {v2}, Lv2/l;->i(Lv2/v;)Lv2/v;

    move-result-object v2

    check-cast v2, Lv2/s;

    .line 7
    iget v3, v2, Lv2/s;->d:I

    .line 8
    iget-object v2, v2, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 9
    monitor-exit v1

    .line 10
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    invoke-virtual {v2, p1}, Lp2/c;->n(I)Lp2/c;

    move-result-object v1

    .line 12
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_0

    .line 13
    :cond_1
    iget-object v2, p0, Lv2/o;->d:Lv2/s;

    .line 14
    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    sget-object v4, Lv2/l;->c:Ljava/lang/Object;

    .line 16
    monitor-enter v4

    .line 17
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v5

    .line 18
    invoke-static {v2, p0, v5}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    move-result-object v2

    check-cast v2, Lv2/s;

    const/4 v6, 0x1

    .line 19
    invoke-static {v2, v3, v1, v6}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 20
    monitor-exit v4

    .line 21
    invoke-static {v5, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    if-eqz v1, :cond_0

    :goto_0
    return-object v0

    :catchall_0
    move-exception p0

    .line 22
    monitor-exit v4

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v1

    throw p0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 6

    .line 23
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 24
    monitor-enter v0

    .line 25
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 26
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    .line 28
    iget v2, v1, Lv2/s;->d:I

    .line 29
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 30
    monitor-exit v0

    .line 31
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 32
    invoke-virtual {v1, p1}, Lmx0/e;->indexOf(Ljava/lang/Object;)I

    move-result v0

    const/4 v3, -0x1

    if-eq v0, v3, :cond_1

    .line 33
    invoke-virtual {v1, v0}, Lp2/c;->n(I)Lp2/c;

    move-result-object v0

    goto :goto_0

    :cond_1
    move-object v0, v1

    .line 34
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/4 p0, 0x0

    return p0

    .line 35
    :cond_2
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 36
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 38
    monitor-enter v3

    .line 39
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    move-result-object v4

    .line 40
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    move-result-object v1

    check-cast v1, Lv2/s;

    const/4 v5, 0x1

    .line 41
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    monitor-exit v3

    .line 43
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p0

    .line 44
    monitor-exit v3

    throw p0

    :catchall_1
    move-exception p0

    monitor-exit v0

    throw p0
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 6

    .line 1
    :cond_0
    sget-object v0, Lv2/p;->a:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 5
    .line 6
    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    .line 7
    .line 8
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {v1}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lv2/s;

    .line 16
    .line 17
    iget v2, v1, Lv2/s;->d:I

    .line 18
    .line 19
    iget-object v1, v1, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    .line 21
    monitor-exit v0

    .line 22
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    new-instance v0, Lp2/b;

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-direct {v0, v3, p1}, Lp2/b;-><init>(ILjava/util/Collection;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v0}, Lp2/c;->m(Lp2/b;)Lp2/c;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_1

    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    return p0

    .line 43
    :cond_1
    iget-object v1, p0, Lv2/o;->d:Lv2/s;

    .line 44
    .line 45
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    .line 46
    .line 47
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    sget-object v3, Lv2/l;->c:Ljava/lang/Object;

    .line 51
    .line 52
    monitor-enter v3

    .line 53
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    invoke-static {v1, p0, v4}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Lv2/s;

    .line 62
    .line 63
    const/4 v5, 0x1

    .line 64
    invoke-static {v1, v2, v0, v5}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    .line 65
    .line 66
    .line 67
    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    monitor-exit v3

    .line 69
    invoke-static {v4, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 70
    .line 71
    .line 72
    if-eqz v0, :cond_0

    .line 73
    .line 74
    return v5

    .line 75
    :catchall_0
    move-exception p0

    .line 76
    monitor-exit v3

    .line 77
    throw p0

    .line 78
    :catchall_1
    move-exception p0

    .line 79
    monitor-exit v0

    .line 80
    throw p0
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 2

    .line 1
    new-instance v0, Lp2/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1, p1}, Lp2/b;-><init>(ILjava/util/Collection;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Lv2/p;->g(Lv2/o;Lay0/k;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p0, p1}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    :cond_0
    sget-object v1, Lv2/p;->a:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    iget-object v2, p0, Lv2/o;->d:Lv2/s;

    .line 9
    .line 10
    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.withCurrent>"

    .line 11
    .line 12
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-static {v2}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Lv2/s;

    .line 20
    .line 21
    iget v3, v2, Lv2/s;->d:I

    .line 22
    .line 23
    iget-object v2, v2, Lv2/s;->c:Lp2/c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 24
    .line 25
    monitor-exit v1

    .line 26
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2, p1, p2}, Lp2/c;->o(ILjava/lang/Object;)Lp2/c;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    iget-object v2, p0, Lv2/o;->d:Lv2/s;

    .line 41
    .line 42
    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateListKt.writable>"

    .line 43
    .line 44
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    sget-object v4, Lv2/l;->c:Ljava/lang/Object;

    .line 48
    .line 49
    monitor-enter v4

    .line 50
    :try_start_1
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    invoke-static {v2, p0, v5}, Lv2/l;->w(Lv2/v;Lv2/t;Lv2/f;)Lv2/v;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Lv2/s;

    .line 59
    .line 60
    const/4 v6, 0x0

    .line 61
    invoke-static {v2, v3, v1, v6}, Lv2/p;->b(Lv2/s;ILp2/c;Z)Z

    .line 62
    .line 63
    .line 64
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 65
    monitor-exit v4

    .line 66
    invoke-static {v5, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 67
    .line 68
    .line 69
    if-eqz v1, :cond_0

    .line 70
    .line 71
    :goto_0
    return-object v0

    .line 72
    :catchall_0
    move-exception p0

    .line 73
    monitor-exit v4

    .line 74
    throw p0

    .line 75
    :catchall_1
    move-exception p0

    .line 76
    monitor-exit v1

    .line 77
    throw p0
.end method

.method public final size()I
    .locals 0

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final subList(II)Ljava/util/List;
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    if-gt p1, p2, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-gt p2, v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    if-nez v0, :cond_1

    .line 15
    .line 16
    const-string v0, "fromIndex or toIndex are out of bounds"

    .line 17
    .line 18
    invoke-static {v0}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    new-instance v0, Lv2/w;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1, p2}, Lv2/w;-><init>(Lv2/o;II)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/l;->a(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 0

    .line 2
    invoke-static {p0, p1}, Lkotlin/jvm/internal/l;->b(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lv2/o;->d:Lv2/s;

    .line 2
    .line 3
    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lv2/s;

    .line 13
    .line 14
    new-instance v1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v2, "SnapshotStateList(value="

    .line 17
    .line 18
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, v0, Lv2/s;->c:Lp2/c;

    .line 22
    .line 23
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    const-string v0, ")@"

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    invoke-static {p0}, Lv2/p;->e(Lv2/o;)Lv2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv2/s;->c:Lp2/c;

    .line 6
    .line 7
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    :goto_0
    if-ge v0, p2, :cond_0

    .line 16
    .line 17
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method
