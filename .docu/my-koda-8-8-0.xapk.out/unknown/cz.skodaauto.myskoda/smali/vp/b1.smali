.class public final Lvp/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Thread$UncaughtExceptionHandler;


# instance fields
.field public final a:Ljava/lang/String;

.field public final synthetic b:Lvp/e1;


# direct methods
.method public constructor <init>(Lvp/e1;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvp/b1;->b:Lvp/e1;

    .line 5
    .line 6
    iput-object p2, p0, Lvp/b1;->a:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final declared-synchronized uncaughtException(Ljava/lang/Thread;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object p1, p0, Lvp/b1;->b:Lvp/e1;

    .line 3
    .line 4
    iget-object p1, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p1, Lvp/g1;

    .line 7
    .line 8
    iget-object p1, p1, Lvp/g1;->i:Lvp/p0;

    .line 9
    .line 10
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lvp/p0;->j:Lvp/n0;

    .line 14
    .line 15
    iget-object v0, p0, Lvp/b1;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {p1, p2, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    .line 20
    monitor-exit p0

    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    throw p1
.end method
