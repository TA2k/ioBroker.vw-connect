.class public final Lhm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh6/j;

.field public final b:Lhm/g;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lh6/j;Lhm/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhm/d;->a:Lh6/j;

    .line 5
    .line 6
    iput-object p2, p0, Lhm/d;->b:Lhm/g;

    .line 7
    .line 8
    new-instance p1, Ljava/lang/Object;

    .line 9
    .line 10
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lhm/d;->c:Ljava/lang/Object;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final a(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lhm/d;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lhm/d;->a:Lh6/j;

    .line 5
    .line 6
    iget-object p0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lc1/i2;

    .line 9
    .line 10
    iput-wide p1, p0, Lc1/i2;->d:J

    .line 11
    .line 12
    invoke-virtual {p0, p1, p2}, Lc1/i2;->g(J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-void

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0

    .line 19
    throw p0
.end method
