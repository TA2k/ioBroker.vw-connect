.class public final Lwz0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final d:Lvz0/d;

.field public final e:Lwz0/z;

.field public final f:Lqz0/a;


# direct methods
.method public constructor <init>(Lvz0/d;Lwz0/z;Lqz0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwz0/o;->d:Lvz0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lwz0/o;->e:Lwz0/z;

    .line 7
    .line 8
    iput-object p3, p0, Lwz0/o;->f:Lqz0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lwz0/o;->e:Lwz0/z;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->x()B

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/16 v0, 0xa

    .line 8
    .line 9
    if-eq p0, v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final next()Ljava/lang/Object;
    .locals 7

    .line 1
    new-instance v0, Lwz0/a0;

    .line 2
    .line 3
    sget-object v2, Lwz0/f0;->f:Lwz0/f0;

    .line 4
    .line 5
    iget-object v6, p0, Lwz0/o;->f:Lqz0/a;

    .line 6
    .line 7
    invoke-interface {v6}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 8
    .line 9
    .line 10
    move-result-object v4

    .line 11
    const/4 v5, 0x0

    .line 12
    iget-object v1, p0, Lwz0/o;->d:Lvz0/d;

    .line 13
    .line 14
    iget-object v3, p0, Lwz0/o;->e:Lwz0/z;

    .line 15
    .line 16
    invoke-direct/range {v0 .. v5}, Lwz0/a0;-><init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v6}, Lwz0/a0;->d(Lqz0/a;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public final remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "Operation is not supported for read-only collection"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
