.class public final Lcm/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/AutoCloseable;


# instance fields
.field public final d:Lcm/a;

.field public e:Z

.field public final synthetic f:Lcm/d;


# direct methods
.method public constructor <init>(Lcm/d;Lcm/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcm/b;->f:Lcm/d;

    .line 5
    .line 6
    iput-object p2, p0, Lcm/b;->d:Lcm/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lcm/b;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lcm/b;->e:Z

    .line 7
    .line 8
    iget-object v0, p0, Lcm/b;->f:Lcm/d;

    .line 9
    .line 10
    iget-object v1, v0, Lcm/d;->k:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v1

    .line 13
    :try_start_0
    iget-object p0, p0, Lcm/b;->d:Lcm/a;

    .line 14
    .line 15
    iget v2, p0, Lcm/a;->h:I

    .line 16
    .line 17
    add-int/lit8 v2, v2, -0x1

    .line 18
    .line 19
    iput v2, p0, Lcm/a;->h:I

    .line 20
    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    iget-boolean v2, p0, Lcm/a;->f:Z

    .line 24
    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Lcm/d;->l(Lcm/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    :goto_0
    monitor-exit v1

    .line 34
    return-void

    .line 35
    :goto_1
    monitor-exit v1

    .line 36
    throw p0

    .line 37
    :cond_1
    return-void
.end method
