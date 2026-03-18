.class public final Lf01/b;
.super Lu01/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public e:Z

.field public final synthetic f:Lf01/g;

.field public final synthetic g:Lf01/c;


# direct methods
.method public constructor <init>(Lu01/h0;Lf01/g;Lf01/c;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lf01/b;->f:Lf01/g;

    .line 2
    .line 3
    iput-object p3, p0, Lf01/b;->g:Lf01/c;

    .line 4
    .line 5
    invoke-direct {p0, p1}, Lu01/n;-><init>(Lu01/h0;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 2

    .line 1
    invoke-super {p0}, Lu01/n;->close()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p0, Lf01/b;->e:Z

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Lf01/b;->e:Z

    .line 10
    .line 11
    iget-object v0, p0, Lf01/b;->f:Lf01/g;

    .line 12
    .line 13
    iget-object p0, p0, Lf01/b;->g:Lf01/c;

    .line 14
    .line 15
    monitor-enter v0

    .line 16
    :try_start_0
    iget v1, p0, Lf01/c;->h:I

    .line 17
    .line 18
    add-int/lit8 v1, v1, -0x1

    .line 19
    .line 20
    iput v1, p0, Lf01/c;->h:I

    .line 21
    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    iget-boolean v1, p0, Lf01/c;->f:Z

    .line 25
    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Lf01/g;->B(Lf01/c;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    :goto_0
    monitor-exit v0

    .line 35
    return-void

    .line 36
    :goto_1
    monitor-exit v0

    .line 37
    throw p0

    .line 38
    :cond_1
    return-void
.end method
