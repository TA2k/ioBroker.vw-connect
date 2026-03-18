.class public final Ll2/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public final d:Lvy0/b0;


# direct methods
.method public constructor <init>(Lvy0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/d0;->d:Lvy0/b0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 0

    .line 1
    return-void
.end method

.method public final e()V
    .locals 2

    .line 1
    iget-object p0, p0, Ll2/d0;->d:Lvy0/b0;

    .line 2
    .line 3
    instance-of v0, p0, Ll2/c2;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Ll2/c2;

    .line 8
    .line 9
    invoke-virtual {p0}, Ll2/c2;->a()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance v0, Ll2/m0;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, v1}, Ll2/m0;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v0}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final h()V
    .locals 2

    .line 1
    iget-object p0, p0, Ll2/d0;->d:Lvy0/b0;

    .line 2
    .line 3
    instance-of v0, p0, Ll2/c2;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Ll2/c2;

    .line 8
    .line 9
    invoke-virtual {p0}, Ll2/c2;->a()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    new-instance v0, Ll2/m0;

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    invoke-direct {v0, v1}, Ll2/m0;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v0}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
