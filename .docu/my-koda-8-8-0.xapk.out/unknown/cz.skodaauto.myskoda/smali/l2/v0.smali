.class public final Ll2/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;
.implements Lvy0/z;


# instance fields
.field public final d:Lpx0/g;

.field public final e:Lay0/n;

.field public final f:Lpw0/a;

.field public g:Lvy0/x1;


# direct methods
.method public constructor <init>(Lpx0/g;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/v0;->d:Lpx0/g;

    .line 5
    .line 6
    iput-object p2, p0, Ll2/v0;->e:Lay0/n;

    .line 7
    .line 8
    sget-object p2, Lw2/b;->e:Lfv/b;

    .line 9
    .line 10
    invoke-interface {p1, p2}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    move-object p2, p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    sget-object p2, Lpx0/h;->d:Lpx0/h;

    .line 19
    .line 20
    :goto_0
    invoke-interface {p1, p2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Ll2/v0;->f:Lpw0/a;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v1, "Old job was still running!"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object v0, p0, Ll2/v0;->e:Lay0/n;

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    iget-object v2, p0, Ll2/v0;->f:Lpw0/a;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static {v2, v3, v3, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 21
    .line 22
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ll2/m0;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v1, v2}, Ll2/m0;-><init>(I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lvy0/p1;->A(Ljava/util/concurrent/CancellationException;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    iput-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 16
    .line 17
    return-void
.end method

.method public final fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p2, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final get(Lpx0/f;)Lpx0/e;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->b(Lpx0/e;Lpx0/f;)Lpx0/e;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getKey()Lpx0/f;
    .locals 0

    .line 1
    sget-object p0, Lvy0/y;->d:Lvy0/y;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h()V
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v1, Ll2/m0;

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-direct {v1, v2}, Ll2/m0;-><init>(I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lvy0/p1;->A(Ljava/util/concurrent/CancellationException;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    iput-object v0, p0, Ll2/v0;->g:Lvy0/x1;

    .line 16
    .line 17
    return-void
.end method

.method public final handleException(Lpx0/g;Ljava/lang/Throwable;)V
    .locals 3

    .line 1
    sget-object v0, Lw2/b;->e:Lfv/b;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lw2/b;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    new-instance v1, Lvu/d;

    .line 12
    .line 13
    const/4 v2, 0x4

    .line 14
    invoke-direct {v1, v2, v0, p0}, Lvu/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p2, v1}, Llp/tc;->c(Ljava/lang/Throwable;Lay0/a;)Z

    .line 18
    .line 19
    .line 20
    :cond_0
    iget-object p0, p0, Ll2/v0;->d:Lpx0/g;

    .line 21
    .line 22
    sget-object v0, Lvy0/y;->d:Lvy0/y;

    .line 23
    .line 24
    invoke-interface {p0, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lvy0/z;

    .line 29
    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    invoke-interface {p0, p1, p2}, Lvy0/z;->handleException(Lpx0/g;Ljava/lang/Throwable;)V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_1
    throw p2
.end method

.method public final minusKey(Lpx0/f;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->c(Lpx0/e;Lpx0/f;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final plus(Lpx0/g;)Lpx0/g;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljp/de;->d(Lpx0/e;Lpx0/g;)Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
