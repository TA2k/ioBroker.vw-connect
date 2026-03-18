.class public final Lvp/w;
.super Lvp/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Landroidx/collection/f;

.field public final g:Landroidx/collection/f;

.field public h:J


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lap0/o;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Landroidx/collection/f;

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lvp/w;->g:Landroidx/collection/f;

    .line 11
    .line 12
    new-instance p1, Landroidx/collection/f;

    .line 13
    .line 14
    invoke-direct {p1, v0}, Landroidx/collection/a1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lvp/w;->f:Landroidx/collection/f;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final b0(JLjava/lang/String;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    if-eqz p3, :cond_1

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 15
    .line 16
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Lvp/a;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    move-object v2, p0

    .line 23
    move-wide v4, p1

    .line 24
    move-object v3, p3

    .line 25
    invoke-direct/range {v1 .. v6}, Lvp/a;-><init>(Lvp/w;Ljava/lang/String;JI)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    :goto_0
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 33
    .line 34
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 38
    .line 39
    const-string p1, "Ad unit id must be a non-empty string"

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final c0(JLjava/lang/String;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    if-eqz p3, :cond_1

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object v0, v0, Lvp/g1;->j:Lvp/e1;

    .line 15
    .line 16
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    new-instance v1, Lvp/a;

    .line 20
    .line 21
    const/4 v6, 0x1

    .line 22
    move-object v2, p0

    .line 23
    move-wide v4, p1

    .line 24
    move-object v3, p3

    .line 25
    invoke-direct/range {v1 .. v6}, Lvp/a;-><init>(Lvp/w;Ljava/lang/String;JI)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    :goto_0
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 33
    .line 34
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 38
    .line 39
    const-string p1, "Ad unit id must be a non-empty string"

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public final d0(J)V
    .locals 6

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    iget-object v0, v0, Lvp/g1;->o:Lvp/u2;

    .line 6
    .line 7
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 8
    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {v0, v1}, Lvp/u2;->g0(Z)Lvp/r2;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lvp/w;->f:Landroidx/collection/f;

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    check-cast v3, Ljava/lang/String;

    .line 36
    .line 37
    invoke-interface {v1, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Ljava/lang/Long;

    .line 42
    .line 43
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 44
    .line 45
    .line 46
    move-result-wide v4

    .line 47
    sub-long v4, p1, v4

    .line 48
    .line 49
    invoke-virtual {p0, v3, v4, v5, v0}, Lvp/w;->f0(Ljava/lang/String;JLvp/r2;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-nez v1, :cond_1

    .line 58
    .line 59
    iget-wide v1, p0, Lvp/w;->h:J

    .line 60
    .line 61
    sub-long v1, p1, v1

    .line 62
    .line 63
    invoke-virtual {p0, v1, v2, v0}, Lvp/w;->e0(JLvp/r2;)V

    .line 64
    .line 65
    .line 66
    :cond_1
    invoke-virtual {p0, p1, p2}, Lvp/w;->g0(J)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final e0(JLvp/r2;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    if-nez p3, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 8
    .line 9
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 13
    .line 14
    const-string p1, "Not logging ad exposure. No active activity"

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    const-wide/16 v0, 0x3e8

    .line 21
    .line 22
    cmp-long v0, p1, v0

    .line 23
    .line 24
    if-gez v0, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 27
    .line 28
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 32
    .line 33
    const-string p3, "Not logging ad exposure. Less than 1000 ms. exposure"

    .line 34
    .line 35
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-virtual {p0, p1, p3}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_1
    new-instance v0, Landroid/os/Bundle;

    .line 44
    .line 45
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 46
    .line 47
    .line 48
    const-string v1, "_xt"

    .line 49
    .line 50
    invoke-virtual {v0, v1, p1, p2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 51
    .line 52
    .line 53
    const/4 p1, 0x1

    .line 54
    invoke-static {p3, v0, p1}, Lvp/d4;->R0(Lvp/r2;Landroid/os/Bundle;Z)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 58
    .line 59
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 60
    .line 61
    .line 62
    const-string p1, "am"

    .line 63
    .line 64
    const-string p2, "_xa"

    .line 65
    .line 66
    invoke-virtual {p0, p1, p2, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public final f0(Ljava/lang/String;JLvp/r2;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    if-nez p4, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 8
    .line 9
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 13
    .line 14
    const-string p1, "Not logging ad unit exposure. No active activity"

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    const-wide/16 v0, 0x3e8

    .line 21
    .line 22
    cmp-long v0, p2, v0

    .line 23
    .line 24
    if-gez v0, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 27
    .line 28
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Lvp/p0;->r:Lvp/n0;

    .line 32
    .line 33
    const-string p1, "Not logging ad unit exposure. Less than 1000 ms. exposure"

    .line 34
    .line 35
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_1
    new-instance v0, Landroid/os/Bundle;

    .line 44
    .line 45
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 46
    .line 47
    .line 48
    const-string v1, "_ai"

    .line 49
    .line 50
    invoke-virtual {v0, v1, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const-string p1, "_xt"

    .line 54
    .line 55
    invoke-virtual {v0, p1, p2, p3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 56
    .line 57
    .line 58
    const/4 p1, 0x1

    .line 59
    invoke-static {p4, v0, p1}, Lvp/d4;->R0(Lvp/r2;Landroid/os/Bundle;Z)V

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lvp/g1;->p:Lvp/j2;

    .line 63
    .line 64
    invoke-static {p0}, Lvp/g1;->i(Lvp/b0;)V

    .line 65
    .line 66
    .line 67
    const-string p1, "am"

    .line 68
    .line 69
    const-string p2, "_xu"

    .line 70
    .line 71
    invoke-virtual {p0, p1, p2, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public final g0(J)V
    .locals 4

    .line 1
    iget-object v0, p0, Lvp/w;->f:Landroidx/collection/f;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {p1, p2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-interface {v0, v2, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_1

    .line 36
    .line 37
    iput-wide p1, p0, Lvp/w;->h:J

    .line 38
    .line 39
    :cond_1
    return-void
.end method
