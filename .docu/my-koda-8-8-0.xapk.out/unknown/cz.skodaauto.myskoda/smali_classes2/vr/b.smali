.class public final Lvr/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvp/k2;


# instance fields
.field public final synthetic a:Lcom/google/android/gms/internal/measurement/k1;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/k1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/h0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/android/gms/internal/measurement/d1;

    .line 7
    .line 8
    const/4 v2, 0x3

    .line 9
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0, v2}, Lcom/google/android/gms/internal/measurement/d1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/h0;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 v1, 0x1f4

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/internal/measurement/h0;->b(J)Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-class v0, Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->c(Landroid/os/Bundle;Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/h0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/android/gms/internal/measurement/d1;

    .line 7
    .line 8
    const/4 v2, 0x4

    .line 9
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0, v2}, Lcom/google/android/gms/internal/measurement/d1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/h0;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 v1, 0x1f4

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/internal/measurement/h0;->b(J)Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-class v0, Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->c(Landroid/os/Bundle;Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method public final c(Landroid/os/Bundle;)V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/y0;

    .line 2
    .line 3
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1}, Lcom/google/android/gms/internal/measurement/y0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Landroid/os/Bundle;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final d(Ljava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/a1;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 5
    .line 6
    invoke-direct {v0, p0, p1, v1}, Lcom/google/android/gms/internal/measurement/a1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final e(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 6

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/x0;

    .line 2
    .line 3
    iget-object v1, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    move-object v2, p1

    .line 7
    move-object v3, p2

    .line 8
    move-object v4, p3

    .line 9
    invoke-direct/range {v0 .. v5}, Lcom/google/android/gms/internal/measurement/x0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;Z)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final f(Ljava/lang/String;)V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/a1;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 5
    .line 6
    invoke-direct {v0, p0, p1, v1}, Lcom/google/android/gms/internal/measurement/a1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public final g()J
    .locals 5

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/h0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/android/gms/internal/measurement/d1;

    .line 7
    .line 8
    const/4 v2, 0x2

    .line 9
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0, v2}, Lcom/google/android/gms/internal/measurement/d1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/h0;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 v1, 0x1f4

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/internal/measurement/h0;->b(J)Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    const-class v1, Ljava/lang/Long;

    .line 24
    .line 25
    invoke-static {v0, v1}, Lcom/google/android/gms/internal/measurement/h0;->c(Landroid/os/Bundle;Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Ljava/lang/Long;

    .line 30
    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    new-instance v0, Ljava/util/Random;

    .line 34
    .line 35
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 36
    .line 37
    .line 38
    move-result-wide v1

    .line 39
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    xor-long/2addr v1, v3

    .line 44
    invoke-direct {v0, v1, v2}, Ljava/util/Random;-><init>(J)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/util/Random;->nextLong()J

    .line 48
    .line 49
    .line 50
    move-result-wide v0

    .line 51
    iget v2, p0, Lcom/google/android/gms/internal/measurement/k1;->d:I

    .line 52
    .line 53
    add-int/lit8 v2, v2, 0x1

    .line 54
    .line 55
    iput v2, p0, Lcom/google/android/gms/internal/measurement/k1;->d:I

    .line 56
    .line 57
    int-to-long v2, v2

    .line 58
    add-long/2addr v0, v2

    .line 59
    return-wide v0

    .line 60
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 61
    .line 62
    .line 63
    move-result-wide v0

    .line 64
    return-wide v0
.end method

.method public final h(Ljava/lang/String;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/k1;->b(Ljava/lang/String;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final i()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/h0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/android/gms/internal/measurement/d1;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0, v2}, Lcom/google/android/gms/internal/measurement/d1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/h0;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 v1, 0x32

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/internal/measurement/h0;->b(J)Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-class v0, Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->c(Landroid/os/Bundle;Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method public final j()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/gms/internal/measurement/h0;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lcom/google/android/gms/internal/measurement/d1;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 10
    .line 11
    invoke-direct {v1, p0, v0, v2}, Lcom/google/android/gms/internal/measurement/d1;-><init>(Lcom/google/android/gms/internal/measurement/k1;Lcom/google/android/gms/internal/measurement/h0;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 15
    .line 16
    .line 17
    const-wide/16 v1, 0x1f4

    .line 18
    .line 19
    invoke-virtual {v0, v1, v2}, Lcom/google/android/gms/internal/measurement/h0;->b(J)Landroid/os/Bundle;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-class v0, Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p0, v0}, Lcom/google/android/gms/internal/measurement/h0;->c(Landroid/os/Bundle;Ljava/lang/Class;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method public final k(Ljava/lang/String;Ljava/lang/String;Z)Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/gms/internal/measurement/k1;->a(Ljava/lang/String;Ljava/lang/String;Z)Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final l(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/z0;

    .line 2
    .line 3
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1, p2, p3}, Lcom/google/android/gms/internal/measurement/z0;-><init>(Lcom/google/android/gms/internal/measurement/k1;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/k1;->c(Lcom/google/android/gms/internal/measurement/g1;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final m(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lvr/b;->a:Lcom/google/android/gms/internal/measurement/k1;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcom/google/android/gms/internal/measurement/k1;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
