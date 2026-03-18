.class public abstract Ll2/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroidx/compose/runtime/DisposableEffectScope;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/runtime/DisposableEffectScope;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/compose/runtime/DisposableEffectScope;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ll2/l0;->a:Landroidx/compose/runtime/DisposableEffectScope;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(Ljava/lang/Object;Lay0/k;Ll2/o;)V
    .locals 1

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 14
    .line 15
    if-ne v0, p0, :cond_1

    .line 16
    .line 17
    :cond_0
    new-instance v0, Ll2/i0;

    .line 18
    .line 19
    invoke-direct {v0, p1}, Ll2/i0;-><init>(Lay0/k;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :cond_1
    check-cast v0, Ll2/i0;

    .line 26
    .line 27
    return-void
.end method

.method public static final b(Ljava/lang/Object;Ljava/lang/Object;Lay0/k;Ll2/o;)V
    .locals 0

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    or-int/2addr p0, p1

    .line 12
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-nez p0, :cond_0

    .line 17
    .line 18
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 19
    .line 20
    if-ne p1, p0, :cond_1

    .line 21
    .line 22
    :cond_0
    new-instance p1, Ll2/i0;

    .line 23
    .line 24
    invoke-direct {p1, p2}, Ll2/i0;-><init>(Lay0/k;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p3, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    check-cast p1, Ll2/i0;

    .line 31
    .line 32
    return-void
.end method

.method public static final c([Ljava/lang/Object;Lay0/k;Ll2/o;)V
    .locals 5

    .line 1
    array-length v0, p0

    .line 2
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    array-length v0, p0

    .line 7
    const/4 v1, 0x0

    .line 8
    move v2, v1

    .line 9
    :goto_0
    if-ge v1, v0, :cond_0

    .line 10
    .line 11
    aget-object v3, p0, v1

    .line 12
    .line 13
    move-object v4, p2

    .line 14
    check-cast v4, Ll2/t;

    .line 15
    .line 16
    invoke-virtual {v4, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    or-int/2addr v2, v3

    .line 21
    add-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    check-cast p2, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-nez v2, :cond_2

    .line 31
    .line 32
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 33
    .line 34
    if-ne p0, v0, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    return-void

    .line 38
    :cond_2
    :goto_1
    new-instance p0, Ll2/i0;

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ll2/i0;-><init>(Lay0/k;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p2, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public static final d(Lay0/n;Ljava/lang/Object;Ll2/o;)V
    .locals 2

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    iget-object v0, p2, Ll2/t;->R:Lpx0/g;

    .line 4
    .line 5
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 16
    .line 17
    if-ne v1, p1, :cond_1

    .line 18
    .line 19
    :cond_0
    new-instance v1, Ll2/v0;

    .line 20
    .line 21
    invoke-direct {v1, v0, p0}, Ll2/v0;-><init>(Lpx0/g;Lay0/n;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    check-cast v1, Ll2/v0;

    .line 28
    .line 29
    return-void
.end method

.method public static final e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V
    .locals 1

    .line 1
    check-cast p3, Ll2/t;

    .line 2
    .line 3
    iget-object v0, p3, Ll2/t;->R:Lpx0/g;

    .line 4
    .line 5
    invoke-virtual {p3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    or-int/2addr p0, p1

    .line 14
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 21
    .line 22
    if-ne p1, p0, :cond_1

    .line 23
    .line 24
    :cond_0
    new-instance p1, Ll2/v0;

    .line 25
    .line 26
    invoke-direct {p1, v0, p2}, Ll2/v0;-><init>(Lpx0/g;Lay0/n;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p3, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_1
    check-cast p1, Ll2/v0;

    .line 33
    .line 34
    return-void
.end method

.method public static final f([Ljava/lang/Object;Lay0/n;Ll2/o;)V
    .locals 5

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    iget-object v0, p2, Ll2/t;->R:Lpx0/g;

    .line 4
    .line 5
    array-length v1, p0

    .line 6
    invoke-static {p0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    array-length v1, p0

    .line 11
    const/4 v2, 0x0

    .line 12
    move v3, v2

    .line 13
    :goto_0
    if-ge v2, v1, :cond_0

    .line 14
    .line 15
    aget-object v4, p0, v2

    .line 16
    .line 17
    invoke-virtual {p2, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v4

    .line 21
    or-int/2addr v3, v4

    .line 22
    add-int/lit8 v2, v2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    if-nez v3, :cond_2

    .line 30
    .line 31
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 32
    .line 33
    if-ne p0, v1, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    return-void

    .line 37
    :cond_2
    :goto_1
    new-instance p0, Ll2/v0;

    .line 38
    .line 39
    invoke-direct {p0, v0, p1}, Ll2/v0;-><init>(Lpx0/g;Lay0/n;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p2, p0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public static final g(Lay0/a;Ll2/o;)V
    .locals 1

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    iget-object p1, p1, Ll2/t;->M:Lm2/b;

    .line 4
    .line 5
    iget-object p1, p1, Lm2/b;->b:Lm2/a;

    .line 6
    .line 7
    iget-object p1, p1, Lm2/a;->b:Lm2/l0;

    .line 8
    .line 9
    sget-object v0, Lm2/b0;->c:Lm2/b0;

    .line 10
    .line 11
    invoke-virtual {p1, v0}, Lm2/l0;->h(Lm2/j0;)V

    .line 12
    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-static {p1, v0, p0}, Lcom/google/android/gms/internal/measurement/c4;->e(Lm2/l0;ILjava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static final h(Ll2/o;)Lvy0/b0;
    .locals 1

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    iget-object p0, p0, Ll2/t;->R:Lpx0/g;

    .line 4
    .line 5
    new-instance v0, Ll2/c2;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Ll2/c2;-><init>(Lpx0/g;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method
