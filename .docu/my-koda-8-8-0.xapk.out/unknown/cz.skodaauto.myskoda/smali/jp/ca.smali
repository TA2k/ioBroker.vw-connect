.class public abstract Ljp/ca;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ln71/a;JLay0/a;)V
    .locals 1

    .line 1
    const-string v0, "$this$dispatchToIOThread"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p2}, Lmy0/c;->e(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    invoke-interface {p0, p1, p2, p3}, Ln71/a;->dispatchToIOThread(JLay0/a;)Ln71/b;

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static final b(Ln71/a;JLay0/a;)Ln71/b;
    .locals 1

    .line 1
    const-string v0, "$this$dispatchToRPAThread"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "function"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1, p2}, Lmy0/c;->e(J)J

    .line 12
    .line 13
    .line 14
    move-result-wide p1

    .line 15
    invoke-interface {p0, p1, p2, p3}, Ln71/a;->dispatchToRPAThread(JLay0/a;)Ln71/b;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public static final c(Lx2/s;F)Lx2/s;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v0, p1, v0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return-object p0

    .line 7
    :cond_0
    const/4 v6, 0x0

    .line 8
    const v7, 0x7feff

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x0

    .line 14
    move-object v1, p0

    .line 15
    move v5, p1

    .line 16
    invoke-static/range {v1 .. v7}, Landroidx/compose/ui/graphics/a;->c(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
