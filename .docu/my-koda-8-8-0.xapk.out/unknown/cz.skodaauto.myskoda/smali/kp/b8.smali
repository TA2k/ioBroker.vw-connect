.class public abstract Lkp/b8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Le21/a;Lkp/a8;)V
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "module"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Lkp/a8;->b(Le21/a;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static b()Lko/f;
    .locals 4

    .line 1
    new-instance v0, Lko/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, -0x1

    .line 6
    invoke-direct {v0, v3, v3, v1, v2}, Lko/g;-><init>(IIIZ)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lko/f;

    .line 10
    .line 11
    invoke-direct {v1, v0}, Lko/f;-><init>(Lko/g;)V

    .line 12
    .line 13
    .line 14
    return-object v1
.end method
