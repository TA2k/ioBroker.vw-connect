.class public abstract Ls7/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Landroidx/lifecycle/x;)Ls7/c;
    .locals 2

    .line 1
    new-instance v0, Ls7/c;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Landroidx/lifecycle/i1;

    .line 5
    .line 6
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, p0, v1}, Ls7/c;-><init>(Landroidx/lifecycle/x;Landroidx/lifecycle/h1;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
