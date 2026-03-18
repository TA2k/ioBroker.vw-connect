.class public abstract Landroidx/lifecycle/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroidx/lifecycle/g1;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/lifecycle/g1;

    .line 5
    .line 6
    invoke-direct {v0}, Landroidx/lifecycle/g1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Landroidx/lifecycle/r;->a:Landroidx/lifecycle/g1;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public abstract a(Landroidx/lifecycle/w;)V
.end method

.method public abstract b()Landroidx/lifecycle/q;
.end method

.method public c()Lyy0/l1;
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    new-instance v1, Landroidx/lifecycle/m;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-direct {v1, v0, v2}, Landroidx/lifecycle/m;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v1}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 16
    .line 17
    .line 18
    new-instance p0, Lyy0/l1;

    .line 19
    .line 20
    invoke-direct {p0, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public abstract d(Landroidx/lifecycle/w;)V
.end method
