.class public final Luo0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lro0/o;


# direct methods
.method public constructor <init>(Lro0/o;)V
    .locals 1

    .line 1
    sget-object v0, Luo0/a;->a:Luo0/a;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Luo0/b;->h:Lro0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final h(Lto0/l;)V
    .locals 4

    .line 1
    const-string v0, "powerpassFlow"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Ltz/o2;

    .line 11
    .line 12
    const/16 v2, 0xf

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v1, v2, p0, p1, v3}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x3

    .line 19
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    return-void
.end method
