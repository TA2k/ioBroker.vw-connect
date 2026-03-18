.class public final Lpp0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpp0/d0;

.field public final b:Lpp0/b0;


# direct methods
.method public constructor <init>(Lpp0/d0;Lpp0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/l0;->a:Lpp0/d0;

    .line 5
    .line 6
    iput-object p2, p0, Lpp0/l0;->b:Lpp0/b0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lpp0/l0;->a:Lpp0/d0;

    .line 2
    .line 3
    check-cast v0, Lnp0/g;

    .line 4
    .line 5
    iget-object v0, v0, Lnp0/g;->b:Lyy0/m1;

    .line 6
    .line 7
    iget-object p0, p0, Lpp0/l0;->b:Lpp0/b0;

    .line 8
    .line 9
    check-cast p0, Lnp0/a;

    .line 10
    .line 11
    iget-object v1, p0, Lnp0/a;->b:Lyy0/l1;

    .line 12
    .line 13
    iget-object p0, p0, Lnp0/a;->d:Lyy0/l1;

    .line 14
    .line 15
    new-instance v2, Lf40/a;

    .line 16
    .line 17
    const/4 v3, 0x4

    .line 18
    const/4 v4, 0x2

    .line 19
    const/4 v5, 0x0

    .line 20
    invoke-direct {v2, v3, v5, v4}, Lf40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {v0, v1, p0, v2}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
