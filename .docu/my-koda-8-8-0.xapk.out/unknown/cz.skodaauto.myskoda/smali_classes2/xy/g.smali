.class public final Lxy/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxy/g;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lxy/g;->b:Lti0/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Laz/i;Ljava/lang/String;Lqp0/r;)Lyy0/m1;
    .locals 7

    .line 1
    const-string v0, "query"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "routeSettings"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ld40/k;

    .line 12
    .line 13
    const/4 v6, 0x0

    .line 14
    move-object v2, p0

    .line 15
    move-object v3, p1

    .line 16
    move-object v4, p2

    .line 17
    move-object v5, p3

    .line 18
    invoke-direct/range {v1 .. v6}, Ld40/k;-><init>(Lxy/g;Laz/i;Ljava/lang/String;Lqp0/r;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Lxy/f;

    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    invoke-direct {p0, p1}, Lxy/f;-><init>(I)V

    .line 25
    .line 26
    .line 27
    const/4 p1, 0x0

    .line 28
    iget-object p2, v2, Lxy/g;->a:Lxl0/f;

    .line 29
    .line 30
    invoke-virtual {p2, v1, p0, p1}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
