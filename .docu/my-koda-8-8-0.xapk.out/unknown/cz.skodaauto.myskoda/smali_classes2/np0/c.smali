.class public final Lnp0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;

.field public final c:Lti0/a;

.field public final d:Lti0/a;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;Lti0/a;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnp0/c;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lnp0/c;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lnp0/c;->c:Lti0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lnp0/c;->d:Lti0/a;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/util/List;Lqp0/s;)Lyy0/m1;
    .locals 7

    .line 1
    new-instance v0, Ld40/k;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/16 v6, 0x9

    .line 5
    .line 6
    move-object v1, p0

    .line 7
    move-object v2, p1

    .line 8
    move-object v3, p2

    .line 9
    move-object v4, p3

    .line 10
    invoke-direct/range {v0 .. v6}, Ld40/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lnh/i;

    .line 14
    .line 15
    const/4 p1, 0x3

    .line 16
    invoke-direct {p0, p1}, Lnh/i;-><init>(I)V

    .line 17
    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    iget-object p2, v1, Lnp0/c;->a:Lxl0/f;

    .line 21
    .line 22
    invoke-virtual {p2, v0, p0, p1}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
