.class public final Lkf0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lif0/u;

.field public final b:Lif0/f0;


# direct methods
.method public constructor <init>(Lif0/u;Lif0/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkf0/l0;->a:Lif0/u;

    .line 5
    .line 6
    iput-object p2, p0, Lkf0/l0;->b:Lif0/f0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lkf0/k0;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lkf0/l0;->a:Lif0/u;

    .line 7
    .line 8
    iget-object p1, v2, Lif0/u;->a:Lxl0/f;

    .line 9
    .line 10
    new-instance v0, La30/b;

    .line 11
    .line 12
    const/16 v1, 0x13

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x0

    .line 17
    invoke-direct/range {v0 .. v5}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 18
    .line 19
    .line 20
    new-instance p2, Li70/q;

    .line 21
    .line 22
    const/16 v1, 0x17

    .line 23
    .line 24
    invoke-direct {p2, v1}, Li70/q;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, v0, p2, v5}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lk31/t;

    .line 32
    .line 33
    const/16 v0, 0xb

    .line 34
    .line 35
    invoke-direct {p2, p0, v5, v0}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {p2, p1}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method
