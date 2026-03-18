.class public final Lqd0/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lqd0/o0;

.field public final b:Lqd0/k0;


# direct methods
.method public constructor <init>(Lqd0/o0;Lqd0/k0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqd0/p0;->a:Lqd0/o0;

    .line 5
    .line 6
    iput-object p2, p0, Lqd0/p0;->b:Lqd0/k0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lqd0/p0;->a:Lqd0/o0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lqd0/o0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object p0, p0, Lqd0/p0;->b:Lqd0/k0;

    .line 10
    .line 11
    invoke-virtual {p0}, Lqd0/k0;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lyy0/i;

    .line 16
    .line 17
    new-instance v1, Lg1/d2;

    .line 18
    .line 19
    const/4 v2, 0x2

    .line 20
    const/4 v3, 0x3

    .line 21
    const/4 v4, 0x0

    .line 22
    invoke-direct {v1, v2, v4, v3}, Lg1/d2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    new-instance v2, Lne0/n;

    .line 26
    .line 27
    invoke-direct {v2, v1, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 28
    .line 29
    .line 30
    new-instance p0, Lh40/u2;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    const/4 v3, 0x1

    .line 34
    invoke-direct {p0, v1, v4, v3}, Lh40/u2;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lbn0/f;

    .line 38
    .line 39
    const/4 v3, 0x5

    .line 40
    invoke-direct {v1, v0, v2, p0, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method
