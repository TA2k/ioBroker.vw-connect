.class public final Lf40/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ld40/n;

.field public final b:Lf40/c1;


# direct methods
.method public constructor <init>(Ld40/n;Lf40/c1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/u;->a:Ld40/n;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/u;->b:Lf40/c1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lf40/u;->b:Lf40/c1;

    .line 4
    .line 5
    check-cast p1, Ld40/e;

    .line 6
    .line 7
    iget-object p1, p1, Ld40/e;->f:Lg40/i0;

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    new-instance p0, Lne0/e;

    .line 12
    .line 13
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Lyy0/m;

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    invoke-direct {p1, p0, p2}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    return-object p1

    .line 23
    :cond_0
    iget-object p1, p0, Lf40/u;->a:Ld40/n;

    .line 24
    .line 25
    iget-object p2, p1, Ld40/n;->a:Lxl0/f;

    .line 26
    .line 27
    new-instance v0, La90/s;

    .line 28
    .line 29
    const/4 v1, 0x5

    .line 30
    const/4 v2, 0x0

    .line 31
    invoke-direct {v0, p1, v2, v1}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lck/b;

    .line 35
    .line 36
    const/16 v1, 0xe

    .line 37
    .line 38
    invoke-direct {p1, v1}, Lck/b;-><init>(I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p2, v0, p1, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance p2, Le30/p;

    .line 46
    .line 47
    const/16 v0, 0x9

    .line 48
    .line 49
    invoke-direct {p2, p0, v2, v0}, Le30/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    new-instance p0, Lne0/n;

    .line 53
    .line 54
    const/4 v0, 0x5

    .line 55
    invoke-direct {p0, p1, p2, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 56
    .line 57
    .line 58
    return-object p0
.end method
