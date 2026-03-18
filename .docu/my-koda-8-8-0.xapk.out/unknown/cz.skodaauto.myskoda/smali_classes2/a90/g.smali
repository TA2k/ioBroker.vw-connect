.class public final La90/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:La90/q;

.field public final b:La90/u;


# direct methods
.method public constructor <init>(La90/q;La90/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La90/g;->a:La90/q;

    .line 5
    .line 6
    iput-object p2, p0, La90/g;->b:La90/u;

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
    iget-object p1, p0, La90/g;->b:La90/u;

    .line 4
    .line 5
    check-cast p1, Ly80/b;

    .line 6
    .line 7
    iget-object p2, p1, Ly80/b;->a:Lxl0/f;

    .line 8
    .line 9
    new-instance v0, Lus0/a;

    .line 10
    .line 11
    const/4 v1, 0x5

    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v0, p1, v2, v1}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Lxy/f;

    .line 17
    .line 18
    invoke-direct {p1, v1}, Lxy/f;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p2, v0, p1, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance p2, La60/f;

    .line 26
    .line 27
    const/4 v0, 0x3

    .line 28
    invoke-direct {p2, p0, v2, v0}, La60/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lne0/n;

    .line 32
    .line 33
    const/4 v0, 0x5

    .line 34
    invoke-direct {p0, p1, p2, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method
