.class public final Lok0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lok0/d;

.field public final b:Lok0/g;


# direct methods
.method public constructor <init>(Lok0/d;Lok0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lok0/e;->a:Lok0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lok0/e;->b:Lok0/g;

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
    iget-object p1, p0, Lok0/e;->b:Lok0/g;

    .line 4
    .line 5
    invoke-virtual {p1}, Lok0/g;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lyy0/i;

    .line 10
    .line 11
    new-instance p2, Lal0/m0;

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    const/16 v1, 0x14

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-direct {p2, v0, v2, v1}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Lne0/n;

    .line 21
    .line 22
    invoke-direct {v0, p2, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, p0, Lok0/e;->a:Lok0/d;

    .line 26
    .line 27
    invoke-virtual {p0}, Lok0/d;->invoke()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lyy0/i;

    .line 32
    .line 33
    new-instance p1, Lal0/y0;

    .line 34
    .line 35
    const/4 p2, 0x3

    .line 36
    const/16 v1, 0x11

    .line 37
    .line 38
    invoke-direct {p1, p2, v2, v1}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    new-instance p2, Lbn0/f;

    .line 42
    .line 43
    const/4 v1, 0x5

    .line 44
    invoke-direct {p2, v0, p0, p1, v1}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 45
    .line 46
    .line 47
    return-object p2
.end method
