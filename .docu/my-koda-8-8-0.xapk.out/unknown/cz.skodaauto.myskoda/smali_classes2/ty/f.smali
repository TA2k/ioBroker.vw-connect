.class public final Lty/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;

.field public final b:Lty/c;


# direct methods
.method public constructor <init>(Lbn0/g;Lty/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lty/f;->a:Lbn0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lty/f;->b:Lty/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Luy/c;)Lyy0/i;
    .locals 3

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    sget-object v1, Luy/c;->d:Luy/c;

    .line 4
    .line 5
    if-ne p1, v1, :cond_0

    .line 6
    .line 7
    const-string v2, "active-ventilation"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v2, "climate-plans"

    .line 11
    .line 12
    :goto_0
    if-ne p1, v1, :cond_1

    .line 13
    .line 14
    const-string p1, "start-stop-active-ventilation"

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    const-string p1, "set-climate-plans"

    .line 18
    .line 19
    :goto_1
    invoke-direct {v0, v2, p1}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Lty/f;->a:Lbn0/g;

    .line 23
    .line 24
    invoke-virtual {p1, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    new-instance v0, Lq10/k;

    .line 29
    .line 30
    const/16 v1, 0x9

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    invoke-direct {v0, p0, v2, v1}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    new-instance p0, Lac/l;

    .line 37
    .line 38
    invoke-direct {p0, p1, v0}, Lac/l;-><init>(Lzy0/j;Lay0/k;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Lru0/l;

    .line 42
    .line 43
    const/4 v0, 0x2

    .line 44
    const/4 v1, 0x7

    .line 45
    invoke-direct {p1, v0, v2, v1}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    new-instance v0, Lne0/n;

    .line 49
    .line 50
    invoke-direct {v0, p1, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 51
    .line 52
    .line 53
    invoke-static {v0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Luy/c;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lty/f;->a(Luy/c;)Lyy0/i;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
