.class public final Ln50/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwr0/i;

.field public final i:Ll50/n;

.field public final j:Ll50/o;


# direct methods
.method public constructor <init>(Lwr0/i;Ll50/n;Ll50/o;)V
    .locals 4

    .line 1
    new-instance v0, Ln50/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    new-instance v2, Llx0/l;

    .line 9
    .line 10
    invoke-direct {v2, v1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v0, v1, v3, v2}, Ln50/d;-><init>(Ljava/lang/String;ZLlx0/l;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Ln50/e;->h:Lwr0/i;

    .line 22
    .line 23
    iput-object p2, p0, Ln50/e;->i:Ll50/n;

    .line 24
    .line 25
    iput-object p3, p0, Ln50/e;->j:Ll50/o;

    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Ln50/c;

    .line 32
    .line 33
    const/4 p3, 0x0

    .line 34
    invoke-direct {p2, p0, v1, p3}, Ln50/c;-><init>(Ln50/e;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p3, 0x3

    .line 38
    invoke-static {p1, v1, v1, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance p2, Ln50/c;

    .line 46
    .line 47
    const/4 v0, 0x1

    .line 48
    invoke-direct {p2, p0, v1, v0}, Ln50/c;-><init>(Ln50/e;Lkotlin/coroutines/Continuation;I)V

    .line 49
    .line 50
    .line 51
    invoke-static {p1, v1, v1, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 52
    .line 53
    .line 54
    new-instance p1, Ln50/c;

    .line 55
    .line 56
    const/4 p2, 0x2

    .line 57
    invoke-direct {p1, p0, v1, p2}, Ln50/c;-><init>(Ln50/e;Lkotlin/coroutines/Continuation;I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method
