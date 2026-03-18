.class public final Lf40/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/k;

.field public final b:Lro0/j;

.field public final c:Lro0/l;


# direct methods
.method public constructor <init>(Lro0/k;Lro0/j;Lro0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/b;->a:Lro0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/b;->b:Lro0/j;

    .line 7
    .line 8
    iput-object p3, p0, Lf40/b;->c:Lro0/l;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lf40/b;->a:Lro0/k;

    .line 2
    .line 3
    invoke-virtual {v0}, Lro0/k;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object v1, p0, Lf40/b;->b:Lro0/j;

    .line 10
    .line 11
    invoke-virtual {v1}, Lro0/j;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lyy0/i;

    .line 16
    .line 17
    iget-object v2, p0, Lf40/b;->c:Lro0/l;

    .line 18
    .line 19
    invoke-virtual {v2}, Lro0/l;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lyy0/i;

    .line 24
    .line 25
    new-instance v3, Lf40/a;

    .line 26
    .line 27
    const/4 v4, 0x4

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    invoke-direct {v3, v4, v6, v5}, Lf40/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {v0, v1, v2, v3}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    new-instance v1, La90/c;

    .line 38
    .line 39
    const/16 v2, 0x17

    .line 40
    .line 41
    invoke-direct {v1, v6, p0, v2}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method
