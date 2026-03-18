.class public final Lal0/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lml0/e;

.field public final b:Lyk0/q;


# direct methods
.method public constructor <init>(Lml0/e;Lyk0/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/u;->a:Lml0/e;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/u;->b:Lyk0/q;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lal0/s;)Lzy0/j;
    .locals 4

    .line 1
    iget-boolean v0, p1, Lal0/s;->c:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, p0, Lal0/u;->a:Lml0/e;

    .line 7
    .line 8
    invoke-virtual {v0}, Lml0/e;->invoke()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    check-cast v0, Lyy0/i;

    .line 13
    .line 14
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    new-instance v2, Lal0/i;

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    invoke-direct {v2, v0, v3}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lne0/e;

    .line 26
    .line 27
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    new-instance v2, Lyy0/m;

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-direct {v2, v0, v3}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    new-instance v0, Lac/k;

    .line 37
    .line 38
    const/4 v3, 0x2

    .line 39
    invoke-direct {v0, v3, p0, p1, v1}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v2, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lal0/s;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lal0/u;->a(Lal0/s;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
