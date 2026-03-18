.class public final Lrt0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lpt0/d;

.field public final b:Lrt0/k;

.field public final c:Lkf0/z;

.field public final d:Lhu0/b;


# direct methods
.method public constructor <init>(Lpt0/d;Lrt0/k;Lkf0/z;Lhu0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrt0/j;->a:Lpt0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lrt0/j;->b:Lrt0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lrt0/j;->c:Lkf0/z;

    .line 9
    .line 10
    iput-object p4, p0, Lrt0/j;->d:Lhu0/b;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lrt0/h;)Lzy0/j;
    .locals 4

    .line 1
    iget-object v0, p0, Lrt0/j;->c:Lkf0/z;

    .line 2
    .line 3
    invoke-virtual {v0}, Lkf0/z;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    invoke-static {v0}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Le71/e;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    const/16 v3, 0xc

    .line 17
    .line 18
    invoke-direct {v1, v3, p1, v2, p0}, Le71/e;-><init>(ILjava/lang/Object;Lkotlin/coroutines/Continuation;Ltr0/d;)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Lrt0/h;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Lrt0/j;->a(Lrt0/h;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
