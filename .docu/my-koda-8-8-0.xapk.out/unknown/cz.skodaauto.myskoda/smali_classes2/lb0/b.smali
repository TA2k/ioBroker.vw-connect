.class public final Llb0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ljb0/x;

.field public final b:Ljb0/e0;

.field public final c:Lkf0/z;


# direct methods
.method public constructor <init>(Ljb0/x;Ljb0/e0;Lkf0/z;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llb0/b;->a:Ljb0/x;

    .line 5
    .line 6
    iput-object p2, p0, Llb0/b;->b:Ljb0/e0;

    .line 7
    .line 8
    iput-object p3, p0, Llb0/b;->c:Lkf0/z;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Llb0/a;)Lzy0/j;
    .locals 4

    .line 1
    iget-object v0, p0, Llb0/b;->c:Lkf0/z;

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
    new-instance v1, Lac/k;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    const/16 v3, 0x16

    .line 17
    .line 18
    invoke-direct {v1, v3, p0, p1, v2}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

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
    check-cast v0, Llb0/a;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Llb0/b;->a(Llb0/a;)Lzy0/j;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
