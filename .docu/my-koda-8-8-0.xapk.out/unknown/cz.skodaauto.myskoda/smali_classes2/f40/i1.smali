.class public final Lf40/i1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/z0;

.field public final b:Lf40/r;


# direct methods
.method public constructor <init>(Lf40/z0;Lf40/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/i1;->a:Lf40/z0;

    .line 5
    .line 6
    iput-object p2, p0, Lf40/i1;->b:Lf40/r;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object v4, p0, Lf40/i1;->a:Lf40/z0;

    .line 4
    .line 5
    move-object p1, v4

    .line 6
    check-cast p1, Ld40/b;

    .line 7
    .line 8
    iget-object p2, p1, Ld40/b;->e:Lyy0/l1;

    .line 9
    .line 10
    iget-object p1, p1, Ld40/b;->c:Lez0/c;

    .line 11
    .line 12
    new-instance v0, La90/r;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/4 v2, 0x7

    .line 16
    const-class v3, Lf40/z0;

    .line 17
    .line 18
    const-string v5, "isDataValid"

    .line 19
    .line 20
    const-string v6, "isDataValid()Z"

    .line 21
    .line 22
    invoke-direct/range {v0 .. v6}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    new-instance v1, Lbq0/i;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const/16 v3, 0xa

    .line 29
    .line 30
    invoke-direct {v1, p0, v2, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p2, p1, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
