.class public final Lc20/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lc20/c;

.field public final b:Lc20/b;


# direct methods
.method public constructor <init>(Lc20/c;Lc20/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc20/d;->a:Lc20/c;

    .line 5
    .line 6
    iput-object p2, p0, Lc20/d;->b:Lc20/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object v2, p0, Lc20/d;->a:Lc20/c;

    .line 4
    .line 5
    move-object p1, v2

    .line 6
    check-cast p1, La20/a;

    .line 7
    .line 8
    iget-object p2, p1, La20/a;->d:Lyy0/l1;

    .line 9
    .line 10
    iget-object p1, p1, La20/a;->b:Lez0/c;

    .line 11
    .line 12
    new-instance v0, La71/z;

    .line 13
    .line 14
    const/4 v6, 0x0

    .line 15
    const/16 v7, 0x1d

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    const-class v3, Lc20/c;

    .line 19
    .line 20
    const-string v4, "isDataValid"

    .line 21
    .line 22
    const-string v5, "isDataValid()Z"

    .line 23
    .line 24
    invoke-direct/range {v0 .. v7}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 25
    .line 26
    .line 27
    new-instance v1, La90/s;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x3

    .line 31
    invoke-direct {v1, p0, v2, v3}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    invoke-static {p2, p1, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
