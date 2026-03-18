.class public final Lcr0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lcr0/h;

.field public final b:Lcr0/b;


# direct methods
.method public constructor <init>(Lcr0/h;Lcr0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcr0/k;->a:Lcr0/h;

    .line 5
    .line 6
    iput-object p2, p0, Lcr0/k;->b:Lcr0/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v4, p0, Lcr0/k;->a:Lcr0/h;

    .line 2
    .line 3
    move-object v0, v4

    .line 4
    check-cast v0, Lar0/b;

    .line 5
    .line 6
    iget-object v7, v0, Lar0/b;->d:Lrz/k;

    .line 7
    .line 8
    iget-object v8, v0, Lar0/b;->b:Lez0/c;

    .line 9
    .line 10
    new-instance v0, La90/r;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    const/4 v2, 0x4

    .line 14
    const-class v3, Lcr0/h;

    .line 15
    .line 16
    const-string v5, "isDataValid"

    .line 17
    .line 18
    const-string v6, "isDataValid()Z"

    .line 19
    .line 20
    invoke-direct/range {v0 .. v6}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    new-instance v1, Lbq0/i;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x6

    .line 27
    invoke-direct {v1, p0, v2, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {v7, v8, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
