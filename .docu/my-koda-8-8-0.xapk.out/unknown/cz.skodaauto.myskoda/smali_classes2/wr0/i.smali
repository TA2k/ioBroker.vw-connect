.class public final Lwr0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwr0/g;

.field public final b:Lwr0/c;


# direct methods
.method public constructor <init>(Lwr0/g;Lwr0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwr0/i;->a:Lwr0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lwr0/i;->b:Lwr0/c;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Lyy0/i;
    .locals 9

    .line 1
    iget-object v4, p0, Lwr0/i;->a:Lwr0/g;

    .line 2
    .line 3
    move-object v0, v4

    .line 4
    check-cast v0, Lur0/g;

    .line 5
    .line 6
    iget-object v7, v0, Lur0/g;->d:Lal0/i;

    .line 7
    .line 8
    iget-object v8, v0, Lur0/g;->c:Lez0/c;

    .line 9
    .line 10
    new-instance v0, La90/r;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    const/16 v2, 0x1b

    .line 14
    .line 15
    const-class v3, Lwr0/g;

    .line 16
    .line 17
    const-string v5, "isUserValid"

    .line 18
    .line 19
    const-string v6, "isUserValid()Z"

    .line 20
    .line 21
    invoke-direct/range {v0 .. v6}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lq10/k;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    const/16 v3, 0xc

    .line 28
    .line 29
    invoke-direct {v1, p0, v2, v3}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    invoke-static {v7, v8, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lwr0/i;->a()Lyy0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
