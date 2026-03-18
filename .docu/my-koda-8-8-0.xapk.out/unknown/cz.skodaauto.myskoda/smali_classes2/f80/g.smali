.class public final Lf80/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf80/f;

.field public final b:Lf80/c;


# direct methods
.method public constructor <init>(Lf80/f;Lf80/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf80/g;->a:Lf80/f;

    .line 5
    .line 6
    iput-object p2, p0, Lf80/g;->b:Lf80/c;

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
    iget-object v4, p0, Lf80/g;->a:Lf80/f;

    .line 4
    .line 5
    move-object p1, v4

    .line 6
    check-cast p1, Le80/a;

    .line 7
    .line 8
    iget-object p2, p1, Le80/a;->f:Lyy0/l1;

    .line 9
    .line 10
    iget-object p1, p1, Le80/a;->b:Lez0/c;

    .line 11
    .line 12
    new-instance v0, La90/r;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    const/16 v2, 0xc

    .line 16
    .line 17
    const-class v3, Lf80/f;

    .line 18
    .line 19
    const-string v5, "isDataValid"

    .line 20
    .line 21
    const-string v6, "isDataValid()Z"

    .line 22
    .line 23
    invoke-direct/range {v0 .. v6}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lbq0/i;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    const/16 v3, 0xf

    .line 30
    .line 31
    invoke-direct {v1, p0, v2, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

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
