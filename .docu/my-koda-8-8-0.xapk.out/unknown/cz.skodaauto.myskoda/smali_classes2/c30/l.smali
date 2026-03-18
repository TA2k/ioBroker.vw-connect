.class public final Lc30/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lc30/i;

.field public final b:Lc30/d;


# direct methods
.method public constructor <init>(Lc30/i;Lc30/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc30/l;->a:Lc30/i;

    .line 5
    .line 6
    iput-object p2, p0, Lc30/l;->b:Lc30/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v2, p0, Lc30/l;->a:Lc30/i;

    .line 2
    .line 3
    move-object v0, v2

    .line 4
    check-cast v0, La30/a;

    .line 5
    .line 6
    iget-object v8, v0, La30/a;->g:Lyy0/l1;

    .line 7
    .line 8
    iget-object v9, v0, La30/a;->k:Lez0/c;

    .line 9
    .line 10
    new-instance v0, Lc3/g;

    .line 11
    .line 12
    const/4 v6, 0x0

    .line 13
    const/4 v7, 0x3

    .line 14
    const/4 v1, 0x0

    .line 15
    const-class v3, Lc30/i;

    .line 16
    .line 17
    const-string v4, "isPrimaryUserValid"

    .line 18
    .line 19
    const-string v5, "isPrimaryUserValid()Z"

    .line 20
    .line 21
    invoke-direct/range {v0 .. v7}, Lc3/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Lbq0/i;

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    const/4 v3, 0x5

    .line 28
    invoke-direct {v1, p0, v2, v3}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v8, v9, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method
