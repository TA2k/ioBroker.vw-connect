.class public final Lw10/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lw10/f;

.field public final b:Lw10/c;


# direct methods
.method public constructor <init>(Lw10/f;Lw10/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw10/g;->a:Lw10/f;

    .line 5
    .line 6
    iput-object p2, p0, Lw10/g;->b:Lw10/c;

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
    iget-object v4, p0, Lw10/g;->a:Lw10/f;

    .line 4
    .line 5
    move-object p1, v4

    .line 6
    check-cast p1, Lu10/b;

    .line 7
    .line 8
    iget-object p1, p1, Lu10/b;->a:Lcom/google/firebase/messaging/w;

    .line 9
    .line 10
    iget-object p2, p1, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p2, Lyy0/k1;

    .line 13
    .line 14
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Lez0/c;

    .line 17
    .line 18
    new-instance v0, La90/r;

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    const/16 v2, 0x1a

    .line 22
    .line 23
    const-class v3, Lw10/f;

    .line 24
    .line 25
    const-string v5, "isDataValid"

    .line 26
    .line 27
    const-string v6, "isDataValid()Z"

    .line 28
    .line 29
    invoke-direct/range {v0 .. v6}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Lus0/a;

    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    const/4 v3, 0x1

    .line 36
    invoke-direct {v1, p0, v2, v3}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p2, p1, v0, v1}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
