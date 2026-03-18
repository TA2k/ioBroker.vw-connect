.class public final Lxo0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lzo0/o;


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;

.field public final c:Lyy0/q1;

.field public final d:Lyy0/q1;


# direct methods
.method public constructor <init>()V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    const/4 v1, 0x5

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iput-object v3, p0, Lxo0/a;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v4, Lyy0/k1;

    .line 14
    .line 15
    invoke-direct {v4, v3}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 16
    .line 17
    .line 18
    iput-object v4, p0, Lxo0/a;->b:Lyy0/k1;

    .line 19
    .line 20
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    iput-object v3, p0, Lxo0/a;->c:Lyy0/q1;

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Lxo0/a;->d:Lyy0/q1;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final a()Lyy0/h2;
    .locals 4

    .line 1
    new-instance v0, Lyy0/k1;

    .line 2
    .line 3
    iget-object v1, p0, Lxo0/a;->c:Lyy0/q1;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lxm0/g;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x1

    .line 12
    invoke-direct {v1, p0, v2, v3}, Lxm0/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    new-instance p0, Lyy0/h2;

    .line 16
    .line 17
    invoke-direct {p0, v0, v1}, Lyy0/h2;-><init>(Lyy0/n1;Lay0/n;)V

    .line 18
    .line 19
    .line 20
    return-object p0
.end method
