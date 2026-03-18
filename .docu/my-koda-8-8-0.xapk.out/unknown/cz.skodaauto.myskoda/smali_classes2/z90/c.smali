.class public final Lz90/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lx90/b;

.field public final b:Lz90/p;


# direct methods
.method public constructor <init>(Lx90/b;Lz90/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/c;->a:Lx90/b;

    .line 5
    .line 6
    iput-object p2, p0, Lz90/c;->b:Lz90/p;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lz90/c;->a:Lx90/b;

    .line 2
    .line 3
    iget-object v1, v0, Lx90/b;->a:Lxl0/f;

    .line 4
    .line 5
    new-instance v2, Lus0/a;

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct {v2, v0, v4, v3}, Lus0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lw81/d;

    .line 13
    .line 14
    const/16 v3, 0xd

    .line 15
    .line 16
    invoke-direct {v0, v3}, Lw81/d;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, v2, v0, v4}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    new-instance v1, Lwa0/c;

    .line 24
    .line 25
    const/16 v2, 0x10

    .line 26
    .line 27
    invoke-direct {v1, p0, v4, v2}, Lwa0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    new-instance p0, Lne0/n;

    .line 31
    .line 32
    const/4 v2, 0x5

    .line 33
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 34
    .line 35
    .line 36
    return-object p0
.end method
