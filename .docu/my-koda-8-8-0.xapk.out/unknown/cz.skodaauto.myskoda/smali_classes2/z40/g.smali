.class public final Lz40/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/s0;

.field public final b:Lwj0/r;


# direct methods
.method public constructor <init>(Lal0/s0;Lwj0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz40/g;->a:Lal0/s0;

    .line 5
    .line 6
    iput-object p2, p0, Lz40/g;->b:Lwj0/r;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lz40/g;->a:Lal0/s0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lal0/s0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object p0, p0, Lz40/g;->b:Lwj0/r;

    .line 10
    .line 11
    invoke-virtual {p0}, Lwj0/r;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lyy0/i;

    .line 16
    .line 17
    new-instance v1, Lru0/l;

    .line 18
    .line 19
    const/4 v2, 0x2

    .line 20
    const/16 v3, 0x1a

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-direct {v1, v2, v4, v3}, Lru0/l;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    new-instance v2, Lne0/n;

    .line 27
    .line 28
    invoke-direct {v2, v1, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lal0/y0;

    .line 32
    .line 33
    const/4 v1, 0x3

    .line 34
    const/16 v3, 0x1d

    .line 35
    .line 36
    invoke-direct {p0, v1, v4, v3}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    new-instance v1, Lbn0/f;

    .line 40
    .line 41
    const/4 v3, 0x5

    .line 42
    invoke-direct {v1, v0, v2, p0, v3}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 43
    .line 44
    .line 45
    return-object v1
.end method
