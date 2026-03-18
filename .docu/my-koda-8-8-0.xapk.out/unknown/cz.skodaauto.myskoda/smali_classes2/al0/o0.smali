.class public final Lal0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/p0;

.field public final b:Lal0/s0;

.field public final c:Lwj0/r;


# direct methods
.method public constructor <init>(Lal0/p0;Lal0/s0;Lwj0/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/o0;->a:Lal0/p0;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/o0;->b:Lal0/s0;

    .line 7
    .line 8
    iput-object p3, p0, Lal0/o0;->c:Lwj0/r;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lal0/o0;->a:Lal0/p0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lal0/p0;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    iget-object v1, p0, Lal0/o0;->b:Lal0/s0;

    .line 10
    .line 11
    invoke-virtual {v1}, Lal0/s0;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lyy0/i;

    .line 16
    .line 17
    iget-object p0, p0, Lal0/o0;->c:Lwj0/r;

    .line 18
    .line 19
    invoke-virtual {p0}, Lwj0/r;->invoke()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lyy0/i;

    .line 24
    .line 25
    new-instance v2, Lal0/m0;

    .line 26
    .line 27
    const/4 v3, 0x2

    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-direct {v2, v3, v5, v4}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    new-instance v3, Lne0/n;

    .line 34
    .line 35
    invoke-direct {v3, v2, p0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 36
    .line 37
    .line 38
    new-instance p0, Lal0/n0;

    .line 39
    .line 40
    const/4 v2, 0x4

    .line 41
    invoke-direct {p0, v2, v5, v4}, Lal0/n0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v0, v1, v3, p0}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method
