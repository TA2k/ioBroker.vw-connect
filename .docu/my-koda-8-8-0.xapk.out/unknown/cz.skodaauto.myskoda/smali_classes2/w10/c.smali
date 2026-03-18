.class public final Lw10/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lu10/c;

.field public final b:Lw10/f;


# direct methods
.method public constructor <init>(Lu10/c;Lw10/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw10/c;->a:Lu10/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw10/c;->b:Lw10/f;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p1, p0, Lw10/c;->a:Lu10/c;

    .line 4
    .line 5
    iget-object p2, p1, Lu10/c;->a:Lxl0/f;

    .line 6
    .line 7
    new-instance v0, La90/s;

    .line 8
    .line 9
    const/16 v1, 0x1a

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-direct {v0, p1, v2, v1}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    new-instance p1, Lt40/a;

    .line 16
    .line 17
    const/16 v1, 0x1d

    .line 18
    .line 19
    invoke-direct {p1, v1}, Lt40/a;-><init>(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p2, v0, p1, v2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    new-instance p2, Lal0/i;

    .line 27
    .line 28
    const/16 v0, 0xe

    .line 29
    .line 30
    invoke-direct {p2, p1, v0}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 31
    .line 32
    .line 33
    new-instance p1, Lvu/j;

    .line 34
    .line 35
    const/4 v0, 0x5

    .line 36
    invoke-direct {p1, p0, v2, v0}, Lvu/j;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    new-instance p0, Lne0/n;

    .line 40
    .line 41
    invoke-direct {p0, p2, p1, v0}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 42
    .line 43
    .line 44
    return-object p0
.end method
