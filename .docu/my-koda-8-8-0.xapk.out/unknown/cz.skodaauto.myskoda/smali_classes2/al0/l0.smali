.class public final Lal0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lal0/a0;


# direct methods
.method public constructor <init>(Lal0/a0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/l0;->a:Lal0/a0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lal0/l0;->a:Lal0/a0;

    .line 2
    .line 3
    check-cast v0, Lyk0/b;

    .line 4
    .line 5
    iget-object v0, v0, Lyk0/b;->b:Lyy0/l1;

    .line 6
    .line 7
    new-instance v1, Lrz/k;

    .line 8
    .line 9
    const/16 v2, 0x15

    .line 10
    .line 11
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 12
    .line 13
    .line 14
    new-instance v0, La90/c;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v3, 0x3

    .line 18
    invoke-direct {v0, v2, p0, v3}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance v0, Lal0/j0;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {v0, p0, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method
