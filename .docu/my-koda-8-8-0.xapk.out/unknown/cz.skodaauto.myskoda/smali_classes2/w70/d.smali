.class public final Lw70/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lu70/c;

.field public final b:Lfg0/d;


# direct methods
.method public constructor <init>(Lu70/c;Lfg0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw70/d;->a:Lu70/c;

    .line 5
    .line 6
    iput-object p2, p0, Lw70/d;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lw70/d;->b:Lfg0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lrz/k;

    .line 10
    .line 11
    const/16 v2, 0x15

    .line 12
    .line 13
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 14
    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    invoke-static {v1, v0}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lqa0/a;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    const/16 v3, 0x17

    .line 25
    .line 26
    invoke-direct {v1, v2, p0, v3}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method
