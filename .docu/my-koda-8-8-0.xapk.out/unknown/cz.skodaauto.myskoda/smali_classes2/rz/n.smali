.class public final Lrz/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/m;

.field public final b:Lqd0/h0;


# direct methods
.method public constructor <init>(Lwj0/m;Lqd0/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrz/n;->a:Lwj0/m;

    .line 5
    .line 6
    iput-object p2, p0, Lrz/n;->b:Lqd0/h0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lrz/n;->b:Lqd0/h0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lqd0/h0;->invoke()Ljava/lang/Object;

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
    const/4 v2, 0x0

    .line 12
    invoke-direct {v1, v0, v2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Lam0/i;

    .line 16
    .line 17
    const/16 v2, 0x18

    .line 18
    .line 19
    invoke-direct {v0, v1, v2}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    new-instance v1, Lqa0/a;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    const/16 v3, 0xa

    .line 26
    .line 27
    invoke-direct {v1, v2, p0, v3}, Lqa0/a;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method
