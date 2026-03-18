.class public final Ll50/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Ll50/d;

.field public final b:Lal0/l1;


# direct methods
.method public constructor <init>(Ll50/d;Lal0/l1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll50/a0;->a:Ll50/d;

    .line 5
    .line 6
    iput-object p2, p0, Ll50/a0;->b:Lal0/l1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Ll50/a0;->a:Ll50/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll50/d;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lk20/a;

    .line 10
    .line 11
    const/16 v2, 0x9

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v1, p0, v3, v2}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lne0/n;

    .line 18
    .line 19
    invoke-direct {v2, v1, v0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 20
    .line 21
    .line 22
    new-instance v0, Lkn/o;

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    invoke-direct {v0, p0, v3, v1}, Lkn/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    new-instance p0, Lyy0/x;

    .line 29
    .line 30
    invoke-direct {p0, v2, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 31
    .line 32
    .line 33
    return-object p0
.end method
