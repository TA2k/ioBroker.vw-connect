.class public final Lk60/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lzo0/d;

.field public final b:Lzo0/l;


# direct methods
.method public constructor <init>(Lzo0/d;Lzo0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk60/a;->a:Lzo0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lk60/a;->b:Lzo0/l;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk60/a;->b:Lzo0/l;

    .line 2
    .line 3
    check-cast v0, Lwo0/b;

    .line 4
    .line 5
    iget-object v0, v0, Lwo0/b;->b:Lrz/k;

    .line 6
    .line 7
    new-instance v1, Lk31/t;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/4 v3, 0x6

    .line 11
    invoke-direct {v1, p0, v2, v3}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance p0, Lne0/n;

    .line 15
    .line 16
    invoke-direct {p0, v1, v0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
