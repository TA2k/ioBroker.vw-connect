.class public final Lzo0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lkf0/o;

.field public final b:Lzo0/i;

.field public final c:Lwo0/e;

.field public final d:Lzo0/l;


# direct methods
.method public constructor <init>(Lkf0/o;Lzo0/i;Lwo0/e;Lzo0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo0/d;->a:Lkf0/o;

    .line 5
    .line 6
    iput-object p2, p0, Lzo0/d;->b:Lzo0/i;

    .line 7
    .line 8
    iput-object p3, p0, Lzo0/d;->c:Lwo0/e;

    .line 9
    .line 10
    iput-object p4, p0, Lzo0/d;->d:Lzo0/l;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lzo0/d;->a:Lkf0/o;

    .line 2
    .line 3
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lal0/f;

    .line 8
    .line 9
    const/16 v2, 0x8

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, v3, p0, v2}, Lal0/f;-><init>(Lkotlin/coroutines/Continuation;Ltr0/d;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v1, Lwa0/c;

    .line 20
    .line 21
    const/16 v2, 0x14

    .line 22
    .line 23
    invoke-direct {v1, p0, v3, v2}, Lwa0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    new-instance p0, Lne0/n;

    .line 27
    .line 28
    const/4 v2, 0x5

    .line 29
    invoke-direct {p0, v0, v1, v2}, Lne0/n;-><init>(Lyy0/i;Lay0/n;I)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method
