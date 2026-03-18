.class public final Lk70/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/x;

.field public final b:Lk70/k;


# direct methods
.method public constructor <init>(Lk70/x;Lk70/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/k0;->a:Lk70/x;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/k0;->b:Lk70/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk70/k0;->a:Lk70/x;

    .line 2
    .line 3
    check-cast v0, Li70/c;

    .line 4
    .line 5
    iget-object v0, v0, Li70/c;->d:Lyy0/l1;

    .line 6
    .line 7
    new-instance v1, Lgb0/z;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const/16 v3, 0x9

    .line 11
    .line 12
    invoke-direct {v1, v2, p0, v3}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
