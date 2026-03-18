.class public final Lp00/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lro0/l;

.field public final b:Lro0/k;

.field public final c:Lz00/i;

.field public final d:Lz00/j;


# direct methods
.method public constructor <init>(Lro0/l;Lro0/k;Lz00/i;Lz00/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp00/b;->a:Lro0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lp00/b;->b:Lro0/k;

    .line 7
    .line 8
    iput-object p3, p0, Lp00/b;->c:Lz00/i;

    .line 9
    .line 10
    iput-object p4, p0, Lp00/b;->d:Lz00/j;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lp00/b;->a:Lro0/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Lro0/l;->invoke()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lyy0/i;

    .line 8
    .line 9
    new-instance v1, Lgb0/z;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/16 v3, 0x1c

    .line 13
    .line 14
    invoke-direct {v1, v2, p0, v3}, Lgb0/z;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
