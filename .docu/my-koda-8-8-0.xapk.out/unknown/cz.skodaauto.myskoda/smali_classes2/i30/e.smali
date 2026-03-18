.class public final Li30/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Li30/d;

.field public final b:Li30/a;


# direct methods
.method public constructor <init>(Li30/d;Li30/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li30/e;->a:Li30/d;

    .line 5
    .line 6
    iput-object p2, p0, Li30/e;->b:Li30/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Li30/e;->a:Li30/d;

    .line 2
    .line 3
    check-cast v0, Lg30/a;

    .line 4
    .line 5
    iget-object v1, v0, Lg30/a;->e:Lyy0/c2;

    .line 6
    .line 7
    iget-object v0, v0, Lg30/a;->b:Lez0/c;

    .line 8
    .line 9
    new-instance v2, Lh50/q0;

    .line 10
    .line 11
    const/4 v3, 0x7

    .line 12
    invoke-direct {v2, p0, v3}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    new-instance v3, Lbq0/i;

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    const/16 v5, 0x12

    .line 19
    .line 20
    invoke-direct {v3, p0, v4, v5}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {v1, v0, v2, v3}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
