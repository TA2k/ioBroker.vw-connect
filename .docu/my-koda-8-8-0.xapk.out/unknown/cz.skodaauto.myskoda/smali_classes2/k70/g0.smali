.class public final Lk70/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/y;

.field public final b:Lk70/v;

.field public final c:Lk70/g;


# direct methods
.method public constructor <init>(Lk70/y;Lk70/v;Lk70/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/g0;->a:Lk70/y;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/g0;->b:Lk70/v;

    .line 7
    .line 8
    iput-object p3, p0, Lk70/g0;->c:Lk70/g;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lk70/g0;->a:Lk70/y;

    .line 2
    .line 3
    check-cast v0, Li70/n;

    .line 4
    .line 5
    iget-object v0, v0, Li70/n;->c:Lyy0/l1;

    .line 6
    .line 7
    new-instance v1, Lac/l;

    .line 8
    .line 9
    const/16 v2, 0x14

    .line 10
    .line 11
    invoke-direct {v1, v2, v0, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lk20/a;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v3, 0x5

    .line 18
    invoke-direct {v0, p0, v2, v3}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Lne0/n;

    .line 22
    .line 23
    invoke-direct {p0, v0, v1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method
