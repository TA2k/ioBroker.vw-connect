.class public final Lk70/n0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/y;

.field public final b:Lk70/m;


# direct methods
.method public constructor <init>(Lk70/y;Lk70/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/n0;->a:Lk70/y;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/n0;->b:Lk70/m;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lk70/n0;->a:Lk70/y;

    .line 10
    .line 11
    check-cast v1, Li70/n;

    .line 12
    .line 13
    iget-object v1, v1, Li70/n;->c:Lyy0/l1;

    .line 14
    .line 15
    new-instance v2, La7/y0;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x4

    .line 19
    invoke-direct {v2, p0, v0, v3, v4}, La7/y0;-><init>(Ljava/lang/Object;ILkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lne0/n;

    .line 23
    .line 24
    invoke-direct {p0, v2, v1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method
