.class public final Lk80/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lj80/d;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Lj80/d;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk80/c;->a:Lj80/d;

    .line 5
    .line 6
    iput-object p2, p0, Lk80/c;->b:Lkf0/o;

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
    check-cast v0, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-object v1, p0, Lk80/c;->b:Lkf0/o;

    .line 10
    .line 11
    invoke-static {v1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    new-instance v2, Lk70/h;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x1

    .line 19
    invoke-direct {v2, p0, v0, v3, v4}, Lk70/h;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    invoke-static {v1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
