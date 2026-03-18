.class public final Lu30/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lu30/a;

.field public final b:Lkf0/o;


# direct methods
.method public constructor <init>(Lu30/a;Lkf0/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu30/h0;->a:Lu30/a;

    .line 5
    .line 6
    iput-object p2, p0, Lu30/h0;->b:Lkf0/o;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

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
    new-instance v1, Lbp0/g;

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    const/16 v3, 0x9

    .line 13
    .line 14
    invoke-direct {v1, p0, v0, v2, v3}, Lbp0/g;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    new-instance p0, Lyy0/m1;

    .line 18
    .line 19
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method
