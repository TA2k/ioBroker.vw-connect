.class public final Lf40/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lf40/c1;

.field public final b:Ld40/n;


# direct methods
.method public constructor <init>(Ld40/n;Lf40/c1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lf40/m;->a:Lf40/c1;

    .line 5
    .line 6
    iput-object p1, p0, Lf40/m;->b:Ld40/n;

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
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    new-instance v1, Le1/e;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/16 v3, 0xc

    .line 9
    .line 10
    invoke-direct {v1, v3, v0, p0, v2}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    new-instance p0, Lyy0/m1;

    .line 14
    .line 15
    invoke-direct {p0, v1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 16
    .line 17
    .line 18
    return-object p0
.end method
